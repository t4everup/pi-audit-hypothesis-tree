/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/tools.ts
 *
 * The agent-facing tool surface.
 *
 * -----------------------------------------------------------------------
 * The division of labour these tools encode
 * -----------------------------------------------------------------------
 *
 * The model is good at: forming a falsifiable hypothesis, deciding which
 * mechanical fact would refute it, and judging what the result means.
 *
 * The model is bad at: remembering the tree across a long session, respecting
 * an anti-tunnelling limit it cannot see, and being trusted to mark its own
 * work correct.
 *
 * So the tools are split along that line:
 *
 *   hypothesis_next     the SCHEDULER picks, not the model — the model cannot
 *                       choose to tunnel because it does not choose
 *   hypothesis_verify   the EXECUTOR collects evidence; the model supplies the
 *                       falsification attempt, never the verdict
 *   hypothesis_record   the only way to change a status, and it refuses a
 *                       verdict with no evidence
 *   hypothesis_add      growth, with the same assertion-shape gate
 *   hypothesis_status   read-only
 *
 * There is deliberately NO tool that can set `allowCommandProbes`. Consent for
 * running commands is a human decision (`/hypothesis config`), and a model that
 * could grant it to itself would make the gate decorative.
 */

import { defineTool, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import type { Evidence, EvidenceKind, HypothesisStatus, Severity } from "./types.js";
import { EVIDENCE_KINDS } from "./types.js";
import { load } from "./store.js";
import { addEvidence, addNode, createTree, getNode, setStatus } from "./tree.js";
import { applySelection, planNextRound, renderDecision } from "./scheduler.js";
import {
  CONSOLIDATION,
  applyCombination,
  applyConsolidation,
  consolidationStatus,
  planConsolidation,
  renderConsolidation,
} from "./combination.js";
import { loadSettings } from "./settings.js";
import {
  type CommandProbe,
  type GrepProbe,
  type LocationProbe,
  type Probe,
  renderOutcome,
  runVerification,
  verificationRefusal,
} from "./executor.js";
import { renderSummary, clip } from "./render.js";

// -----------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------

function text(value: string, details: Record<string, unknown> = {}): { content: Array<{ type: "text"; text: string }>; details: Record<string, unknown> } {
  return { content: [{ type: "text", text: value }], details };
}

/** Every tool resolves the project from the invocation context, never from a
 * captured registration-time value. */
function projectRootOf(ctx: ExtensionContext): string {
  return ctx.cwd;
}

// -----------------------------------------------------------------
// Probe parameter normalization
// -----------------------------------------------------------------

/** The flat probe shape the model fills in. */
export interface ProbeParams {
  kind: "location" | "grep" | "command";
  file?: string;
  line?: number;
  pattern?: string;
  expectation?: "present" | "absent";
  subPath?: string;
  ignoreCase?: boolean;
  command?: string;
  args?: string[];
  expectExit?: "zero" | "nonzero";
  timeoutMs?: number;
  note?: string;
}

/**
 * Validate and convert the model's flat probe objects.
 *
 * A malformed probe is REJECTED with a specific message rather than dropped: a
 * silently skipped probe would make an "all probes held" result a lie, because
 * the probe that would have refuted the hypothesis never ran.
 */
export function normalizeProbes(input: readonly ProbeParams[]): { ok: true; probes: Probe[] } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  const probes: Probe[] = [];

  input.forEach((raw, index) => {
    const at = `probes[${index}]`;
    if (!raw || typeof raw !== "object") {
      errors.push(`${at}: must be an object`);
      return;
    }
    if (raw.kind === "location") {
      if (typeof raw.file !== "string" || raw.file.trim() === "") {
        errors.push(`${at} (location): "file" is required`);
        return;
      }
      if (typeof raw.line !== "number" || !Number.isFinite(raw.line) || raw.line < 1) {
        errors.push(`${at} (location): "line" is required and must be a positive number`);
        return;
      }
      const probe: LocationProbe = { kind: "location", file: raw.file, line: Math.floor(raw.line) };
      if (raw.expectation === "present" || raw.expectation === "absent") probe.expectation = raw.expectation;
      if (raw.note) probe.note = raw.note;
      probes.push(probe);
      return;
    }
    if (raw.kind === "grep") {
      if (typeof raw.pattern !== "string" || raw.pattern === "") {
        errors.push(`${at} (grep): "pattern" is required`);
        return;
      }
      if (raw.expectation !== "present" && raw.expectation !== "absent") {
        errors.push(
          `${at} (grep): "expectation" is required and must be "present" or "absent" — a grep with no stated prediction cannot falsify anything`,
        );
        return;
      }
      const probe: GrepProbe = { kind: "grep", pattern: raw.pattern, expectation: raw.expectation };
      if (raw.subPath) probe.subPath = raw.subPath;
      if (typeof raw.ignoreCase === "boolean") probe.ignoreCase = raw.ignoreCase;
      if (raw.note) probe.note = raw.note;
      probes.push(probe);
      return;
    }
    if (raw.kind === "command") {
      if (typeof raw.command !== "string" || raw.command.trim() === "") {
        errors.push(`${at} (command): "command" is required`);
        return;
      }
      const probe: CommandProbe = { kind: "command", command: raw.command.trim() };
      if (Array.isArray(raw.args)) {
        const bad = raw.args.find((a) => typeof a !== "string");
        if (bad !== undefined) {
          errors.push(`${at} (command): every entry of "args" must be a string`);
          return;
        }
        probe.args = [...raw.args];
      }
      if (raw.expectExit === "zero" || raw.expectExit === "nonzero") probe.expectation = raw.expectExit;
      if (typeof raw.timeoutMs === "number" && Number.isFinite(raw.timeoutMs)) probe.timeoutMs = raw.timeoutMs;
      if (raw.note) probe.note = raw.note;
      probes.push(probe);
      return;
    }
    errors.push(`${at}: unknown probe kind ${JSON.stringify(raw.kind)} — use "location", "grep", or "command"`);
  });

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, probes };
}

/** The typebox schema for one probe, shared by the verify tool. */
const PROBE_SCHEMA = Type.Object({
  kind: Type.Union([Type.Literal("location"), Type.Literal("grep"), Type.Literal("command")], {
    description: "location = read file:line and capture the slice; grep = bounded regex search; command = run a bounded command (needs allowCommandProbes).",
  }),
  file: Type.Optional(Type.String({ description: "location: project-relative path." })),
  line: Type.Optional(Type.Number({ description: "location: 1-based line number." })),
  pattern: Type.Optional(Type.String({ description: "grep: JavaScript regular expression source." })),
  expectation: Type.Optional(
    Type.Union([Type.Literal("present"), Type.Literal("absent")], {
      description: "grep/location: what the hypothesis PREDICTS. 'present' = if this is NOT here, my hypothesis is wrong. REQUIRED for grep.",
    }),
  ),
  subPath: Type.Optional(Type.String({ description: "grep: restrict the walk to this project-relative directory." })),
  ignoreCase: Type.Optional(Type.Boolean({ description: "grep: defaults to true." })),
  command: Type.Optional(Type.String({ description: "command: executable, no shell." })),
  args: Type.Optional(Type.Array(Type.String(), { description: "command: argument vector." })),
  expectExit: Type.Optional(
    Type.Union([Type.Literal("zero"), Type.Literal("nonzero")], { description: "command: expected exit code. Defaults to 'zero'." }),
  ),
  timeoutMs: Type.Optional(Type.Number({ description: "command: per-probe timeout, clamped to the project ceiling." })),
  note: Type.Optional(Type.String({ description: "Why this probe is the right falsification attempt." })),
});

// -----------------------------------------------------------------
// Registration
// -----------------------------------------------------------------

export function registerHypothesisTools(pi: ExtensionAPI): void {
  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_status",
      label: "Hypothesis status",
      description:
        "Show the code-audit hypothesis tree: counts by status and category, depth, the scheduler's current run lengths, and the open hypotheses in the order the scheduler would consider them. Read-only.",
      promptSnippet: "hypothesis_status — the audit hypothesis tree's state",
      promptGuidelines: [
        "Call hypothesis_status before deciding anything about the audit: it shows which hypotheses are open and what the scheduler's run lengths are.",
      ],
      parameters: Type.Object({
        limit: Type.Optional(Type.Number({ description: "How many open hypotheses to list (default 15)." })),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const { snapshot, readError, malformed, unknown } = load(root);
        if (readError) return text(`Could not read the hypothesis log: ${readError}`);
        if (!snapshot.rootId) {
          return text(
            "No hypothesis tree in this project yet. Start one with `/hypothesis new \"<a falsifiable assertion>\"`, or call hypothesis_add after a tree exists.",
          );
        }
        const limit = typeof params.limit === "number" && params.limit > 0 ? Math.floor(params.limit) : 15;
        const lines = renderSummary(snapshot);
        const open = snapshot.nodes.filter((n) => n.status !== "confirmed" && n.status !== "rejected");
        lines.push("");
        lines.push(`Open hypotheses (${open.length}, scheduler order):`);
        const { buildContext, scoreCandidate } = await import("./scheduler.js");
        const context = buildContext(snapshot, snapshot.rounds + 1);
        const ranked = open
          .map((n) => ({ node: n, score: scoreCandidate(n, context).total }))
          .sort((a, b) => (b.score !== a.score ? b.score - a.score : a.node.depth - b.node.depth || a.node.id.localeCompare(b.node.id)));
        for (const { node, score } of ranked.slice(0, limit)) {
          lines.push(`  ${node.id} [${node.status}] ${node.category} d${node.depth} score ${score.toFixed(1)}  ${clip(node.description, 80)}`);
        }
        if (ranked.length > limit) lines.push(`  … and ${ranked.length - limit} more`);
        if (malformed > 0 || unknown > 0) {
          lines.push("");
          lines.push(`WARNING: ${malformed} malformed and ${unknown} unrecognized log line(s) were skipped.`);
        }
        return text(lines.join("\n"), { openCount: open.length, treeId: snapshot.treeId, rounds: snapshot.rounds });
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_next",
      label: "Next hypothesis",
      description:
        "Ask the SCHEDULER which hypothesis to examine next, and record the choice. The scheduler enforces the anti-rabbit-hole limits (max 3 levels of consecutive descent, max 2 consecutive rounds on one node, max 40% of recent picks in one category) and explains its decision. You do not choose the node — that is the point.",
      promptSnippet: "hypothesis_next — let the scheduler pick the next hypothesis to examine",
      promptGuidelines: [
        "Use hypothesis_next to start a round instead of picking a hypothesis yourself; the scheduler exists to stop you tunnelling into one branch.",
        "After hypothesis_next returns a node, examine THAT node: run hypothesis_verify against it, then hypothesis_record the verdict.",
        "If the decision says a limit was RELAXED, the tree is skewed — prefer adding hypotheses in other categories when you next grow the tree.",
      ],
      parameters: Type.Object({
        round: Type.Optional(Type.Number({ description: "Explicit round number. Defaults to the next round." })),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;
        if (!snapshot.rootId) {
          return text("No hypothesis tree in this project. Create one with `/hypothesis new \"<falsifiable assertion>\"` first.");
        }

        // The combination pass is a FORCED trigger: a due pass blocks new
        // scheduling. Left optional it would never happen, because the model is
        // always busy with the round in front of it — and an audit that only
        // ever adds single findings never finds the chains, which are the
        // reason to keep a tree at all.
        const pending = planConsolidation(snapshot);
        if (pending.due) {
          return text(
            [
              "BLOCKED: a consolidation pass is due, and it must run before a new round is scheduled.",
              `  ${pending.reason}`,
              "",
              "Call hypothesis_consolidate first (it is cheap when there is nothing to examine, and it records the result either way).",
            ].join("\n"),
            { blockedBy: "consolidation", reason: pending.reason },
          );
        }

        const round = typeof params.round === "number" && Number.isInteger(params.round) ? params.round : snapshot.rounds + 1;
        const decision = planNextRound(snapshot, { round });
        const lines = renderDecision(decision);
        if (!decision.selected) {
          return text(lines.join("\n"), { selected: null });
        }
        const applied = applySelection(root, decision);
        if (!applied.ok) {
          return text(`Scheduling failed: ${applied.errors.join("; ")} — the tree is unchanged.`);
        }
        lines.push("");
        lines.push(`Recorded as round ${round}. ${decision.selected.id} is now "testing".`);
        lines.push(
          `Next: run hypothesis_verify on ${decision.selected.id} with the probes that would REFUTE "${clip(decision.selected.description, 100)}", then hypothesis_record the verdict.`,
        );
        return text(lines.join("\n"), {
          selected: decision.selected.id,
          round,
          score: decision.breakdown?.total ?? null,
          relaxations: decision.relaxations,
          populationSkew: decision.populationSkew,
        });
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_verify",
      label: "Verify hypothesis",
      description:
        "Run bounded probes against one hypothesis and turn their raw output into durable evidence. Each probe is a FALSIFICATION ATTEMPT: you state what the hypothesis predicts about one mechanical fact, and the tool reports whether that prediction held. It returns a SUGGESTION only — it never changes the node's status. Evidence is attached automatically.",
      promptSnippet: "hypothesis_verify — run falsification probes against a hypothesis and collect evidence",
      promptGuidelines: [
        "A grep probe REQUIRES 'expectation' ('present' or 'absent'): state what your hypothesis predicts, or the probe cannot falsify anything.",
        "Probes check mechanical facts, not the hypothesis. A surviving probe means 'not refuted here', never 'proven'.",
        "One falsified probe refutes the hypothesis — if a probe fails, record 'rejected' with that counterexample rather than looking for a probe that agrees.",
        "A command probe is refused unless the project has allowCommandProbes enabled; a refusal is reported as inconclusive, not as a pass.",
      ],
      parameters: Type.Object({
        id: Type.String({ description: "The hypothesis id to verify, e.g. H-0003." }),
        probes: Type.Array(PROBE_SCHEMA, { description: "The falsification attempts to run." }),
        attachEvidence: Type.Optional(
          Type.Boolean({ description: "Attach the produced evidence to the node. Defaults to true; set false for a dry run." }),
        ),
      }),
      async execute(_id, params, signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;
        const node = getNode(snapshot, params.id);
        if (!node) {
          return text(`Hypothesis ${params.id} is not in the tree. Call hypothesis_status to see the open ids.`);
        }
        const refusal = verificationRefusal(node);
        if (refusal) return text(refusal);

        const normalized = normalizeProbes((params.probes ?? []) as ProbeParams[]);
        if (!normalized.ok) {
          return text(`The probe list was rejected — nothing ran:\n${normalized.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        if (normalized.probes.length === 0) {
          return text("No probes supplied. A hypothesis cannot be settled without at least one falsification attempt.");
        }

        const { settings, source, error } = loadSettings(root);
        const outcome = await runVerification({
          projectRoot: root,
          node,
          probes: normalized.probes,
          settings,
          exec: (command, args, options) => pi.exec(command, args, options),
          ...(signal ? { signal } : {}),
        });

        const attach = params.attachEvidence !== false;
        let attached = 0;
        if (attach) {
          for (const evidence of outcome.evidence) {
            if (addEvidence(root, node.id, evidence).ok) attached++;
          }
        }

        const lines = renderOutcome(outcome);
        if (attach) {
          lines.push(`  Attached ${attached} of ${outcome.evidence.length} evidence entry/entries to ${node.id}.`);
        } else {
          lines.push("  (attachEvidence=false — nothing was written)");
        }
        if (source === "defaults" && error) lines.push(`  NOTE: settings could not be read (${error}); using defaults.`);
        if (!settings.allowCommandProbes && normalized.probes.some((p) => p.kind === "command")) {
          lines.push("  NOTE: command probes are disabled for this project; the user can enable them with `/hypothesis config allowCommandProbes=true`.");
        }

        return text(lines.join("\n"), {
          nodeId: node.id,
          suggestedVerdict: outcome.suggestedVerdict,
          counterexample: outcome.counterexample,
          evidenceAttached: attached,
          needsMoreProbes: outcome.needsMoreProbes,
        });
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_record",
      label: "Record hypothesis verdict",
      description:
        "Record a verdict on a hypothesis: confirmed (the assertion is supported by evidence), rejected (refuted by a counterexample), blocked (cannot be examined yet — needs a reason), or pending (reopen a verdict — needs a reason). A verdict REQUIRES evidence, either already on the node or supplied here.",
      promptSnippet: "hypothesis_record — record a confirmed/rejected/blocked verdict with evidence",
      promptGuidelines: [
        "Record 'rejected' when a probe produced a counterexample; a rejection is a RESULT that prunes the search space, not a failure.",
        "Never record 'confirmed' from a surviving grep alone — a pattern match is not a data flow. State in the reason what the evidence actually establishes.",
        "Do not record a verdict to close a node you did not examine; use 'blocked' with a reason instead.",
      ],
      parameters: Type.Object({
        id: Type.String({ description: "The hypothesis id." }),
        verdict: Type.Union([Type.Literal("confirmed"), Type.Literal("rejected"), Type.Literal("blocked"), Type.Literal("pending")], {
          description: "confirmed | rejected | blocked | pending (pending reopens an existing verdict).",
        }),
        severity: Type.Optional(
          Type.Union([Type.Literal("critical"), Type.Literal("high"), Type.Literal("medium"), Type.Literal("low"), Type.Literal("info")], {
            description: "How bad it is if the assertion is true. Set it when confirming: a completion contract like 'find one high-severity finding' cannot be evaluated without it. An unrated finding is 'not yet judged', never 'low'.",
          }),
        ),
        reason: Type.String({
          description:
            "For rejected: the counterexample. For blocked: what it waits on. For confirmed: what the evidence establishes and what it does not. For pending: why the old verdict no longer holds.",
        }),
        evidence: Type.Optional(
          Type.Array(
            Type.Object({
              kind: Type.Union(EVIDENCE_KINDS.map((k) => Type.Literal(k))),
              detail: Type.String({ description: "The verbatim excerpt, request, or output." }),
              file: Type.Optional(Type.String()),
              line: Type.Optional(Type.Number()),
              command: Type.Optional(Type.String({ description: "Required for command-output evidence." })),
            }),
            { description: "Evidence to attach in the same call. Optional when the node already carries evidence." },
          ),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;
        const node = getNode(snapshot, params.id);
        if (!node) return text(`Hypothesis ${params.id} is not in the tree.`);

        const supplied: Evidence[] = [];
        for (const [index, raw] of (params.evidence ?? []).entries()) {
          if (typeof raw.detail !== "string" || raw.detail.trim() === "") {
            return text(`evidence[${index}] has an empty detail — an evidence entry without the verbatim artifact proves nothing.`);
          }
          const location = typeof raw.file === "string" && raw.file
            ? { file: raw.file, line: typeof raw.line === "number" && raw.line >= 1 ? Math.floor(raw.line) : 1 }
            : undefined;
          supplied.push({
            kind: raw.kind as EvidenceKind,
            at: "",
            ...(location ? { location } : {}),
            ...(typeof raw.command === "string" && raw.command ? { command: raw.command } : {}),
            detail: raw.detail,
          });
        }

        const status: HypothesisStatus = params.verdict;
        const result = setStatus(root, params.id, status, {
          reason: params.reason,
          ...(params.severity ? { severity: params.severity as Severity } : {}),
          ...(supplied.length > 0 ? { evidence: supplied } : {}),
        });
        if (!result.ok) {
          return text(`Verdict REJECTED — ${params.id} is still "${node.status}":\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const after = result.value;
        const tail =
          status === "confirmed"
            ? params.severity
              ? `A confirmed ${params.severity} finding. Consider whether it combines with another confirmed one (hypothesis_consolidate).`
              : "A confirmed finding, but it carries NO severity — a contract like 'find one high-severity finding' cannot count it. Record the severity with hypothesis_record if you can judge impact."
            : status === "rejected"
              ? "Rejection prunes the branch. If the refutation raises a follow-up question, add it as a CHILD of this node with hypothesis_add."
              : status === "blocked"
                ? "Blocked hypotheses stay in the queue and are re-scheduled later."
                : "Reopened — it is back in the scheduling queue.";
        return text(
          `${params.id}: ${node.status} → ${after.status} (${after.evidence.length} evidence entry/entries${after.severity ? `, severity ${after.severity}` : ""}).\n${tail}`,
          { nodeId: after.id, status: after.status, severity: after.severity ?? null, evidenceCount: after.evidence.length },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_add",
      label: "Add hypothesis",
      description:
        "Add a child hypothesis: a NEW falsifiable assertion derived from what you just learned. It must read as a claim about the codebase, not as a task — 'the refresh handler shares the missing signature check' passes, 'check the refresh handler' is refused.",
      promptSnippet: "hypothesis_add — record a new falsifiable assertion in the tree",
      promptGuidelines: [
        "Phrase a child as a claim that can be proven WRONG, never as an instruction. The store refuses task-shaped descriptions.",
        "After REFUTING a hypothesis, the useful child is usually the question the refutation raised ('then how is the token trusted?'), not a restatement.",
        "Do not re-add an assertion that is already in the tree — the store refuses it and names the existing node; link to that id instead.",
      ],
      parameters: Type.Object({
        description: Type.String({ description: "The falsifiable assertion." }),
        category: Type.String({ description: "Vulnerability class, e.g. auth-bypass, idor, sqli, ssrf, race-condition." }),
        parentId: Type.Optional(Type.String({ description: "Parent hypothesis id. Defaults to the root." })),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;

        // No tree yet: this assertion IS the root. Without this branch the tool
        // surface would have no way to start an audit at all — only the
        // `/hypothesis new` command could — and an agent that cannot start is
        // not a tool an agent can use.
        if (!snapshot.rootId) {
          const created = createTree(root, params.description, { category: params.category });
          if (!created.ok) {
            return text(`Hypothesis REJECTED — no tree was created:\n${created.errors.map((e) => `  - ${e}`).join("\n")}`);
          }
          return text(
            `Created hypothesis tree ${created.value.snapshot.treeId} with ${created.value.root.id} as its ROOT:\n` +
              `  ${created.value.root.description}\n\n` +
              `The root must be an assertion you can be proven WRONG about. Grow it with hypothesis_add (children), then call hypothesis_next to let the scheduler pick what to examine.`,
            { nodeId: created.value.root.id, root: true, treeId: created.value.snapshot.treeId },
          );
        }

        const result = addNode(root, {
          description: params.description,
          category: params.category,
          ...(params.parentId ? { parentId: params.parentId } : {}),
        });
        if (!result.ok) {
          return text(`Hypothesis REJECTED — nothing was added:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const node = result.value.node;
        return text(
          `Added ${node.id} (depth ${node.depth}, ${node.category}): ${node.description}\nIt is now in the scheduling queue; hypothesis_next may pick it.`,
          { nodeId: node.id, depth: node.depth, category: node.category },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_consolidate",
      label: "Consolidate findings",
      description:
        "Run a vulnerability-combination pass: the extension ranks the pairs of confirmed findings by STRUCTURAL signal (shared files, line proximity, tree relation, classes) and hands you the top ones plus lateral-extension candidates. You judge which combinations are real; this tool does not. The pass is recorded whether or not it produces anything.",
      promptSnippet: "hypothesis_consolidate — look for chains and shared root causes among confirmed findings",
      promptGuidelines: [
        "A consolidation pass is DUE every few rounds or whenever a finding is confirmed; hypothesis_next refuses to schedule while one is pending.",
        "A strong structural signal does not mean the findings are related. Reporting no combination is the correct answer when that is the truth — a fabricated chain sends the next rounds after something that does not exist.",
        "Produce a combination with hypothesis_combine, never by restating a finding as a new node.",
      ],
      parameters: Type.Object({
        force: Type.Optional(Type.Boolean({ description: "Run a pass even when the trigger has not fired." })),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;
        if (!snapshot.rootId) return text("No hypothesis tree in this project — nothing to consolidate.");

        const plan = planConsolidation(snapshot, params.force ? { force: "manual" } : {});
        const lines = renderConsolidation(plan);
        if (!plan.due) {
          return text(lines.join("\n"), { due: false, reason: plan.reason });
        }
        const recorded = applyConsolidation(root, plan);
        if (!recorded.ok) {
          return text(`Consolidation could not be recorded: ${recorded.errors.join("; ")} — the tree is unchanged.`);
        }
        lines.push("");
        lines.push(`Recorded: pass at round ${plan.round} (${plan.trigger}), ${plan.pairs.length} pair(s) and ${plan.singles.length} singleton(s) handed over.`);
        return text(lines.join("\n"), {
          due: true,
          trigger: plan.trigger,
          pairs: plan.pairs.map((p) => p.key),
          singles: plan.singles.map((s) => s.id),
          skipped: plan.skipped,
        });
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_combine",
      label: "Record a combination",
      description:
        "Insert a hypothesis produced by combining CONFIRMED findings: a chain (A needs B), a shared root cause (one missing check produces both), or a lateral extension (A bypasses X; the same technique may bypass Y). Every id in spawnedFrom must be a confirmed finding.",
      promptSnippet: "hypothesis_combine — insert a chain / shared-root-cause / lateral-extension hypothesis",
      promptGuidelines: [
        "spawnedFrom must name CONFIRMED findings — the store refuses ids that are not confirmed, because a combination of unconfirmed hypotheses is speculation stacked on speculation.",
        "The description must be a NEW falsifiable assertion, not a restatement of either source finding.",
        "Use kind=chain or shared-root-cause only with 2+ ids; kind=lateral-extension generalizes ONE finding.",
      ],
      parameters: Type.Object({
        description: Type.String({ description: "The new falsifiable assertion." }),
        category: Type.String({ description: "The class of the NEW assertion (may differ from the sources)." }),
        kind: Type.Union([
          Type.Literal("chain"),
          Type.Literal("shared-root-cause"),
          Type.Literal("lateral-extension"),
        ]),
        spawnedFrom: Type.Array(Type.String(), { description: "The CONFIRMED finding ids this is derived from." }),
        parentId: Type.Optional(Type.String({ description: "Attach under this node instead of the root." })),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;
        if (!snapshot.rootId) return text("No hypothesis tree in this project.");

        const result = applyCombination(root, snapshot, {
          description: params.description,
          category: params.category,
          kind: params.kind,
          spawnedFrom: params.spawnedFrom ?? [],
          ...(params.parentId ? { parentId: params.parentId } : {}),
        });
        if (!result.ok) {
          return text(`Combination REJECTED — nothing was added:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const node = result.node!;
        const lineage = node.spawnedFrom.join(" + ");
        return text(
          `Added ${node.id} (${node.combinationKind}, depth ${node.depth}, ${node.category}): ${node.description}\n` +
            `  derived from: ${lineage}\n` +
            `It is a new hypothesis, so it must be TESTED like any other — call hypothesis_verify on it before recording a verdict.`,
          { nodeId: node.id, kind: node.combinationKind, spawnedFrom: node.spawnedFrom },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_evidence",
      label: "Attach hypothesis evidence",
      description:
        "Attach one raw evidence entry to a hypothesis without changing its status. Use it when you found something quotable but are not yet ready to decide.",
      promptSnippet: "hypothesis_evidence — attach a raw artifact to a hypothesis",
      parameters: Type.Object({
        id: Type.String({ description: "The hypothesis id." }),
        kind: Type.Union(EVIDENCE_KINDS.map((k) => Type.Literal(k)), {
          description: "file | code-slice | request | command-output | reasoning. 'reasoning' is the weakest — use it only when there is no artifact.",
        }),
        detail: Type.String({ description: "The verbatim excerpt, request, or command output." }),
        file: Type.Optional(Type.String({ description: "Project-relative path, for file/code-slice evidence." })),
        line: Type.Optional(Type.Number({ description: "1-based line, with file." })),
        command: Type.Optional(Type.String({ description: "Required for command-output evidence." })),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;
        if (!getNode(snapshot, params.id)) return text(`Hypothesis ${params.id} is not in the tree.`);
        const location = typeof params.file === "string" && params.file
          ? { file: params.file, line: typeof params.line === "number" && params.line >= 1 ? Math.floor(params.line) : 1 }
          : undefined;
        const result = addEvidence(root, params.id, {
          kind: params.kind as EvidenceKind,
          at: "",
          ...(location ? { location } : {}),
          ...(typeof params.command === "string" && params.command ? { command: params.command } : {}),
          detail: params.detail,
        });
        if (!result.ok) {
          return text(`Evidence REJECTED:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        return text(`${params.id} now carries ${result.value.evidence.length} evidence entry/entries.`, {
          nodeId: params.id,
          evidenceCount: result.value.evidence.length,
        });
      },
    }),
  );
}

/** The tool names this extension registers — exported so a test (and a future
 * tool-visibility self-heal) can assert the whole surface is present. */
export const HYPOTHESIS_TOOL_NAMES = [
  "hypothesis_status",
  "hypothesis_next",
  "hypothesis_verify",
  "hypothesis_record",
  "hypothesis_add",
  "hypothesis_consolidate",
  "hypothesis_combine",
  "hypothesis_evidence",
] as const;
