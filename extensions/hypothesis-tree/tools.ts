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

import type { AttackVector, Evidence, EvidenceKind, HypothesisStatus, Severity } from "./types.js";
import { EVIDENCE_KINDS, chainState } from "./types.js";
import { appendEvent, load, nowIso } from "./store.js";
import { addEvidence, addNode, applyNodePatch, createTree, getNode, setStatus } from "./tree.js";
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
import { renderLadder } from "./ladders.js";
import { renderContradictions } from "./contradictions.js";
import {
  type CommandProbe,
  type GrepProbe,
  type LocationProbe,
  type Probe,
  renderOutcome,
  runVerification,
  verificationRefusal,
} from "./executor.js";
import {
  describeVector,
  nextOpenSegment,
  reconNotePath,
  recordSegmentOutcome,
  segmentById,
  segmentCoverage,
  submitRecon,
} from "./recon.js";
import { renderSummary, clip } from "./render.js";

/**
 * Convert the tool's flat `{ detail, file, line }` steps into the model's
 * `{ detail, location? }` shape.
 *
 * The flat form is what the model fills in reliably; the nested form is what
 * the tree stores. Doing the conversion here keeps the schema the model sees
 * simple and the persisted shape exact.
 */
function toAttackVector(input: {
  entrypoint: string;
  technique: string;
  path?: Array<{ detail: string; file?: string; line?: number }>;
  payload?: string;
  impact?: string;
  poc?: string;
  pocExpected?: string;
  preAuth?: boolean;
  preconditions?: string[];
}): AttackVector {
  return {
    entrypoint: input.entrypoint,
    technique: input.technique,
    path: (input.path ?? []).map((step) => ({
      ...(step.file ? { location: { file: step.file, line: typeof step.line === "number" && step.line >= 1 ? Math.floor(step.line) : 1 } } : {}),
      detail: step.detail,
    })),
    ...(input.payload ? { payload: input.payload } : {}),
    ...(input.impact ? { impact: input.impact } : {}),
    ...(input.poc ? { poc: input.poc } : {}),
    ...(input.pocExpected ? { pocExpected: input.pocExpected } : {}),
    ...(typeof input.preAuth === "boolean" ? { preAuth: input.preAuth } : {}),
    ...(input.preconditions && input.preconditions.length > 0 ? { preconditions: input.preconditions } : {}),
  };
}

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

/** The attack-vector schema, module-level so the nesting stays readable. */
const ATTACK_VECTOR_SCHEMA = Type.Object(
  {
    entrypoint: Type.String({ description: "How the attacker gets in: a route, a queue, a CLI verb, a file drop." }),
    technique: Type.String({ description: "The attack itself, e.g. 'alg=none JWT forgery'." }),
    path: Type.Optional(
      Type.Array(
        Type.Object({
          detail: Type.String({ description: "What happens at this step." }),
          file: Type.Optional(Type.String({ description: "Project-relative path, when the step is a code location." })),
          line: Type.Optional(Type.Number()),
        }),
        { description: "The chain from the entrypoint to the sink, in order." },
      ),
    ),
    payload: Type.Optional(Type.String({ description: "A concrete payload or reproduction sketch, when one is known." })),
    poc: Type.Optional(
      Type.String({
        description:
          "A COPY-PASTEABLE request a human can run by hand — a curl line or a raw HTTP request, e.g. 'GET /dsview/servlet/AxisServlet'. NOT the same as payload (what to inject): this is the whole thing you paste. entrypoint is prose and cannot be pasted; this can.",
      }),
    ),
    pocExpected: Type.Optional(
      Type.String({
        description:
          "What to LOOK FOR after sending it — '200 with the AxisServlet banner', 'a 5-second delay', 'the file contents in the body'. Without this the reader runs the request and cannot tell whether it worked.",
      }),
    ),
    preAuth: Type.Optional(
      Type.Boolean({
        description:
          "Can an UNAUTHENTICATED request reach this sink? true = pre-auth, false = post-auth. Omit ONLY if you have not determined it — the report says 'not assessed' and does NOT count it as pre-auth, so omitting is visible rather than silent.",
      }),
    ),
    impact: Type.Optional(
      Type.String({
        description:
          "What the attacker GETS if it works — 'take over any account including admin', 'read any tenant's data'. Not how you do it (that is technique) and not what you think of it. The report has a section for this and says 'not assessed' when it is missing, so omitting it is visible rather than silent.",
      }),
    ),
    preconditions: Type.Optional(Type.Array(Type.String())),
  },
  {
    description:
      "How the attacker would actually reach and trigger this. Omit when it is not yet known — an absent vector means 'unknown', not 'unreachable'.",
  },
);

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
            "No hypothesis tree in this project yet. Create one with `/hypothesis new \"<a falsifiable assertion>\"`, or call hypothesis_add — with no tree it creates the root itself.",
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

        // PERSIST the outcome. It used to live only in this response text, so by
        // the time `hypothesis_record` ran there was nothing left to check and the
        // one place a mechanical fact can contradict the model was thrown away.
        const survived = outcome.results.filter((r) => r.outcome === "survived").length;
        const falsified = outcome.results.filter((r) => r.outcome === "falsified");
        const inconclusive = outcome.results.filter((r) => r.outcome === "inconclusive").length;
        appendEvent(root, {
          type: "verification_recorded",
          at: nowIso(),
          id: node.id,
          record: {
            at: nowIso(),
            suggestedVerdict: outcome.suggestedVerdict,
            survived,
            falsified: falsified.length,
            inconclusive,
            counterexamples: falsified.map((r) => r.summary),
          },
        });

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
        override: Type.Optional(
          Type.String({
            description:
              "Why a FALSIFIED probe should be disregarded. Required to record `confirmed` when the last verification run refuted the hypothesis. A probe can be wrong — a bad pattern, the wrong path — but that is a claim, so it is recorded and printed in the report.",
          }),
        ),
        refutation: Type.Optional(
          Type.String({
            description:
              "What would have made this finding FALSE, and what you found when you looked for it. Required to record `confirmed` when no verification run survived — either run hypothesis_verify first, or say what you tried to refute it with. A confirmation with nothing behind it is the auditor agreeing with itself.",
          }),
        ),
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
        // THE ONE HARD CHECK IN THE WHOLE SYSTEM, and it runs BEFORE the write.
        //
        // A falsified probe means the round stated what the hypothesis predicts about
        // one mechanical fact and the prediction did NOT hold. That is the only place a
        // mechanical fact can contradict the model, and it used to be advisory: the
        // executor suggested `rejected` and `hypothesis_record` accepted `confirmed`
        // anyway, because the outcome was never persisted.
        //
        // It is not an absolute refusal. A probe CAN be wrong, and the model may know
        // better than its own grep — but overriding it is a claim, so it needs a reason,
        // and the reason is printed.
        const before = load(root).snapshot.byId.get(params.id);
        const last = before?.lastVerification;
        const refuted = last && last.falsified > 0 ? last : null;
        // A CONFIRMATION MUST HAVE AN ATTEMPT TO REFUTE IT BEHIND IT.
        //
        // The probe machinery records one: each probe states what the hypothesis
        // predicts about a mechanical fact, and a prediction that does not hold is a
        // counterexample. But the machinery can be SKIPPED — measured on a real
        // Checkmk run, 7 confirmed findings and `verification_recorded: 0`, so not
        // one probe had run and the falsified-probe check above was inert.
        //
        // So: a survived verification run, or a written attempt. Nothing else.
        const verified = last !== undefined && last.survived > 0 && last.falsified === 0;
        // Only when there IS evidence. A call with none fails on that first — it is
        // the more fundamental problem, and letting this gate answer first would
        // hide it behind a message about refutation.
        const willHaveEvidence = (before?.evidence.length ?? 0) + supplied.length > 0;
        if (status === "confirmed" && willHaveEvidence && !refuted && !verified && !params.refutation) {
          return text(
            [
              `${params.id} has no recorded attempt to REFUTE it, so a "confirmed" verdict is refused.`,
              "",
              "Nothing has tried to prove this wrong, and a confirmation with nothing behind it is",
              "the auditor agreeing with itself.",
              "",
              "  the usual way — state what it PREDICTS and check that:",
              `      hypothesis_verify { id: "${params.id}", probes: [{ kind: "grep", pattern: "…", expectation: "present" }] }`,
              "      A prediction that does not hold is a counterexample, and one refutes.",
              "",
              "  or, if you established it another way, say what you tried:",
              `      hypothesis_record { id: "${params.id}", verdict: "confirmed", refutation: "…" }`,
              "      refutation = what would have made this FALSE, and what you found looking for it.",
              "",
              "Either way the attempt is recorded and printed in the report.",
              "",
              "Nothing was written.",
            ].join("\n"),
            { nodeId: params.id, refused: true, needsRefutation: true },
          );
        }
        if (refuted && status === "confirmed" && !params.override) {
          return text(
            [
              `${params.id} was REFUTED by its own probes, so a "confirmed" verdict is refused.`,
              "",
              `  ${refuted.falsified} of ${refuted.falsified + refuted.survived + refuted.inconclusive} probe(s) falsified — one counterexample refutes.`,
              ...refuted.counterexamples.map((c) => `  counterexample: ${c}`),
              "",
              "Record `rejected` with the counterexample, or, if the PROBE was wrong (a bad",
              "pattern, the wrong path, a file that moved), pass `override` with the reason —",
              "it will be accepted and printed in the report as an override.",
              "",
              "Nothing was written.",
            ].join("\n"),
            { nodeId: params.id, refused: true, falsified: refuted.falsified },
          );
        }
        const result = setStatus(root, params.id, status, {
          reason: params.reason,
          ...(params.severity ? { severity: params.severity as Severity } : {}),
          ...(supplied.length > 0 ? { evidence: supplied } : {}),
        });
        if (!result.ok) {
          return text(`Verdict REJECTED — ${params.id} is still "${node.status}":\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const after = result.value;
        // An override of a falsified probe is a CLAIM, so it is stored with its
        // reason and printed in the report rather than vanishing.
        if (status === "confirmed" && params.refutation && !verified) {
          applyNodePatch(root, after.id, { refutation: { at: nowIso(), attempt: params.refutation } }, nowIso());
        }
        if (refuted && status === "confirmed" && params.override) {
          applyNodePatch(
            root,
            after.id,
            {
              falsificationOverride: {
                at: nowIso(),
                reason: params.override,
                counterexamples: refuted.counterexamples,
              },
            },
            nowIso(),
          );
        }
        const gates = after.requires ?? [];
        const chain = chainState(after, (id: string) => load(root).snapshot.byId.get(id));
        // THE NUDGE THAT MAKES A CHAIN REAL.
        //
        // `preconditions` is prose: recorded, printed in the report, and never tested
        // by anything. A sink whose exploitability depends on an unverified condition is
        // therefore presented as though it were usable. Saying so at the moment of
        // confirmation is the only point where the model still has the finding in hand.
        const untracked =
          status === "confirmed" && gates.length === 0 && (after.attackVector?.preconditions?.length ?? 0) > 0;
        const chainTail = untracked
          ? [
              "",
              "UNTRACKED PRECONDITIONS. This finding records " +
                `${after.attackVector!.preconditions!.length} precondition(s) that NOTHING will ever test:`,
              ...after.attackVector!.preconditions!.map((p) => `  - ${p}`),
              "As it stands the report presents this as USABLE, and it may not be.",
              "For each precondition that is not already established:",
              `  1. hypothesis_add it as its own falsifiable assertion (a gate), then`,
              `  2. hypothesis_vector ${after.id} requires=[<the gate id>] to link them.`,
              "Then the chain is tracked: the gate gets scheduled, and confirming it makes this",
              "finding chain-ready instead of merely confirmed.",
            ].join("\n")
          : gates.length > 0
            ? `

CHAIN: ${chain.state} — gates ${gates.join(" + ")}` +
              (chain.pending.length > 0 ? ` (still open: ${chain.pending.join(", ")})` : "") +
              (chain.refuted.length > 0 ? ` (REFUTED: ${chain.refuted.join(", ")} — the chain as stated cannot work)` : "") +
              (chain.confirmed.length > 0 ? ` (confirmed: ${chain.confirmed.join(", ")})` : "")
            : "";
        // THE LADDER, at the moment the model still has the finding in hand.
        const ladderTail =
          status === "confirmed" && chain.state !== "chain-ready"
            ? [
                "",
                "---",
                "",
                renderLadder(after.category, after.id),
                "",
                gates.length > 0
                  ? `(gates already linked: ${gates.join(", ")})`
                  : "(no gates linked yet — until some are, this finding is reported as UNASSESSED, not as usable)",
              ].join("\n")
            : "";
        const refutationNote =
          status === "confirmed" && params.refutation && !verified
            ? "\n\nREFUTATION ATTEMPT recorded — a written one, not a probe. It is printed in the report as the weaker evidence it is."
            : "";
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
          `${params.id}: ${node.status} → ${after.status} (${after.evidence.length} evidence entry/entries${after.severity ? `, severity ${after.severity}` : ""}).\n${tail}${refutationNote}${chainTail}${renderContradictions(after)}${ladderTail}`,
          {
            nodeId: after.id,
            status: after.status,
            severity: after.severity ?? null,
            evidenceCount: after.evidence.length,
            chainState: chain.state,
            gates,
            untrackedPreconditions: untracked,
          },
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
        segmentId: Type.Optional(
          Type.String({ description: "The recon segment this came from (e.g. S-000-1a2b3c4d). Supplying it is what closes the segment." }),
        ),
        attackVector: Type.Optional(ATTACK_VECTOR_SCHEMA),
        requires: Type.Optional(
          Type.Array(Type.String(), {
            description:
              "Ids of hypotheses that must be CONFIRMED for this one to be exploitable — its GATES. Use it for a sink whose reachability depends on something not yet verified: 'ScheduledTask.a() deserializes without a filter' requires 'the schedule_data column is writable pre-auth'. Record the gate as its own hypothesis first; an untracked precondition is prose that never gets tested.",
          }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;

        // No tree yet: this assertion IS the root. Without this branch the tool
        // surface would have no way to start an audit at all — only the
        // `/hypothesis new` command could — and an agent that cannot start is
        // not a tool an agent can use.
        if (!snapshot.rootId) {
          const created = createTree(root, params.description, {
            category: params.category,
            ...(params.attackVector ? { attackVector: toAttackVector(params.attackVector) } : {}),
          });
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
          ...(params.segmentId ? { segmentId: params.segmentId } : {}),
          ...(params.attackVector ? { attackVector: toAttackVector(params.attackVector) } : {}),
          ...(params.requires && params.requires.length > 0 ? { requires: params.requires } : {}),
        });
        if (!result.ok) {
          return text(`Hypothesis REJECTED — nothing was added:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const node = result.value.node;
        const vector = node.attackVector ? `\n  vector: ${describeVector(node.attackVector)}` : "\n  vector: (none recorded — how to reach it is not yet known)";
        const closed = params.segmentId
          ? `\n  Segment ${params.segmentId} is now closed (it produced at least one hypothesis).`
          : "";
        return text(
          `Added ${node.id} (depth ${node.depth}, ${node.category}): ${node.description}${vector}${closed}\n` +
            `It is now in the scheduling queue; hypothesis_next may pick it.`,
          { nodeId: node.id, depth: node.depth, category: node.category, segmentId: node.segmentId ?? null, hasVector: !!node.attackVector },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  // Fill in an attack vector after the fact.
  // ---------------------------------------------------------------
  //
  // A hypothesis is GENERATED before it is verified, so the order is often
  // "this looks wrong" → confirm it → work out how to reach it and what it gets
  // you. Without this tool the only chance to record a vector is at add time,
  // which means a finding confirmed first can never gain the call chain or the
  // impact its report section needs — the section would stay empty forever.
  pi.registerTool(
    defineTool({
      name: "hypothesis_vector",
      label: "Record an attack vector",
      description:
        "Record or update the attack vector on an EXISTING hypothesis: the call chain from entrypoint to sink, the impact, the payload, the preconditions. Use it when you confirmed a finding before you worked out how to reach it — hypothesis_add only sets a vector at creation time. A field you omit is KEPT, not cleared.",
      promptSnippet: "hypothesis_vector — record the call chain and the impact on a hypothesis that already exists",
      promptGuidelines: [
        "The report renders three sections per finding: call chain, impact, and PoC. This tool is what fills the first two.",
        "impact is what the attacker GETS, not how they do it and not your opinion of the severity. 'read any tenant's records' is an impact; 'critical' is not.",
        "Each path step should carry file and line when it is a code location. A call chain without locations is a story.",
        "A field you omit is kept as it was. Omit entrypoint or technique only when you have neither, since they are required to create a vector.",
      ],
      parameters: Type.Object({
        id: Type.String({ description: "The hypothesis id, e.g. H-0007." }),
        entrypoint: Type.Optional(
          Type.String({ description: "How the attacker gets in. Required the first time; kept if omitted." }),
        ),
        technique: Type.Optional(Type.String({ description: "The attack itself. Required the first time; kept if omitted." })),
        path: Type.Optional(
          Type.Array(
            Type.Object({
              detail: Type.String({ description: "What happens at this step." }),
              file: Type.Optional(Type.String({ description: "Project-relative path, when the step is a code location." })),
              line: Type.Optional(Type.Number()),
            }),
            { description: "The chain from the entrypoint to the sink, in order. Replaces the existing chain when given." },
          ),
        ),
        payload: Type.Optional(Type.String({ description: "A concrete payload or reproduction sketch." })),
        impact: Type.Optional(
          Type.String({
            description: "What the attacker GETS if it works. The report says 'not assessed' when this is missing.",
          }),
        ),
        preconditions: Type.Optional(Type.Array(Type.String())),
    poc: Type.Optional(
      Type.String({
        description:
          "A COPY-PASTEABLE request a human can run by hand — a curl line or a raw HTTP request, e.g. 'GET /dsview/servlet/AxisServlet'. NOT the same as payload (what to inject): this is the whole thing you paste. entrypoint is prose and cannot be pasted; this can.",
      }),
    ),
    pocExpected: Type.Optional(
      Type.String({
        description:
          "What to LOOK FOR after sending it — '200 with the AxisServlet banner', 'a 5-second delay', 'the file contents in the body'. Without this the reader runs the request and cannot tell whether it worked.",
      }),
    ),
        preAuth: Type.Optional(
          Type.Boolean({
            description:
              "Can an UNAUTHENTICATED request reach this sink? true = pre-auth, false = post-auth. THE question a pre-auth audit asks, and the report counts it.",
          }),
        ),
        requires: Type.Optional(
          Type.Array(Type.String(), {
            description:
              "Ids of hypotheses that must be CONFIRMED for this finding to be exploitable — its GATES. This is how a confirmed sink is marked as conditional rather than presented as a working exploit. An EMPTY array removes the gates.",
          }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;
        const node = getNode(snapshot, params.id);
        if (!node) return text(`${params.id} is not in the tree — nothing was recorded.`);

        // Merge rather than replace: a model that only knows the impact must be
        // able to record it without restating the chain it already gave.
        const existing = node.attackVector;
        const entrypoint = params.entrypoint?.trim() || existing?.entrypoint;
        const technique = params.technique?.trim() || existing?.technique;
        if (!entrypoint || !technique) {
          return text(
            [
              `${params.id} has no attack vector yet, so entrypoint and technique are both required to create one.`,
              "Nothing was recorded.",
              "",
              "If you do not know how to reach it yet, that is a legitimate state — the report says so explicitly.",
              "Do not invent a chain to fill the section.",
            ].join("\n"),
          );
        }

        const merged = toAttackVector({
          entrypoint,
          technique,
          ...(params.path ? { path: params.path } : existing ? { path: existing.path.map((s) => ({ detail: s.detail, ...(s.location ? { file: s.location.file, line: s.location.line } : {}) })) } : {}),
          ...(params.payload ?? existing?.payload ? { payload: params.payload ?? existing?.payload } : {}),
          ...(params.poc ?? existing?.poc ? { poc: params.poc ?? existing?.poc } : {}),
          ...(params.pocExpected ?? existing?.pocExpected ? { pocExpected: params.pocExpected ?? existing?.pocExpected } : {}),
          ...(typeof (params.preAuth ?? existing?.preAuth) === "boolean"
            ? { preAuth: (params.preAuth ?? existing?.preAuth) as boolean }
            : {}),
          ...(params.impact ?? existing?.impact ? { impact: params.impact ?? existing?.impact } : {}),
          ...(params.preconditions ?? existing?.preconditions ? { preconditions: params.preconditions ?? existing?.preconditions } : {}),
        });

        const result = applyNodePatch(
          root,
          node.id,
          { attackVector: merged, ...(params.requires !== undefined ? { requires: params.requires } : {}) },
          nowIso(),
        );
        if (!result.ok) return text(`${node.id} could not be updated: ${result.errors.join("; ")} — the tree is unchanged.`);

        const lines: string[] = [`${node.id} attack vector recorded.`, ""];
        lines.push(`  entrypoint: ${merged.entrypoint}`);
        lines.push(`  technique:  ${merged.technique}`);
        lines.push(`  call chain: ${merged.path.length} step(s)${merged.path.some((s) => s.location) ? " (with code locations)" : " — no code locations, so the report cannot point a reader at a line"}`);
        lines.push(`  impact:     ${merged.impact ? merged.impact : "NOT RECORDED — the report will say 'not assessed'"}`);
        if (merged.payload) lines.push(`  payload:    ${merged.payload}`);
        if (merged.preconditions?.length) lines.push(`  needs:      ${merged.preconditions.join("; ")}`);
        const gates = params.requires !== undefined ? params.requires : (node.requires ?? []);
        lines.push(`  gates:      ${gates.length > 0 ? gates.join(" + ") : "none — this finding is reported as usable on its own"}`);
        const reach = merged.preAuth === undefined ? "NOT ASSESSED" : merged.preAuth ? "pre-auth" : "post-auth";
        lines.push(`  reach:      ${reach}${merged.preAuth === undefined ? " — the report will NOT count it as pre-auth" : ""}`);
        lines.push("");
        lines.push("The report renders this as the call chain and impact sections of the finding.");
        return text(lines.join("\n"), { nodeId: node.id, steps: merged.path.length, hasImpact: !!merged.impact });
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_recon",
      label: "Submit recon notes",
      description:
        "Submit the reconnaissance note for an unfamiliar project: what it is, its entrypoints, its trust boundaries, its data flows, and what you could not work out. The note is chunked into segments of 3-5 paragraphs and each segment becomes one hypothesis-generation round. Write it AS PARAGRAPHS — one coherent thought per paragraph.",
      promptSnippet: "hypothesis_recon — write the recon note that the hypotheses are derived from",
      promptGuidelines: [
        "Call hypothesis_recon once, at the start of an audit, after actually reading the project — not before.",
        "Write PARAGRAPHS, not one giant block: the note is split into 3-5 paragraph segments and each becomes a generation round.",
        "Do NOT write hypotheses in the recon note. Observation only; the hypotheses come from the segments.",
        "State what you could NOT work out. An honest gap is more useful than a confident guess.",
      ],
      parameters: Type.Object({
        notes: Type.String({
          description:
            "The recon note. Markdown paragraphs separated by blank lines; fenced code blocks are kept intact. One paragraph per coherent thought about one part of the project.",
        }),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const { settings } = loadSettings(root);
        const submitted = submitRecon(root, params.notes ?? "", { paragraphsPerSegment: settings.reconSegmentParagraphs });
        if (!submitted.ok) {
          return text(`Recon REJECTED — nothing was recorded:\n${submitted.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const snapshot = load(root).snapshot;
        const lines: string[] = [
          `Recon note recorded: ${params.notes.length} chars → ${submitted.segments!.length} segment(s).`,
          "",
          "Segments (each becomes one generation round):",
        ];
        for (const segment of submitted.segments!) {
          lines.push(`  ${segment.id}  ${segment.paragraphs} paragraph(s)  ${clip(segment.text.replace(/\s+/g, " "), 70)}`);
        }
        lines.push("");
        lines.push(`Note written to ${reconNotePath(root)} for human review.`);
        lines.push("Next: the loop hands you segment 1; call hypothesis_add per hypothesis with segmentId set.");
        void snapshot;
        return text(lines.join("\n"), { segments: submitted.segments!.map((s) => s.id) });
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "hypothesis_cover_segment",
      label: "Close a recon segment",
      description:
        "Close a recon segment WITHOUT adding a hypothesis: you examined it and there is no attack surface there. The note is required — 'examined and empty' and 'did not look' must not be the same record. This is a RESULT, not a failure, and it is what keeps coverage honest.",
      promptSnippet: "hypothesis_cover_segment — close a recon segment that yielded nothing",
      promptGuidelines: [
        "Use this when a segment genuinely contains no attack surface. Do NOT use it to skip a segment you have not read.",
        "The note must say what you actually examined, or the segment is not closed.",
      ],
      parameters: Type.Object({
        segmentId: Type.String({ description: "The segment id, e.g. S-000-1a2b3c4d." }),
        note: Type.String({ description: "What you examined and why there is nothing to hypothesise about." }),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const snapshot = load(root).snapshot;
        if (!segmentById(snapshot, params.segmentId)) {
          const known = snapshot.segments.map((s) => s.id).join(", ") || "(none — run hypothesis_recon first)";
          return text(`Segment ${params.segmentId} is not in the inventory. Known segments: ${known}`);
        }
        const recorded = recordSegmentOutcome(root, params.segmentId, "nothing-found", { note: params.note });
        if (!recorded.ok) {
          return text(`Segment NOT closed:\n${recorded.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const after = segmentCoverage(load(root).snapshot);
        return text(
          `Segment ${params.segmentId} closed with nothing found.\n` +
            `Coverage: ${after.covered}/${after.total}${after.open.length > 0 ? ` — next ${after.open[0]}` : " — generation complete, verification rounds follow"}`,
          { segmentId: params.segmentId, coverage: after },
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
  "hypothesis_recon",
  "hypothesis_cover_segment",
  "hypothesis_verify",
  "hypothesis_record",
  "hypothesis_add",
  "hypothesis_vector",
  "hypothesis_consolidate",
  "hypothesis_combine",
  "hypothesis_evidence",
] as const;
