/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/index.ts
 *
 * The extension entry point. Pi loads this file and calls the default export
 * with the `ExtensionAPI`.
 *
 * Stage 1 scope (this file): the data model, the append-only store, the tree
 * CRUD, and a `/hypothesis` command so the tree can be driven and inspected
 * by hand. The scheduler (stage 2), the verification executor (stage 3), the
 * combination module (stage 4), and the `/goal` + `/loop` integration
 * (stage 5) are NOT here yet — the command surface is the verification
 * surface for stage 1.
 *
 * Why a command and not only tools: tools are callable by the model, which
 * makes them useless for checking the model's own bookkeeping. A command is
 * typed by the human, so "create a tree, add a child, confirm it with
 * evidence, print the tree" is a real end-to-end check of the store rather
 * than a check of the model's willingness to call something.
 */

import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";

import { HYPOTHESIS_CATEGORIES, type Evidence, type EvidenceKind, type HypothesisCategory } from "./types.js";
import { load, repairTornTail, compact, eventsSinceSnapshot, treeLogPath } from "./store.js";
import {
  addEvidence,
  addNode,
  confirmedNodes,
  createTree,
  getNode,
  markTesting,
  openNodes,
  recordRound,
  rejectedNodes,
  setStatus,
  subtree,
} from "./tree.js";
import {
  SCHEDULER_LIMITS,
  SCORE_WEIGHTS,
  applySelection,
  buildContext,
  planNextRound,
  renderDecision,
} from "./scheduler.js";
import { renderSummary, renderTree, toJson, clip } from "./render.js";

// -----------------------------------------------------------------
// Argument parsing
// -----------------------------------------------------------------

/**
 * Parse `"quoted text" key=value key="quoted value"` into a positional list
 * plus a flag map.
 *
 * Written by hand rather than with a dependency because the grammar has to
 * tolerate an ASSERTION as the positional argument — full of quotes, colons,
 * parentheses and arrows — and a generic CLI parser would mangle it.
 */
export function parseArgs(input: string): { positional: string[]; flags: Record<string, string> } {
  const positional: string[] = [];
  const flags: Record<string, string> = {};
  let i = 0;
  const text = input ?? "";

  const readToken = (stopAtEquals: boolean): string => {
    let out = "";
    while (i < text.length) {
      const ch = text[i]!;
      if (ch === '"' || ch === "'") {
        const quote = ch;
        i++;
        while (i < text.length && text[i] !== quote) {
          if (text[i] === "\\" && i + 1 < text.length) i++;
          out += text[i]!;
          i++;
        }
        i++; // closing quote
        continue;
      }
      if (stopAtEquals && ch === "=") break;
      if (!stopAtEquals && /\s/.test(ch)) break;
      if (stopAtEquals && /\s/.test(ch)) break;
      out += ch;
      i++;
    }
    return out;
  };

  while (i < text.length) {
    while (i < text.length && /\s/.test(text[i]!)) i++;
    if (i >= text.length) break;

    // Look ahead for `key=` at the current token start.
    const keyMatch = /^([A-Za-z][A-Za-z0-9_-]*)=/.exec(text.slice(i));
    if (keyMatch) {
      const key = keyMatch[1]!;
      i += keyMatch[0].length;
      flags[key] = readToken(true);
      continue;
    }
    const token = readToken(false);
    if (token) positional.push(token);
  }
  return { positional, flags };
}

/** Wrap a value in quotes for a round-trip through `parseArgs` (used in the
 * error messages that show the exact command to retype). */
function quote(value: string): string {
  return `"${value.replace(/"/g, '\\"')}"`;
}

// -----------------------------------------------------------------
// Command surface
// -----------------------------------------------------------------

const USAGE = [
  "Hypothesis tree — a code audit organized as falsifiable assertions.",
  "",
  "  /hypothesis                          status: counts, categories, depth",
  "  /hypothesis tree [--evidence]        render the tree",
  "  /hypothesis json                     full tree as JSON",
  "  /hypothesis next [round=<n>]         SCHEDULE the next round and record it",
  "  /hypothesis schedule [round=<n>]     same decision, dry run (writes nothing)",
  "  /hypothesis history [n]              the last n scheduling decisions + rationale",
  "  /hypothesis limits                   the anti-rabbit-hole limits and score weights",
  "  /hypothesis new \"<root assertion>\" [category=<c>]",
  "                                       create the tree from the audit objective",
  "  /hypothesis add \"<assertion>\" [parent=<id>] [category=<c>]",
  "                                       add a child hypothesis",
  "  /hypothesis evidence <id> <kind> \"<detail>\" [file=<f>] [line=<n>] [command=\"<c>\"]",
  "                                       attach raw evidence (kinds: file, code-slice,",
  "                                       request, command-output, reasoning)",
  "  /hypothesis confirm <id> [reason=\"…\"]   verdict: supported by evidence",
  "  /hypothesis reject  <id> [reason=\"…\"]   verdict: refuted by evidence",
  "  /hypothesis block   <id> reason=\"…\"     cannot be examined yet",
  "  /hypothesis reopen  <id> reason=\"…\"     return a verdict to the queue",
  "  /hypothesis testing <id>             mark as being examined now",
  "  /hypothesis round <n>                record that loop round n ran",
  "  /hypothesis repair                   drop a torn tail (crash recovery)",
  "  /hypothesis compact                  append a state snapshot (bounded reads)",
].join("\n");

function completionsFor(prefix: string): Array<{ value: string; label: string; description?: string }> {
  const verbs: Array<[string, string]> = [
    ["status", "counts, categories, depth"],
    ["tree", "render the tree"],
    ["json", "full tree as JSON"],
    ["next", "schedule the next round (records the decision)"],
    ["schedule", "the same decision, dry run"],
    ["history", "recent scheduling decisions and their rationale"],
    ["limits", "the anti-rabbit-hole limits and score weights"],
    ["new", 'create the tree: new "<root assertion>"'],
    ["add", 'add a child: add "<assertion>" parent=<id>'],
    ["evidence", "attach raw evidence to a node"],
    ["confirm", "verdict: the assertion is supported"],
    ["reject", "verdict: the assertion is refuted"],
    ["block", "cannot be examined yet"],
    ["reopen", "return a verdict to the queue"],
    ["testing", "mark a node as being examined now"],
    ["round", "record that a loop round ran"],
    ["repair", "drop a torn tail"],
    ["compact", "append a state snapshot"],
    ["help", "show this usage"],
  ];
  return verbs
    .filter(([value]) => value.startsWith(prefix.trim()))
    .map(([value, description]) => ({ value: value + " ", label: value, description }));
}

// -----------------------------------------------------------------
// Entry
// -----------------------------------------------------------------

export default function hypothesisTreeExtension(pi: ExtensionAPI): void {
  pi.registerCommand("hypothesis", {
    description:
      "Code audit as a hypothesis tree: every node is a falsifiable assertion with raw evidence. Subcommands: status | tree | json | new | add | evidence | confirm | reject | block | reopen | testing | round | repair | compact. Use this to inspect and drive the tree by hand; the scheduler and /goal + /loop integration arrive in later stages.",
    getArgumentCompletions: (prefix: string) => completionsFor(prefix ?? ""),
    handler: async (args: string, ctx: ExtensionCommandContext) => {
      const { positional, flags } = parseArgs(args ?? "");
      const verb = (positional.shift() ?? "status").toLowerCase();
      const cwd = ctx.cwd;

      const notify = (message: string, type: "info" | "warning" | "error" = "info"): void => {
        ctx.ui.notify(message, type);
      };
      const fail = (errors: string[]): void => {
        notify(errors.map((e) => `REJECTED: ${e}`).join("\n"), "warning");
      };

      switch (verb) {
        // ---------------------------------------------------------
        case "help": {
          notify(USAGE, "info");
          return;
        }

        // ---------------------------------------------------------
        case "status": {
          const { snapshot, readError, malformed, unknown } = load(cwd);
          if (readError) {
            notify(`Could not read ${treeLogPath(cwd)}: ${readError}`, "error");
            return;
          }
          const lines = renderSummary(snapshot);
          if (malformed > 0 || unknown > 0) {
            lines.push("");
            lines.push(
              `WARNING: ${malformed} malformed and ${unknown} unrecognized line(s) were skipped — the log is damaged or was written by a newer version. Inspect ${treeLogPath(cwd)} before trusting these counts.`,
            );
          }
          notify(lines.join("\n"), "info");
          return;
        }

        // ---------------------------------------------------------
        case "tree": {
          const { snapshot, readError } = load(cwd);
          if (readError) {
            notify(`Could not read ${treeLogPath(cwd)}: ${readError}`, "error");
            return;
          }
          const showEvidence = positional.includes("--evidence") || flags.evidence === "true";
          const lines = renderTree(snapshot, { showEvidence });
          const s = renderSummary(snapshot);
          notify([...lines, "", ...s].join("\n"), "info");
          return;
        }

        // ---------------------------------------------------------
        case "json": {
          const { snapshot, readError } = load(cwd);
          if (readError) {
            notify(`Could not read ${treeLogPath(cwd)}: ${readError}`, "error");
            return;
          }
          notify(toJson(snapshot), "info");
          return;
        }

        // ---------------------------------------------------------
        case "new": {
          const objective = positional.join(" ").trim();
          if (!objective) {
            notify(`Usage: /hypothesis new ${quote("<falsifiable root assertion>")} [category=<c>]`, "warning");
            return;
          }
          const result = createTree(cwd, objective, {
            category: (flags.category as HypothesisCategory) ?? "other",
          });
          if (!result.ok) {
            fail(result.errors);
            return;
          }
          notify(
            [
              `Tree ${result.value.snapshot.treeId} created. Root: ${result.value.root.id} — ${clip(result.value.root.description, 120)}`,
              "",
              "The root must be an assertion you can be proven WRONG about. Add children with:",
              `  /hypothesis add ${quote("<a more specific assertion that could fail>")}`,
            ].join("\n"),
            "info",
          );
          return;
        }

        // ---------------------------------------------------------
        case "add": {
          const description = positional.join(" ").trim();
          if (!description) {
            notify(`Usage: /hypothesis add ${quote("<assertion>")} [parent=<id>] [category=<c>]`, "warning");
            return;
          }
          const parentId = flags.parent ?? flags.parentid ?? undefined;
          const result = addNode(cwd, {
            description,
            category: (flags.category as HypothesisCategory) ?? "other",
            ...(parentId ? { parentId } : {}),
            ...(flags.status ? { status: flags.status as never } : {}),
            ...(flags.reason ? { statusReason: flags.reason } : {}),
            ...(flags.spawnedFrom ? { spawnedFrom: flags.spawnedFrom.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
          });
          if (!result.ok) {
            fail(result.errors);
            return;
          }
          const node = result.value.node;
          const warnings = result.warnings.length ? `\n(${result.warnings.join("; ")})` : "";
          notify(`Added ${node.id} (depth ${node.depth}, ${node.category}): ${clip(node.description, 120)}${warnings}`, "info");
          return;
        }

        // ---------------------------------------------------------
        case "evidence": {
          const id = positional.shift();
          const kind = positional.shift() as EvidenceKind | undefined;
          const detail = positional.join(" ").trim();
          if (!id || !kind || !detail) {
            notify(
              `Usage: /hypothesis evidence <id> <${"file|code-slice|request|command-output|reasoning"}> ${quote("<verbatim excerpt>")} [file=<f>] [line=<n>] [command=${quote("<cmd>")}]`,
              "warning",
            );
            return;
          }
          const evidence: Evidence = {
            kind,
            at: "",
            ...(flags.file ? { location: { file: flags.file, line: Number(flags.line ?? 1) || 1 } } : {}),
            ...(flags.command ? { command: flags.command } : {}),
            detail,
          };
          const result = addEvidence(cwd, id, evidence);
          if (!result.ok) {
            fail(result.errors);
            return;
          }
          notify(`Evidence attached to ${id} (now ${result.value.evidence.length} entry/entries).`, "info");
          return;
        }

        // ---------------------------------------------------------
        case "confirm":
        case "reject":
        case "block":
        case "testing": {
          const id = positional.shift();
          if (!id) {
            notify(`Usage: /hypothesis ${verb} <id>${verb === "block" ? ` reason=${quote("…")}` : ""}`, "warning");
            return;
          }
          if (verb === "testing") {
            const result = markTesting(cwd, id);
            if (!result.ok) {
              fail(result.errors);
              return;
            }
            notify(`${id} is now being examined.`, "info");
            return;
          }
          const status = verb === "confirm" ? "confirmed" : verb === "reject" ? "rejected" : "blocked";
          const reason = flags.reason ?? positional.join(" ").trim() ?? "";
          const result = setStatus(cwd, id, status, reason ? { reason } : {});
          if (!result.ok) {
            fail(result.errors);
            return;
          }
          notify(`${id} → ${status}.${reason ? ` Reason: ${clip(reason, 120)}` : ""}`, "info");
          return;
        }

        // ---------------------------------------------------------
        case "reopen": {
          const id = positional.shift();
          const reason = flags.reason ?? positional.join(" ").trim();
          if (!id || !reason) {
            notify(`Usage: /hypothesis reopen <id> reason=${quote("why the verdict no longer holds")}`, "warning");
            return;
          }
          const result = setStatus(cwd, id, "pending", { reason });
          if (!result.ok) {
            fail(result.errors);
            return;
          }
          notify(`${id} reopened for re-testing: ${clip(reason, 120)}`, "info");
          return;
        }

        // ---------------------------------------------------------
        case "round": {
          // `Number("")` is 0, so a bare `/hypothesis round` would silently
          // record round 0 instead of asking for the number. Require the
          // argument explicitly.
          const raw = positional.shift() ?? flags.n;
          const n = raw === undefined || raw.trim() === "" ? Number.NaN : Number(raw);
          if (!Number.isInteger(n) || n < 0) {
            notify("Usage: /hypothesis round <n>", "warning");
            return;
          }
          const result = recordRound(cwd, n);
          if (!result.ok) {
            fail(result.errors);
            return;
          }
          notify(`Round ${n} recorded.`, "info");
          return;
        }

        // ---------------------------------------------------------
        case "repair": {
          const result = repairTornTail(cwd);
          notify(
            result.repaired
              ? `Repaired: dropped ${result.droppedBytes} byte(s) of torn tail from ${treeLogPath(cwd)}.`
              : `Nothing to repair (${result.reason}).`,
            result.repaired ? "info" : "info",
          );
          return;
        }

        // ---------------------------------------------------------
        case "compact": {
          const before = eventsSinceSnapshot(cwd);
          const done = compact(cwd);
          notify(
            done
              ? `Snapshot appended (${before} event(s) since the previous one). Reads are now bounded.`
              : "Nothing to compact (no tree, or no events since the last snapshot).",
            "info",
          );
          return;
        }

        // ---------------------------------------------------------
        case "schedule":
        case "next": {
          const dryRun = verb === "schedule";
          const snapshot = load(cwd).snapshot;
          const roundFlag = flags.round;
          const round = roundFlag !== undefined && roundFlag.trim() !== "" && Number.isInteger(Number(roundFlag))
            ? Number(roundFlag)
            : snapshot.rounds + 1;
          const decision = planNextRound(snapshot, { round });
          const lines = renderDecision(decision);
          if (!decision.selected) {
            notify(lines.join("\n"), "warning");
            return;
          }
          if (dryRun) {
            lines.push("", `(dry run — nothing recorded; run /hypothesis next to start round ${round})`);
            notify(lines.join("\n"), "info");
            return;
          }
          const applied = applySelection(cwd, decision);
          if (!applied.ok) {
            fail(applied.errors);
            return;
          }
          lines.push("", `Recorded: round ${round} → ${decision.selected.id} (now "testing"). Examine it, then /hypothesis confirm|reject it.`);
          notify(lines.join("\n"), "info");
          return;
        }

        // ---------------------------------------------------------
        case "history": {
          const snapshot = load(cwd).snapshot;
          const raw = positional.shift() ?? "10";
          const want = raw.trim() === "" ? 10 : Number(raw);
          if (!Number.isInteger(want) || want < 1) {
            notify("Usage: /hypothesis history [n]", "warning");
            return;
          }
          const history = snapshot.selections.slice(-want);
          if (history.length === 0) {
            notify("No scheduling decisions recorded yet — /hypothesis next runs the first round.", "info");
            return;
          }
          const lines: string[] = [`Scheduling history (last ${history.length} of ${snapshot.selections.length} kept):`, ""];
          for (const record of history) {
            const node = snapshot.byId.get(record.nodeId);
            const flagsOut: string[] = [];
            if (record.vetoes.length > 0) flagsOut.push(`${record.vetoes.length} vetoed`);
            if (record.relaxations.length > 0) flagsOut.push(`RELAXED ${record.relaxations.length}`);
            if (record.populationSkew.length > 0) flagsOut.push("skewed");
            lines.push(
              `  r${String(record.round).padStart(3)}  ${record.nodeId}  ${record.score.toFixed(1).padStart(6)}  ` +
                `${node ? clip(node.description, 70) : "(node no longer in the tree)"}${flagsOut.length ? `  [${flagsOut.join(", ")}]` : ""}`,
            );
          }
          const last = history[history.length - 1]!;
          if (last.relaxations.length > 0) {
            lines.push("");
            lines.push(`  Last round relaxed: ${last.relaxations.join("; ")}`);
          }
          notify(lines.join("\n"), "info");
          return;
        }

        // ---------------------------------------------------------
        case "limits": {
          const snapshot = load(cwd).snapshot;
          const context = buildContext(snapshot, snapshot.rounds + 1);
          const lines = [
            "Anti-rabbit-hole limits (hard constraints; relaxed only when unsatisfiable, always recorded):",
            `  MAX_CONSECUTIVE_DEPTH  ${SCHEDULER_LIMITS.MAX_CONSECUTIVE_DEPTH}    levels of consecutive descent down one branch`,
            `  MAX_SAME_NODE_ROUNDS   ${SCHEDULER_LIMITS.MAX_SAME_NODE_ROUNDS}    consecutive rounds on one hypothesis`,
            `  MAX_CATEGORY_RATIO     ${Math.round(SCHEDULER_LIMITS.MAX_CATEGORY_RATIO * 100)}%   of the last ${SCHEDULER_LIMITS.CATEGORY_WINDOW} picks (applied once the window has ${SCHEDULER_LIMITS.MIN_WINDOW_FOR_CATEGORY_CAP}+)`,
            "",
            "Score = novelty + evidence + category-diversity + testing-boost − depth − recency − blocked:",
            `  novelty          ${SCORE_WEIGHTS.novelty} / (1 + timesSelected)`,
            `  evidence         ${SCORE_WEIGHTS.evidencePerEntry} per entry, capped at ${SCORE_WEIGHTS.evidenceCap}`,
            `  diversity        ${SCORE_WEIGHTS.categoryDiversity} × (1 − the category's share of the window)`,
            `  depth            −${SCORE_WEIGHTS.depthPenaltyPerLevel} per level`,
            `  recency          −${SCORE_WEIGHTS.recencyPenaltyAtZero} at 0 rounds since, −${SCORE_WEIGHTS.recencyPenaltyDecayPerRound} per round, floor 0`,
            `  blocked          −${SCORE_WEIGHTS.blockedPenalty}`,
            `  testing          +${SCORE_WEIGHTS.testingBoost}`,
            "",
            "Current run state:",
            `  same-node run    ${context.sameNodeRun}/${SCHEDULER_LIMITS.MAX_SAME_NODE_ROUNDS}`,
            `  descent run      ${context.descentLevels}/${SCHEDULER_LIMITS.MAX_CONSECUTIVE_DEPTH} level(s) in ${context.descentRun} step(s)`,
            `  last selected    ${context.lastSelectedId ?? "(none)"}`,
            `  round            ${snapshot.rounds} recorded, next is ${snapshot.rounds + 1}`,
          ];
          notify(lines.join("\n"), "info");
          return;
        }

        // ---------------------------------------------------------
        default: {
          notify(`Unknown /hypothesis action "${verb}".\n\n${USAGE}`, "warning");
          return;
        }
      }
    },
  });

  // A read-only convenience for scripts and for the model: the current
  // status block, with no side effects. Registered as a command rather than a
  // tool at this stage so the tool surface stays empty until stage 3 defines
  // the executor that the tools will drive.
  pi.registerCommand("hypothesis-status", {
    description: "Print the hypothesis tree status block (read-only alias of /hypothesis status).",
    handler: async (_args: string, ctx: ExtensionCommandContext) => {
      const { snapshot, readError } = load(ctx.cwd);
      if (readError) {
        ctx.ui.notify(`Could not read the hypothesis log: ${readError}`, "error");
        return;
      }
      ctx.ui.notify(renderSummary(snapshot).join("\n"), "info");
    },
  });
}

// Re-exported for tests and for later stages that need the same primitives.
export { load, repairTornTail, compact, eventsSinceSnapshot, treeLogPath } from "./store.js";
export * from "./types.js";
export * from "./tree.js";
export * from "./render.js";
export { openNodes, confirmedNodes, rejectedNodes, subtree, getNode };
