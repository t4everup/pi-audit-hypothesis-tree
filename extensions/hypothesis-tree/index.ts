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
import * as fs from "node:fs";

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
import { DEFAULT_SETTINGS, type HypothesisSettings, loadSettings, saveSettings, settingsPath } from "./settings.js";
import { renderOutcome, runVerification, verificationRefusal, type Probe } from "./executor.js";
import {
  describeVector,
  reconNotePath,
  renderCoverage,
  segmentCoverage,
  submitRecon,
} from "./recon.js";
import {
  CONSOLIDATION,
  applyCombination,
  applyConsolidation,
  consolidationStatus,
  planConsolidation,
  renderConsolidation,
} from "./combination.js";
import {
  type ContractClauses,
  buildContract,
  findingsLedgerPath,
  parkOnSendFailure,
  pauseLoop,
  renderLoopStatus,
  renderWidget,
  resumeLoop,
  startLoop,
  stopLoop,
  tickLoop,
} from "./loop.js";
import type { AuditLoopKind, Severity } from "./types.js";import { registerHypothesisTools } from "./tools.js";
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
  "  /hypothesis recon [file=<p>|<note>]  show coverage, or submit a recon note",
  "  /hypothesis segments                 list the recon segments and their state",
  "  /hypothesis consolidate [--force]    vulnerability combination: rank the confirmed pairs",
  "  /hypothesis combine kind=<k> spawnedFrom=<a,b> category=<c> \"<assertion>\"",
  "                                       insert a chain / shared-root-cause / extension",
  "  /hypothesis verify <id> file=<f> line=<n>",
  "                                       read a location and capture the slice",
  "  /hypothesis verify <id> grep=\"<re>\" expect=present|absent [path=<sub>]",
  "                                       bounded search; 'expect' is what you predict",
  "  /hypothesis verify <id> command=\"<exe>\" [args=\"a b\"] [expectExit=zero|nonzero]",
  "                                       run a bounded command (needs config consent)",
  "  /hypothesis config [key=value]       show or set project settings",
  "  /hypothesis new \"<root assertion>\" [category=<c>]",
  "                                       create the tree from the audit objective",
  "  /hypothesis add \"<assertion>\" [parent=<id>] [category=<c>] [segmentId=<s>]",
  "                       [entrypoint=\"<where>\" technique=\"<how>\"] [payload=\"<p>\"] [precondition=\"a;b\"]",
  "                                       add a child hypothesis, optionally with its attack vector",
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
    ["recon", "show recon coverage, or submit a note (file=<path> or inline)"],
    ["segments", "list the recon segments and their state"],
    ["consolidate", "vulnerability combination over the confirmed findings"],
    ["combine", "insert a chain / shared-root-cause / lateral-extension hypothesis"],
    ["verify", "run falsification probes against a hypothesis"],
    ["config", "show or set project settings"],
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
  registerHypothesisTools(pi);

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
          lines.push("", ...renderLoopStatus(snapshot));
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
            ...(flags.segmentId ? { segmentId: flags.segmentId } : {}),
            ...(flags.entrypoint && flags.technique
              ? {
                  attackVector: {
                    entrypoint: flags.entrypoint,
                    technique: flags.technique,
                    path: [],
                    ...(flags.payload ? { payload: flags.payload } : {}),
                    ...(flags.precondition ? { preconditions: flags.precondition.split(";").map((s) => s.trim()).filter(Boolean) } : {}),
                  },
                }
              : {}),
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
          const vector = node.attackVector ? `  vector: ${describeVector(node.attackVector)}` : "  vector: (none — how to reach it is not yet known)";
          notify(`Added ${node.id} (depth ${node.depth}, ${node.category}): ${clip(node.description, 120)}\n${vector}${warnings}`, "info");
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
          const severity = flags.severity && ["critical", "high", "medium", "low", "info"].includes(flags.severity)
            ? (flags.severity as Severity)
            : undefined;
          const result = setStatus(cwd, id, status, {
            ...(reason ? { reason } : {}),
            ...(severity ? { severity } : {}),
          });
          if (!result.ok) {
            fail(result.errors);
            return;
          }
          notify(
            `${id} → ${status}${severity ? ` (severity ${severity})` : ""}.${reason ? ` Reason: ${clip(reason, 120)}` : ""}`,
            "info",
          );
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
          // The combination pass is a FORCED trigger: while one is due, a new
          // round cannot be scheduled. Left optional it would never happen —
          // the model is always busy with the round in front of it.
          const pending = planConsolidation(snapshot);
          if (pending.due) {
            notify(
              [
                "BLOCKED: a consolidation pass is due and must run before a new round is scheduled.",
                `  ${pending.reason}`,
                "",
                "Run /hypothesis consolidate (cheap when there is nothing to examine, and recorded either way).",
              ].join("\n"),
              "warning",
            );
            return;
          }
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
        case "verify": {
          const id = positional.shift();
          if (!id) {
            notify(
              `Usage:\n  /hypothesis verify <id> file=<f> line=<n>\n  /hypothesis verify <id> grep="<re>" expect=present|absent [path=<sub>]\n  /hypothesis verify <id> command="<exe>" [args="a b"] [expectExit=zero|nonzero]`,
              "warning",
            );
            return;
          }
          const snapshot = load(cwd).snapshot;
          const node = getNode(snapshot, id);
          if (!node) {
            notify(`Hypothesis ${id} is not in the tree. /hypothesis status to see the open ids.`, "warning");
            return;
          }
          const refusal = verificationRefusal(node);
          if (refusal) {
            notify(refusal, "warning");
            return;
          }

          // One probe per invocation: the flag set determines which kind.
          const probes: Probe[] = [];
          if (flags.grep !== undefined) {
            const expectation = flags.expect === "present" || flags.expect === "absent" ? flags.expect : undefined;
            if (!expectation) {
              notify(`A grep probe needs expect=present|absent — without a stated prediction it cannot falsify anything.`, "warning");
              return;
            }
            probes.push({ kind: "grep", pattern: flags.grep, expectation, ...(flags.path ? { subPath: flags.path } : {}), ...(flags.ignoreCase ? { ignoreCase: flags.ignoreCase !== "false" } : {}) });
          } else if (flags.command !== undefined) {
            probes.push({
              kind: "command",
              command: flags.command,
              ...(flags.args ? { args: flags.args.split(/\s+/).filter(Boolean) } : {}),
              ...(flags.expectExit === "zero" || flags.expectExit === "nonzero" ? { expectation: flags.expectExit } : {}),
              ...(flags.timeoutMs && Number.isFinite(Number(flags.timeoutMs)) ? { timeoutMs: Number(flags.timeoutMs) } : {}),
            });
          } else if (flags.file !== undefined) {
            const line = Number(flags.line ?? 1);
            if (!Number.isInteger(line) || line < 1) {
              notify(`A location probe needs a positive line=<n> (got ${flags.line ?? "(missing)"}).`, "warning");
              return;
            }
            probes.push({ kind: "location", file: flags.file, line });
          } else {
            notify(`No probe given. Supply file=/line=, grep=/expect=, or command=.`, "warning");
            return;
          }

          const loaded = loadSettings(cwd);
          const outcome = await runVerification({
            projectRoot: cwd,
            node,
            probes,
            settings: loaded.settings,
            exec: (command, args, options) => pi.exec(command, args, options),
          });
          let attached = 0;
          for (const evidence of outcome.evidence) {
            if (addEvidence(cwd, node.id, evidence).ok) attached++;
          }
          const lines = renderOutcome(outcome);
          lines.push(`  Attached ${attached} of ${outcome.evidence.length} evidence entry/entries to ${node.id}.`);
          if (!loaded.settings.allowCommandProbes && probes.some((p) => p.kind === "command")) {
            lines.push("  NOTE: command probes are disabled for this project; /hypothesis config allowCommandProbes=true to enable them.");
          }
          notify(lines.join("\n"), outcome.suggestedVerdict === "rejected" ? "warning" : "info");
          return;
        }

        // ---------------------------------------------------------
        case "consolidate": {
          const snapshot = load(cwd).snapshot;
          if (!snapshot.rootId) {
            notify("No hypothesis tree in this project — nothing to consolidate.", "warning");
            return;
          }
          const forced = flags.force === "true" || flags.force === "1" || flags.force === "on" || positional.includes("--force");
          const plan = planConsolidation(snapshot, forced ? { force: "manual" } : {});
          const lines = renderConsolidation(plan);
          if (!plan.due) {
            notify(lines.join("\n"), "info");
            return;
          }
          const recorded = applyConsolidation(cwd, plan);
          if (!recorded.ok) {
            fail(recorded.errors);
            return;
          }
          lines.push("");
          lines.push(
            `Recorded: pass at round ${plan.round} (${plan.trigger}), ${plan.pairs.length} pair(s) and ${plan.singles.length} singleton(s) handed over.`,
          );
          notify(lines.join("\n"), "info");
          return;
        }

        // ---------------------------------------------------------
        case "combine": {
          const description = positional.join(" ").trim();
          const kind = flags.kind;
          if (!description || !kind) {
            notify(
              `Usage: /hypothesis combine kind=chain|shared-root-cause|lateral-extension spawnedFrom=H-0002,H-0003 category=<c> ${quote("<new falsifiable assertion>")}`,
              "warning",
            );
            return;
          }
          const snapshot = load(cwd).snapshot;
          const result = applyCombination(cwd, snapshot, {
            description,
            category: flags.category ?? "other",
            kind: kind as never,
            spawnedFrom: (flags.spawnedFrom ?? "").split(",").map((s) => s.trim()).filter(Boolean),
            ...(flags.parent ? { parentId: flags.parent } : {}),
          });
          if (!result.ok) {
            fail(result.errors);
            return;
          }
          const node = result.node!;
          notify(
            `Added ${node.id} (${node.combinationKind}, ${node.category}): ${clip(node.description, 140)}\n` +
              `  derived from: ${node.spawnedFrom.join(" + ")}\n` +
              `  It is a new hypothesis — /hypothesis verify ${node.id} before recording a verdict.`,
            "info",
          );
          return;
        }

        // ---------------------------------------------------------
        case "recon": {
          const file = flags.file;
          const inline = positional.join(" ").trim();
          if (!file && !inline) {
            const { snapshot, readError } = load(cwd);
            if (readError) {
              notify(`Could not read the hypothesis log: ${readError}`, "error");
              return;
            }
            const coverage = segmentCoverage(snapshot);
            const lines = [renderCoverage(snapshot), ""];
            if (snapshot.segments.length === 0) {
              lines.push("No recon note yet. The first round of /goal or /loop reads the project and");
              lines.push("submits one; or supply your own:");
              lines.push(`  /hypothesis recon file=${quote("<path-to-notes.md>")}`);
              lines.push(`  /hypothesis recon ${quote("<a few paragraphs of prose>")}`);
            } else {
              lines.push(`note: ${reconNotePath(cwd)}`);
              for (const segment of snapshot.segments) {
                const closed = coverage.open.includes(segment.id) ? "open   " : "covered";
                lines.push(`  ${closed}  ${segment.id}  ${segment.paragraphs}p  ${clip(segment.text.replace(/\s+/g, " "), 60)}`);
              }
            }
            notify(lines.join("\n"), "info");
            return;
          }
          let note = inline;
          if (file) {
            try {
              note = fs.readFileSync(file, "utf-8");
            } catch (error) {
              notify(`Could not read ${file}: ${error instanceof Error ? error.message : String(error)}`, "error");
              return;
            }
          }
          const loaded = loadSettings(cwd);
          const submitted = submitRecon(cwd, note, { paragraphsPerSegment: loaded.settings.reconSegmentParagraphs });
          if (!submitted.ok) {
            fail(submitted.errors);
            return;
          }
          notify(
            [
              `Recon note recorded: ${note.length} chars → ${submitted.segments!.length} segment(s).`,
              `  note: ${reconNotePath(cwd)}`,
              "",
              "Segments (each becomes one generation round):",
              ...submitted.segments!.map((s) => `  ${s.id}  ${s.paragraphs}p  ${clip(s.text.replace(/\s+/g, " "), 60)}`),
            ].join("\n"),
            "info",
          );
          return;
        }

        // ---------------------------------------------------------
        case "segments": {
          const { snapshot, readError } = load(cwd);
          if (readError) {
            notify(`Could not read the hypothesis log: ${readError}`, "error");
            return;
          }
          if (snapshot.segments.length === 0) {
            notify("No recon segments yet — run /hypothesis recon (or start a /goal, which reads the project first).", "info");
            return;
          }
          const coverage = segmentCoverage(snapshot);
          const lines = [renderCoverage(snapshot), ""];
          for (const segment of snapshot.segments) {
            const isOpen = coverage.open.includes(segment.id);
            lines.push(`${isOpen ? "open   " : "covered"}  ${segment.id}  ${segment.paragraphs}p`);
            lines.push(`    ${clip(segment.text.replace(/\s+/g, " "), 100)}`);
            const produced = snapshot.nodes.filter((n) => n.segmentId === segment.id);
            for (const node of produced) {
              const vector = node.attackVector ? ` → ${describeVector(node.attackVector)}` : " (no vector)";
              lines.push(`      ${node.id} [${node.status}] ${clip(node.description, 60)}${vector}`);
            }
          }
          notify(lines.join("\n"), "info");
          return;
        }

        // ---------------------------------------------------------
        case "config": {
          const loaded = loadSettings(cwd);
          const assignments = Object.entries(flags);
          if (assignments.length === 0) {
            const lines = [
              `Project settings (${settingsPath(cwd)}) — source: ${loaded.source}`,
              loaded.error ? `  WARNING: ${loaded.error}` : "",
              "",
            ].filter(Boolean);
            for (const [key, value] of Object.entries(loaded.settings)) {
              const isDefault = value === (DEFAULT_SETTINGS as unknown as Record<string, unknown>)[key];
              lines.push(`  ${key.padEnd(22)} ${String(value).padEnd(9)}${isDefault ? "  (default)" : ""}`);
            }
            lines.push("");
            lines.push("  Set one with: /hypothesis config <key>=<value>");
            lines.push("  allowCommandProbes is the consent gate for `command` probes — it is OFF by default and no agent tool can turn it on.");
            notify(lines.join("\n"), "info");
            return;
          }
          const patch: Record<string, unknown> = {};
          for (const [key, value] of assignments) {
            const current = (loaded.settings as unknown as Record<string, unknown>)[key];
            if (typeof current === "boolean") patch[key] = value === "true" || value === "1" || value === "on";
            else if (typeof current === "number") patch[key] = Number(value);
            else patch[key] = value;
          }
          const saved = saveSettings(cwd, patch as Partial<HypothesisSettings>);
          if (!saved.ok) {
            fail(saved.errors);
            return;
          }
          notify(`Settings written to ${settingsPath(cwd)}:\n${assignments.map(([k, v]) => `  ${k} = ${String((saved.settings as unknown as Record<string, unknown>)[k] ?? v)}`).join("\n")}`, "info");
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
      ctx.ui.notify([...renderSummary(snapshot), "", ...renderLoopStatus(snapshot)].join("\n"), "info");
    },
  });

  // ===============================================================
  // Stage 5: /goal and /loop — the round engine
  // ===============================================================
  //
  // `/goal` runs until a completion contract is satisfied; `/loop` runs until
  // stopped or the well runs dry. Both share this handler: the only difference
  // is the kind, the default contract, and the default bounds.
  //
  // The command NAMES are the spec's. They are free because the previously
  // installed pi-goal-list-loop-audit was removed — if it is ever reinstalled,
  // pi suffixes every duplicate registration and the bare names stop routing, so
  // do not install both at once.

  /** Refresh the TUI widget from the current state. Silent when there is no UI. */
  const refreshWidget = (ctx: ExtensionCommandContext): void => {
    try {
      if (!ctx.hasUI) return;
      const lines = renderWidget(load(ctx.cwd).snapshot);
      ctx.ui.setWidget("hypothesis-loop", lines ?? undefined, { placement: "belowEditor" });
    } catch {
      // A widget is a convenience; never let it break a command.
    }
  };

  const registerAuditLoopCommand = (kind: AuditLoopKind): void => {
    const isGoal = kind === "goal";
    const verbs = ["start", "status", "pause", "resume", "stop", "cancel", "next", "tree", "log", "help"];
    pi.registerCommand(kind, {
      description: isGoal
        ? 'Run ONE audited objective until a mechanical completion contract is met: /goal "<objective>" [confirmed=1] [severity=high] [category=a,b] [maxRounds=20] [plateau=5]. Each round the scheduler picks a hypothesis, you falsify it, and the verdict is recorded. Subcommands: status | pause | resume | stop | cancel | next | tree | log.'
        : 'Keep auditing until stopped or the well runs dry: /loop ["<objective>"] [maxRounds=0] [plateau=8]. Same round flow as /goal with no finish line. Subcommands: status | pause | resume | stop | next | tree | log.',
      getArgumentCompletions: (prefix: string) =>
        verbs
          .filter((v) => v.startsWith((prefix ?? "").trim()))
          .map((v) => ({
            value: v + " ",
            label: v,
            description:
              v === "status"
                ? "the loop, the contract gap, and the recent rounds"
                : v === "next"
                  ? "run one round now instead of waiting for the turn to end"
                  : v === "log"
                    ? "the findings ledger"
                    : v === "tree"
                      ? "render the hypothesis tree"
                      : `the ${kind} ${v}`,
          })),
      handler: async (args: string, ctx: ExtensionCommandContext) => {
        const { positional, flags } = parseArgs(args ?? "");
        const first = (positional[0] ?? "").toLowerCase();
        const verb = verbs.includes(first) ? first : null;
        const rest = verb ? positional.slice(1).join(" ").trim() : positional.join(" ").trim();
        const cwd = ctx.cwd;
        const notify = (m: string, t: "info" | "warning" | "error" = "info"): void => ctx.ui.notify(m, t);

        /** Prepare a round and hand the brief to the model. */
        const runRound = (): void => {
          const snapshot = load(cwd).snapshot;
          const result = tickLoop(cwd, snapshot);
          refreshWidget(ctx);
          if (result.summary) notify(result.summary.join("\n"), "info");
          if (result.brief) {
            try {
              pi.sendUserMessage(result.brief);
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error);
              parkOnSendFailure(cwd, `round ${result.round} was recorded but its brief could not be delivered: ${message}`);
              refreshWidget(ctx);
              notify(
                `Round ${result.round} was recorded but the brief could NOT be sent: ${message}\n` +
                  `The loop is PAUSED. Run /${kind} resume to re-offer the same work — the round number advances, the segment does not.`,
                "error",
              );
              return;
            }
          } else if (result.action !== "sent") {
            notify(`${result.action}: ${result.reason}`, result.action === "stopped" || result.action === "complete" ? "info" : "warning");
          }
        };

        switch (verb) {
          case "help": {
            notify(
              [
                `${isGoal ? "/goal" : "/loop"} — the audit round engine`,
                "",
                isGoal
                  ? '  /goal "<objective>" [confirmed=1] [severity=high] [category=a,b] [maxRounds=20] [plateau=5]'
                  : '  /loop ["<objective>"] [maxRounds=0] [plateau=8]',
                `  /${kind} status              the loop, the contract gap, the recent rounds`,
                `  /${kind} pause|resume|stop   control it`,
                `  /${kind} next                run one round now`,
                `  /${kind} tree                render the hypothesis tree`,
                `  /${kind} log                 the findings ledger`,
                "",
                "A round: the scheduler picks a hypothesis, you falsify it, the verdict is recorded,",
                "a due combination pass runs first, and the round is written to the ledger.",
              ].join("\n"),
              "info",
            );
            return;
          }

          case "status": {
            const { snapshot, readError } = load(cwd);
            if (readError) {
              notify(`Could not read the hypothesis log: ${readError}`, "error");
              return;
            }
            notify([...renderLoopStatus(snapshot), "", ...renderSummary(snapshot)].join("\n"), "info");
            refreshWidget(ctx);
            return;
          }

          case "pause": {
            const result = pauseLoop(cwd, load(cwd).snapshot, rest || "paused by the user");
            notify(result.ok ? result.message! : `REJECTED: ${result.errors.join("; ")}`, result.ok ? "info" : "warning");
            refreshWidget(ctx);
            return;
          }

          case "resume": {
            const result = resumeLoop(cwd, load(cwd).snapshot);
            if (!result.ok) {
              notify(`REJECTED: ${result.errors.join("; ")}`, "warning");
              return;
            }
            notify(result.message!, "info");
            runRound();
            return;
          }

          case "stop":
          case "cancel": {
            const result = stopLoop(cwd, load(cwd).snapshot, rest || "stopped by the user");
            notify(result.ok ? result.message! : `REJECTED: ${result.errors.join("; ")}`, result.ok ? "info" : "warning");
            refreshWidget(ctx);
            return;
          }

          case "next": {
            const snapshot = load(cwd).snapshot;
            if (!snapshot.loop) {
              notify(`No audit ${kind} is running. Start one with /${kind} "<objective>".`, "warning");
              return;
            }
            runRound();
            return;
          }

          case "tree": {
            const { snapshot, readError } = load(cwd);
            if (readError) {
              notify(`Could not read the hypothesis log: ${readError}`, "error");
              return;
            }
            notify([...renderTree(snapshot, { showEvidence: true }), "", ...renderSummary(snapshot)].join("\n"), "info");
            return;
          }

          case "log": {
            const file = findingsLedgerPath(cwd);
            try {
              const text = fs.readFileSync(file, "utf-8");
              const tail = text.split("\n").slice(-60).join("\n");
              notify(`Findings ledger (tail of ${file}):\n${tail}`, "info");
            } catch {
              notify(`No findings ledger yet at ${file} — it is written at the end of each round.`, "info");
            }
            return;
          }
        }

        // No verb: this is a START.
        //
        // With no tree, an audit of an unread project starts from a SCOPE, not a
        // hypothesis: there is nothing to hypothesise about until the project
        // has been read, and forcing the user to phrase a boundary as a claim
        // produces a root like "this project contains a vulnerability", which
        // no evidence can refute. The scope node is exempt from the assertion
        // gate and is never scheduled; the hypotheses arrive from the recon
        // segments on the following rounds.
        let snapshot = load(cwd).snapshot;
        let bootstrapped = false;
        if (!snapshot.rootId) {
          const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
          if (!created.ok) {
            notify(`REJECTED: ${created.errors.join("; ")}`, "warning");
            return;
          }
          snapshot = created.value.snapshot;
          bootstrapped = true;
        }
        const objective = rest || snapshot.objective;
        const clauses: ContractClauses = {};
        if (flags.confirmed !== undefined && Number.isInteger(Number(flags.confirmed))) clauses.confirmed = Number(flags.confirmed);
        if (flags.severity && ["critical", "high", "medium", "low", "info"].includes(flags.severity)) {
          clauses.severity = flags.severity as Severity;
        }
        if (flags.category) clauses.category = flags.category.split(",").map((s) => s.trim()).filter(Boolean);
        if (flags.requireConsolidated !== undefined) clauses.requireConsolidated = flags.requireConsolidated !== "false";

        const started = startLoop(cwd, snapshot, {
          kind,
          objective,
          ...(isGoal ? { contract: buildContract(clauses) } : {}),
          ...(flags.maxRounds !== undefined && Number.isInteger(Number(flags.maxRounds)) ? { maxRounds: Number(flags.maxRounds) } : {}),
          ...(flags.plateau !== undefined && Number.isInteger(Number(flags.plateau)) ? { plateauWindow: Number(flags.plateau) } : {}),
        });
        if (!started.ok) {
          notify(`REJECTED: ${started.errors.join("; ")}`, "warning");
          return;
        }
        const contract = started.loop!.contract;
        notify(
          [
            `${isGoal ? "Goal" : "Loop"} started: ${clip(objective, 120)}`,
            ...(bootstrapped
              ? [
                  `  no tree existed, so a SCOPE root was created (${snapshot.rootId}): the first round reads the project`,
                ]
              : []),
            isGoal && contract
              ? `  contract: at least ${contract.minConfirmed} confirmed finding(s)` +
                (contract.minSeverity ? ` at severity >= ${contract.minSeverity}` : "") +
                `; plateau after ${started.loop!.plateauWindow} unproductive rounds; cap ${started.loop!.maxRounds} rounds`
              : `  unbounded; plateau after ${started.loop!.plateauWindow} unproductive rounds`,
            `  findings ledger: ${findingsLedgerPath(cwd)}`,
          ].join("\n"),
          "info",
        );
        runRound();
      },
    });
  };

  registerAuditLoopCommand("goal");
  registerAuditLoopCommand("loop");

  // ---------------------------------------------------------------
  // The round driver: a SETTLED turn advances the loop.
  // ---------------------------------------------------------------
  //
  // `agent_settled`, NOT `agent_end`.
  //
  // Pi's own docs draw the distinction: `agent_end` fires "when an agent run
  // ends", while `agent_settled` fires "after an agent run has fully settled and
  // no automatic retry, compaction, or queued continuation will run". Sending a
  // new user message on `agent_end` therefore fails with "Agent is already
  // processing" — the run has ended but the agent is not yet idle — and the loop
  // stops dead after round 1 with its fence set and no turn in flight.
  //
  // `awaitingRound` is the anti-stacking fence: the loop only advances when a
  // round it started is actually in flight, so a slow or failed turn cannot
  // pile rounds on top of each other. `ticking` guards re-entrancy within one
  // event.
  let ticking = false;
  pi.on("agent_settled", async (_event, ctx) => {
    if (ticking) return;
    const snapshot = load(ctx.cwd).snapshot;
    const loop = snapshot.loop;
    if (!loop || loop.status !== "running" || loop.awaitingRound === null) return;
    ticking = true;
    try {
      const result = tickLoop(ctx.cwd, snapshot);
      if (result.summary) ctx.ui.notify(result.summary.join("\n"), "info");
      if (result.brief) {
        try {
          pi.sendUserMessage(result.brief);
        } catch (error) {
          // No automatic retry exists: the agent is idle, so no further event
          // will arrive to try again. Park the loop and hand the decision back.
          const message = error instanceof Error ? error.message : String(error);
          parkOnSendFailure(ctx.cwd, `round ${result.round} was recorded but its brief could not be delivered: ${message}`);
          ctx.ui.notify(
            `Round ${result.round} was recorded but its brief could NOT be delivered: ${message}\n` +
              `The audit loop is PAUSED. Run /goal resume (or /loop resume) to re-offer the same work — the round number advances, the segment does not.`,
            "error",
          );
          return;
        }
      }
      try {
        if (ctx.hasUI) {
          ctx.ui.setWidget("hypothesis-loop", renderWidget(load(ctx.cwd).snapshot) ?? undefined, { placement: "belowEditor" });
        }
      } catch {
        /* a widget must never break the loop */
      }
    } catch (error) {
      // A driver failure must PARK the loop rather than spin: an exception here
      // would otherwise repeat on every subsequent turn.
      const message = error instanceof Error ? error.message : String(error);
      stopLoop(ctx.cwd, load(ctx.cwd).snapshot, `driver error: ${message}`);
      ctx.ui.notify(`Audit loop stopped — the round driver threw: ${message}`, "error");
    } finally {
      ticking = false;
    }
  });
}

// Re-exported for tests and for later stages that need the same primitives.
export { load, repairTornTail, compact, eventsSinceSnapshot, treeLogPath } from "./store.js";
export * from "./types.js";
export * from "./tree.js";
export * from "./render.js";
export * from "./scheduler.js";
export * from "./settings.js";
export * from "./executor.js";
export * from "./combination.js";
export * from "./loop.js";
export { registerHypothesisTools, HYPOTHESIS_TOOL_NAMES, normalizeProbes } from "./tools.js";
export { openNodes, confirmedNodes, rejectedNodes, subtree, getNode };
