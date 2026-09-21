/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/loop.ts
 *
 * Stage 5: `/goal` and `/loop` — the round engine.
 *
 * -----------------------------------------------------------------------
 * The six-step round, and who owns which step
 * -----------------------------------------------------------------------
 *
 *   1. the scheduler picks a node            → the EXTENSION (mechanical)
 *   2. the node is examined                  → the MODEL's turn
 *   3. status + evidence are updated         → the MODEL, through tools
 *   4. whether to combine is decided         → the EXTENSION (mechanical trigger)
 *   5. the findings ledger is written        → the EXTENSION
 *   6. a round summary is emitted            → the EXTENSION
 *
 * The extension cannot examine a hypothesis — that is the model's job — so a
 * round is driven by handing the model a BRIEF and letting its turn do steps
 * 2–3. Everything the extension can do mechanically, it does; nothing it cannot
 * do is faked.
 *
 * -----------------------------------------------------------------------
 * The anti-stacking fence
 * -----------------------------------------------------------------------
 *
 * `AuditLoopState.awaitingRound` records the round whose turn is in flight. A
 * tick only sends a brief when nothing is awaiting completion, so a slow,
 * failed, or aborted turn cannot pile rounds on top of each other. The next tick
 * evaluates the finished round before deciding anything.
 *
 * That evaluation is DERIVED, not recorded: the round record stores the node's
 * status and evidence count at the start, and the tick compares them against
 * now. Derived beats recorded because there is no window in which the two can
 * disagree — a second "outcome" event could be lost to a crash, and then the
 * stall counter would be wrong forever.
 *
 * -----------------------------------------------------------------------
 * Why the loop stops itself
 * -----------------------------------------------------------------------
 *
 * A loop with no exit is a loop that burns a night producing nothing. Three
 * bounds, all mechanical:
 *
 *   - the COMPLETION CONTRACT is satisfied (`/goal` only);
 *   - the PLATEAU: `plateauWindow` consecutive rounds that produced neither a
 *     verdict nor new evidence — the well is dry;
 *   - `maxRounds`.
 *
 * Each stop records a reason, and every reason distinguishes "finished" from
 * "gave up".
 */

import * as fs from "node:fs";
import * as path from "node:path";

import {
  type AuditLoopKind,
  type AuditLoopState,
  type CompletionContract,
  type Hypothesis,
  type RoundRecord,
  type Severity,
  type TreeSnapshot,
  isVerdict,
  meetsSeverity,
  severityRank,
} from "./types.js";
import { STATE_DIR_NAME, appendEvent, load, nowIso } from "./store.js";
import { applySelection, planNextRound, renderDecision } from "./scheduler.js";
import { applyConsolidation, consolidationStatus, planConsolidation, renderConsolidation } from "./combination.js";
import { renderTree, clip } from "./render.js";

// -----------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------

export const LOOP_DEFAULTS = {
  /** `/goal` gives up after this many unproductive rounds. */
  GOAL_PLATEAU: 5,
  /** `/loop` is more patient — it is meant to run for hours. */
  LOOP_PLATEAU: 8,
  /** `/goal` round cap. 0 would be unbounded; a goal should not be. */
  GOAL_MAX_ROUNDS: 20,
  /** `/loop` is unbounded by default. */
  LOOP_MAX_ROUNDS: 0,
  /** Nodes listed in a ledger tree snapshot. */
  LEDGER_TREE_LINES: 40,
} as const;

export const FINDINGS_LEDGER_NAME = "findings.md";

export function findingsLedgerPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, FINDINGS_LEDGER_NAME);
}

// -----------------------------------------------------------------
// The completion contract
// -----------------------------------------------------------------

export interface ContractClauses {
  confirmed?: number;
  severity?: Severity;
  category?: string[];
  requireConsolidated?: boolean;
}

/** Build a contract from parsed command flags. */
export function buildContract(clauses: ContractClauses): CompletionContract {
  return {
    minConfirmed: clauses.confirmed ?? 1,
    ...(clauses.severity ? { minSeverity: clauses.severity } : {}),
    ...(clauses.category && clauses.category.length > 0 ? { categories: clauses.category } : {}),
    requireConsolidated: clauses.requireConsolidated ?? true,
  };
}

export function describeContract(contract: CompletionContract | null): string {
  if (!contract) return "none (runs until stopped)";
  const parts = [`at least ${contract.minConfirmed} confirmed finding(s)`];
  if (contract.minSeverity) parts.push(`at severity >= ${contract.minSeverity}`);
  if (contract.categories && contract.categories.length > 0) parts.push(`in ${contract.categories.join(" or ")}`);
  if (contract.requireConsolidated) parts.push("with no combination pass pending");
  return parts.join(", ");
}

export interface ContractEvaluation {
  met: boolean;
  /** Human lines, always including the numbers, so a reader can see the gap. */
  detail: string[];
}

/**
 * Evaluate the completion contract against the folded tree.
 *
 * Every clause is mechanical. A completion condition the extension cannot check
 * is a condition the model grades itself on, which is the failure this project
 * exists to avoid.
 */
export function contractMet(snapshot: TreeSnapshot, contract: CompletionContract | null): ContractEvaluation {
  if (!contract) return { met: false, detail: ["no contract (a /loop has no finish line)"] };

  const inScope = snapshot.nodes.filter((n) => {
    if (n.status !== "confirmed") return false;
    if (contract.categories && contract.categories.length > 0 && !contract.categories.includes(n.category)) return false;
    return true;
  });
  const detail: string[] = [];

  const countOk = inScope.length >= contract.minConfirmed;
  detail.push(
    `${inScope.length}/${contract.minConfirmed} confirmed finding(s)` +
      (contract.categories && contract.categories.length > 0 ? ` in ${contract.categories.join(" or ")}` : ""),
  );

  let severityOk = true;
  if (contract.minSeverity) {
    const rated = inScope.filter((n) => n.severity);
    severityOk = rated.some((n) => meetsSeverity(n.severity, contract.minSeverity!));
    const unrated = inScope.length - rated.length;
    detail.push(
      `${rated.filter((n) => meetsSeverity(n.severity, contract.minSeverity!)).length} at severity >= ${contract.minSeverity}` +
        (unrated > 0 ? ` (${unrated} confirmed finding(s) carry no severity yet — they are NOT counted as low)` : ""),
    );
  }

  let consolidatedOk = true;
  if (contract.requireConsolidated) {
    const due = planConsolidation(snapshot).due;
    consolidatedOk = !due;
    detail.push(due ? "a combination pass is still pending" : "combination passes are up to date");
  }

  return { met: countOk && severityOk && consolidatedOk, detail };
}

// -----------------------------------------------------------------
// Loop state
// -----------------------------------------------------------------

export interface StartLoopOptions {
  kind: AuditLoopKind;
  objective: string;
  contract?: CompletionContract | null;
  maxRounds?: number;
  plateauWindow?: number;
  at?: string;
}

/** Refuse to start when a loop is already running — two drivers would race. */
export function startLoop(projectRoot: string, snapshot: TreeSnapshot, opts: StartLoopOptions): { ok: boolean; errors: string[]; loop?: AuditLoopState } {
  const existing = snapshot.loop;
  if (existing && (existing.status === "running" || existing.status === "paused")) {
    return {
      ok: false,
      errors: [
        `an audit ${existing.kind} is already ${existing.status} at round ${existing.round} ("${clip(existing.objective, 60)}"). ` +
          `Stop it first (/${existing.kind} stop) or resume it.`,
      ],
    };
  }
  if (!snapshot.rootId) {
    return { ok: false, errors: ["no hypothesis tree in this project — create one with `/hypothesis new \"<falsifiable assertion>\"` first"] };
  }

  const at = opts.at ?? nowIso();
  const loop: AuditLoopState = {
    kind: opts.kind,
    objective: opts.objective,
    contract: opts.kind === "goal" ? (opts.contract ?? buildContract({})) : null,
    status: "running",
    startedAt: at,
    updatedAt: at,
    round: 0,
    awaitingRound: null,
    maxRounds: opts.maxRounds ?? (opts.kind === "goal" ? LOOP_DEFAULTS.GOAL_MAX_ROUNDS : LOOP_DEFAULTS.LOOP_MAX_ROUNDS),
    plateauWindow: opts.plateauWindow ?? (opts.kind === "goal" ? LOOP_DEFAULTS.GOAL_PLATEAU : LOOP_DEFAULTS.LOOP_PLATEAU),
    stallRounds: 0,
  };
  if (!appendEvent(projectRoot, { type: "loop_updated", at, loop })) {
    return { ok: false, errors: ["the loop state could not be written — nothing changed"] };
  }
  return { ok: true, errors: [], loop };
}

/** Write an updated loop state (latest wins). `null` clears it. */
export function writeLoop(projectRoot: string, loop: AuditLoopState | null, at = nowIso()): boolean {
  const next = loop ? { ...loop, updatedAt: at } : null;
  return appendEvent(projectRoot, { type: "loop_updated", at, loop: next });
}

export interface LoopControlResult {
  ok: boolean;
  errors: string[];
  loop?: AuditLoopState;
  message?: string;
}

export function pauseLoop(projectRoot: string, snapshot: TreeSnapshot, reason: string): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project"] };
  if (loop.status !== "running") return { ok: false, errors: [`the audit ${loop.kind} is already ${loop.status}`] };
  const next: AuditLoopState = { ...loop, status: "paused", pausedReason: reason };
  if (!writeLoop(projectRoot, next)) return { ok: false, errors: ["the loop state could not be written"] };
  return { ok: true, errors: [], loop: next, message: `Paused at round ${loop.round}.` };
}

export function resumeLoop(projectRoot: string, snapshot: TreeSnapshot): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project"] };
  if (loop.status === "complete") return { ok: false, errors: ["this /goal already met its contract — start a new one instead of resuming"] };
  if (loop.status === "running") return { ok: false, errors: [`the audit ${loop.kind} is already running`] };
  const { pausedReason, stopReason, ...rest } = loop;
  void pausedReason;
  void stopReason;
  const next: AuditLoopState = { ...rest, status: "running", stallRounds: 0 };
  if (!writeLoop(projectRoot, next)) return { ok: false, errors: ["the loop state could not be written"] };
  return {
    ok: true,
    errors: [],
    loop: next,
    message: `Resumed at round ${loop.round}; the stall counter was reset so the plateau starts fresh.`,
  };
}

export function stopLoop(projectRoot: string, snapshot: TreeSnapshot, reason: string): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project"] };
  if (loop.status === "stopped" || loop.status === "complete") return { ok: false, errors: [`the audit ${loop.kind} is already ${loop.status}`] };
  const next: AuditLoopState = { ...loop, status: "stopped", stopReason: reason, awaitingRound: null };
  if (!writeLoop(projectRoot, next)) return { ok: false, errors: ["the loop state could not be written"] };
  return { ok: true, errors: [], loop: next, message: `Stopped at round ${loop.round}: ${reason}` };
}

// -----------------------------------------------------------------
// Round evaluation
// -----------------------------------------------------------------

export interface RoundOutcome {
  round: number;
  kind: RoundRecord["kind"];
  /** A verdict was reached on the round's node (or a finding was confirmed). */
  verdictReached: boolean;
  /** New evidence landed. */
  evidenceAdded: boolean;
  /** One line for the summary. */
  detail: string;
  /** True when the round moved the audit forward in any way. */
  produced: boolean;
}

/**
 * Judge a finished round by comparing the tree against the round's baseline.
 *
 * Derived rather than recorded — see the module header. `produced` is the
 * plateau signal: a round that reached no verdict and added no evidence is a
 * round that spent tokens and learned nothing.
 */
export function evaluateRound(snapshot: TreeSnapshot, record: RoundRecord): RoundOutcome {
  const confirmedNow = snapshot.nodes.filter((n) => n.status === "confirmed").length;
  const confirmedGrew = confirmedNow > record.confirmedAtStart;

  if (record.kind === "consolidate") {
    const verdictReached = confirmedGrew;
    const evidenceAdded = false;
    const detail = confirmedGrew
      ? `a finding was confirmed during the pass (${record.confirmedAtStart} → ${confirmedNow})`
      : "the pass produced no new confirmed finding";
    return { round: record.round, kind: record.kind, verdictReached, evidenceAdded, detail, produced: verdictReached };
  }

  const node = record.nodeId ? snapshot.byId.get(record.nodeId) : undefined;
  if (!node) {
    return {
      round: record.round,
      kind: record.kind,
      verdictReached: false,
      evidenceAdded: false,
      detail: record.nodeId ? `${record.nodeId} is no longer in the tree` : "the round had no node",
      produced: false,
    };
  }

  const verdictReached = isVerdict(node.status) && !isVerdict(record.nodeStatusAtStart ?? "pending");
  const evidenceAdded = node.evidence.length > record.nodeEvidenceAtStart;
  const detail = verdictReached
    ? `${node.id} → ${node.status} (${node.evidence.length} evidence entry/entries)`
    : evidenceAdded
      ? `${node.id} gained evidence but no verdict yet (${record.nodeEvidenceAtStart} → ${node.evidence.length})`
      : `${node.id} produced no verdict and no new evidence`;
  return { round: record.round, kind: record.kind, verdictReached, evidenceAdded, detail, produced: verdictReached || evidenceAdded || confirmedGrew };
}

// -----------------------------------------------------------------
// The round brief
// -----------------------------------------------------------------

/**
 * The message handed to the model to drive one round.
 *
 * It states the node, WHY the scheduler chose it, the current contract gap, and
 * exactly which tools to call. It also repeats the falsification rule, because
 * a round brief is the only instruction the model sees on this turn and the
 * rule is what makes the resulting verdict worth having.
 */
export function renderRoundBrief(
  snapshot: TreeSnapshot,
  loop: AuditLoopState,
  round: number,
  kind: RoundRecord["kind"],
  node: Hypothesis | null,
  previous: RoundOutcome | null,
): string {
  const lines: string[] = [];
  lines.push(`[AUDIT ROUND ${round} — ${kind === "consolidate" ? "COMBINE" : "VERIFY"}]`);
  lines.push("");
  lines.push(`Audit ${loop.kind}: ${loop.objective}`);
  if (loop.contract) {
    const evaluation = contractMet(snapshot, loop.contract);
    lines.push(`Contract: ${describeContract(loop.contract)}`);
    lines.push(`  ${evaluation.detail.join("; ")}`);
  }
  lines.push("");

  if (previous) {
    lines.push(`Last round (${previous.round}): ${previous.detail}`);
    lines.push("");
  }

  if (kind === "consolidate") {
    lines.push("This is a COMBINATION round: a pass is due, and it must run before more single hypotheses are examined.");
    lines.push("");
    lines.push(...renderConsolidation(planConsolidation(snapshot, { force: "manual" })));
    return lines.join("\n");
  }

  if (!node) {
    lines.push("There is no node to examine this round.");
    return lines.join("\n");
  }

  lines.push(`YOUR NODE: ${node.id} — "${node.description}"`);
  lines.push(
    `  class ${node.category}${node.combinationKind ? `+${node.combinationKind}` : ""} · depth ${node.depth} · ` +
      `${node.evidence.length} evidence entry/entries · status ${node.status}` +
      (node.severity ? ` · severity ${node.severity}` : ""),
  );
  if (node.spawnedFrom.length > 0) lines.push(`  derived from ${node.spawnedFrom.join(" + ")}`);
  lines.push("");
  lines.push("The scheduler picked it because:");
  for (const reason of renderDecision(planNextRound(snapshot, { round })).slice(0, 6)) lines.push(`  ${reason.trim()}`);
  lines.push("");
  lines.push("DO THIS, in order:");
  lines.push("  1. Decide which MECHANICAL fact would refute this assertion. State it as a probe.");
  lines.push(`  2. Call hypothesis_verify on ${node.id} with those probes.`);
  lines.push(`     - a grep probe REQUIRES expectation: "present" or "absent" — what the hypothesis PREDICTS.`);
  lines.push(`     - a probe that cannot fail proves nothing.`);
  lines.push(`  3. Call hypothesis_record with the verdict and the counterexample or the support.`);
  lines.push("     - one counterexample refutes: record \"rejected\" when a probe fails.");
  lines.push("     - never record \"confirmed\" from a surviving grep alone — a pattern match is not a data flow.");
  lines.push("     - if the evidence does not settle it, record \"blocked\" with what it waits on.");
  lines.push("  4. If the verdict raises a NEW question, call hypothesis_add for it.");
  lines.push("");
  lines.push("Then stop. The next round is scheduled automatically after this turn ends.");
  return lines.join("\n");
}

// -----------------------------------------------------------------
// The round summary and the ledger
// -----------------------------------------------------------------

/** The readable per-round summary — the acceptance criterion for `/loop`. */
export function renderRoundSummary(
  snapshot: TreeSnapshot,
  loop: AuditLoopState,
  round: number,
  kind: RoundRecord["kind"],
  node: Hypothesis | null,
  previous: RoundOutcome | null,
): string[] {
  const nodes = snapshot.nodes;
  const confirmed = nodes.filter((n) => n.status === "confirmed").length;
  const rejected = nodes.filter((n) => n.status === "rejected").length;
  const open = nodes.length - confirmed - rejected;
  const depth = nodes.reduce((max, n) => Math.max(max, n.depth), 0);
  const combo = consolidationStatus(snapshot);
  const lines: string[] = [];

  lines.push(`ROUND ${round} — ${kind === "consolidate" ? "combine findings" : `verify ${node?.id ?? "(none)"}`}`);
  if (previous) lines.push(`  last round: ${previous.detail}`);
  if (kind === "verify" && node) {
    lines.push(`  node: "${clip(node.description, 90)}"`);
    lines.push(`  ${node.category} · depth ${node.depth} · ${node.evidence.length} evidence · status ${node.status}`);
  }
  lines.push(`  tree: ${nodes.length} nodes · ${confirmed} confirmed · ${rejected} rejected · ${open} open · depth ${depth}`);
  lines.push(
    `  combinations: ${combo.passes} pass(es)` +
      (combo.lastRound !== null ? `, last at round ${combo.lastRound}` : "") +
      `, ${combo.examinedPairs} pair(s) examined` +
      (combo.due ? " — a pass is DUE" : ""),
  );
  if (loop.contract) {
    const evaluation = contractMet(snapshot, loop.contract);
    lines.push(`  contract: ${describeContract(loop.contract)}`);
    for (const line of evaluation.detail) lines.push(`    ${line}${evaluation.met ? " ✓" : ""}`);
  }
  lines.push(`  stall: ${loop.stallRounds}/${loop.plateauWindow}${loop.maxRounds > 0 ? ` · round cap ${loop.maxRounds}` : " · unbounded"}`);
  lines.push(kind === "verify" && node ? `  next: hypothesis_verify ${node.id} → hypothesis_record` : "  next: the combination brief in this turn");
  return lines;
}

/**
 * Append the round to the human-readable findings ledger.
 *
 * Append-only, like every other durable artifact here: a ledger that can be
 * rewritten is a ledger whose earlier state cannot be trusted. Each entry
 * carries the confirmed findings and a bounded tree snapshot, so a reader can
 * reconstruct what the audit looked like at that round without the JSONL.
 */
export function appendFindingsLedger(
  projectRoot: string,
  snapshot: TreeSnapshot,
  round: number,
  summary: string[],
  at = nowIso(),
): boolean {
  const confirmed = snapshot.nodes.filter((n) => n.status === "confirmed");
  const body: string[] = [];
  body.push("");
  body.push(`## Round ${round} — ${at}`);
  body.push("");
  body.push("```");
  body.push(...summary);
  body.push("```");
  body.push("");
  body.push(`### Confirmed findings (${confirmed.length})`);
  if (confirmed.length === 0) {
    body.push("");
    body.push("_none yet_");
  } else {
    body.push("");
    for (const node of confirmed) {
      const where = node.evidence.find((e) => e.location)?.location;
      const sev = node.severity ? `[${node.severity}] ` : "[unrated] ";
      const combo = node.combinationKind ? ` (${node.combinationKind} of ${node.spawnedFrom.join("+")})` : "";
      body.push(`- ${sev}**${node.id}** ${node.description} — ${node.category}${combo}${where ? ` — ${where.file}:${where.line}` : ""}`);
    }
  }
  body.push("");
  body.push(`### Tree snapshot (${snapshot.nodes.length} nodes)`);
  body.push("");
  body.push("```");
  body.push(...renderTree(snapshot, { maxNodes: LOOP_DEFAULTS.LEDGER_TREE_LINES, width: 110 }));
  body.push("```");
  body.push("");

  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    fs.appendFileSync(findingsLedgerPath(projectRoot), body.join("\n"), "utf-8");
    return true;
  } catch {
    return false;
  }
}

// -----------------------------------------------------------------
// The tick
// -----------------------------------------------------------------

export interface TickOptions {
  /** Suppress sending the brief; still evaluates and records. */
  dryRun?: boolean;
  at?: string;
}

export interface TickResult {
  action: "sent" | "paused" | "stopped" | "complete" | "idle";
  reason: string;
  round?: number;
  nodeId?: string | null;
  brief?: string;
  summary?: string[];
  previous?: RoundOutcome | null;
}

/**
 * Advance the audit loop by one round.
 *
 * Evaluates the in-flight round first (if any), then decides whether to send the
 * next brief. Returns the brief rather than sending it, so the caller owns the
 * transport and this module stays testable without a host.
 */
export function tickLoop(projectRoot: string, snapshot: TreeSnapshot, opts: TickOptions = {}): TickResult {
  const at = opts.at ?? nowIso();
  const loop = snapshot.loop;
  if (!loop) return { action: "idle", reason: "no audit loop in this project" };
  if (loop.status === "complete") return { action: "complete", reason: loop.stopReason ?? "the completion contract is satisfied" };
  if (loop.status === "stopped") return { action: "stopped", reason: loop.stopReason ?? "stopped" };
  if (loop.status === "paused") return { action: "paused", reason: loop.pausedReason ?? "paused" };

  let current = loop;
  let previous: RoundOutcome | null = null;

  // 1. Evaluate the in-flight round before deciding anything.
  if (current.awaitingRound !== null) {
    const record = snapshot.roundRecords.find((r) => r.round === current.awaitingRound);
    if (record) {
      previous = evaluateRound(snapshot, record);
      current = {
        ...current,
        awaitingRound: null,
        stallRounds: previous.produced ? 0 : current.stallRounds + 1,
      };
    } else {
      // The record is missing (a torn write, or a wipe). Clearing the fence is
      // the honest move: the round's outcome is unknowable, so do not invent one.
      current = { ...current, awaitingRound: null };
    }
  }

  // 2. The completion contract (`/goal` only).
  if (current.contract) {
    const evaluation = contractMet(snapshot, current.contract);
    if (evaluation.met) {
      const done: AuditLoopState = {
        ...current,
        status: "complete",
        stopReason: `contract satisfied at round ${current.round}: ${evaluation.detail.join("; ")}`,
      };
      writeLoop(projectRoot, done, at);
      return { action: "complete", reason: done.stopReason!, round: current.round, previous };
    }
  }

  // 3. The plateau.
  if (current.stallRounds >= current.plateauWindow) {
    const stopped: AuditLoopState = {
      ...current,
      status: "stopped",
      stopReason:
        `plateau — ${current.stallRounds} consecutive round(s) produced no verdict and no new evidence ` +
        `(window ${current.plateauWindow}); the well looks dry`,
    };
    writeLoop(projectRoot, stopped, at);
    return { action: "stopped", reason: stopped.stopReason!, round: current.round, previous };
  }

  // 4. The round cap.
  if (current.maxRounds > 0 && current.round >= current.maxRounds) {
    const stopped: AuditLoopState = {
      ...current,
      status: "stopped",
      stopReason: `round cap reached (${current.maxRounds})`,
    };
    writeLoop(projectRoot, stopped, at);
    return { action: "stopped", reason: stopped.stopReason!, round: current.round, previous };
  }

  // 5. Which kind of round? A due combination pass pre-empts verification,
  //    because it is a forced trigger.
  const round = current.round + 1;
  const pendingConsolidation = planConsolidation(snapshot);
  const kind: RoundRecord["kind"] = pendingConsolidation.due ? "consolidate" : "verify";

  let node: Hypothesis | null = null;
  let recorded = false;

  if (kind === "consolidate") {
    recorded = applyConsolidation(projectRoot, pendingConsolidation, at).ok;
  } else {
    const decision = planNextRound(snapshot, { round });
    if (!decision.selected) {
      const stopped: AuditLoopState = {
        ...current,
        status: "stopped",
        stopReason: `no open hypotheses remain (${decision.reasons[0] ?? "every node has a verdict"})`,
      };
      writeLoop(projectRoot, stopped, at);
      return { action: "stopped", reason: stopped.stopReason!, round: current.round, previous };
    }
    node = decision.selected;
    recorded = applySelection(projectRoot, decision, at).ok;
  }

  if (!recorded) {
    return { action: "idle", reason: "the round could not be recorded — the tree is unchanged", round: current.round, previous };
  }

  // Re-read: applySelection/applyConsolidation wrote events.
  const after = reload(projectRoot);
  // And re-read the NODE from the fresh snapshot. `decision.selected` is the
  // pre-selection object, so its status is still "pending" while the tree now
  // says "testing" — reporting the stale one would make the summary disagree
  // with the tree it describes.
  if (node) node = after.byId.get(node.id) ?? null;

  const summary = renderRoundSummary(after, current, round, kind, node, previous);
  const brief = renderRoundBrief(after, current, round, kind, node, previous);

  const record: RoundRecord = {
    round,
    at,
    kind,
    nodeId: node?.id ?? null,
    nodeStatusAtStart: node?.status ?? null,
    nodeEvidenceAtStart: node?.evidence.length ?? 0,
    confirmedAtStart: after.nodes.filter((n) => n.status === "confirmed").length,
    summary,
  };
  if (!appendEvent(projectRoot, { type: "round_detail", at, record })) {
    return { action: "idle", reason: "the round record could not be written", round, previous };
  }
  appendFindingsLedger(projectRoot, after, round, summary, at);

  if (!opts.dryRun) {
    writeLoop(projectRoot, { ...current, round, awaitingRound: round }, at);
  }

  return { action: "sent", reason: `round ${round} prepared`, round, nodeId: node?.id ?? null, brief, summary, previous };
}

/**
 * Re-fold after a write.
 *
 * `applySelection` and `applyConsolidation` append their own events, so the
 * snapshot the caller passed in is now stale. Re-reading is the only correct
 * move: mutating a stale snapshot by hand would be a second source of truth.
 */
function reload(projectRoot: string): TreeSnapshot {
  return load(projectRoot).snapshot;
}

// -----------------------------------------------------------------
// Status and widget
// -----------------------------------------------------------------

export function renderLoopStatus(snapshot: TreeSnapshot): string[] {
  const loop = snapshot.loop;
  if (!loop) {
    return [
      "No audit loop in this project.",
      "  /goal \"<objective>\"   one audited objective, until a contract is met",
      "  /loop                 keep auditing until stopped or the well runs dry",
    ];
  }
  const lines: string[] = [];
  lines.push(`Audit ${loop.kind}: ${loop.status.toUpperCase()} — ${clip(loop.objective, 100)}`);
  lines.push(
    `  round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : " (unbounded)"}` +
      ` · stall ${loop.stallRounds}/${loop.plateauWindow}` +
      (loop.awaitingRound !== null ? ` · round ${loop.awaitingRound} in flight` : " · nothing in flight"),
  );
  if (loop.contract) {
    const evaluation = contractMet(snapshot, loop.contract);
    lines.push(`  contract: ${describeContract(loop.contract)} — ${evaluation.met ? "MET" : "not met"}`);
    for (const line of evaluation.detail) lines.push(`    ${line}`);
  }
  if (loop.stopReason) lines.push(`  stop reason: ${loop.stopReason}`);
  if (loop.pausedReason) lines.push(`  paused: ${loop.pausedReason}`);
  lines.push(`  started ${loop.startedAt}, updated ${loop.updatedAt}`);

  const recent = snapshot.roundRecords.slice(-3);
  if (recent.length > 0) {
    lines.push("  recent rounds:");
    for (const record of recent) {
      lines.push(`    r${record.round} ${record.kind} ${record.nodeId ?? "-"} — ${clip(record.summary[0] ?? "", 70)}`);
    }
  }
  return lines;
}

/** A three-line widget: enough to see the loop is alive and where it is. */
export function renderWidget(snapshot: TreeSnapshot): string[] | null {
  const loop = snapshot.loop;
  if (!loop) return null;
  const confirmed = snapshot.nodes.filter((n) => n.status === "confirmed").length;
  const rejected = snapshot.nodes.filter((n) => n.status === "rejected").length;
  const open = snapshot.nodes.length - confirmed - rejected;
  const glyph = loop.status === "running" ? "▶" : loop.status === "paused" ? "‖" : loop.status === "complete" ? "✓" : "■";
  const contract = loop.contract ? contractMet(snapshot, loop.contract) : null;
  const lines = [
    `hypothesis ${glyph} ${loop.kind} round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : ""} · ${confirmed} confirmed · ${rejected} rejected · ${open} open`,
  ];
  if (loop.awaitingRound !== null) lines.push(`  in flight: round ${loop.awaitingRound} · stall ${loop.stallRounds}/${loop.plateauWindow}`);
  if (contract) lines.push(`  contract ${contract.met ? "MET" : "open"}: ${contract.detail[0] ?? ""}`);
  return lines;
}

export { severityRank };
