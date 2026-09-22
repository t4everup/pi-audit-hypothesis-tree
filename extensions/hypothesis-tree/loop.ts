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
  type HypothesisStatus,
  type ReconSegment,
  type RoundRecord,
  type Severity,
  type TreeSnapshot,
  describeTiming,
  formatDuration,
  chainState,
  authReach,
  hasBeenChallenged,
  isResolved,
  isSchedulable,
  isVerdict,
  meetsSeverity,
  loopTiming,
  severityRank,
  type LoopTiming,
  type ReportLanguage,
  verificationTier,
} from "./types.js";
import { STATE_DIR_NAME, appendEvent, load, nowIso } from "./store.js";
import { applySelection, planNextRound, renderDecision } from "./scheduler.js";
import { applyNodePatch } from "./tree.js";
import { applyConsolidation, consolidationStatus, planConsolidation, renderConsolidation } from "./combination.js";
import { markNotesDelivered, pendingNotes, renderNotesSection, renderNotesStatus, writeOperatorMirror } from "./notes.js";
import { loadSettings } from "./settings.js";
import { renderLadder } from "./ladders.js";
import {
  COVERAGE,
  type CoverageReport,
  coverageGaps,
  hasCoverageGap,
  renderCoverageBrief,
} from "./coverage.js";
import { writeReport } from "./report.js";
import { renderTree, clip } from "./render.js";
import {
  closedSegmentIds,
  nextOpenSegment,
  renderCoverage,
  renderReconBrief,
  renderSegmentBrief,
  segmentCoverage,
} from "./recon.js";

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
  /**
   * Rounds between challenges once the first one has run.
   *
   * The FIRST challenge fires as soon as a finding is confirmed — that is the
   * valuable one. Later confirmations are attacked on this cadence so a long
   * run does not spend every round re-attacking its own output.
   */
  CHALLENGE_INTERVAL: 5,
  /**
   * Is a pursuit already OPEN (started, not finished)?
   *
   * An open pursuit outranks a due combination pass. The pass sits above challenge
   * and pursue in the chain, and its trigger fires on almost every new finding, so
   * on a real audit the sequence became `consolidate, verify, consolidate, verify`
   * — seven passes in 27 rounds, combining nothing, with the depth round never
   * getting a slot. A pursuit is BOUNDED (two rounds per finding, closed the moment
   * it produces nothing), so it cannot starve anything by going first.
   */
  /**
   * Rounds between PURSUE rounds.
   *
   * This is the anti-starvation invariant, and it is the lesson from the
   * combination bug: a round kind that can pre-empt every other kind eventually
   * does exactly that. A gap of 2 means two pursue rounds are never adjacent, so
   * verification keeps at least half the rounds no matter how many findings want
   * depth.
   */
  PURSUE_INTERVAL: 2,
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
  requireArtifact?: boolean;
  requireReproduced?: boolean;
  requireChallenged?: boolean;
  requireImpact?: boolean;
  requireExploitable?: boolean;
  requirePreAuth?: boolean;
}

/**
 * Build a contract from parsed command flags.
 *
 * The DEFAULTS are what a code audit actually wants, because the old ones were
 * not: `minConfirmed: 1` alone let the first confirmed finding end the goal,
 * including an unrated one or one resting on nothing but an argument. A security
 * audit means "at least one HIGH-or-worse finding that is anchored in code", so
 * that is the default.
 */
export function buildContract(clauses: ContractClauses): CompletionContract {
  return {
    minConfirmed: clauses.confirmed ?? 1,
    minSeverity: clauses.severity ?? "high",
    ...(clauses.category && clauses.category.length > 0 ? { categories: clauses.category } : {}),
    requireConsolidated: clauses.requireConsolidated ?? true,
    requireArtifact: clauses.requireArtifact ?? true,
    requireReproduced: clauses.requireReproduced ?? false,
    requireChallenged: clauses.requireChallenged ?? true,
    requireImpact: clauses.requireImpact ?? false,
    requireExploitable: clauses.requireExploitable ?? false,
    requirePreAuth: clauses.requirePreAuth ?? false,
  };
}

export function describeContract(contract: CompletionContract | null): string {
  if (!contract) return "none (runs until stopped)";
  const parts = [`at least ${contract.minConfirmed} confirmed finding(s)`];
  if (contract.minSeverity) parts.push(`at severity >= ${contract.minSeverity}`);
  if (contract.categories && contract.categories.length > 0) parts.push(`in ${contract.categories.join(" or ")}`);
  if (contract.requireArtifact) parts.push("each anchored in real code (not reasoning alone)");
  if (contract.requireReproduced) parts.push("each reproduced by a command");
  if (contract.requireChallenged) parts.push("each having SURVIVED an attempt to refute it");
  if (contract.requireImpact) parts.push("each stating what an attacker gains");
  if (contract.requireExploitable) parts.push("each with a COMPLETE exploitation chain (no unverified precondition)");
  if (contract.requirePreAuth) parts.push("each reachable WITHOUT authentication");
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

  const allConfirmed = snapshot.nodes.filter((n) => n.status === "confirmed");
  const inScope = allConfirmed.filter((n) => {
    if (contract.categories && contract.categories.length > 0 && !contract.categories.includes(n.category)) return false;
    return true;
  });
  const detail: string[] = [];

  // Tier filtering: a finding that rests on an argument is not a finding.
  const qualifying = inScope.filter((n) => {
    const tier = verificationTier(n);
    if (contract.requireArtifact && tier === "reasoning-only") return false;
    if (contract.requireReproduced && tier !== "reproduced") return false;
    if (contract.requireChallenged && !hasBeenChallenged(n)) return false;
    if (contract.requireImpact && !n.attackVector?.impact?.trim()) return false;
    if (contract.requirePreAuth && authReach(n.attackVector) !== "pre-auth") return false;
    if (contract.requireExploitable) {
      const chain = chainState(n, (id) => snapshot.byId.get(id)).state;
      // `standalone` counts: a finding with no gates has a complete chain by
      // definition, and excluding it would make the clause mean "must have a
      // gate" rather than "must be usable".
      if (chain !== "standalone" && chain !== "chain-ready") return false;
    }
    return true;
  });
  const droppedForTier = inScope.length - qualifying.length;

  const countOk = qualifying.length >= contract.minConfirmed;
  detail.push(
    `${qualifying.length}/${contract.minConfirmed} qualifying confirmed finding(s)` +
      (contract.categories && contract.categories.length > 0 ? ` in ${contract.categories.join(" or ")}` : "") +
      (droppedForTier > 0
        ? ` (${droppedForTier} confirmed finding(s) excluded: ${
            contract.requireChallenged ? "not yet challenged" : contract.requireReproduced ? "not reproduced by a command" : "reasoning only, no artifact"
          })`
        : ""),
  );
  if (contract.requireChallenged && inScope.length > 0) {
    const challenged = inScope.filter((n) => hasBeenChallenged(n)).length;
    detail.push(`${challenged}/${inScope.length} confirmed finding(s) have been challenged`);
  }
  if (contract.requirePreAuth && inScope.length > 0) {
    const pre = inScope.filter((n) => authReach(n.attackVector) === "pre-auth").length;
    const notAssessed = inScope.filter((n) => authReach(n.attackVector) === "unassessed").length;
    detail.push(
      `${pre}/${inScope.length} confirmed finding(s) are reachable WITHOUT authentication` +
        (notAssessed > 0
          ? ` — ${notAssessed} have NOT been assessed and do not count: "nobody determined it" is not "pre-auth"`
          : ""),
    );
  }
  if (contract.requireExploitable && inScope.length > 0) {
    const usable = inScope.filter((n) => {
      const state = chainState(n, (id) => snapshot.byId.get(id)).state;
      return state === "standalone" || state === "chain-ready";
    }).length;
    detail.push(
      `${usable}/${inScope.length} confirmed finding(s) have a COMPLETE exploitation chain` +
        (usable < inScope.length
          ? ` — ${inScope.length - usable} are real but gated on an unverified precondition (the sink is confirmed, the way in is not)`
          : ""),
    );
  }

  let severityOk = true;
  if (contract.minSeverity) {
    const rated = qualifying.filter((n) => n.severity);
    severityOk = rated.some((n) => meetsSeverity(n.severity, contract.minSeverity!));
    const unrated = qualifying.length - rated.length;
    detail.push(
      `${rated.filter((n) => meetsSeverity(n.severity, contract.minSeverity!)).length} at severity >= ${contract.minSeverity}` +
        (unrated > 0 ? ` (${unrated} qualifying finding(s) carry no severity yet — they are NOT counted as low)` : ""),
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
  /** The classes this run is FOR. See AuditLoopState.focus. */
  focus?: string[];
  at?: string;
}

export interface StartLoopResult {
  ok: boolean;
  errors: string[];
  loop?: AuditLoopState;
  /** True when an existing PAUSED loop was resumed instead of a new one started. */
  resumed?: boolean;
}

/**
 * Can `/start` be satisfied by resuming the loop that is already there?
 *
 * Two things make it a DIFFERENT audit rather than a continuation, and resuming
 * would then silently keep the old one:
 *
 *   - a different KIND (`/goal` start over a paused `/loop`),
 *   - a different OBJECTIVE.
 */
function canResumeInPlace(existing: AuditLoopState, opts: StartLoopOptions): boolean {
  if (existing.kind !== opts.kind) return false;
  const wanted = opts.objective.trim();
  return !wanted || wanted === existing.objective.trim();
}

/**
 * Why `/start` could not be honoured, naming the exact command that would work.
 *
 * A refusal that says "stop it first or resume it" without the arguments is a
 * refusal the reader has to guess their way out of.
 */
function describeStartRefusal(existing: AuditLoopState, opts: StartLoopOptions): string {
  const where = `at round ${existing.round} ("${clip(existing.objective, 60)}")`;
  if (existing.status === "running") {
    return (
      `the audit ${existing.kind} is already RUNNING ${where}. ` +
      `/${existing.kind} status to watch it, or /${existing.kind} pause to stop the clock.`
    );
  }
  if (existing.kind !== opts.kind) {
    return (
      `a PAUSED /${existing.kind} exists ${where}, so /${opts.kind} start would abandon it. ` +
      `Resume it with /${existing.kind} resume, or end it with /${existing.kind} stop first.`
    );
  }
  return (
    `a PAUSED /${existing.kind} exists ${where} with a DIFFERENT objective, and resuming would silently keep that one. ` +
    `Resume it with /${existing.kind} resume, or end it with /${existing.kind} stop and then start this one.`
  );
}

/**
 * Start an audit, or RESUME the paused one that is already there.
 *
 * A paused loop is resumed rather than refused. "start" is the word a person
 * types when they want the audit to go again, and with a paused loop present
 * that is exactly what they mean: the tree and the round state are preserved
 * either way, and the old refusal left them holding a message that named neither
 * the right verb nor its arguments.
 *
 * A RUNNING loop is still refused — there is nothing to do but watch it — and so
 * is a paused loop with a different kind or objective, because resuming that
 * would silently keep an objective the user is no longer asking for.
 */
export function startLoop(projectRoot: string, snapshot: TreeSnapshot, opts: StartLoopOptions): StartLoopResult {
  const existing = snapshot.loop;
  if (existing && (existing.status === "running" || existing.status === "paused")) {
    if (existing.status === "paused" && canResumeInPlace(existing, opts)) {
      const resumed = resumeLoop(projectRoot, snapshot, {
        ...(opts.maxRounds !== undefined ? { maxRounds: opts.maxRounds } : {}),
      });
      if (!resumed.ok || !resumed.loop) return { ok: false, errors: resumed.errors };
      return { ok: true, errors: [], loop: resumed.loop, resumed: true };
    }
    return { ok: false, errors: [describeStartRefusal(existing, opts)] };
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
    ...(opts.focus && opts.focus.length > 0 ? { focus: [...opts.focus] } : {}),
    pausedMs: 0,
    pausedAt: null,
    endedAt: null,
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

export function pauseLoop(projectRoot: string, snapshot: TreeSnapshot, reason: string, at = nowIso()): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project"] };
  if (loop.status !== "running") {
    return {
      ok: false,
      errors: [
        loop.status === "paused"
          ? `the audit ${loop.kind} is ALREADY PAUSED at round ${loop.round}. Resume it with /${loop.kind} resume.`
          : `the audit ${loop.kind} is ${loop.status}, so there is no clock to stop. Start a new one with /${loop.kind} start.`,
      ],
    };
  }
  // `pausedAt` opens a pause interval. It is CLOSED by resumeLoop (banking the
  // span into pausedMs) or, if the loop is stopped while paused, by `endedAt`
  // in loopTiming — so a pause that is never resumed is still counted.
  const next: AuditLoopState = { ...loop, status: "paused", pausedReason: reason, pausedAt: at };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return { ok: true, errors: [], loop: next, message: `Paused at round ${loop.round}.` };
}

export function resumeLoop(
  projectRoot: string,
  snapshot: TreeSnapshot,
  opts: { maxRounds?: number } = {},
  at = nowIso(),
): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project"] };
  if (loop.status === "complete") return { ok: false, errors: ["this /goal already met its contract — start a new one instead of resuming"] };
  if (loop.status === "running") {
    return { ok: false, errors: [`the audit ${loop.kind} is already RUNNING at round ${loop.round} — nothing to resume.`] };
  }

  // The round cap is DURABLE, so resuming past it does nothing: the tick would
  // immediately re-stop with the same reason. Silently "succeeding" there is
  // worse than refusing — the user sees a resume message and no progress.
  //
  // The PLATEAU does not have this problem: resume resets `stallRounds`, so a
  // plateau stop genuinely recovers in place.
  const capReached = loop.maxRounds > 0 && loop.round >= loop.maxRounds;
  const raised = opts.maxRounds !== undefined && opts.maxRounds > loop.maxRounds;
  if (capReached && !raised) {
    const suggested = loop.round + 10;
    return {
      ok: false,
      errors: [
        `the round cap (${loop.maxRounds}) is already reached at round ${loop.round}, so resuming would stop again immediately and send no round.`,
        `Raise the cap in place:  /${loop.kind} resume maxRounds=${suggested}`,
        `Or start a new one:      /${loop.kind} start "<objective>" maxRounds=${suggested}  (the tree and its hypotheses are kept either way)`,
      ],
    };
  }

  const { pausedReason, stopReason, ...rest } = loop;
  void pausedReason;
  void stopReason;
  // Resuming is work: bring the widget back if the operator had closed it.
  const { widgetHidden, ...restWithoutHidden } = rest;
  void widgetHidden;
  // Bank the pause interval being closed, so `activeMs` does not include time
  // the audit spent unable to work. Clamped at zero for a backwards clock jump.
  const pausedAt = loop.pausedAt ? Date.parse(loop.pausedAt) : NaN;
  const resumedAt = Date.parse(at);
  const closedPause =
    Number.isFinite(pausedAt) && Number.isFinite(resumedAt) ? Math.max(0, resumedAt - pausedAt) : 0;
  const next: AuditLoopState = {
    ...restWithoutHidden,
    status: "running",
    stallRounds: 0,
    pausedMs: loop.pausedMs + closedPause,
    pausedAt: null,
    ...(opts.maxRounds !== undefined && opts.maxRounds > 0 ? { maxRounds: opts.maxRounds } : {}),
  };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return {
    ok: true,
    errors: [],
    loop: next,
    message:
      `Resumed at round ${loop.round}; the stall counter was reset so the plateau starts fresh.` +
      (raised ? ` Round cap raised to ${opts.maxRounds}.` : ""),
  };
}

/**
 * Park the loop after a brief could not be delivered.
 *
 * The FENCE IS CLEARED, not left set. `awaitingRound` means "a turn for this
 * round is in flight"; a brief that never reached the model has no turn, so
 * leaving the fence set would make the next tick judge a round that never ran
 * as unproductive and burn a plateau slot for nothing.
 *
 * The loop is PAUSED rather than left running, because a failed send has no
 * automatic retry path: the agent is idle, so no further lifecycle event will
 * arrive to try again. Parking hands the decision back to the user with an
 * explicit resume.
 */
export function parkOnSendFailure(projectRoot: string, reason: string, at = nowIso()): boolean {
  const loop = load(projectRoot).snapshot.loop;
  if (!loop) return false;
  return writeLoop(projectRoot, { ...loop, status: "paused", awaitingRound: null, pausedReason: reason }, at);
}

export function stopLoop(projectRoot: string, snapshot: TreeSnapshot, reason: string, at = nowIso()): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project"] };
  if (loop.status === "stopped" || loop.status === "complete") return { ok: false, errors: [`the audit ${loop.kind} is already ${loop.status}`] };
  // `endedAt` freezes the clock. Without it a stopped loop's elapsed time would
  // keep growing every time the status was printed.
  const next: AuditLoopState = { ...loop, status: "stopped", stopReason: reason, awaitingRound: null, endedAt: at };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return { ok: true, errors: [], loop: next, message: `Stopped at round ${loop.round} after ${formatDuration(loopTiming(next)?.activeMs ?? 0)}: ${reason}` };
}

/**
 * The round records belonging to the CURRENT run.
 *
 * `/loop start` on an existing tree restarts the round counter at 0, so round
 * numbers are NOT unique across a tree's life: a tree that ran 48 rounds and was
 * then restarted has two records for round 1. Every lookup by round number alone
 * therefore has to say WHICH run it means, and `startedAt` is what separates
 * them.
 *
 * Without this, a restarted loop evaluating its round 1 found the PREVIOUS run's
 * round 1 — a round that had been productive — and reset its stall counter to
 * zero, so the plateau never fired and the widget showed `stall 0/8` while
 * dozens of unproductive rounds went by.
 */
export function currentRunRounds(snapshot: TreeSnapshot): RoundRecord[] {
  const loop = snapshot.loop;
  if (!loop) return snapshot.roundRecords;
  return snapshot.roundRecords.filter((r) => r.at >= loop.startedAt);
}

/**
 * Only findings this bad get pursued for depth.
 *
 * Depth is the expensive round: it is the one that does not advance the
 * breadth-first sweep. Spending it on an `info` finding costs a round that a
 * `high` finding's whole bug class could have used.
 */
export const PURSUE_MIN_SEVERITY: Severity = "high";

/**
 * The finding the next PURSUE round should go DEEPER on, or null.
 *
 * Every other round kind moves to a SIBLING hypothesis. A tree built that way is
 * wide and shallow — measured on a real audit: 29 nodes at depth 1, 8 at depth 2,
 * 1 at depth 3 — and a finding is rarely one endpoint. A missing check is
 * usually missing in a shared helper, a base class or a framework default that
 * the whole surface inherits, and "one bug" only becomes "the whole class" by
 * staying on the lead.
 *
 * Bounded three ways, because an unbounded round kind is how the combination bug
 * starved verification:
 *
 *   1. never two in a row (PURSUE_INTERVAL),
 *   2. a per-finding budget (`pursueSpent < budget`),
 *   3. an unproductive round closes the pursuit immediately.
 */
/** What a report renders when coverage was not computed for this round. */
function emptyCoverage(): CoverageReport {
  return { citedFiles: 0, projectFiles: null, truncated: false, reason: "not computed", gaps: [], skipNote: "" };
}

/**
 * May this round be a coverage round, and what is the gap?
 *
 * Four conditions, and each one exists because of a way this could go wrong:
 *
 *   the first note is FINISHED   — expanding breadth before the material is
 *                                  generated just moves the queue around
 *   a hypothesis exists already  — "nothing cited yet" would make every directory
 *                                  a gap on round one
 *   there IS a gap              — a brief with an empty list is a wasted round
 *   the budget is not spent     — bounded, like every other side quest here
 */
function coverageCandidate(projectRoot: string, snapshot: TreeSnapshot, loop: AuditLoopState): CoverageReport | null {
  if ((loop.coverageRounds ?? 0) >= COVERAGE.MAX_ROUNDS) return null;
  if (nextOpenSegment(snapshot) !== null) return null;
  const hypotheses = snapshot.nodes.filter((n) => n.nodeKind !== "scope");
  if (hypotheses.length === 0) return null;
  const report = coverageGaps(snapshot, projectRoot);
  return hasCoverageGap(report) ? report : null;
}

/** A pursuit that has started and not finished. See LOOP_DEFAULTS on why it goes first. */
export function hasOpenPursuit(snapshot: TreeSnapshot, budget: number): boolean {
  return snapshot.nodes.some(
    (n) => n.status === "confirmed" && (n.pursueSpent ?? 0) > 0 && (n.pursueSpent ?? 0) < budget,
  );
}

export function nextPursueTarget(snapshot: TreeSnapshot, currentRound: number, budget: number): Hypothesis | null {
  if (budget <= 0) return null;

  const lastPursue = currentRunRounds(snapshot)
    .filter((r) => r.kind === "pursue")
    .reduce<number | null>((max, r) => (max === null || r.round > max ? r.round : max), null);
  if (lastPursue !== null && currentRound - lastPursue < LOOP_DEFAULTS.PURSUE_INTERVAL) return null;

  const candidates = snapshot.nodes.filter(
    (n) => n.status === "confirmed" && (n.pursueSpent ?? 0) < budget && meetsSeverity(n.severity, PURSUE_MIN_SEVERITY),
  );
  if (candidates.length === 0) return null;

  // An OPEN pursuit is finished before a new one starts. Hopping to the next
  // finding after a single round is exactly the breadth-first behaviour this
  // round exists to correct.
  const open = candidates.filter((n) => (n.pursueSpent ?? 0) > 0);
  if (open.length > 0) {
    return [...open].sort((a, b) => (a.pursueSpent ?? 0) - (b.pursueSpent ?? 0) || a.id.localeCompare(b.id))[0]!;
  }

  // Otherwise open one on the worst finding that has never been pursued: a false
  // HIGH is the most expensive thing this audit can produce, and so is an
  // unexplored HIGH.
  return [...candidates].sort((a, b) => {
    const ra = a.severity ? severityRank(a.severity) : 99;
    const rb = b.severity ? severityRank(b.severity) : 99;
    if (ra !== rb) return ra - rb;
    return a.id.localeCompare(b.id);
  })[0]!;
}

/**
 * Round kinds that do NOT advance the breadth-first sweep.
 *
 * These are the side quests: they are all valuable, and they are all capable of
 * pre-empting the round that actually examines the next hypothesis. Measured on a
 * real audit, three of them with independent cadences squeezed verification down
 * to one round in nine — the same starvation the combination bug caused, arriving
 * by a different route.
 *
 * So they share ONE rule instead of one each: never two in a row. That
 * guarantees the sweep keeps at least half the rounds however many side quests
 * are due, and it needs no coordination between their cadences.
 */
const SIDE_QUESTS: readonly RoundRecord["kind"][] = ["consolidate", "challenge", "pursue"];

/** The finding the next challenge round should attack, or null.
 *
 * A confirmation is a hypothesis too. Without this, the model's first confident
 * judgement is permanent: a false positive satisfies a `/goal` contract (so the
 * audit stops on it) or sits in a `/loop`'s report as a finding nobody ever
 * attacked. The only thing that catches it is an attempt to falsify it.
 *
 * Bounded on purpose: one challenge per confirmation, then a cadence, so this
 * cannot become a loop of re-attacking the same finding.
 */
export function nextChallengeCandidate(snapshot: TreeSnapshot, currentRound: number): Hypothesis | null {
  const confirmed = snapshot.nodes.filter((n) => n.status === "confirmed");
  if (confirmed.length === 0) return null;

  const lastChallengeRound = currentRunRounds(snapshot)
    .filter((r) => r.kind === "challenge")
    .reduce<number | null>((max, r) => (max === null || r.round > max ? r.round : max), null);
  if (lastChallengeRound !== null && currentRound - lastChallengeRound < LOOP_DEFAULTS.CHALLENGE_INTERVAL) return null;

  const unchallenged = confirmed.filter((n) => !hasBeenChallenged(n));
  if (unchallenged.length === 0) return null;
  // Worst first: a false HIGH costs more than a false LOW.
  return [...unchallenged].sort((a, b) => {
    const ra = a.severity ? severityRank(a.severity) : 99;
    const rb = b.severity ? severityRank(b.severity) : 99;
    if (ra !== rb) return ra - rb;
    return a.id.localeCompare(b.id);
  })[0]!;
}

// -----------------------------------------------------------------
// Round evaluation
// -----------------------------------------------------------------

export interface RoundOutcome {
  round: number;
  kind: RoundRecord["kind"];
  /** The node the round examined, when it had one. */
  nodeId?: string | null;
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

  if (record.kind === "recon") {
    // A recon round produces the segment inventory itself, so "did it produce"
    // is "was a note submitted after this round started". ISO strings compare
    // correctly as strings, and the round's own `at` is the baseline.
    const submitted = snapshot.reconAt !== null && snapshot.reconAt >= record.at;
    const detail = submitted
      ? `recon note submitted — ${snapshot.segments.length} segment(s) to generate from`
      : "no recon note was submitted this round";
    return { round: record.round, kind: record.kind, verdictReached: false, evidenceAdded: false, detail, produced: submitted };
  }

  if (record.kind === "generate") {
    const id = record.segmentId ?? null;
    const closed = id ? closedSegmentIds(snapshot).has(id) : false;
    const produced = id ? snapshot.nodes.filter((n) => n.segmentId === id).length : 0;
    const detail = !id
      ? "the generate round named no segment"
      : closed
        ? produced > 0
          ? `segment ${id} closed — ${produced} hypothesis(es) added`
          : `segment ${id} closed with nothing found`
        : `segment ${id} produced no hypotheses and was not closed`;
    return { round: record.round, kind: record.kind, verdictReached: false, evidenceAdded: false, detail, produced: closed };
  }

  if (record.kind === "challenge") {
    const node = record.nodeId ? snapshot.byId.get(record.nodeId) : undefined;
    if (!node) {
      return {
        round: record.round,
        kind: record.kind,
        verdictReached: false,
        evidenceAdded: false,
        detail: record.nodeId ? `the challenged finding ${record.nodeId} is no longer in the tree` : "the challenge round named no finding",
        produced: false,
      };
    }
    const refuted = node.status === "rejected";
    const evidenceAdded = node.evidence.length > record.nodeEvidenceAtStart;
    const detail = refuted
      ? `${node.id} was REFUTED by the challenge — a false positive removed`
      : evidenceAdded
        ? `${node.id} survived the challenge (${node.evidence.length} evidence entry/entries)`
        : `${node.id} was challenged but nothing was recorded either way`;
    return { round: record.round, kind: record.kind, verdictReached: refuted, evidenceAdded, detail, produced: refuted || evidenceAdded };
  }

  if (record.kind === "coverage") {
    // A coverage round produces a NEW recon note, exactly like the first recon. The
    // test is whether one arrived after this round started — the note replaces the
    // segment inventory, so a later note is what "produced something" means here.
    const submitted = snapshot.reconAt !== null && snapshot.reconAt >= record.at;
    const detail = submitted
      ? `coverage recon submitted — ${snapshot.segments.length} new segment(s) from the untouched areas`
      : "no coverage recon note was submitted this round";
    return { round: record.round, kind: record.kind, verdictReached: false, evidenceAdded: false, detail, produced: submitted };
  }

  if (record.kind === "pursue") {
    const node = record.nodeId ? snapshot.byId.get(record.nodeId) : undefined;
    const added = Math.max(0, snapshot.nodes.length - record.nodeCountAtStart);
    const children = node ? snapshot.nodes.filter((n) => n.parentId === node.id).length : 0;
    if (!node) {
      return {
        round: record.round,
        kind: record.kind,
        verdictReached: false,
        evidenceAdded: false,
        detail: record.nodeId ? `the pursued finding ${record.nodeId} is no longer in the tree` : "the pursue round named no finding",
        produced: false,
      };
    }
    // The ONLY output a pursue round has is new hypotheses. Adding none means the
    // lead is exhausted — which is a result, and it closes the pursuit rather
    // than spending the rest of the budget on it.
    const detail =
      added > 0
        ? `${node.id} pursued for depth — ${added} new hypothesis(es) derived from it (${children} child(ren) total)`
        : `${node.id} produced no new hypothesis — this lead looks exhausted, so the pursuit stops here`;
    return { round: record.round, kind: record.kind, verdictReached: false, evidenceAdded: false, detail, produced: added > 0, nodeId: node.id };
  }

  if (record.kind === "consolidate") {
    const evidenceAdded = false;
    // THE PASS'S OWN OUTPUT IS NEW COMBINATION NODES, not whether a finding happened
    // to be confirmed while it ran. `confirmedGrew` was measuring the model's other
    // work, which made a pass that combined nothing look productive — and a pass
    // that combined nothing is exactly what should count against the plateau.
    const combined = Math.max(0, snapshot.nodes.length - record.nodeCountAtStart);
    const verdictReached = combined > 0 || confirmedGrew;
    const detail =
      combined > 0
        ? `the pass produced ${combined} new combination(s)`
        : confirmedGrew
          ? `a finding was confirmed during the pass (${record.confirmedAtStart} → ${confirmedNow})`
          : "the pass handed over candidates and nothing was combined — the next one is backed off";
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

  const verdictReached = isResolved(node.status) && !isResolved(record.nodeStatusAtStart ?? "pending");
  const evidenceAdded = node.evidence.length > record.nodeEvidenceAtStart;
  const detail = verdictReached
    ? node.status === "blocked"
      ? `${node.id} → blocked (a real examination that cannot be settled from the source alone — counted as progress, not as nothing)`
      : `${node.id} → ${node.status} (${node.evidence.length} evidence entry/entries)`
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
/**
 * The challenge round: attack a finding this audit already confirmed.
 *
 * This is the answer to "a false positive ends the audit". A confirmation is a
 * hypothesis like any other, and the only thing that catches a wrong one is an
 * attempt to falsify it — made by a turn that has nothing invested in the
 * finding being right.
 */
export function renderChallengeBrief(node: Hypothesis, objective: string, round: number): string {
  const lines: string[] = [];
  lines.push(`[AUDIT ROUND ${round} — CHALLENGE]`);
  lines.push("");
  lines.push(`Audit objective: ${objective}`);
  lines.push("");
  lines.push("This finding was CONFIRMED earlier in this audit:");
  lines.push("");
  lines.push(`  ${node.id} — ${(node.severity ?? "UNRATED").toUpperCase()} — ${node.category}`);
  lines.push(`  "${node.description}"`);
  lines.push("");
  if (node.statusReason) {
    lines.push("The auditor's stated basis for confirming it:");
    lines.push("");
    lines.push(`  ${clip(node.statusReason, 900)}`);
    lines.push("");
  }
  lines.push("**Your job this round is to REFUTE it.** A confirmation is a hypothesis too, and a false");
  lines.push("positive is the most expensive thing this audit can produce: it ends a /goal, and it sits in");
  lines.push("the report as a finding nobody ever attacked.");
  lines.push("");
  lines.push("Attack it, concretely:");
  lines.push("  - Find the check, guard, middleware, framework default, or caller that makes the claim");
  lines.push("    FALSE. Grep for it with expectation: \"present\" — if it is there, the finding is wrong.");
  lines.push("  - Re-read the exact lines the finding cites and ask whether they say what the finding claims.");
  lines.push("  - Attack the REACHABILITY assumption: is that controller actually routed at that path? Does");
  lines.push("    the parent class, a listener, or a framework default apply a global check?");
  lines.push("  - Attack the PRECONDITIONS: do they hold in a real deployment, or only in theory?");
  lines.push("");
  lines.push("Then:");
  lines.push(`  - If you find what makes it false → hypothesis_record ${node.id} rejected, with that counterexample`);
  lines.push("    as the reason. That is a RESULT, not a failure: it removes a false positive.");
  lines.push(`  - If you cannot refute it → attach what you checked with hypothesis_evidence on ${node.id} and`);
  lines.push("    record NO status change. The finding keeps its status and gains \"survived a challenge\".");
  lines.push("  - If you found it is PARTLY wrong → record the corrected assertion as a new hypothesis with");
  lines.push("    hypothesis_add.");
  lines.push("");
  lines.push("Do NOT re-confirm it to be safe. An unchallenged confirmation and a challenge-survived one are");
  lines.push("different things, and the report says which is which.");
  lines.push("");
  lines.push("---");
  lines.push("");
  // The axes are what to ATTACK: "there really is no echo channel" is a claim
  // that can be checked, and checking it is exactly this round's job.
  lines.push(renderLadder(node.category, node.id));
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("Then stop. The next round is scheduled automatically after this turn ends.");
  return lines.join("\n");
}

/**
 * The PURSUE round: go DEEPER on a finding this audit already confirmed.
 *
 * Every other round kind moves to a sibling hypothesis, which produces a wide,
 * shallow tree. This is the round that turns "one endpoint is missing a check"
 * into "the check is missing in the shared helper the whole surface inherits".
 *
 * The four questions are the ones that actually produce depth, and they are
 * asked in the order that costs least: what else does the root cause imply, who
 * reaches this, how far does it go, what does it combine with.
 */
export function renderPursueBrief(node: Hypothesis, objective: string, round: number, budget: number, spent: number): string {
  const lines: string[] = [];
  lines.push(`[AUDIT ROUND ${round} — PURSUE]`);
  lines.push("");
  lines.push(`Audit objective: ${objective}`);
  lines.push("");
  lines.push("Every other round moves to a SIBLING hypothesis. This one stays on a single CONFIRMED");
  lines.push("finding and goes DEEPER.");
  lines.push("");
  lines.push(`  ${node.id} — ${(node.severity ?? "UNRATED").toUpperCase()} — ${node.category}`);
  lines.push(`  "${node.description}"`);
  lines.push("");
  if (node.attackVector?.impact) {
    lines.push("The impact recorded for it:");
    lines.push("");
    lines.push(`  ${clip(node.attackVector.impact, 600)}`);
    lines.push("");
  }
  lines.push(`Pursuit round ${spent} of ${budget}. A tree built by moving to the next sibling is wide and`);
  lines.push("shallow; a finding is rarely ONE endpoint. A missing check is usually missing in a shared");
  lines.push("helper, a base class or a framework default that the whole surface inherits.");
  lines.push("");
  lines.push("Answer these, concretely, and record each answer as a NEW child hypothesis:");
  lines.push("");
  lines.push("  1. WHAT ELSE does this root cause imply? If the check is missing HERE, where else is it");
  lines.push("     missing? Find the siblings that share the same helper / base class / config entry, and");
  lines.push("     grep for them with expectation: \"present\". This is usually the highest-yield question:");
  lines.push("     it turns one finding into a class of findings.");
  lines.push("  2. WHO CALLS this? Trace the callers. Is there a path that reaches the same sink from a");
  lines.push("     MORE privileged position, or from an UNAUTHENTICATED one?");
  lines.push("  3. HOW FAR does it go? The impact recorded above is the FIRST thing an attacker gets.");
  lines.push("     What does that unlock next — read → write, write → execute, execute → lateral movement?");
  lines.push("  4. WHAT does it combine with? Is there another confirmed finding that, together with this");
  lines.push("     one, reaches somewhere neither reaches alone? Use hypothesis_combine.");
  lines.push("");
  lines.push("---");
  lines.push("");
  // THE LADDER. Without it, question 3 is answered from the model's own recall,
  // and the axes it happens not to think of are never asked about — which is how
  // "is the response reflected back?" goes unassessed on a confirmed SSRF.
  lines.push(renderLadder(node.category, node.id));
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("Record it with:");
  lines.push(`  - hypothesis_add with parentId=${node.id} for each new assertion (and its attackVector).`);
  lines.push("  - hypothesis_combine for a chain, a shared root cause, or a lateral extension.");
  lines.push(`  - hypothesis_vector ${node.id} if question 3 taught you more about the impact than is`);
  lines.push("    already recorded.");
  lines.push("");
  lines.push("**If the lead is exhausted, SAY SO.** Attach what you checked with hypothesis_evidence and add");
  lines.push("nothing. An honest \"this line ends here\" is a result, and it stops the pursuit immediately");
  lines.push("instead of spending the rest of the budget on a dead lead.");
  lines.push("");
  lines.push("Do NOT re-confirm it, and do NOT restate it as a child. A child that says the same thing in");
  lines.push("different words is a duplicated branch, and the store will refuse it.");
  lines.push("");
  lines.push("Then stop. The next round is scheduled automatically after this turn ends.");
  return lines.join("\n");
}

/**
 * Put the operator's input where it will actually be read.
 *
 * Every brief opens with its own `[...]` banner, and the model uses that banner
 * to orient itself. So the notes go immediately AFTER it — at the top of the
 * body, but not above the thing that says which round this is.
 */
export function withNotes(brief: string, snapshot: TreeSnapshot): string {
  const section = renderNotesSection(snapshot);
  if (!section) return brief;
  const lines = brief.split("\n");
  if (lines[0]?.startsWith("[")) {
    const rest = lines.slice(1);
    while (rest.length > 0 && rest[0] === "") rest.shift();
    return [lines[0], "", section, "", ...rest].join("\n");
  }
  return [section, "", ...lines].join("\n");
}

/**
 * What the audit demands of every word the model writes.
 *
 * Repeated in every brief rather than stated once, because a brief is the only
 * instruction the model sees on this turn — and because the report renders the
 * model's own text verbatim. A Chinese report full of English assertions is not
 * a Chinese report, and a finding with no call chain or no impact leaves a
 * section that says so.
 *
 * The language is the OPERATOR's choice (settings.reportLanguage), so this block
 * is generated rather than a constant.
 */
export function renderOutputRequirements(lang: ReportLanguage): string {
  if (lang === "zh") {
    return [
      "## 输出要求（本审计的硬性要求）",
      "",
      "**语言：中文。**你的 description（断言）、statusReason（判定理由）、evidence 的 detail（证据摘录），",
      "以及 attackVector 的每一个字段，全部用中文写。报告**直接引用这些原文**，不翻译、不改写——",
      "所以用英文写，报告就会变成中英混杂。",
      "",
      "**攻击向量必须齐全。**报告对每条发现固定渲染三段，缺哪一段就会明说缺哪一段：",
      "",
      "  1. **调用链** — `attackVector.path`，从入口到 sink 逐步写，**每一步带 `file` 和 `line`**。",
      "     没有 file:line 的调用链只是故事，报告没法让读者去看那一行。",
      "  2b. **是否需要身份认证** — `attackVector.preAuth`：`true` = 认证前可达，`false` = 认证后。",
      "     **没确定就不要填**——报告会写「未评估」，并且**不会**把它算进认证前。没填是看得见的，",
      "     瞎填不是。",
      "  2. **可利用干什么** — `attackVector.impact`。写**打下来能拿到什么**（「接管任意账号，包括管理员」、",
      "     「读取任意租户的数据」）。**不是手法**（那是 technique），**也不是你的评价**（「严重」不是影响）。",
      "  3. **PoC 验证** — 三样东西，缺一样读者就跑不了：",
      "     a) `attackVector.poc` —— **一条可复制的请求**，人拿到就能手动验证：",
      "        `GET /dsview/servlet/AxisServlet` 或 `curl -sS 'https://TARGET/api/x' -d '...'`。",
      "        **不是 payload**（payload 是「注入什么」，poc 是「整条你粘贴的东西」）。",
      "        `entrypoint` 是散文（「api 防火墙选中的任意路由」），粘不了；poc 能。",
      "     b) `attackVector.pocExpected` —— **看什么才算成功**：",
      "        「返回 200 且响应体含 AxisServlet 版本横幅」「延迟 5 秒」「文件内容出现在 body 里」。",
      "        没有它，读者跑完请求也不知道成没成——手工 PoC 就变成手工挠头。",
      "     c) 证据本身：一个**带 file:line 的代码锚点**（code-slice）。",
      "     如果 allowCommandProbes 开着，**就把 poc 跑一遍并记下输出**——那才让它从 STATIC 变成 REPRODUCED。",
      "     只有论证、没有物证，报告会标成「仅推理」，并明确告诉你**不要把它当漏洞**。",
      "  4. **利用前提** — 要到达这个 sink，**还需要什么成立**？",
      "     每一件还没确定的事，写成一条独立假设，再用 `attackVector` 之外的 `requires` 挂上",
      "     （`hypothesis_add { requires: [...] }` 或 `hypothesis_vector { id, requires: [...] }`）。",
      "     **如果你查过了、确实没有依赖，就显式写 `requires: []`。**",
      "     不写的话报告会一直把它报成「利用前提未评估」——那是「没人问过」，",
      "     不是「不需要」。硬编码密钥、调试端点这类本来就自包含的发现，必须显式声明。",
      "",
      "**不要为了填满而编造。**缺一段就让它缺——报告会诚实地写「未评估」，而一个编造的调用链",
      "比一个空白的调用链危险得多。",
    ].join("\n");
  }
  return [
    "## Output requirements (hard requirements for this audit)",
    "",
    "**Language: English.** Write your description, statusReason, evidence detail and every",
    "attackVector field in English. The report quotes them VERBATIM — it does not translate or",
    "paraphrase, so a mixed-language report is what mixed-language input produces.",
    "",
    "**The attack vector must be complete.** The report renders three sections per finding and says",
    "explicitly which one is missing:",
    "",
    "  1. **Call chain** — `attackVector.path`, step by step from entrypoint to sink, **each step",
    "     carrying `file` and `line`**. A chain without locations is a story the reader cannot check.",
    "  1b. **Auth requirement** — `attackVector.preAuth`: `true` = reachable WITHOUT authentication,",
    "     `false` = a session is required. Omit ONLY if you have not determined it — the report says",
    "     \"not assessed\" and does NOT count it as pre-auth. Omitting is visible; guessing is not.",
    "  2. **Impact** — `attackVector.impact`. What the attacker GETS if it works. NOT the technique,",
    "     and NOT your judgement of it (\"critical\" is not an impact).",
    "  3. **PoC** — three things, and the reader cannot check it without all of them:",
    "     a) `attackVector.poc` — a COPY-PASTEABLE request a human can run by hand:",
    "        `GET /dsview/servlet/AxisServlet`, or a curl line. NOT the payload (that is what to",
    "        inject); this is the whole thing you paste. `entrypoint` is prose and cannot be pasted.",
    "     b) `attackVector.pocExpected` — WHAT TO LOOK FOR: \"200 with the AxisServlet banner\",",
    "        \"a 5-second delay\", \"the file contents in the body\". Without it the reader runs the",
    "        request and cannot tell whether it worked.",
    "     c) the evidence: a **code anchor with file:line**.",
    "     If allowCommandProbes is on, RUN the poc and record the output — that is what moves it",
    "     from STATIC to REPRODUCED. An argument with no artifact is marked reasoning-only.",
    "  4. **Exploitation preconditions** — what else must hold to REACH this sink?",
    "     Each thing you have not settled becomes its own hypothesis, linked with `requires`",
    "     (`hypothesis_add { requires: [...] }` or `hypothesis_vector { id, requires: [...] }`).",
    "     **If you checked and there is nothing, write `requires: []` explicitly.**",
    "     Without it the report keeps calling this \"preconditions not assessed\" — which means",
    "     nobody asked, not that none are needed. A hardcoded secret or an exposed debug endpoint",
    "     IS self-contained, and saying so is a claim you have to make.",
    "",
    "**Do not invent to fill a section.** The report says \"not assessed\" honestly, and a fabricated",
    "call chain is far more dangerous than an empty one.",
  ].join("\n");
}

/**
 * What to do about the agent's own SKILLS.
 *
 * pi puts a skill LIST in the system prompt and expects the model to `read` a
 * SKILL.md when the task matches. Its own docs warn that "models don't always
 * do this" — and a round brief makes that worse, because the brief is a complete
 * procedure ("DO THIS, in order: 1… 2… 3…"), so the model has no reason to go
 * looking for another set of instructions. Without this block a matching skill is
 * never opened.
 *
 * The second half is the part that matters. A skill written for the same job
 * (there are published ones for exactly this) carries its OWN vocabulary — node
 * labels like H1.2.3, status words like "Supported", quotas like "generate 5-10
 * children". All of that CONFLICTS with this extension's mechanism, and a model
 * holding both will produce a tree the tools cannot read. So the split is stated
 * explicitly: take the skill's DOMAIN KNOWLEDGE (what to look for), keep this
 * extension's MECHANISM (how to record it).
 */
export function renderSkillGuidance(lang: ReportLanguage): string {
  if (lang === "zh") {
    return [
      "## 技能（skills）",
      "",
      "你的技能列表里如果有匹配本次审计的（平台 / 框架 / 漏洞类别的专项技能），**先 read 它的 SKILL.md**，",
      "把它的内容当作「**找什么**」：目标类别、绕过手法、要检查的配置项、该平台的坑。",
      "",
      "但「**怎么记**」以本扩展为准：",
      "",
      "  - 节点编号用工具返回的 `H-xxxx`，**不要用技能自创的** `H1.2.3` 之类；",
      "  - 状态词只用 `hypothesis_record` 支持的那几个（confirmed / rejected / blocked / pending），",
      "    **不要用技能自造的** Supported / Refuted 之类；",
      "  - 技能若描述了自己的轮次流程，或「生成 5-10 个子节点」这类配额，**忽略它的流程部分**——",
      "    轮次和配额由本扩展的调度器决定，它带反钻牛角尖的硬限制。",
      "",
      "技能里没有匹配的就跳过，**不要为了读技能浪费一轮**。",
    ].join("\n");
  }
  return [
    "## Skills",
    "",
    "If your skill list contains one that matches this audit (a platform, framework or",
    "vulnerability-class skill), **read its SKILL.md first** and treat it as WHAT TO LOOK FOR:",
    "target classes, bypass techniques, configuration to check, that platform's traps.",
    "",
    "HOW TO RECORD stays with this extension:",
    "",
    "  - node ids are the `H-xxxx` the tools return — do NOT use a skill's own `H1.2.3` labels;",
    "  - status words are only the ones `hypothesis_record` accepts (confirmed / rejected /",
    "    blocked / pending) — do NOT use a skill's own vocabulary such as Supported or Refuted;",
    "  - if a skill describes its own round flow, or quotas like \"generate 5-10 children\",",
    "    **ignore the process half** — rounds and quotas belong to this extension's scheduler,",
    "    which carries the anti-tunnelling limits.",
    "",
    "If nothing matches, skip it — **do not spend a round reading a skill**.",
  ].join("\n");
}

/**
 * Everything a brief carries that is not the round itself.
 *
 * One composer rather than four edits: the output requirements, the skill
 * guidance and the operator's notes must appear in EVERY brief — recon, generate,
 * verify, consolidate and challenge alike — and a rule that is enforced in four
 * places is a rule that will eventually be enforced in three.
 */
export function withBriefExtras(brief: string, snapshot: TreeSnapshot, lang: ReportLanguage): string {
  return withNotes(`${brief}\n\n${renderOutputRequirements(lang)}\n\n${renderSkillGuidance(lang)}`, snapshot);
}

/**
 * The operator's scope, stated as a PREFERENCE.
 *
 * Not a filter. Generation is told to spend the round here, and the scheduler
 * prefers these classes — but a pre-auth RCE is routinely reached by chaining a
 * finding from somewhere else, and refusing the elsewhere would make exactly that
 * chain unfindable. So the brief says: record anything you find, and do not spend
 * THIS round on it.
 */
export function renderFocus(focus: readonly string[]): string {
  return [
    `THIS RUN IS SCOPED TO: ${focus.join(", ")}`,
    "",
    "Spend this round on those classes. If you find something in another class, RECORD it —",
    "a pre-auth RCE is often reached by chaining a finding from somewhere else — but do not",
    "spend this round on it, and do not open a new branch in it.",
  ].join("\n");
}

export function renderRoundBrief(
  snapshot: TreeSnapshot,
  loop: AuditLoopState,
  round: number,
  kind: RoundRecord["kind"],
  node: Hypothesis | null,
  previous: RoundOutcome | null,
  segment: ReconSegment | null = null,
  pursueBudget = 2,
  coverageReport: CoverageReport = emptyCoverage(),
): string {
  const lines: string[] = [];

  // The coverage round hands over the GAP and nothing else.
  if (kind === "coverage") {
    lines.push(...renderCoverageBrief(coverageReport, loop.objective, round).split("\n"));
    if (previous) {
      lines.push("");
      lines.push(`Last round (${previous.round}): ${previous.detail}`);
    }
    return lines.join("\n");
  }

  // The recon round has no tree to describe, so it gets its own brief entirely.
  if (kind === "recon") {
    lines.push(...renderReconBrief(snapshot, loop.objective).split("\n"));
    if (previous) {
      lines.push("");
      lines.push(`Last round (${previous.round}): ${previous.detail}`);
    }
    return lines.join("\n");
  }

  // The generate round is driven by ONE segment, and the brief IS that segment.
  if (kind === "generate" && segment) {
    lines.push(...renderSegmentBrief(snapshot, segment, loop.objective, segmentCoverage(snapshot)).split("\n"));
    if (previous) {
      lines.push("");
      lines.push(`Last round (${previous.round}): ${previous.detail}`);
    }
    return lines.join("\n");
  }

  // The challenge round attacks a finding this audit already confirmed.
  if (kind === "challenge" && node) {
    lines.push(...renderChallengeBrief(node, loop.objective, round).split("\n"));
    if (previous) {
      lines.push("");
      lines.push(`Last round (${previous.round}): ${previous.detail}`);
    }
    return lines.join("\n");
  }

  // The pursue round goes deeper on a finding this audit already confirmed.
  if (kind === "pursue" && node) {
    lines.push(...renderPursueBrief(node, loop.objective, round, pursueBudget, node.pursueSpent ?? 1).split("\n"));
    if (previous) {
      lines.push("");
      lines.push(`Last round (${previous.round}): ${previous.detail}`);
    }
    return lines.join("\n");
  }

  lines.push(`[AUDIT ROUND ${round} — ${kind === "consolidate" ? "COMBINE" : "VERIFY"}]`);
  lines.push("");
  if (loop.focus && loop.focus.length > 0) lines.push(...renderFocus(loop.focus).split("\n"));
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
  segment: ReconSegment | null = null,
): string[] {
  const nodes = snapshot.nodes;
  const confirmed = nodes.filter((n) => n.status === "confirmed").length;
  const rejected = nodes.filter((n) => n.status === "rejected").length;
  const open = nodes.filter((n) => n.nodeKind !== "scope" && n.status !== "confirmed" && n.status !== "rejected").length;
  const depth = nodes.reduce((max, n) => Math.max(max, n.depth), 0);
  const combo = consolidationStatus(snapshot);
  const lines: string[] = [];

  const title =
    kind === "recon"
      ? "read the project (recon)"
      : kind === "generate"
        ? `generate hypotheses from ${segment?.id ?? "(no segment)"}`
        : kind === "consolidate"
          ? "combine findings"
          : kind === "coverage"
            ? "read what the first recon note never mentioned"
            : kind === "challenge"
              ? `challenge ${node?.id ?? "(none)"} — try to REFUTE it`
            : kind === "pursue"
              ? `pursue ${node?.id ?? "(none)"} — go DEEPER on it`
              : `verify ${node?.id ?? "(none)"}`;
  lines.push(`ROUND ${round} — ${title}`);
  if (previous) lines.push(`  last round: ${previous.detail}`);
  if ((kind === "verify" || kind === "challenge" || kind === "pursue") && node) {
    lines.push(`  node: "${clip(node.description, 90)}"`);
    lines.push(`  ${node.category} · depth ${node.depth} · ${node.evidence.length} evidence · status ${node.status}`);
  }
  if (kind === "generate" && segment) {
    lines.push(`  segment ${segment.index + 1}: ${segment.paragraphs} paragraph(s)`);
    lines.push(`  ${clip(segment.text.replace(/\s+/g, " "), 100)}`);
  }
  lines.push(`  tree: ${nodes.length} nodes · ${confirmed} confirmed · ${rejected} rejected · ${open} open · depth ${depth}`);
  lines.push(`  ${renderCoverage(snapshot)}`);
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
  lines.push(
    kind === "coverage"
      ? "  next: hypothesis_recon with a note covering ONLY the directories listed above"
      : kind === "recon"
        ? "  next: hypothesis_recon with the recon note (as paragraphs)"
      : kind === "generate"
        ? "  next: hypothesis_add per hypothesis (with attackVector + segmentId), or hypothesis_cover_segment"
        : kind === "challenge" && node
          ? `  next: refute ${node.id} → hypothesis_record rejected, or hypothesis_evidence if you cannot`
          : kind === "pursue" && node
            ? `  next: hypothesis_add with parentId=${node.id} for each deeper assertion, or hypothesis_evidence if the lead is dead`
            : kind === "verify" && node
            ? `  next: hypothesis_verify ${node.id} → hypothesis_record`
          : "  next: the combination brief in this turn",
  );
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
  /** For a `generate` round: which segment was handed over. */
  segmentId?: string;
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
  // Read once per tick, so every decision in this round sees the same budget.
  const pursueBudget = pursueRoundsOf(projectRoot);
  const loop = snapshot.loop;
  if (!loop) return { action: "idle", reason: "no audit loop in this project" };
  if (loop.status === "complete") return { action: "complete", reason: loop.stopReason ?? "the completion contract is satisfied" };
  if (loop.status === "stopped") return { action: "stopped", reason: loop.stopReason ?? "stopped" };
  if (loop.status === "paused") return { action: "paused", reason: loop.pausedReason ?? "paused" };
  if (!snapshot.rootId) {
    // The scope root is created by the /goal and /loop commands before the loop
    // starts, so reaching this means the tree was wiped underneath a running
    // loop. Say so instead of reporting "no open hypotheses".
    return { action: "idle", reason: "no hypothesis tree in this project — the scope root is missing; start a new /goal or /loop" };
  }

  let current = loop;
  let previous: RoundOutcome | null = null;

  // 1. Evaluate the in-flight round before deciding anything.
  if (current.awaitingRound !== null) {
    // The LAST record with this round number, not the first: the in-flight round
    // is the most recently appended one, and a previous run may share the number.
    const record = [...currentRunRounds(snapshot)].reverse().find((r) => r.round === current.awaitingRound);
    if (record) {
      previous = evaluateRound(snapshot, record);
      // A pursue round that added NO hypotheses exhausted its lead. Close the
      // pursuit outright rather than letting it spend the rest of its budget on
      // a dead end — the same rule that stops an empty combination pass from
      // being scheduled again.
      if (previous.kind === "pursue" && !previous.produced && previous.nodeId) {
        applyNodePatch(projectRoot, previous.nodeId, { pursueSpent: pursueBudget }, at);
      }
      // A pass that combined nothing earns a longer wait; one that combined
      // something resets the backoff. Same shape as the pursue rule above.
      if (previous.kind === "coverage") {
        current = { ...current, coverageRounds: (current.coverageRounds ?? 0) + 1 };
      }
      if (previous.kind === "consolidate") {
        const stall = current.consolidationStall ?? 0;
        current = { ...current, consolidationStall: previous.produced ? 0 : stall + 1 };
      }
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
        endedAt: at,
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
        endedAt: at,
        stopReason:
        `plateau — ${current.stallRounds} consecutive round(s) produced no verdict and no new evidence ` +
        `(window ${current.plateauWindow}); the well looks dry`,    };
    writeLoop(projectRoot, stopped, at);
    return { action: "stopped", reason: stopped.stopReason!, round: current.round, previous };
  }

  // 4. The round cap.
  if (current.maxRounds > 0 && current.round >= current.maxRounds) {
    const stopped: AuditLoopState = {
        ...current,
        status: "stopped",
        endedAt: at,
        stopReason: `round cap reached (${current.maxRounds})`,
    };
    writeLoop(projectRoot, stopped, at);
    return { action: "stopped", reason: stopped.stopReason!, round: current.round, previous };
  }

  // 5. Which kind of round?
  //
  //    generate    — recon segments remain uncovered; finish creating the material
  //    consolidate — a forced combination pass is due
  //    challenge   — attack a finding this audit already confirmed
  //    recon       — there is nothing to verify AND the project has never been
  //                  read. Only then: a tree whose root is a hand-written
  //                  hypothesis (the /hypothesis new path) already has work to
  //                  do, and forcing a recon round on it would delay the audit
  //                  the user explicitly asked for.
  //    verify      — falsify a hypothesis
  //
  // Generate is placed BEFORE consolidate on purpose. Generation adds PENDING
  // hypotheses, so it cannot change what a combination pass would find; and
  // while the material is still being created, finishing it is the better use
  // of the round.
  //
  // CHALLENGE OUTRANKS RECON. Once a finding is confirmed, attacking it is worth
  // more than reading more of the project — and a confirmed finding leaves
  // `hasWork` false (nothing is schedulable), so with recon first the loop would
  // go read the project instead of checking its own conclusion, and the false
  // positive would never be tested.
  //
  // PURSUE sits after CHALLENGE and before RECON. After challenge, because there
  // is no point deepening a finding that may be false — refuting it is cheaper
  // and more valuable than extending it. Before recon, for the same reason
  // challenge is: once a finding exists, depth on it beats reading more of the
  // project. And it can never starve verification, because it is capped at one
  // round in PURSUE_INTERVAL and at a per-finding budget.
  const round = current.round + 1;
  const pendingConsolidation = planConsolidation(snapshot);
  const openSegment = nextOpenSegment(snapshot);
  const hasWork = snapshot.nodes.some(isSchedulable);
  const challengeTarget = nextChallengeCandidate(snapshot, round);
  const pursueTarget = nextPursueTarget(snapshot, round, pursueBudget);
  // An OPEN pursuit is not interrupted by a combination pass. See LOOP_DEFAULTS.
  const openPursuit = hasOpenPursuit(snapshot, pursueBudget) && pursueTarget !== null;
  // THE COVERAGE ROUND, and why it goes this high.
  //
  // Expanding breadth is worth more EARLY than one more verification: if the
  // untouched directories hold the pre-auth RCE, verifying the hypotheses the
  // first note produced will never find it. It fires only once the first note's
  // segments are all closed, only when there is a real gap, and at most
  // COVERAGE.MAX_ROUNDS times — a round kind that can always justify itself is
  // the failure mode this codebase has hit three times.
  const coverageTarget = coverageCandidate(projectRoot, snapshot, current);
  const pendingCoverage = coverageTarget ?? emptyCoverage();
  const lastRound = [...currentRunRounds(snapshot)].reverse()[0] ?? null;
  const sideQuestBlocked = lastRound !== null && SIDE_QUESTS.includes(lastRound.kind);
  const kind: RoundRecord["kind"] = openSegment
    ? "generate"
    : sideQuestBlocked && hasWork
      ? "verify"
      : coverageTarget
        ? "coverage"
        : openPursuit
        ? "pursue"
        : pendingConsolidation.due
          ? "consolidate"
          : challengeTarget
            ? "challenge"
            : pursueTarget
              ? "pursue"
              : !hasWork && snapshot.reconAt === null
                ? "recon"
                : "verify";

  let node: Hypothesis | null = null;
  let recorded = false;
  let segment: ReconSegment | null = null;
  // Set only for a verify round; see the selection branch below.
  let statusAtStart: HypothesisStatus | null = null;

  if (kind === "recon") {
    // Nothing is written here: the ROUND is the brief, and the model's
    // submission (hypothesis_recon) is what records the segments.
    recorded = true;
  } else if (kind === "generate") {
    // Likewise: the segment is closed by the hypotheses the model adds, or by
    // an explicit hypothesis_cover_segment.
    segment = openSegment;
    recorded = true;
  } else if (kind === "coverage") {
    // Nothing is written here, like a recon round: the ROUND is the brief, and the
    // model's hypothesis_recon submission is what records the new segments.
    recorded = true;
  } else if (kind === "challenge") {
    node = challengeTarget;
    // Mark the attempt BEFORE the round runs, so a crash, a lost round or a
    // stalled model cannot re-challenge the same finding forever.
    recorded = node ? applyNodePatch(projectRoot, node.id, { challengedRound: round }, at).ok : false;
  } else if (kind === "pursue") {
    node = pursueTarget;
    // Spend the budget on PREPARE, for the same reason: a crash must not let the
    // same finding be pursued forever. An unproductive round then closes the
    // pursuit outright (below), so a dead lead costs one round, not the budget.
    recorded = node ? applyNodePatch(projectRoot, node.id, { pursueSpent: (node.pursueSpent ?? 0) + 1 }, at).ok : false;
  } else if (kind === "consolidate") {
    recorded = applyConsolidation(projectRoot, pendingConsolidation, at).ok;
  } else {
    const decision = planNextRound(snapshot, { round });
    if (!decision.selected) {
      const stopped: AuditLoopState = {
        ...current,
        status: "stopped",
        endedAt: at,
        stopReason: `no open hypotheses remain (${decision.reasons[0] ?? "every node has a verdict"})`,
      };
      writeLoop(projectRoot, stopped, at);
      return { action: "stopped", reason: stopped.stopReason!, round: current.round, previous };
    }
    node = decision.selected;
    // The status BEFORE the selection moves it to `testing`.
    //
    // `applySelection` turns pending/blocked into testing, so reading the status
    // back afterwards always gives "testing" — and `evaluateRound` compares
    // against it to decide whether the round REACHED a verdict. With "testing" as
    // the baseline, re-blocking an already-blocked node counted as a fresh
    // verdict, which made every round productive, which meant the plateau could
    // never fire. A tree where every node is blocked would then cycle through
    // them forever, adding rounds and learning nothing.
    const statusBefore = node.status;
    recorded = applySelection(projectRoot, decision, at).ok;
    if (recorded) statusAtStart = statusBefore;
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

  const summary = renderRoundSummary(after, current, round, kind, node, previous, segment);
  const brief = withBriefExtras(
    renderRoundBrief(after, current, round, kind, node, previous, segment, pursueBudget, pendingCoverage),
    after,
    reportLanguageOf(projectRoot),
  );

  const record: RoundRecord = {
    round,
    at,
    kind,
    ...(segment ? { segmentId: segment.id } : {}),
    nodeId: node?.id ?? null,
    nodeStatusAtStart: statusAtStart ?? node?.status ?? null,
    nodeEvidenceAtStart: node?.evidence.length ?? 0,
    confirmedAtStart: after.nodes.filter((n) => n.status === "confirmed").length,
    nodeCountAtStart: after.nodes.length,
    summary,
  };
  if (!appendEvent(projectRoot, { type: "round_detail", at, record })) {
    return { action: "idle", reason: "the round record could not be written", round, previous };
  }
  appendFindingsLedger(projectRoot, after, round, summary, at);

  if (!opts.dryRun) {
    writeLoop(projectRoot, { ...current, round, awaitingRound: round }, at);
    // The report is regenerated EVERY round, not only when the loop stops.
    //
    // A /loop can run for hours, and the operator wants to watch it work — a
    // report that only appears at the end is a report they cannot steer by. It
    // is a pure function of the snapshot, so regenerating it is cheap and can
    // never disagree with the tree.
    writeReport(projectRoot, after, { ...current, round, awaitingRound: round }, { at, language: reportLanguageOf(projectRoot) });
    // A human-readable mirror of what the operator has told the audit, so they
    // can see it landed without reading the ledger.
    writeOperatorMirror(projectRoot, after);
    // The notes in THIS brief are now delivered. Recorded rather than inferred:
    // if the model never answers, the next tick must not re-deliver them as if
    // they were new, and the ledger must show they were shown.
    const delivered = pendingNotes(after).filter((n) => !n.pinned).map((n) => n.id);
    if (delivered.length > 0) markNotesDelivered(projectRoot, delivered, round, at);
  }

  return { action: "sent", reason: `round ${round} prepared`, round, nodeId: node?.id ?? null, ...(segment ? { segmentId: segment.id } : {}), brief, summary, previous };
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

/**
 * The report language, read from the project's settings.
 *
 * Read per call rather than cached: the operator can change it mid-run with
 * `/hypothesis config reportLanguage=en`, and a report that keeps coming out in
 * the old language after that is a setting that looks broken.
 */
export function reportLanguageOf(projectRoot: string): ReportLanguage {
  try {
    return loadSettings(projectRoot).settings.reportLanguage;
  } catch {
    return "zh";
  }
}

/** The per-finding pursue budget, read from the project's settings. */
export function pursueRoundsOf(projectRoot: string): number {
  try {
    return loadSettings(projectRoot).settings.pursueRounds;
  } catch {
    return 2;
  }
}

// -----------------------------------------------------------------
// Status and widget
// -----------------------------------------------------------------

export function renderLoopStatus(snapshot: TreeSnapshot, nowMs = Date.now()): string[] {
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
  // Operator input, when there is any. Shown because "did my hint land?" is the
  // question an operator has while watching a long run, and the pending count
  // answers it without opening the ledger.
  if (snapshot.notes.length > 0) lines.push(`  ${renderNotesStatus(snapshot)}`);
  lines.push(`  ${describeTiming(loopTiming(loop, nowMs), loop.round)}`);
  // A hidden widget is otherwise invisible state: the operator closed the panel
  // and has no way to tell whether it is still there.
  if (loop.widgetHidden) lines.push(`  widget: HIDDEN — /${loop.kind} show to bring it back`);
  const waiting = inFlightAge(snapshot, loop, nowMs);
  if (waiting) lines.push(`  the round in flight has been waiting ${waiting} — a turn that is not moving is a stuck turn`);
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

/**
 * Hide the widget without discarding the audit.
 *
 * The widget is re-set on every settle and on every command, so hiding it once
 * is not enough — `setWidget(name, undefined)` is undone by the next refresh
 * unless the STATE says to stay hidden. That is why this is a flag on the loop
 * rather than a one-off UI call.
 *
 * The tree, the round history, the contract, the clock and the report all
 * survive. Dismissing a panel and discarding an audit are different actions.
 */
export function dismissLoop(projectRoot: string, snapshot: TreeSnapshot, at = nowIso()): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project — there is no widget to close"] };
  if (loop.widgetHidden) return { ok: false, errors: ["the widget is already hidden"] };
  const next: AuditLoopState = { ...loop, widgetHidden: true };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  const stillGoing = loop.status === "running" || loop.status === "paused";
  return {
    ok: true,
    errors: [],
    loop: next,
    message: stillGoing
      ? `Widget hidden. The ${loop.kind} is still ${loop.status} at round ${loop.round} and keeps running — /${loop.kind} status still reports it, /${loop.kind} show brings the widget back.`
      : `Widget hidden. The ${loop.kind} finished at round ${loop.round}; its report and the tree are untouched. /${loop.kind} show brings it back, /${loop.kind} start begins a new audit.`,
  };
}

/** Bring a dismissed widget back. */
export function showLoop(projectRoot: string, snapshot: TreeSnapshot, at = nowIso()): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project — /loop start begins one"] };
  if (!loop.widgetHidden) return { ok: false, errors: ["the widget is already showing"] };
  const { widgetHidden, ...rest } = loop;
  void widgetHidden;
  const next: AuditLoopState = { ...rest };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return { ok: true, errors: [], loop: next, message: `Widget shown again (${loop.kind} ${loop.status}, round ${loop.round}).` };
}

/** A three-line widget: enough to see the loop is alive and where it is. */
export function renderWidget(snapshot: TreeSnapshot, nowMs = Date.now()): string[] | null {
  const loop = snapshot.loop;
  if (!loop) return null;
  // Checked before anything is computed: a dismissed widget must not cost a
  // render, and returning null is what removes it from the editor.
  if (loop.widgetHidden) return null;
  const confirmed = snapshot.nodes.filter((n) => n.status === "confirmed").length;
  const rejected = snapshot.nodes.filter((n) => n.status === "rejected").length;
  // Scope nodes are boundaries, not work. Counting one as "open" would make the
  // widget read one too high for the entire audit — the same reason summarize()
  // skips them.
  const open = snapshot.nodes.filter(
    (n) => n.nodeKind !== "scope" && n.status !== "confirmed" && n.status !== "rejected",
  ).length;
  const glyph = loop.status === "running" ? "▶" : loop.status === "paused" ? "‖" : loop.status === "complete" ? "✓" : "■";
  const contract = loop.contract ? contractMet(snapshot, loop.contract) : null;
  const timing = loopTiming(loop, nowMs);
  const lines = [
    `hypothesis ${glyph} ${loop.kind} round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : ""} · ${confirmed} confirmed · ${rejected} rejected · ${open} open`,
  ];
  // The clock lives on the state line, next to what the loop is currently doing:
  // "in flight round 15 · 3m" and "elapsed 2h 14m" answer the two questions a
  // watcher has — is it stuck, and how long has this been going.
  const state: string[] = [];
  // The in-flight age is suppressed while paused: the round is frozen, not
  // waiting, and an age that keeps climbing on a paused loop reads as a hang.
  const age = loop.status === "paused" ? null : inFlightAge(snapshot, loop, nowMs);
  if (loop.awaitingRound !== null) {
    state.push(`in flight: round ${loop.awaitingRound}${age ? ` · ${age}` : ""}`);
  }
  state.push(`stall ${loop.stallRounds}/${loop.plateauWindow}`);
  state.push(shortTiming(loop, timing));
  lines.push(`  ${state.join(" · ")}`);
  if (contract) lines.push(`  contract ${contract.met ? "MET" : "open"}: ${contract.detail[0] ?? ""}`);
  return lines;
}

/**
 * How long the in-flight round has been waiting, or null.
 *
 * A round that has been "in flight" for an hour is a stuck turn, and that is
 * invisible from the round number alone. Measured from the round record's own
 * timestamp, so it survives a reload.
 */
export function inFlightAge(snapshot: TreeSnapshot, loop: AuditLoopState, nowMs = Date.now()): string | null {
  if (loop.awaitingRound === null) return null;
  const record = [...snapshot.roundRecords].reverse().find((r) => r.round === loop.awaitingRound);
  if (!record) return null;
  const started = Date.parse(record.at);
  if (!Number.isFinite(started)) return null;
  return formatDuration(Math.max(0, nowMs - started));
}

/**
 * The clock in its shortest honest form.
 *
 * Active time always, with paused time in parentheses only when there is some:
 * a loop that sat paused overnight must not report a night of work, and a
 * "0m paused" clause on every line is a clause the reader learns to skip.
 */
export function shortTiming(loop: AuditLoopState, timing: LoopTiming | null): string {
  if (!timing) return "elapsed unknown";
  const active = formatDuration(timing.activeMs);
  if (timing.ended) return `ran ${active}`;
  if (loop.status === "paused") return `paused · ${active} active`;
  return timing.pausedMs > 0 ? `elapsed ${active} (${formatDuration(timing.pausedMs)} paused)` : `elapsed ${active}`;
}

export { severityRank };
