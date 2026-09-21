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
  type ReconSegment,
  type RoundRecord,
  type Severity,
  type TreeSnapshot,
  describeTiming,
  formatDuration,
  hasBeenChallenged,
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
  if (loop.status !== "running") return { ok: false, errors: [`the audit ${loop.kind} is already ${loop.status}`] };
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
  if (loop.status === "running") return { ok: false, errors: [`the audit ${loop.kind} is already running`] };

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
  // Bank the pause interval being closed, so `activeMs` does not include time
  // the audit spent unable to work. Clamped at zero for a backwards clock jump.
  const pausedAt = loop.pausedAt ? Date.parse(loop.pausedAt) : NaN;
  const resumedAt = Date.parse(at);
  const closedPause =
    Number.isFinite(pausedAt) && Number.isFinite(resumedAt) ? Math.max(0, resumedAt - pausedAt) : 0;
  const next: AuditLoopState = {
    ...rest,
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
 * The finding the next challenge round should attack, or null.
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

  const lastChallengeRound = snapshot.roundRecords
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
      "  2. **可利用干什么** — `attackVector.impact`。写**打下来能拿到什么**（「接管任意账号，包括管理员」、",
      "     「读取任意租户的数据」）。**不是手法**（那是 technique），**也不是你的评价**（「严重」不是影响）。",
      "  3. **PoC 验证** — 证据本身。要么一条**可重跑的命令**（command 探针，需要 allowCommandProbes），",
      "     要么一个**带 file:line 的代码锚点**（code-slice）。只有论证、没有物证，报告会标成「仅推理」，",
      "     并明确告诉你**不要把它当漏洞**。",
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
    "  2. **Impact** — `attackVector.impact`. What the attacker GETS if it works. NOT the technique,",
    "     and NOT your judgement of it (\"critical\" is not an impact).",
    "  3. **PoC** — the evidence itself: either a **re-runnable command** (a command probe, which",
    "     needs allowCommandProbes) or a **code anchor with file:line**. An argument with no artifact",
    "     is marked reasoning-only, and the report tells the reader not to treat it as a vulnerability.",
    "",
    "**Do not invent to fill a section.** The report says \"not assessed\" honestly, and a fabricated",
    "call chain is far more dangerous than an empty one.",
  ].join("\n");
}

/**
 * Everything a brief carries that is not the round itself.
 *
 * One composer rather than four edits: the output requirements and the operator's
 * notes must appear in EVERY brief — recon, generate, verify, consolidate and
 * challenge alike — and a rule that is enforced in four places is a rule that
 * will eventually be enforced in three.
 */
export function withBriefExtras(brief: string, snapshot: TreeSnapshot, lang: ReportLanguage): string {
  return withNotes(`${brief}\n\n${renderOutputRequirements(lang)}`, snapshot);
}

export function renderRoundBrief(
  snapshot: TreeSnapshot,
  loop: AuditLoopState,
  round: number,
  kind: RoundRecord["kind"],
  node: Hypothesis | null,
  previous: RoundOutcome | null,
  segment: ReconSegment | null = null,
): string {
  const lines: string[] = [];

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
          : kind === "challenge"
            ? `challenge ${node?.id ?? "(none)"} — try to REFUTE it`
            : `verify ${node?.id ?? "(none)"}`;
  lines.push(`ROUND ${round} — ${title}`);
  if (previous) lines.push(`  last round: ${previous.detail}`);
  if ((kind === "verify" || kind === "challenge") && node) {
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
    kind === "recon"
      ? "  next: hypothesis_recon with the recon note (as paragraphs)"
      : kind === "generate"
        ? "  next: hypothesis_add per hypothesis (with attackVector + segmentId), or hypothesis_cover_segment"
        : kind === "challenge" && node
          ? `  next: refute ${node.id} → hypothesis_record rejected, or hypothesis_evidence if you cannot`
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
  const round = current.round + 1;
  const pendingConsolidation = planConsolidation(snapshot);
  const openSegment = nextOpenSegment(snapshot);
  const hasWork = snapshot.nodes.some(isSchedulable);
  const challengeTarget = nextChallengeCandidate(snapshot, round);
  const kind: RoundRecord["kind"] = openSegment
    ? "generate"
    : pendingConsolidation.due
      ? "consolidate"
      : challengeTarget
        ? "challenge"
        : !hasWork && snapshot.reconAt === null
          ? "recon"
          : "verify";

  let node: Hypothesis | null = null;
  let recorded = false;
  let segment: ReconSegment | null = null;

  if (kind === "recon") {
    // Nothing is written here: the ROUND is the brief, and the model's
    // submission (hypothesis_recon) is what records the segments.
    recorded = true;
  } else if (kind === "generate") {
    // Likewise: the segment is closed by the hypotheses the model adds, or by
    // an explicit hypothesis_cover_segment.
    segment = openSegment;
    recorded = true;
  } else if (kind === "challenge") {
    node = challengeTarget;
    // Mark the attempt BEFORE the round runs, so a crash, a lost round or a
    // stalled model cannot re-challenge the same finding forever.
    recorded = node ? applyNodePatch(projectRoot, node.id, { challengedRound: round }, at).ok : false;
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

  const summary = renderRoundSummary(after, current, round, kind, node, previous, segment);
  const brief = withBriefExtras(renderRoundBrief(after, current, round, kind, node, previous, segment), after, reportLanguageOf(projectRoot));

  const record: RoundRecord = {
    round,
    at,
    kind,
    ...(segment ? { segmentId: segment.id } : {}),
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

/** A three-line widget: enough to see the loop is alive and where it is. */
export function renderWidget(snapshot: TreeSnapshot, nowMs = Date.now()): string[] | null {
  const loop = snapshot.loop;
  if (!loop) return null;
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
