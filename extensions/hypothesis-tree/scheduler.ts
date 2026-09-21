/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/scheduler.ts
 *
 * The anti-rabbit-hole scheduler.
 *
 * -----------------------------------------------------------------------
 * The failure this module exists to prevent
 * -----------------------------------------------------------------------
 *
 * An audit agent left to itself tunnels. It picks the most interesting
 * hypothesis, confirms it, derives a child, confirms that, derives another —
 * and twenty rounds later it has produced a beautiful five-level analysis of
 * one input-validation bug while the unauthenticated admin route it never
 * looked at sits three files away.
 *
 * The tunneling is not a discipline problem, it is an incentive problem: the
 * deepest node is always the most concrete and therefore always feels most
 * tractable. So the fix is structural — three hard limits that make continued
 * descent IMPOSSIBLE rather than discouraged, and a score that actively pays
 * for going somewhere else.
 *
 * -----------------------------------------------------------------------
 * The three hard limits
 * -----------------------------------------------------------------------
 *
 *   MAX_CONSECUTIVE_DEPTH = 3
 *     Three consecutive rounds that each moved to a DESCENDANT of the previous
 *     pick, and the next pick may not be a descendant at all. The run is
 *     measured over consecutive descents, not over absolute tree depth: a
 *     node at depth 7 is fine if you got there by jumping sideways, and a node
 *     at depth 3 is not fine if you walked straight down to it.
 *
 *   MAX_SAME_NODE_ROUNDS = 2
 *     Two consecutive rounds on the same node, and a third is refused. This
 *     catches the other shape of stuck: not descending, but grinding — re-
 *     examining one hypothesis while producing no verdict and no new evidence.
 *
 *   MAX_CATEGORY_RATIO = 40%
 *     The next pick may not push its category above 40% of the recent
 *     selection window. This is the one that stops a whole audit from being
 *     about authentication.
 *
 * -----------------------------------------------------------------------
 * Why a limit may be RELAXED, and why that is never silent
 * -----------------------------------------------------------------------
 *
 * If every open hypothesis is `auth-bypass`, the category cap is unsatisfiable
 * and a scheduler that treated it as an absolute veto would refuse to schedule
 * anything — a deadlock, which is worse than a skewed round. So when no
 * candidate survives, the limits are relaxed in a fixed order and every
 * relaxation is recorded in `SelectionRecord.relaxations`.
 *
 * An empty `relaxations` array means the limits held. A non-empty one is a
 * finding in its own right: it says the TREE is skewed, not just the last pick.
 *
 * Pure: takes a snapshot, returns a decision. No fs, no pi, so every rule is
 * unit-testable and the ranking can be reproduced from the record.
 */

import {
  type Hypothesis,
  type HypothesisCategory,
  type ScoreBreakdown,
  type ScheduleConstraint,
  type ScheduleDecision,
  type ScheduleVeto,
  type SelectionRecord,
  type TreeSnapshot,
  combinationTag,
  isOpen,
  isSchedulable,
} from "./types.js";
import { HISTORY_WINDOW, appendEvent, nowIso } from "./store.js";
import { applyNodePatch, pathToRoot } from "./tree.js";

// -----------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------

export const SCHEDULER_LIMITS = {
  /** Consecutive descents allowed before a lateral move is forced. */
  MAX_CONSECUTIVE_DEPTH: 3,
  /** Consecutive rounds allowed on one node. */
  MAX_SAME_NODE_ROUNDS: 2,
  /** Maximum share of the recent selection window one category may take. */
  MAX_CATEGORY_RATIO: 0.4,
  /** How many recent selections the category share is measured over. */
  CATEGORY_WINDOW: 10,
  /**
   * The category cap is not applied to a window shorter than this. With fewer
   * than three picks the arithmetic is meaningless (one pick is always 100% of
   * its own category), and applying it would refuse to start the audit.
   */
  MIN_WINDOW_FOR_CATEGORY_CAP: 3,
} as const;

export const SCORE_WEIGHTS = {
  /** Full novelty for an unexamined node; halves per prior selection. */
  novelty: 10,
  /** Per evidence entry — a node near a verdict is cheap value to finish. */
  evidencePerEntry: 2,
  evidenceCap: 6,
  /** Full diversity bonus when the category has 0% of the window. */
  categoryDiversity: 8,
  depthPenaltyPerLevel: 1.5,
  /** Recency penalty at zero rounds since the last selection, decaying to 0. */
  recencyPenaltyAtZero: 8,
  recencyPenaltyDecayPerRound: 2,
  /** A blocked node was blocked for a reason. */
  blockedPenalty: 4,
  /** A node left mid-examination should be finished before opening a new front. */
  testingBoost: 3,
} as const;

/**
 * The order limits are relaxed in when nothing survives.
 *
 * Category first: it is the weakest rule (a preference about spreading
 * attention) and the most likely to be unsatisfiable for an honest reason — a
 * tree where one class of bug really is most of the remaining work.
 *
 * Descent next: it is structural, so relaxing it is a real concession, but a
 * tree that is nothing but one long chain still has to be auditable.
 *
 * Same-node last: a third consecutive round on one node means the round
 * produced neither a verdict nor a new lead, which is the most pathological
 * state and the last thing to permit.
 */
export const RELAXATION_ORDER: readonly ScheduleConstraint[] = [
  "max-category-ratio",
  "max-consecutive-depth",
  "max-same-node-rounds",
];

// -----------------------------------------------------------------
// Context
// -----------------------------------------------------------------

export interface SchedulingContext {
  round: number;
  lastSelectedId: string | null;
  /** Consecutive trailing selections of the same node. */
  sameNodeRun: number;
  /** Consecutive trailing descents (a move to a strict descendant). */
  descentRun: number;
  /**
   * LEVELS gained by the current consecutive-descent run.
   *
   * Measured in tree levels, not in steps, because the limit is expressed in
   * levels ("3 层"). A single round can jump several levels when a deep
   * hypothesis is added directly, and counting that as one "step" would let
   * the limit be walked past three levels at a time.
   */
  descentLevels: number;
  /** The node the current descent run started from (the last pick before it
   * began descending), or null when no run is in progress. */
  descentStartId: string | null;
  /** Every strict descendant of the last selected node. */
  descendantsOfLast: Set<string>;
  /** The recent selection window used for the category share. */
  window: SelectionRecord[];
  categoryCounts: Map<string, number>;
}

/** Is `candidateId` a strict descendant of `ancestorId`? */
function isDescendantOf(snapshot: TreeSnapshot, candidateId: string, ancestorId: string): boolean {
  if (candidateId === ancestorId) return false;
  const chain = pathToRoot(snapshot, candidateId);
  // A broken chain returns [], which correctly yields false.
  return chain.some((n) => n.id === ancestorId);
}

export function buildContext(snapshot: TreeSnapshot, round: number): SchedulingContext {
  const selections = snapshot.selections;
  const lastSelectedId = selections.length > 0 ? selections[selections.length - 1]!.nodeId : null;

  let sameNodeRun = 0;
  if (lastSelectedId) {
    for (let i = selections.length - 1; i >= 0; i--) {
      if (selections[i]!.nodeId !== lastSelectedId) break;
      sameNodeRun++;
    }
  }

  // Walk back over the trailing run of strict descents and measure the LEVELS
  // it gained. The run starts at the first selection that was NOT reached by
  // descending from its predecessor.
  let descentRun = 0;
  let descentStartIndex = selections.length - 1;
  for (let i = selections.length - 1; i >= 1; i--) {
    const current = selections[i]!;
    const previous = selections[i - 1]!;
    if (current.nodeId === previous.nodeId) break; // a same-node repeat, not a descent
    if (!isDescendantOf(snapshot, current.nodeId, previous.nodeId)) break;
    descentRun++;
    descentStartIndex = i - 1;
  }
  const depthOf = (id: string): number => snapshot.byId.get(id)?.depth ?? 0;
  const descentStartId = descentRun > 0 ? (selections[descentStartIndex]?.nodeId ?? null) : null;
  const descentLevels = descentRun > 0 && lastSelectedId
    ? Math.max(0, depthOf(lastSelectedId) - depthOf(descentStartId ?? lastSelectedId))
    : 0;

  const descendantsOfLast = new Set<string>();
  if (lastSelectedId && snapshot.byId.has(lastSelectedId)) {
    for (const node of snapshot.nodes) {
      if (isDescendantOf(snapshot, node.id, lastSelectedId)) descendantsOfLast.add(node.id);
    }
  }

  const window = selections.slice(-SCHEDULER_LIMITS.CATEGORY_WINDOW);
  const categoryCounts = new Map<string, number>();
  for (const record of window) {
    const node = snapshot.byId.get(record.nodeId);
    if (!node) continue;
    categoryCounts.set(node.category, (categoryCounts.get(node.category) ?? 0) + 1);
  }

  return { round, lastSelectedId, sameNodeRun, descentRun, descentLevels, descentStartId, descendantsOfLast, window, categoryCounts };
}

// -----------------------------------------------------------------
// Scoring
// -----------------------------------------------------------------

/** `roundsSince` is the number of rounds since the node was last selected;
 * `null` means never. */
export function scoreCandidate(
  node: Hypothesis,
  context: SchedulingContext,
): ScoreBreakdown {
  const w = SCORE_WEIGHTS;

  const novelty = w.novelty / (1 + node.timesSelected);
  const evidence = Math.min(w.evidenceCap, w.evidencePerEntry * node.evidence.length);

  const windowSize = context.window.length;
  const share = windowSize > 0 ? (context.categoryCounts.get(node.category) ?? 0) / windowSize : 0;
  const categoryDiversity = w.categoryDiversity * (1 - share);

  const depthPenalty = w.depthPenaltyPerLevel * node.depth;

  const roundsSince = node.lastSelectedRound === null ? null : Math.max(0, context.round - node.lastSelectedRound);
  const recencyPenalty = roundsSince === null
    ? 0
    : Math.max(0, w.recencyPenaltyAtZero - w.recencyPenaltyDecayPerRound * roundsSince);

  const blockedPenalty = node.status === "blocked" ? w.blockedPenalty : 0;
  const testingBoost = node.status === "testing" ? w.testingBoost : 0;

  const total = novelty + evidence + categoryDiversity + testingBoost - depthPenalty - recencyPenalty - blockedPenalty;

  return { novelty, evidence, categoryDiversity, depthPenalty, recencyPenalty, blockedPenalty, testingBoost, total };
}

// -----------------------------------------------------------------
// Constraints
// -----------------------------------------------------------------

/** Which hard limits disqualify this candidate, and why. Returns one entry per
 * violated limit so a relaxation can drop them individually. */
export function violations(node: Hypothesis, context: SchedulingContext): ScheduleVeto[] {
  const out: ScheduleVeto[] = [];
  const limits = SCHEDULER_LIMITS;

  if (
    context.lastSelectedId !== null &&
    node.id === context.lastSelectedId &&
    context.sameNodeRun >= limits.MAX_SAME_NODE_ROUNDS
  ) {
    out.push({
      nodeId: node.id,
      constraint: "max-same-node-rounds",
      detail: `${node.id} has been selected ${context.sameNodeRun} round(s) in a row (limit ${limits.MAX_SAME_NODE_ROUNDS})`,
    });
  }

  if (context.descentLevels >= limits.MAX_CONSECUTIVE_DEPTH && context.descendantsOfLast.has(node.id)) {
    out.push({
      nodeId: node.id,
      constraint: "max-consecutive-depth",
      detail:
        `the current run has already descended ${context.descentLevels} level(s) from ${context.descentStartId ?? "?"} ` +
        `(limit ${limits.MAX_CONSECUTIVE_DEPTH}); ${node.id} continues the same branch`,
    });
  }

  if (context.window.length >= limits.MIN_WINDOW_FOR_CATEGORY_CAP) {
    const count = context.categoryCounts.get(node.category) ?? 0;
    const after = (count + 1) / (context.window.length + 1);
    if (after > limits.MAX_CATEGORY_RATIO) {
      out.push({
        nodeId: node.id,
        constraint: "max-category-ratio",
        detail: `"${node.category}" would reach ${Math.round(after * 100)}% of the last ${context.window.length + 1} picks (limit ${Math.round(limits.MAX_CATEGORY_RATIO * 100)}%)`,
      });
    }
  }

  return out;
}

/** Categories whose share of the OPEN population already exceeds the cap.
 * A diagnostic about the tree: the scheduler cannot spread attention when one
 * class of bug is nearly all the remaining work. */
export function populationSkew(snapshot: TreeSnapshot): string[] {
  const open = snapshot.nodes.filter((n) => isOpen(n.status));
  if (open.length < SCHEDULER_LIMITS.MIN_WINDOW_FOR_CATEGORY_CAP) return [];
  const counts = new Map<HypothesisCategory, number>();
  for (const node of open) counts.set(node.category, (counts.get(node.category) ?? 0) + 1);
  const out: string[] = [];
  for (const [category, count] of counts) {
    const share = count / open.length;
    if (share > SCHEDULER_LIMITS.MAX_CATEGORY_RATIO) {
      out.push(`"${category}" is ${Math.round(share * 100)}% of the ${open.length} open hypotheses (${count})`);
    }
  }
  return out.sort();
}

// -----------------------------------------------------------------
// Planning
// -----------------------------------------------------------------

export interface PlanOptions {
  /** Round number for this decision. Defaults to `snapshot.rounds + 1`. */
  round?: number;
}

/**
 * Choose the next hypothesis to examine.
 *
 * Deterministic: the same snapshot and round always produce the same decision,
 * so a round can be re-derived from the log for review.
 */
export function planNextRound(snapshot: TreeSnapshot, opts: PlanOptions = {}): ScheduleDecision {
  const round = opts.round ?? snapshot.rounds + 1;
  const context = buildContext(snapshot, round);
  const skew = populationSkew(snapshot);

  const candidates = snapshot.nodes.filter(isSchedulable);
  if (!snapshot.rootId) {
    return {
      round, selected: null, breakdown: null, vetoes: [], relaxations: [], candidates: 0, populationSkew: [],
      reasons: ["No hypothesis tree in this project — nothing to schedule. Start one with /hypothesis new."],
      ranked: [],
    };
  }
  if (candidates.length === 0) {
    return {
      round, selected: null, breakdown: null, vetoes: [], relaxations: [], candidates: 0, populationSkew: skew,
      reasons: [
        "No open hypotheses — every node has a verdict. The next move is to re-audit (spawn fresh hypotheses) or combine the confirmed findings into new ones.",
      ],
      ranked: [],
    };
  }

  const scored = candidates.map((node) => ({ node, breakdown: scoreCandidate(node, context), vetoes: violations(node, context) }));

  // Rank: score desc, then shallower first, then id — total order, no ties.
  scored.sort((a, b) => {
    if (b.breakdown.total !== a.breakdown.total) return b.breakdown.total - a.breakdown.total;
    if (a.node.depth !== b.node.depth) return a.node.depth - b.node.depth;
    return a.node.id.localeCompare(b.node.id);
  });

  const ranked = scored.map((entry) => ({
    nodeId: entry.node.id,
    score: entry.breakdown.total,
    vetoedBy: (entry.vetoes[0]?.constraint ?? null) as ScheduleConstraint | null,
  }));

  const reasons: string[] = [];
  const relaxed: ScheduleConstraint[] = [];

  /** Candidates that survive with `active` limits in force. */
  const survivors = (active: ReadonlySet<ScheduleConstraint>) =>
    scored.filter((entry) => !entry.vetoes.some((v) => active.has(v.constraint)));

  let active = new Set<ScheduleConstraint>(RELAXATION_ORDER);
  let pool = survivors(active);
  while (pool.length === 0 && active.size > 0) {
    // Drop the next limit in the fixed order and try again.
    const dropped = RELAXATION_ORDER.find((c) => active.has(c));
    if (!dropped) break;
    active.delete(dropped);
    relaxed.push(dropped);
    pool = survivors(active);
  }
  // Defensive: with every limit dropped the pool is every candidate, so this
  // can only be reached with an empty candidate list (handled above).
  if (pool.length === 0) pool = scored;

  const winner = pool[0]!;
  const allVetoes = scored.flatMap((entry) => entry.vetoes);

  // --- reasons, in derivation order -------------------------------------
  reasons.push(
    `round ${round}: selected ${winner.node.id} (score ${winner.breakdown.total.toFixed(1)}) from ${candidates.length} open hypothesis(es)`,
  );
  const b = winner.breakdown;
  reasons.push(
    `  score: novelty ${b.novelty.toFixed(1)} + evidence ${b.evidence.toFixed(1)} + diversity ${b.categoryDiversity.toFixed(1)} + testing ${b.testingBoost.toFixed(1)}` +
      ` − depth ${b.depthPenalty.toFixed(1)} − recency ${b.recencyPenalty.toFixed(1)} − blocked ${b.blockedPenalty.toFixed(1)}`,
  );
  reasons.push(
    `  ${winner.node.id}: "${truncate(winner.node.description, 90)}" — ${winner.node.category}${winner.node.combinationKind ? `+${combinationTag(winner.node.combinationKind)}` : ""}, depth ${winner.node.depth}, status ${winner.node.status}, ${winner.node.timesSelected} prior selection(s)${winner.node.spawnedFrom.length > 0 ? `, derived from ${winner.node.spawnedFrom.join("+")}` : ""}`,
  );
  reasons.push(
    `  runs: same-node ${context.sameNodeRun}/${SCHEDULER_LIMITS.MAX_SAME_NODE_ROUNDS}, ` +
      `descent ${context.descentLevels}/${SCHEDULER_LIMITS.MAX_CONSECUTIVE_DEPTH} level(s) in ${context.descentRun} step(s)` +
      `${context.descentStartId ? ` from ${context.descentStartId}` : ""}`,
  );
  if (context.window.length > 0) {
    const shares = [...context.categoryCounts.entries()]
      .map(([category, count]) => `${category} ${Math.round((count / context.window.length) * 100)}%`)
      .sort();
    reasons.push(`  category window (last ${context.window.length}): ${shares.join(", ")}`);
  }
  if (allVetoes.length > 0) {
    reasons.push(`  vetoed ${allVetoes.length} candidate(s):`);
    for (const veto of allVetoes.slice(0, 6)) reasons.push(`    ${veto.constraint}: ${veto.detail}`);
    if (allVetoes.length > 6) reasons.push(`    … and ${allVetoes.length - 6} more`);
  } else {
    reasons.push("  no candidate was vetoed — the limits held");
  }
  for (const constraint of relaxed) {
    reasons.push(
      `  RELAXED ${constraint}: no candidate satisfied it, so it was dropped for this round. ` +
        `This means the TREE is skewed, not just the last pick — add hypotheses in other categories or close the open ones.`,
    );
  }
  for (const line of skew) reasons.push(`  SKEW WARNING: ${line}`);

  return {
    round,
    selected: winner.node,
    breakdown: winner.breakdown,
    reasons,
    vetoes: allVetoes,
    relaxations: relaxed.map(
      (c) => `${c}: no candidate satisfied it (${candidates.length} open hypothesis(es) considered)`,
    ),
    candidates: candidates.length,
    populationSkew: skew,
    ranked,
  };
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max - 1) + "…";
}

// -----------------------------------------------------------------
// Persisting a decision
// -----------------------------------------------------------------

export interface ApplySelectionResult {
  ok: boolean;
  errors: string[];
  record?: SelectionRecord;
}

/**
 * Persist a decision: record the round, the selection (with its full score
 * breakdown and rationale), and the node's scheduling counters.
 *
 * The node is moved to `testing` when it was `pending` or `blocked`: choosing a
 * hypothesis IS starting to examine it, and leaving it `pending` would let the
 * tree claim nothing is in flight while a round is running.
 *
 * Refuses a decision with no selection — there is nothing to record, and
 * writing a selection event with no node would corrupt the descent-run
 * arithmetic for every later round.
 */
export function applySelection(
  projectRoot: string,
  decision: ScheduleDecision,
  at = nowIso(),
): ApplySelectionResult {
  if (!decision.selected) {
    return { ok: false, errors: ["nothing was scheduled — no selection to record"] };
  }
  const node = decision.selected;
  const breakdown = decision.breakdown;
  if (!breakdown) {
    return { ok: false, errors: ["the decision carries no score breakdown — refusing to record an unexplained selection"] };
  }

  const record: SelectionRecord = {
    round: decision.round,
    nodeId: node.id,
    at,
    score: breakdown.total,
    breakdown,
    reasons: decision.reasons,
    vetoes: decision.vetoes,
    relaxations: decision.relaxations,
    candidates: decision.candidates,
    populationSkew: decision.populationSkew,
  };

  if (!appendEvent(projectRoot, { type: "round_recorded", at, round: decision.round })) {
    return { ok: false, errors: ["the round could not be recorded — the tree is unchanged"] };
  }
  if (!appendEvent(projectRoot, { type: "selection_recorded", at, record })) {
    return { ok: false, errors: ["the selection could not be recorded — the tree is unchanged"] };
  }

  const nextStatus = node.status === "pending" || node.status === "blocked" ? "testing" : node.status;
  const patched = applyNodePatch(projectRoot, node.id, {
    score: breakdown.total,
    timesSelected: node.timesSelected + 1,
    lastSelectedRound: decision.round,
    status: nextStatus,
  }, at);
  if (!patched.ok) {
    return { ok: false, errors: [...patched.errors, "the selection was recorded but the node counters were not — repair before continuing"] };
  }

  return { ok: true, errors: [], record };
}

// -----------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------

/** The decision as text, for the round summary and `/hypothesis next`. */
export function renderDecision(decision: ScheduleDecision): string[] {
  const lines: string[] = [...decision.reasons];
  if (decision.ranked.length > 1) {
    lines.push("");
    lines.push(`  ranking (${decision.ranked.length}):`);
    for (const entry of decision.ranked.slice(0, 10)) {
      const mark = decision.selected && entry.nodeId === decision.selected.id ? "->" : "  ";
      const veto = entry.vetoedBy ? `  [${entry.vetoedBy}]` : "";
      lines.push(`    ${mark} ${entry.nodeId}  ${entry.score.toFixed(1).padStart(6)}${veto}`);
    }
    if (decision.ranked.length > 10) lines.push(`    … and ${decision.ranked.length - 10} more`);
  }
  return lines;
}

export { HISTORY_WINDOW };
