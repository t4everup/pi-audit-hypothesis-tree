/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/combination.ts
 *
 * Stage 4: vulnerability combination.
 *
 * -----------------------------------------------------------------------
 * What is mechanical here, and what is not
 * -----------------------------------------------------------------------
 *
 * "Do these two findings share a root cause?" is a SEMANTIC judgement. A module
 * that answered it by comparing words would be guessing, and a guess dressed as
 * analysis is the failure mode this whole extension exists to avoid.
 *
 * So the division is the same as stage 3's, applied to a different question:
 *
 *   MECHANICAL (this module)     SEMANTIC (the model)
 *   -------------------------    ------------------------------
 *   which pairs are worth a      whether the pair is actually related
 *   look, and in what order      and how
 *   the structural facts about   the hypothesis that expresses it
 *   a pair (shared files, line
 *   proximity, tree relation)
 *   that a pair has already      whether the earlier answer was good
 *   been examined
 *   validating and inserting     phrasing the assertion
 *   the produced hypothesis
 *
 * Concretely: with N confirmed findings there are N² pairs, and the model
 * cannot be handed all of them, cannot rank them, and cannot be trusted to
 * remember which ones it already considered. This module does exactly those
 * three things and nothing more.
 *
 * -----------------------------------------------------------------------
 * The three combination kinds
 * -----------------------------------------------------------------------
 *
 *   chain              A depends on B — you need B to reach A
 *   shared-root-cause  A and B are both consequences of one missing check
 *   lateral-extension  A bypasses X; the same technique may bypass Y
 *
 * The first two are relations BETWEEN findings, so they consume a pair. The
 * third generalizes ONE finding, which is why a pass also considers
 * singletons — and why the trigger cannot be "only when there are ≥2 findings"
 * without losing lateral extension entirely.
 *
 * -----------------------------------------------------------------------
 * The pass is recorded even when it produces nothing
 * -----------------------------------------------------------------------
 *
 * "We looked and found no combination" is a result. A pass that left no record
 * is indistinguishable from a pass that never ran, and that is exactly the
 * state that makes a reviewer distrust the whole tree.
 */

import {
  type CombinationKind,
  type ConsolidationPair,
  type ConsolidationPlan,
  type ConsolidationRecord,
  type ConsolidationSingle,
  type ConsolidationTrigger,
  type Hypothesis,
  type TreeSnapshot,
  COMBINATION_KINDS,
  isVerdict,
} from "./types.js";
import { CONSOLIDATION_HISTORY_WINDOW, appendEvent, nowIso } from "./store.js";
import { addNode, applyNodePatch, children, pathToRoot } from "./tree.js";

// -----------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------

export const CONSOLIDATION = {
  /** Rounds between forced passes. */
  INTERVAL: 3,
  /** Below this many confirmed findings there is nothing to pair. */
  MIN_CONFIRMED_FOR_PAIRING: 2,
  /** Cap on the confirmed set considered, so N² stays bounded. */
  MAX_CONFIRMED_CONSIDERED: 12,
  /** Cap on pairs handed to the model in one pass. */
  MAX_PAIRS: 6,
  /** Cap on lateral-extension candidates in one pass. */
  MAX_SINGLES: 3,
  /** Two evidence lines within this many lines count as "the same region". */
  NEAR_LINE_DISTANCE: 50,
  /** Within this many lines counts as "the same area, probably not the same site". */
  SAME_AREA_LINE_DISTANCE: 200,
} as const;

export const PAIR_WEIGHTS = {
  perSharedFile: 6,
  sharedFileCap: 12,
  nearLine: 5,
  sameArea: 2,
  sameCategory: 3,
  /** Different classes can chain, and a cross-class chain is the most valuable
   * combination if it is real. Both directions get a bonus so neither crowds
   * the other out of the cut. */
  differentCategory: 2,
  ancestorOrDescendant: 4,
  sibling: 2,
  /** Per average evidence entry across the pair, capped. */
  evidencePerEntry: 1.5,
  evidenceCap: 3,
} as const;

// -----------------------------------------------------------------
// Pair keys
// -----------------------------------------------------------------

/** Order-independent pair identity, so (a,b) and (b,a) are one examined pair. */
export function pairKey(aId: string, bId: string): string {
  return aId <= bId ? `${aId}|${bId}` : `${bId}|${aId}`;
}

/** Every pair key already handed to the model in a previous pass. */
export function examinedPairKeys(snapshot: TreeSnapshot): Set<string> {
  const keys = new Set<string>();
  for (const record of snapshot.consolidations) {
    for (const key of record.pairKeys) keys.add(key);
  }
  return keys;
}

// -----------------------------------------------------------------
// Scoring
// -----------------------------------------------------------------

/** Every evidence location a finding cites, as `file:line`. */
function evidenceLocations(node: Hypothesis): Array<{ file: string; line: number }> {
  const out: Array<{ file: string; line: number }> = [];
  for (const e of node.evidence) {
    if (e.location) out.push({ file: e.location.file.replace(/\\/g, "/"), line: e.location.line });
  }
  return out;
}

/** Ancestor / descendant / sibling / unrelated, from the tree alone. */
export function treeRelation(snapshot: TreeSnapshot, aId: string, bId: string): ConsolidationPair["treeRelation"] {
  const aChain = pathToRoot(snapshot, aId).map((n) => n.id);
  const bChain = pathToRoot(snapshot, bId).map((n) => n.id);
  if (aChain.includes(bId) || bChain.includes(aId)) return "ancestor";
  const aParent = snapshot.byId.get(aId)?.parentId ?? null;
  const bParent = snapshot.byId.get(bId)?.parentId ?? null;
  if (aParent !== null && aParent === bParent) return "sibling";
  return "unrelated";
}

/**
 * Score a pair and describe WHY, using only structural facts.
 *
 * The signals list is the point: it is what lets the model make a grounded
 * judgement instead of reading two prose summaries and pattern-matching on
 * vocabulary.
 */
export function scorePair(snapshot: TreeSnapshot, a: Hypothesis, b: Hypothesis): ConsolidationPair {
  const w = PAIR_WEIGHTS;
  const signals: string[] = [];
  let score = 0;

  const aLocs = evidenceLocations(a);
  const bLocs = evidenceLocations(b);
  const aFiles = new Set(aLocs.map((l) => l.file));
  const sharedFiles = [...new Set(bLocs.map((l) => l.file).filter((f) => aFiles.has(f)))].sort();

  if (sharedFiles.length > 0) {
    score += Math.min(w.sharedFileCap, w.perSharedFile * sharedFiles.length);
    signals.push(`both cite ${sharedFiles.join(", ")} (${sharedFiles.length} shared file(s))`);
  }

  let minLineDistance: number | null = null;
  for (const file of sharedFiles) {
    for (const la of aLocs.filter((l) => l.file === file)) {
      for (const lb of bLocs.filter((l) => l.file === file)) {
        const distance = Math.abs(la.line - lb.line);
        if (minLineDistance === null || distance < minLineDistance) minLineDistance = distance;
      }
    }
  }
  if (minLineDistance !== null) {
    if (minLineDistance <= CONSOLIDATION.NEAR_LINE_DISTANCE) {
      score += w.nearLine;
      signals.push(`evidence lines are ${minLineDistance} apart — plausibly the same region`);
    } else if (minLineDistance <= CONSOLIDATION.SAME_AREA_LINE_DISTANCE) {
      score += w.sameArea;
      signals.push(`evidence lines are ${minLineDistance} apart — the same area, probably not the same site`);
    }
  }

  if (a.category === b.category) {
    score += w.sameCategory;
    signals.push(`same class (${a.category}) — a shared root cause is plausible`);
  } else {
    score += w.differentCategory;
    signals.push(`different classes (${a.category} + ${b.category}) — a cross-class chain is possible and valuable if real`);
  }

  const relation = treeRelation(snapshot, a.id, b.id);
  if (relation === "ancestor") {
    score += w.ancestorOrDescendant;
    signals.push("one is an ancestor of the other — a dependency (chain) is plausible");
  } else if (relation === "sibling") {
    score += w.sibling;
    signals.push("they share a parent hypothesis");
  } else {
    signals.push("unrelated in the tree — any combination would be a new link, not a restatement");
  }

  const evidenceDepth = (a.evidence.length + b.evidence.length) / 2;
  const evidenceBonus = Math.min(w.evidenceCap, w.evidencePerEntry * evidenceDepth);
  if (evidenceBonus > 0) score += evidenceBonus;

  return {
    aId: a.id,
    bId: b.id,
    key: pairKey(a.id, b.id),
    score,
    signals,
    sharedFiles,
    minLineDistance,
    treeRelation: relation,
  };
}

/** Has this finding already been generalized into a lateral-extension child? */
export function isGeneralized(snapshot: TreeSnapshot, id: string): boolean {
  return snapshot.nodes.some((n) => n.combinationKind === "lateral-extension" && n.spawnedFrom.includes(id));
}

/** Score a confirmed finding as a lateral-extension candidate. */
export function scoreSingle(snapshot: TreeSnapshot, node: Hypothesis): ConsolidationSingle {
  const signals: string[] = [];
  let score = node.evidence.length * 2;
  signals.push(`${node.evidence.length} evidence entry/entries`);

  const kids = children(snapshot, node.id);
  if (kids.length === 0) {
    score += 3;
    signals.push("nothing has been derived from it yet");
  } else {
    signals.push(`${kids.length} child hypothesis(es) already derived`);
  }
  if (node.evidence.some((e) => e.location)) {
    score += 2;
    signals.push("it cites a concrete location, so the bypass surface around it is inspectable");
  }
  const category = node.category;
  const sameCategory = snapshot.nodes.filter((n) => n.category === category).length;
  if (sameCategory <= 2) {
    score += 1;
    signals.push(`only ${sameCategory} hypothesis(es) in class "${category}"`);
  }
  return { id: node.id, score, signals };
}

// -----------------------------------------------------------------
// Planning
// -----------------------------------------------------------------

/** The newest consolidation pass, or null. */
export function lastConsolidation(snapshot: TreeSnapshot): ConsolidationRecord | null {
  return snapshot.consolidations.length > 0 ? snapshot.consolidations[snapshot.consolidations.length - 1]! : null;
}

/**
 * The last pass belonging to the CURRENT run.
 *
 * `/loop start` restarts the round counter, so a pass recorded at round 48 by a
 * previous run would make `round - previous.round` NEGATIVE — and a negative gap
 * never reaches the interval, so the periodic re-pass would be switched off
 * silently for the rest of the tree's life.
 */
export function lastConsolidationInRun(snapshot: TreeSnapshot): ConsolidationRecord | null {
  const loop = snapshot.loop;
  if (!loop) return lastConsolidation(snapshot);
  const inRun = snapshot.consolidations.filter((c) => c.at >= loop.startedAt);
  return inRun.length > 0 ? inRun[inRun.length - 1]! : null;
}

export interface PlanConsolidationOptions {
  /** The round the pass is attributed to. Defaults to `snapshot.rounds`. */
  round?: number;
  /** Run the pass regardless of the trigger, recording this as the reason. */
  force?: ConsolidationTrigger;
}

/**
 * Decide whether a consolidation pass is due, and if so, which pairs and
 * singletons to hand over.
 *
 * Trigger precedence when not forced:
 *   1. a finding was confirmed since the last pass   → "new-finding"
 *   2. INTERVAL rounds have passed                   → "interval"
 *
 * The "new-finding" trigger fires on a COUNT increase rather than a set diff,
 * so a finding that was reopened and re-confirmed does not masquerade as new
 * work. Reopening and re-confirming the same finding is not new information
 * about the codebase.
 */
export function planConsolidation(snapshot: TreeSnapshot, opts: PlanConsolidationOptions = {}): ConsolidationPlan {
  const round = opts.round ?? snapshot.rounds;
  const confirmedAll = snapshot.nodes.filter((n) => n.status === "confirmed");
  // Scoped to this run: see lastConsolidationInRun.
  const previous = lastConsolidationInRun(snapshot);

  let trigger: ConsolidationTrigger | null = opts.force ?? null;
  let reason: string;

  if (trigger) {
    reason = `forced (${trigger})`;
  } else if (!previous) {
    trigger = confirmedAll.length > 0 ? "new-finding" : null;
    reason = confirmedAll.length > 0
      ? "first pass: findings have been confirmed and none has been combined yet"
      : "no findings confirmed yet — nothing to combine";
  } else if (confirmedAll.length > previous.confirmedIds.length) {
    trigger = "new-finding";
    reason = `${confirmedAll.length - previous.confirmedIds.length} new finding(s) since the pass at round ${previous.round}`;
  } else if (round - previous.round >= CONSOLIDATION.INTERVAL) {
    trigger = "interval";
    reason = `${round - previous.round} round(s) since the pass at round ${previous.round} (interval ${CONSOLIDATION.INTERVAL})`;
  } else {
    trigger = null;
    reason = `not due: ${round - previous.round} round(s) since the last pass (interval ${CONSOLIDATION.INTERVAL}) and no new finding`;
  }

  // The confirmed set, bounded and ordered by how well grounded each finding is.
  const confirmed = [...confirmedAll]
    .sort((a, b) => (b.evidence.length !== a.evidence.length ? b.evidence.length - a.evidence.length : a.id.localeCompare(b.id)))
    .slice(0, CONSOLIDATION.MAX_CONFIRMED_CONSIDERED);
  const capped = confirmedAll.length - confirmed.length;

  if (!trigger) {
    return {
      round,
      trigger: "interval",
      due: false,
      reason,
      confirmed,
      confirmedIds: confirmedAll.map((n) => n.id),
      pairs: [],
      singles: [],
      skipped: null,
    };
  }

  const examined = examinedPairKeys(snapshot);
  const pairs: ConsolidationPair[] = [];
  for (let i = 0; i < confirmed.length; i++) {
    for (let j = i + 1; j < confirmed.length; j++) {
      const a = confirmed[i]!;
      const b = confirmed[j]!;
      const key = pairKey(a.id, b.id);
      if (examined.has(key)) continue;
      pairs.push(scorePair(snapshot, a, b));
    }
  }
  pairs.sort((a, b) => (b.score !== a.score ? b.score - a.score : a.key.localeCompare(b.key)));
  const pairsCapped = Math.max(0, pairs.length - CONSOLIDATION.MAX_PAIRS);
  const chosenPairs = pairs.slice(0, CONSOLIDATION.MAX_PAIRS);

  const singles: ConsolidationSingle[] = confirmed
    .filter((n) => !isGeneralized(snapshot, n.id))
    .map((n) => scoreSingle(snapshot, n))
    .sort((a, b) => (b.score !== a.score ? b.score - a.score : a.id.localeCompare(b.id)));
  const chosenSingles = singles.slice(0, CONSOLIDATION.MAX_SINGLES);

  let skipped: string | null = null;
  if (chosenPairs.length === 0 && chosenSingles.length === 0) {
    if (confirmed.length < CONSOLIDATION.MIN_CONFIRMED_FOR_PAIRING) {
      skipped =
        `only ${confirmed.length} confirmed finding(s) and every one has already been generalized — ` +
        `there is nothing to pair and nothing new to extend`;
    } else {
      skipped = `every pair among the ${confirmed.length} confirmed finding(s) has already been examined`;
    }
  }

  const notes: string[] = [reason];
  if (capped > 0) notes.push(`${capped} confirmed finding(s) beyond the ${CONSOLIDATION.MAX_CONFIRMED_CONSIDERED} considered`);
  if (pairsCapped > 0) notes.push(`${pairsCapped} unexamined pair(s) beyond the ${CONSOLIDATION.MAX_PAIRS} handed over`);

  // A PASS WITH NOTHING TO EXAMINE IS NOT DUE.
  //
  // The trigger fires on a schedule, but a scheduled pass that has nothing to
  // hand over spends a round to produce nothing — which both wastes the round and
  // counts against the plateau, so a long run of empty passes ends the audit
  // claiming the well is dry while hypotheses are still unexamined. Reporting
  // `due: false` also keeps the `requireConsolidated` contract clause satisfiable
  // when there is genuinely nothing to consolidate.
  if (skipped !== null) {
    return {
      round,
      trigger,
      due: false,
      reason: `${notes.join("; ")} — ${skipped}`,
      confirmed,
      confirmedIds: confirmedAll.map((n) => n.id),
      pairs: [],
      singles: [],
      skipped,
    };
  }

  return {
    round,
    trigger,
    due: true,
    reason: notes.join("; "),
    confirmed,
    confirmedIds: confirmedAll.map((n) => n.id),
    pairs: chosenPairs,
    singles: chosenSingles,
    skipped,
  };
}

// -----------------------------------------------------------------
// Recording
// -----------------------------------------------------------------

/**
 * Record a pass so its pairs are marked examined.
 *
 * Recorded even when `skipped` is set: a pass that found nothing must be
 * distinguishable from a pass that never ran, or the forced trigger would fire
 * forever.
 */
export function applyConsolidation(projectRoot: string, plan: ConsolidationPlan, at = nowIso()): { ok: boolean; errors: string[] } {
  if (!plan.due) {
    return { ok: false, errors: [`the consolidation pass is not due (${plan.reason})`] };
  }
  const record: ConsolidationRecord = {
    round: plan.round,
    at,
    trigger: plan.trigger,
    confirmedIds: plan.confirmedIds,
    pairKeys: plan.pairs.map((p) => p.key),
    singleIds: plan.singles.map((s) => s.id),
    skipped: plan.skipped,
  };
  if (!appendEvent(projectRoot, { type: "consolidation_recorded", at, record })) {
    return { ok: false, errors: ["the consolidation record could not be written — the tree is unchanged"] };
  }
  return { ok: true, errors: [] };
}

// -----------------------------------------------------------------
// Validating a produced combination
// -----------------------------------------------------------------

export interface CombinationInput {
  description: string;
  category: string;
  kind: CombinationKind;
  /** The confirmed findings this combination is derived from. */
  spawnedFrom: string[];
  parentId?: string;
}

export interface CombinationValidation {
  ok: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Validate a combination before it enters the tree.
 *
 * The load-bearing rule: **every `spawnedFrom` id must be a CONFIRMED finding.**
 * A combination derived from an unconfirmed hypothesis is speculation stacked
 * on speculation, and it would let the tree grow without any of the evidence
 * that makes a node worth having.
 *
 * The description-shape gate is left to `addNode`, so a combination cannot be
 * phrased as a task either.
 */
export function validateCombination(snapshot: TreeSnapshot, input: Partial<CombinationInput>): CombinationValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!input.kind || !COMBINATION_KINDS.includes(input.kind)) {
    errors.push(`kind must be one of ${COMBINATION_KINDS.join("|")}`);
  }
  const ids = input.spawnedFrom ?? [];
  if (ids.length === 0) {
    errors.push(
      "spawnedFrom must name the confirmed finding(s) this combination is derived from — an unexplained combination is indistinguishable from a guess",
    );
  }
  for (const id of ids) {
    const node = snapshot.byId.get(id);
    if (!node) {
      errors.push(`spawnedFrom references ${id}, which is not in the tree`);
      continue;
    }
    if (node.status !== "confirmed") {
      errors.push(
        `spawnedFrom references ${id}, whose status is "${node.status}" — only CONFIRMED findings can be combined; a combination of unconfirmed hypotheses is speculation stacked on speculation`,
      );
    }
  }
  if (input.kind === "chain" || input.kind === "shared-root-cause") {
    if (ids.length < 2) {
      errors.push(`a "${input.kind}" is a relation BETWEEN findings and needs at least 2 ids in spawnedFrom (got ${ids.length})`);
    }
  }
  if (input.kind === "lateral-extension" && ids.length !== 1) {
    warnings.push(
      `a "lateral-extension" usually generalizes ONE finding; ${ids.length} ids were given, so the assertion should name the technique being extended, not the pair`,
    );
  }
  if (input.parentId && !snapshot.byId.has(input.parentId)) {
    errors.push(`parentId ${input.parentId} is not in the tree`);
  }
  // A duplicate description is refused by addNode, but naming it here gives a
  // better message than "already in the tree".
  const key = input.description?.trim().toLowerCase();
  if (key) {
    const existing = snapshot.nodes.find((n) => n.description.trim().toLowerCase() === key);
    if (existing) errors.push(`this assertion is already in the tree as ${existing.id} (status ${existing.status})`);
  }

  return { ok: errors.length === 0, errors, warnings };
}

/** Insert a validated combination as a new hypothesis. */
export function applyCombination(
  projectRoot: string,
  snapshot: TreeSnapshot,
  input: CombinationInput,
): { ok: boolean; errors: string[]; node?: Hypothesis } {
  const validation = validateCombination(snapshot, input);
  if (!validation.ok) return { ok: false, errors: validation.errors };

  const result = addNode(projectRoot, {
    description: input.description,
    category: input.category,
    ...(input.parentId ? { parentId: input.parentId } : {}),
    spawnedFrom: input.spawnedFrom,
    roundIntroduced: snapshot.rounds,
  });
  if (!result.ok) return { ok: false, errors: result.errors };

  // Record the KIND. `addNode` cannot, because the kind is a property of how
  // the node was derived, not of the node's content.
  const patched = applyNodePatch(projectRoot, result.value.node.id, { combinationKind: input.kind }, nowIso());
  if (!patched.ok) {
    return { ok: false, errors: [...patched.errors, "the combination was added but its kind was not recorded"] };
  }
  return { ok: true, errors: [], node: patched.value };
}

// -----------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------

/**
 * The BRIEF handed to the model.
 *
 * This is the payload that decides whether stage 4 produces anything useful, so
 * it states the structural facts, names all three combination kinds, and says
 * explicitly that "no combination" is an acceptable answer. A brief that
 * pressured the model into producing something would manufacture the very
 * speculation the tree is built to avoid.
 */
export function renderConsolidation(plan: ConsolidationPlan): string[] {
  const lines: string[] = [
    `CONSOLIDATION PASS — round ${plan.round}, trigger: ${plan.trigger}`,
    `  ${plan.reason}`,
    `  ${plan.confirmed.length} confirmed finding(s) considered`,
    "",
  ];

  if (plan.skipped) {
    lines.push(`  NOTHING TO EXAMINE: ${plan.skipped}`);
    lines.push("");
    lines.push("  This is a recorded result, not a failure. Continue auditing; the next pass will have new material.");
    return lines;
  }

  if (plan.pairs.length > 0) {
    lines.push(`PAIRS to consider (${plan.pairs.length}), strongest structural signal first:`);
    lines.push("");
    for (const pair of plan.pairs) {
      const a = pair.aId;
      const b = pair.bId;
      lines.push(`  ${pair.key}   score ${pair.score.toFixed(1)}   [${pair.treeRelation}]`);
      for (const signal of pair.signals) lines.push(`      - ${signal}`);
      lines.push(`      consider: chain (${a} needs ${b}) · shared-root-cause (one missing check produces both) · cross-class chain`);
      lines.push("");
    }
  }

  if (plan.singles.length > 0) {
    lines.push(`LATERAL-EXTENSION candidates (${plan.singles.length}) — generalize ONE finding:`);
    lines.push("");
    for (const single of plan.singles) {
      lines.push(`  ${single.id}   score ${single.score.toFixed(1)}`);
      for (const signal of single.signals) lines.push(`      - ${signal}`);
    }
    lines.push("");
  }

  lines.push("For each combination you believe is REAL, call hypothesis_combine with:");
  lines.push("  kind            chain | shared-root-cause | lateral-extension");
  lines.push("  spawnedFrom     the CONFIRMED finding ids it is derived from");
  lines.push("  description     a new falsifiable assertion (not a restatement of either finding)");
  lines.push("  category        the class of the NEW assertion");
  lines.push("");
  lines.push("A pair with a strong structural signal may still have NO real relationship. Reporting none is the");
  lines.push("correct answer then — a fabricated chain is worse than no chain, because it sends the next rounds");
  lines.push("after something that does not exist. Every spawnedFrom id must be a confirmed finding.");
  return lines;
}

export interface ConsolidationStatus {
  passes: number;
  lastRound: number | null;
  lastTrigger: ConsolidationTrigger | null;
  examinedPairs: number;
  produced: Record<CombinationKind, number>;
  /** True when a pass is currently due. */
  due: boolean;
}

/** Status for the summary block. */
export function consolidationStatus(snapshot: TreeSnapshot): ConsolidationStatus {
  const last = lastConsolidation(snapshot);
  const produced: Record<CombinationKind, number> = { chain: 0, "shared-root-cause": 0, "lateral-extension": 0 };
  for (const node of snapshot.nodes) {
    if (node.combinationKind) produced[node.combinationKind]++;
  }
  return {
    passes: snapshot.consolidations.length,
    lastRound: last?.round ?? null,
    lastTrigger: last?.trigger ?? null,
    examinedPairs: examinedPairKeys(snapshot).size,
    produced,
    due: planConsolidation(snapshot).due,
  };
}

export { CONSOLIDATION_HISTORY_WINDOW };
