// pi-audit-hypothesis-tree — tests/scheduler.test.ts
//
// Pins the anti-rabbit-hole scheduler. The last test in this file is the one
// that matters most: it simulates many rounds against a deliberately
// tunnel-shaped tree and asserts that the emergent behaviour is NOT a
// straight descent.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { compact, load } from "../extensions/hypothesis-tree/store.ts";
import { addEvidence, addNode, createTree, getNode, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import {
  RELAXATION_ORDER,
  SCHEDULER_LIMITS,
  SCORE_WEIGHTS,
  applySelection,
  buildContext,
  planNextRound,
  populationSkew,
  renderDecision,
  scoreCandidate,
  violations,
} from "../extensions/hypothesis-tree/scheduler.ts";
import type { Hypothesis, SelectionRecord } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-sched-"));
}

const ROOT = "the login handler accepts a JWT without verifying its signature";

function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, ROOT, { category: "auth-bypass" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

function add(cwd: string, description: string, category: string, parentId?: string): Hypothesis {
  const result = addNode(cwd, {
    description,
    category,
    ...(parentId ? { parentId } : {}),
  });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result.ok ? result.value.node : (undefined as never);
}

/** A node literal for the pure score tests. */
function node(over: Partial<Hypothesis> = {}): Hypothesis {
  return {
    id: "H-0001",
    nodeKind: "hypothesis",
    parentId: null,
    description: "the login handler accepts a JWT without verifying its signature",
    category: "auth-bypass",
    status: "pending",
    evidence: [],
    depth: 0,
    createdAt: "2026-01-01T00:00:00.000Z",
    lastTouchedAt: "2026-01-01T00:00:00.000Z",
    score: 0,
    spawnedFrom: [],
    roundIntroduced: 0,
    timesSelected: 0,
    lastSelectedRound: null,
    ...over,
  };
}

/** A selection record for the pure context tests. */
function sel(nodeId: string, round: number): SelectionRecord {
  return {
    round,
    nodeId,
    at: "2026-01-01T00:00:00.000Z",
    score: 0,
    breakdown: { novelty: 0, evidence: 0, categoryDiversity: 0, depthPenalty: 0, recencyPenalty: 0, blockedPenalty: 0, testingBoost: 0, gateBoost: 0, focusBoost: 0, total: 0 },
    reasons: [],
    vetoes: [],
    relaxations: [],
    candidates: 0,
    populationSkew: [],
  };
}

// -----------------------------------------------------------------
// Configuration — the spec's numbers
// -----------------------------------------------------------------

test("the three limits are the values the design specifies", () => {
  assert.equal(SCHEDULER_LIMITS.MAX_CONSECUTIVE_DEPTH, 3);
  assert.equal(SCHEDULER_LIMITS.MAX_SAME_NODE_ROUNDS, 2);
  assert.equal(SCHEDULER_LIMITS.MAX_CATEGORY_RATIO, 0.4);
});

test("relaxation order is category, then descent, then same-node", () => {
  assert.deepEqual([...RELAXATION_ORDER], ["max-category-ratio", "max-consecutive-depth", "max-same-node-rounds"]);
});

// -----------------------------------------------------------------
// Scoring
// -----------------------------------------------------------------

function ctx(over: Partial<Parameters<typeof scoreCandidate>[1]> = {}) {
  return {
    round: 1,
    lastSelectedId: null,
    sameNodeRun: 0,
    descentRun: 0,
    descentLevels: 0,
    descentStartId: null,
    descendantsOfLast: new Set<string>(),
    window: [],
    categoryCounts: new Map<string, number>(),
    gatesOfConfirmed: new Set<string>(),
    focus: new Set<string>(),
    ...over,
  };
}

test("novelty halves with each prior selection", () => {
  assert.equal(scoreCandidate(node({ timesSelected: 0 }), ctx()).novelty, SCORE_WEIGHTS.novelty);
  assert.equal(scoreCandidate(node({ timesSelected: 1 }), ctx()).novelty, SCORE_WEIGHTS.novelty / 2);
  assert.equal(scoreCandidate(node({ timesSelected: 3 }), ctx()).novelty, SCORE_WEIGHTS.novelty / 4);
});

test("evidence raises the score but saturates", () => {
  const one = scoreCandidate(node({ evidence: [{ kind: "reasoning", at: "", detail: "x" }] }), ctx());
  assert.equal(one.evidence, SCORE_WEIGHTS.evidencePerEntry);
  const many = scoreCandidate(
    node({ evidence: Array.from({ length: 9 }, () => ({ kind: "reasoning" as const, at: "", detail: "x" })) }),
    ctx(),
  );
  assert.equal(many.evidence, SCORE_WEIGHTS.evidenceCap, "the evidence term must not grow without bound");
});

test("a category that already owns the whole window gets no diversity bonus", () => {
  const window = [sel("H-0001", 1), sel("H-0002", 2), sel("H-0003", 3)];
  const c = ctx({ window, categoryCounts: new Map([["auth-bypass", 3]]) });
  assert.equal(scoreCandidate(node({ category: "auth-bypass" }), c).categoryDiversity, 0);
  // A category absent from the window gets the full bonus.
  assert.equal(scoreCandidate(node({ category: "ssrf" }), c).categoryDiversity, SCORE_WEIGHTS.categoryDiversity);
});

test("depth is penalised linearly and recency decays to zero", () => {
  assert.equal(scoreCandidate(node({ depth: 4 }), ctx()).depthPenalty, SCORE_WEIGHTS.depthPenaltyPerLevel * 4);
  // Selected this round → full penalty; 4+ rounds ago → none.
  assert.equal(scoreCandidate(node({ lastSelectedRound: 5 }), ctx({ round: 5 })).recencyPenalty, SCORE_WEIGHTS.recencyPenaltyAtZero);
  assert.equal(scoreCandidate(node({ lastSelectedRound: 1 }), ctx({ round: 5 })).recencyPenalty, 0);
  assert.equal(scoreCandidate(node({ lastSelectedRound: 3 }), ctx({ round: 5 })).recencyPenalty, 4);
});

test("blocked is penalised and mid-examination is boosted", () => {
  assert.equal(scoreCandidate(node({ status: "blocked" }), ctx()).blockedPenalty, SCORE_WEIGHTS.blockedPenalty);
  assert.equal(scoreCandidate(node({ status: "testing" }), ctx()).testingBoost, SCORE_WEIGHTS.testingBoost);
  assert.equal(scoreCandidate(node({ status: "pending" }), ctx()).blockedPenalty, 0);
});

test("total is the signed sum of every term", () => {
  const b = scoreCandidate(node({ depth: 2, timesSelected: 1, status: "testing", lastSelectedRound: 1 }), ctx({ round: 3 }));
  const expected = b.novelty + b.evidence + b.categoryDiversity + b.testingBoost - b.depthPenalty - b.recencyPenalty - b.blockedPenalty;
  assert.equal(b.total, expected);
});

// -----------------------------------------------------------------
// Context: same-node run and descent run
// -----------------------------------------------------------------

test("same-node run counts only the trailing repeats", () => {
  const cwd = seeded();
  const snap = load(cwd).snapshot;
  assert.equal(buildContext({ ...snap, selections: [sel("H-0001", 1), sel("H-0001", 2)] }, 3).sameNodeRun, 2);
  assert.equal(buildContext({ ...snap, selections: [sel("H-0001", 1), sel("H-0001", 2), sel("H-0002", 3)] }, 4).sameNodeRun, 1);
  assert.equal(buildContext({ ...snap, selections: [] }, 1).sameNodeRun, 0);
});

test("descent is measured in LEVELS, so one jump of three levels counts as three", () => {
  const cwd = seeded();
  const a = add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  const b = add(cwd, "the alg=none case reaches the verifier and is accepted", "auth-bypass", a.id);
  const c = add(cwd, "the verifier accepts a key of length zero for alg=none", "auth-bypass", b.id);
  const snap = load(cwd).snapshot;

  // A straight walk root -> a -> b -> c is 3 levels of descent in 3 steps.
  const walked = buildContext({ ...snap, selections: [sel("H-0001", 1), sel(a.id, 2), sel(b.id, 3), sel(c.id, 4)] }, 5);
  assert.equal(walked.descentRun, 3);
  assert.equal(walked.descentLevels, 3, "three levels gained");
  assert.equal(walked.descentStartId, "H-0001");

  // A single jump from the root straight to the deepest node is 3 levels in
  // ONE step — and must count as 3, or the limit could be walked past.
  const jumped = buildContext({ ...snap, selections: [sel("H-0001", 1), sel(c.id, 2)] }, 3);
  assert.equal(jumped.descentRun, 1);
  assert.equal(jumped.descentLevels, 3, "one step, three levels");
});

test("a lateral move resets the descent run", () => {
  const cwd = seeded();
  const a = add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  const b = add(cwd, "the token expiry is never compared against the current time", "auth-bypass");
  const snap = load(cwd).snapshot;
  const c = buildContext({ ...snap, selections: [sel("H-0001", 1), sel(a.id, 2), sel(b.id, 3)] }, 4);
  assert.equal(c.descentRun, 0, "a sibling is not a descent");
  assert.equal(c.descentLevels, 0);
});

// -----------------------------------------------------------------
// Constraints
// -----------------------------------------------------------------

test("MAX_SAME_NODE_ROUNDS vetoes a third consecutive round on one node", () => {
  const cwd = seeded();
  const snap = load(cwd).snapshot;
  const target = snap.byId.get("H-0001")!;
  const context = buildContext({ ...snap, selections: [sel("H-0001", 1), sel("H-0001", 2)] }, 3);
  const vetoes = violations(target, context);
  assert.equal(vetoes.length, 1);
  assert.equal(vetoes[0]!.constraint, "max-same-node-rounds");
});

test("two consecutive rounds on one node is still allowed (the limit is 2)", () => {
  const cwd = seeded();
  const snap = load(cwd).snapshot;
  const context = buildContext({ ...snap, selections: [sel("H-0001", 1)] }, 2);
  assert.deepEqual(violations(snap.byId.get("H-0001")!, context), []);
});

test("MAX_CONSECUTIVE_DEPTH vetoes the descendant that would continue the run", () => {
  const cwd = seeded();
  const a = add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  const b = add(cwd, "the alg=none case reaches the verifier and is accepted", "auth-bypass", a.id);
  const c = add(cwd, "the verifier accepts a key of length zero for alg=none", "auth-bypass", b.id);
  const d = add(cwd, "the verifier compares the HMAC against a zero-length key", "auth-bypass", c.id);
  const snap = load(cwd).snapshot;

  const context = buildContext({ ...snap, selections: [sel("H-0001", 1), sel(a.id, 2), sel(b.id, 3), sel(c.id, 4)] }, 5);
  const vetoes = violations(snap.byId.get(d.id)!, context);
  // The category cap fires too (the whole window is auth-bypass), so assert on
  // the specific constraint rather than on the veto count.
  assert.ok(
    vetoes.some((v) => v.constraint === "max-consecutive-depth"),
    `the descent limit must veto ${d.id}: ${JSON.stringify(vetoes)}`,
  );
  assert.match(vetoes.find((v) => v.constraint === "max-consecutive-depth")!.detail, /already descended 3 level\(s\) from H-0001/);

  // A sibling inside the same branch is NOT a descendant of the last pick, so
  // the descent rule does not touch it — the limit forces a sideways move, not
  // an exit from the branch.
  const sibling = add(cwd, "the audience claim is not validated at all", "auth-bypass", b.id);
  const snap2 = load(cwd).snapshot;
  assert.ok(
    !violations(snap2.byId.get(sibling.id)!, context).some((v) => v.constraint === "max-consecutive-depth"),
    "a sibling is not a continuation of the descent",
  );
});

test("MAX_CATEGORY_RATIO vetoes a pick that would exceed 40% of the window", () => {
  const cwd = seeded();
  const snap = load(cwd).snapshot;
  // 4 of the last 6 picks are auth-bypass: adding a fifth → 5/7 = 71% > 40%.
  const window = [sel("H-0001", 1), sel("H-0002", 2), sel("H-0003", 3), sel("H-0004", 4), sel("H-0005", 5), sel("H-0006", 6)];
  const context = buildContext({ ...snap, selections: window }, 7);
  // The window's nodes are not all in the tree, so build the counts directly.
  context.categoryCounts = new Map([["auth-bypass", 4], ["idor", 2]]);
  const vetoes = violations(snap.byId.get("H-0001")!, context);
  assert.ok(vetoes.some((v) => v.constraint === "max-category-ratio"), JSON.stringify(vetoes));
});

test("the category cap is not applied to a window shorter than the minimum", () => {
  const cwd = seeded();
  const snap = load(cwd).snapshot;
  const context = buildContext({ ...snap, selections: [sel("H-0001", 1), sel("H-0001", 2)] }, 3);
  context.categoryCounts = new Map([["auth-bypass", 2]]);
  assert.ok(
    !violations(snap.byId.get("H-0001")!, context).some((v) => v.constraint === "max-category-ratio"),
    "one pick is always 100% of its own category; applying the cap that early would refuse to start",
  );
});

// -----------------------------------------------------------------
// Planning
// -----------------------------------------------------------------

test("no tree → nothing scheduled, with an actionable reason", () => {
  const decision = planNextRound(load(tmpProject()).snapshot);
  assert.equal(decision.selected, null);
  assert.match(decision.reasons[0]!, /No hypothesis tree/);
  assert.equal(decision.candidates, 0);
});

test("all verdicts → nothing scheduled, and the reason names the next move", () => {
  const cwd = seeded();
  setStatus(cwd, "H-0001", "rejected", { evidence: [{ kind: "code-slice", at: "", detail: "verify() is called" }] });
  const decision = planNextRound(load(cwd).snapshot);
  assert.equal(decision.selected, null);
  assert.match(decision.reasons[0]!, /No open hypotheses/);
  assert.match(decision.reasons[0]!, /combine the confirmed findings/);
});

test("the first round picks the shallowest unexamined node", () => {
  const cwd = seeded();
  add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  const decision = planNextRound(load(cwd).snapshot);
  assert.equal(decision.selected?.id, "H-0001");
  assert.equal(decision.candidates, 2);
});

test("the decision is deterministic — same snapshot, same round, same pick", () => {
  const cwd = seeded();
  add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  add(cwd, "the token expiry is never compared against the current time", "auth-bypass");
  const snap = load(cwd).snapshot;
  const a = planNextRound(snap, { round: 1 });
  const b = planNextRound(snap, { round: 1 });
  assert.equal(a.selected?.id, b.selected?.id);
  assert.deepEqual(a.ranked, b.ranked);
});

test("the reason block states the score breakdown, the runs, and the window", () => {
  const cwd = seeded();
  add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  const decision = planNextRound(load(cwd).snapshot, { round: 1 });
  const text = decision.reasons.join("\n");
  assert.match(text, /round 1: selected H-0001/);
  assert.match(text, /score: novelty .* evidence .* diversity .* testing/);
  assert.match(text, /runs: same-node 0\/2, descent 0\/3/);
  assert.match(text, /no candidate was vetoed/);
});

// -----------------------------------------------------------------
// The emergent property — the whole point
// -----------------------------------------------------------------

test("simulated rounds do NOT tunnel: a straight chain is never walked past the limit", () => {
  const cwd = seeded();
  // A deliberately tunnel-shaped tree: one long chain plus one sibling.
  let parent = "H-0001";
  for (let i = 0; i < 8; i++) {
    const child = add(cwd, `chain level ${i} does not validate the audience claim at all`, "auth-bypass", parent);
    parent = child.id;
  }
  const sibling = add(cwd, "the export endpoint returns records the caller does not own", "idor");

  const picked: string[] = [];
  for (let round = 1; round <= 10; round++) {
    const snapshot = load(cwd).snapshot;
    const decision = planNextRound(snapshot, { round });
    if (!decision.selected) break;
    picked.push(decision.selected.id);
    const applied = applySelection(cwd, decision);
    assert.equal(applied.ok, true, applied.errors.join("; "));
  }

  assert.equal(picked.length, 10, "ten rounds must all schedule something");

  // The chain has 9 nodes (H-0001..H-0009). If the scheduler tunnelled it would
  // be a prefix of the chain; assert that it never descends more than the limit
  // without a lateral move.
  const snap = load(cwd).snapshot;
  let maxConsecutiveDescent = 0;
  let run = 0;
  for (let i = 1; i < picked.length; i++) {
    const prev = snap.byId.get(picked[i - 1]!)!;
    const cur = snap.byId.get(picked[i]!)!;
    const descended = cur.depth > prev.depth && isUnder(snap, cur.id, prev.id);
    run = descended ? run + 1 : 0;
    maxConsecutiveDescent = Math.max(maxConsecutiveDescent, run);
  }
  assert.ok(
    maxConsecutiveDescent <= SCHEDULER_LIMITS.MAX_CONSECUTIVE_DEPTH,
    `never descends more than ${SCHEDULER_LIMITS.MAX_CONSECUTIVE_DEPTH} levels consecutively; observed ${maxConsecutiveDescent} in ${picked.join(" -> ")}`,
  );
  // And the sibling category was actually visited, not ignored.
  assert.ok(picked.includes(sibling.id), `the idor branch was visited: ${picked.join(" -> ")}`);
});

test("simulated rounds do not grind one node: no node takes three rounds in a row", () => {
  const cwd = seeded();
  add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  add(cwd, "the token expiry is never compared against the current time", "auth-bypass");

  const picked: string[] = [];
  for (let round = 1; round <= 8; round++) {
    const decision = planNextRound(load(cwd).snapshot, { round });
    if (!decision.selected) break;
    picked.push(decision.selected.id);
    assert.equal(applySelection(cwd, decision).ok, true);
  }
  let run = 0;
  let maxRun = 0;
  for (let i = 0; i < picked.length; i++) {
    run = i > 0 && picked[i] === picked[i - 1] ? run + 1 : 1;
    maxRun = Math.max(maxRun, run);
  }
  assert.ok(maxRun <= SCHEDULER_LIMITS.MAX_SAME_NODE_ROUNDS, `max same-node run ${maxRun} in ${picked.join(" -> ")}`);
});

function isUnder(snapshot: ReturnType<typeof load>["snapshot"], candidateId: string, ancestorId: string): boolean {
  let current: string | null = candidateId;
  const seen = new Set<string>();
  while (current) {
    if (seen.has(current)) return false;
    seen.add(current);
    const node: Hypothesis | undefined = snapshot.byId.get(current);
    if (!node) return false;
    if (node.parentId === ancestorId) return true;
    current = node.parentId;
  }
  return false;
}

// -----------------------------------------------------------------
// Relaxation — never deadlock, never silent
// -----------------------------------------------------------------

test("when every open node is one category the cap is RELAXED, not deadlocked", () => {
  const cwd = seeded();
  // Nine more auth-bypass nodes and nothing else: the 40% cap is unsatisfiable.
  for (let i = 0; i < 9; i++) {
    add(cwd, `auth-bypass hypothesis number ${i} about the token handling path`, "auth-bypass");
  }
  const picked: string[] = [];
  for (let round = 1; round <= 6; round++) {
    const decision = planNextRound(load(cwd).snapshot, { round });
    assert.ok(decision.selected, `round ${round} must still schedule something (no deadlock)`);
    picked.push(decision.selected!.id);
    assert.equal(applySelection(cwd, decision).ok, true);
  }
  // By round 4 the cap must have become unsatisfiable and been recorded.
  const history = load(cwd).snapshot.selections;
  const relaxedRounds = history.filter((h) => h.relaxations.some((r) => r.startsWith("max-category-ratio")));
  assert.ok(relaxedRounds.length > 0, `the cap was relaxed and recorded: ${JSON.stringify(history.map((h) => h.relaxations))}`);
  const decision = planNextRound(load(cwd).snapshot, { round: 20 });
  assert.match(decision.reasons.join("\n"), /RELAXED max-category-ratio/);
  assert.match(decision.reasons.join("\n"), /the TREE is skewed/);
});

test("a relaxed round says which limit was dropped and why", () => {
  const cwd = seeded();
  for (let i = 0; i < 5; i++) add(cwd, `auth-bypass hypothesis number ${i} about the token handling path`, "auth-bypass");
  for (let round = 1; round <= 5; round++) {
    const decision = planNextRound(load(cwd).snapshot, { round });
    assert.equal(applySelection(cwd, decision).ok, true);
  }
  const decision = planNextRound(load(cwd).snapshot, { round: 6 });
  if (decision.relaxations.length > 0) {
    assert.match(decision.relaxations[0]!, /^max-[a-z-]+: no candidate satisfied it \(\d+ open hypothesis\(es\) considered\)$/);
  } else {
    // If nothing needed relaxing, the limits must have held — assert that too.
    assert.equal(decision.vetoes.filter((v) => v.constraint === "max-category-ratio").length > 0, true);
  }
});

test("population skew is reported even when the current pick is fine", () => {
  const cwd = seeded();
  for (let i = 0; i < 9; i++) add(cwd, `auth-bypass hypothesis number ${i} about the token handling path`, "auth-bypass");
  add(cwd, "the export endpoint returns records the caller does not own", "idor");
  const skew = populationSkew(load(cwd).snapshot);
  assert.equal(skew.length, 1);
  assert.match(skew[0]!, /auth-bypass" is \d+% of the 11 open hypotheses/);
  assert.match(planNextRound(load(cwd).snapshot, { round: 1 }).reasons.join("\n"), /SKEW WARNING/);
});

test("no skew is reported for a balanced tree", () => {
  const cwd = seeded();
  add(cwd, "the export endpoint returns records the caller does not own", "idor");
  add(cwd, "the webhook fetcher follows redirects to internal addresses", "ssrf");
  assert.deepEqual(populationSkew(load(cwd).snapshot), []);
});

// -----------------------------------------------------------------
// Persistence
// -----------------------------------------------------------------

test("applySelection records the round, the counters and the in-flight status", () => {
  const cwd = seeded();
  const decision = planNextRound(load(cwd).snapshot, { round: 1 });
  const applied = applySelection(cwd, decision);
  assert.equal(applied.ok, true);

  const snap = load(cwd).snapshot;
  assert.equal(snap.rounds, 1);
  assert.equal(snap.selections.length, 1);
  const node = getNode(snap, "H-0001")!;
  assert.equal(node.timesSelected, 1);
  assert.equal(node.lastSelectedRound, 1);
  assert.equal(node.status, "testing", "selecting a hypothesis IS starting to examine it");
  assert.equal(node.score, decision.breakdown!.total);
});

test("the recorded selection carries the full rationale for review", () => {
  const cwd = seeded();
  applySelection(cwd, planNextRound(load(cwd).snapshot, { round: 1 }));
  const record = load(cwd).snapshot.selections[0]!;
  assert.equal(record.round, 1);
  assert.equal(record.nodeId, "H-0001");
  assert.ok(record.reasons.length >= 3);
  assert.equal(typeof record.breakdown.total, "number");
  assert.equal(record.candidates, 1);
  assert.deepEqual(record.relaxations, []);
});

test("applySelection refuses a decision with nothing selected", () => {
  const cwd = tmpProject();
  const applied = applySelection(cwd, planNextRound(load(cwd).snapshot));
  assert.equal(applied.ok, false);
  assert.match(applied.errors[0]!, /nothing was scheduled/);
  assert.equal(load(cwd).snapshot.selections.length, 0, "nothing was written");
});

test("the selection history survives a compaction snapshot", () => {
  const cwd = seeded();
  add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  for (let round = 1; round <= 4; round++) {
    const decision = planNextRound(load(cwd).snapshot, { round });
    assert.equal(applySelection(cwd, decision).ok, true);
  }
  assert.equal(load(cwd).snapshot.selections.length, 4);
  assert.equal(compact(cwd), true);
  const after = load(cwd).snapshot;
  assert.equal(after.selections.length, 4, "compaction must not lose the history the scheduler depends on");
  assert.equal(after.compactions, 1);
  // And the counters on the node are intact too.
  assert.ok(after.byId.get("H-0001")!.timesSelected >= 1);
});

test("per-node counters survive compaction so novelty cannot be re-awarded", () => {
  const cwd = seeded();
  for (let round = 1; round <= 4; round++) {
    const decision = planNextRound(load(cwd).snapshot, { round });
    assert.equal(applySelection(cwd, decision).ok, true);
  }
  const before = getNode(load(cwd).snapshot, "H-0001")!;
  compact(cwd);
  const after = getNode(load(cwd).snapshot, "H-0001")!;
  assert.equal(after.timesSelected, before.timesSelected);
  assert.equal(after.lastSelectedRound, before.lastSelectedRound);
  assert.ok(after.timesSelected > 0, "the counter must be non-zero or novelty resets after every compaction");
});

// -----------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------

test("renderDecision includes the ranking with the winner marked and vetoes named", () => {
  const cwd = seeded();
  add(cwd, "the signature is checked but the algorithm comes from the token header", "auth-bypass");
  add(cwd, "the token expiry is never compared against the current time", "auth-bypass");
  const decision = planNextRound(load(cwd).snapshot, { round: 1 });
  const text = renderDecision(decision).join("\n");
  assert.match(text, /ranking \(3\):/);
  assert.match(text, /-> H-0001/);
});

test("renderDecision on an unschedulable round explains instead of printing an empty list", () => {
  const text = renderDecision(planNextRound(load(tmpProject()).snapshot)).join("\n");
  assert.match(text, /No hypothesis tree/);
});
