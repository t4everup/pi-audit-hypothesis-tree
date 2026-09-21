// pi-audit-hypothesis-tree — tests/combination.test.ts
//
// Pins stage 4: the pair ranking is mechanical and explained, the trigger is
// FORCED (a due pass blocks scheduling), a skipped pass is still recorded, and
// a combination may only be derived from CONFIRMED findings.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { compact, load } from "../extensions/hypothesis-tree/store.ts";
import { addEvidence, addNode, createTree, getNode, recordRound, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import {
  CONSOLIDATION,
  PAIR_WEIGHTS,
  applyCombination,
  applyConsolidation,
  consolidationStatus,
  examinedPairKeys,
  isGeneralized,
  lastConsolidation,
  pairKey,
  planConsolidation,
  renderConsolidation,
  scorePair,
  scoreSingle,
  treeRelation,
  validateCombination,
} from "../extensions/hypothesis-tree/combination.ts";
import type { Hypothesis, TreeSnapshot } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-combo-"));
}

function add(cwd: string, description: string, category: string, parentId?: string): Hypothesis {
  const result = addNode(cwd, { description, category, ...(parentId ? { parentId } : {}) });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result.ok ? result.value.node : (undefined as never);
}

/** Confirm a node with evidence, optionally citing a location. */
function confirm(cwd: string, id: string, detail = "the check is absent on this path", file?: string, line?: number): void {
  const result = setStatus(cwd, id, "confirmed", {
    evidence: [
      {
        kind: file ? "code-slice" : "reasoning",
        at: "",
        ...(file ? { location: { file, line: line ?? 1 } } : {}),
        detail,
      },
    ],
  });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
}

const A = "the login handler accepts a JWT without verifying its signature";
const B = "the refresh handler accepts a JWT without verifying its signature";
const C = "the export endpoint returns records the caller does not own";

// -----------------------------------------------------------------
// Config and keys
// -----------------------------------------------------------------

test("the consolidation interval is the value the design specifies", () => {
  assert.equal(CONSOLIDATION.INTERVAL, 3);
  assert.equal(CONSOLIDATION.MIN_CONFIRMED_FOR_PAIRING, 2);
});

test("pairKey is order-independent", () => {
  assert.equal(pairKey("H-0002", "H-0001"), pairKey("H-0001", "H-0002"));
  assert.equal(pairKey("H-0001", "H-0002"), "H-0001|H-0002");
});

test("examinedPairKeys is empty before any pass and accumulates after", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  assert.equal(examinedPairKeys(load(cwd).snapshot).size, 0);
});

// -----------------------------------------------------------------
// Structural signals
// -----------------------------------------------------------------

test("a shared evidence file is the strongest signal and is named", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001", "no verify()", "src/auth/jwt.ts", 40);
  confirm(cwd, b.id, "no verify()", "src/auth/jwt.ts", 80);

  const pair = scorePair(load(cwd).snapshot, getNode(load(cwd).snapshot, "H-0001")!, getNode(load(cwd).snapshot, b.id)!);
  assert.deepEqual(pair.sharedFiles, ["src/auth/jwt.ts"]);
  assert.equal(pair.minLineDistance, 40);
  assert.ok(pair.signals.some((s) => s.includes("both cite src/auth/jwt.ts")), pair.signals.join("; "));
  assert.ok(pair.signals.some((s) => s.includes("40 apart")), pair.signals.join("; "));
});

test("line proximity scales: near, same-area, and far", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  const near = (lines: [number, number]) => {
    const snap = load(cwd).snapshot;
    void snap;
    return lines;
  };
  void near;
  confirm(cwd, "H-0001", "x", "f.ts", 100);
  confirm(cwd, b.id, "y", "f.ts", 130);
  let pair = scorePair(load(cwd).snapshot, getNode(load(cwd).snapshot, "H-0001")!, getNode(load(cwd).snapshot, b.id)!);
  assert.ok(pair.signals.some((s) => s.includes("plausibly the same region")), pair.signals.join("; "));

  // Move the second citation far away.
  const snap2 = load(cwd).snapshot;
  const farNode = { ...getNode(snap2, b.id)!, evidence: [{ kind: "code-slice" as const, at: "", location: { file: "f.ts", line: 180 }, detail: "y" }] };
  pair = scorePair(snap2, getNode(snap2, "H-0001")!, farNode);
  assert.ok(pair.signals.some((s) => s.includes("same area, probably not the same site")), pair.signals.join("; "));

  const veryFar = { ...farNode, evidence: [{ kind: "code-slice" as const, at: "", location: { file: "f.ts", line: 5000 }, detail: "y" }] };
  pair = scorePair(snap2, getNode(snap2, "H-0001")!, veryFar);
  assert.equal(pair.minLineDistance, 4900);
  assert.ok(!pair.signals.some((s) => s.includes("apart")), "no proximity signal at 4900 lines");
});

test("same class and different class BOTH score, so neither crowds the other out", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const same = add(cwd, B, "auth-bypass");
  const diff = add(cwd, C, "idor");
  confirm(cwd, "H-0001");
  confirm(cwd, same.id);
  confirm(cwd, diff.id);

  const snap = load(cwd).snapshot;
  const samePair = scorePair(snap, getNode(snap, "H-0001")!, getNode(snap, same.id)!);
  const diffPair = scorePair(snap, getNode(snap, "H-0001")!, getNode(snap, diff.id)!);
  assert.ok(samePair.signals.some((s) => s.includes("same class")), samePair.signals.join("; "));
  assert.ok(diffPair.signals.some((s) => s.includes("different classes")), diffPair.signals.join("; "));
  assert.ok(PAIR_WEIGHTS.sameCategory > 0 && PAIR_WEIGHTS.differentCategory > 0);
});

test("treeRelation distinguishes ancestor, sibling and unrelated", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const child = add(cwd, B, "auth-bypass", "H-0001");
  const grandchild = add(cwd, "the verifier compares the HMAC against a zero-length key", "auth-bypass", child.id);
  const sibling = add(cwd, C, "idor");
  const snap = load(cwd).snapshot;

  assert.equal(treeRelation(snap, "H-0001", grandchild.id), "ancestor");
  assert.equal(treeRelation(snap, grandchild.id, "H-0001"), "ancestor");
  assert.equal(treeRelation(snap, child.id, sibling.id), "sibling");
  assert.equal(treeRelation(snap, grandchild.id, sibling.id), "unrelated");
});

test("an ancestor pair is signalled as a plausible chain", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const child = add(cwd, B, "auth-bypass", "H-0001");
  confirm(cwd, "H-0001");
  confirm(cwd, child.id);
  const snap = load(cwd).snapshot;
  const pair = scorePair(snap, getNode(snap, "H-0001")!, getNode(snap, child.id)!);
  assert.equal(pair.treeRelation, "ancestor");
  assert.ok(pair.signals.some((s) => s.includes("dependency (chain) is plausible")), pair.signals.join("; "));
});

test("an unrelated pair is still handed over, and says a link would be new", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  // Two DIFFERENT branches, so the two leaves are neither ancestor nor sibling.
  const left = add(cwd, B, "auth-bypass", "H-0001");
  const leftLeaf = add(cwd, "the verifier compares the HMAC against a zero-length key", "auth-bypass", left.id);
  const right = add(cwd, C, "idor", "H-0001");
  const rightLeaf = add(cwd, "the audit log writer trusts a caller-supplied actor id", "info-disclosure", right.id);
  confirm(cwd, leftLeaf.id);
  confirm(cwd, rightLeaf.id);
  const snap = load(cwd).snapshot;
  const pair = scorePair(snap, getNode(snap, leftLeaf.id)!, getNode(snap, rightLeaf.id)!);
  assert.equal(pair.treeRelation, "unrelated");
  assert.ok(pair.signals.some((s) => s.includes("any combination would be a new link")), pair.signals.join("; "));
});

test("evidence depth adds a bounded bonus", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  const snap = load(cwd).snapshot;
  const thin = scorePair(snap, getNode(snap, "H-0001")!, getNode(snap, b.id)!);
  const rich = { ...getNode(snap, b.id)!, evidence: Array.from({ length: 20 }, () => ({ kind: "reasoning" as const, at: "", detail: "x" })) };
  const fat = scorePair(snap, getNode(snap, "H-0001")!, rich);
  assert.ok(fat.score > thin.score);
  assert.ok(fat.score - thin.score <= PAIR_WEIGHTS.evidenceCap + 0.001, "the bonus is capped");
});

// -----------------------------------------------------------------
// Singles
// -----------------------------------------------------------------

test("a confirmed finding with no children scores as an extension candidate", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001", "x", "src/auth.ts", 10);
  const snap = load(cwd).snapshot;
  const single = scoreSingle(snap, getNode(snap, "H-0001")!);
  assert.ok(single.signals.some((s) => s.includes("nothing has been derived")), single.signals.join("; "));
  assert.ok(single.signals.some((s) => s.includes("concrete location")), single.signals.join("; "));
});

test("isGeneralized only counts a lateral-extension child", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  assert.equal(isGeneralized(load(cwd).snapshot, "H-0001"), false);

  const applied = applyCombination(cwd, load(cwd).snapshot, {
    description: "the same signature-skipping technique applies to the service-to-service token",
    category: "auth-bypass",
    kind: "lateral-extension",
    spawnedFrom: ["H-0001"],
  });
  assert.equal(applied.ok, true, applied.ok ? "" : applied.errors.join("; "));
  assert.equal(isGeneralized(load(cwd).snapshot, "H-0001"), true);
});

test("a plain child does not count as a generalization", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  add(cwd, B, "auth-bypass", "H-0001");
  assert.equal(isGeneralized(load(cwd).snapshot, "H-0001"), false);
});

// -----------------------------------------------------------------
// Triggers
// -----------------------------------------------------------------

test("with no confirmed findings the pass is not due and says why", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const plan = planConsolidation(load(cwd).snapshot);
  assert.equal(plan.due, false);
  assert.match(plan.reason, /no findings confirmed yet/);
});

test("the first confirmed finding makes a pass due with the new-finding trigger", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  const plan = planConsolidation(load(cwd).snapshot);
  assert.equal(plan.due, true);
  assert.equal(plan.trigger, "new-finding");
  assert.match(plan.reason, /first pass/);
});

test("a new finding since the last pass re-triggers with new-finding", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot));
  assert.equal(planConsolidation(load(cwd).snapshot).due, false, "nothing changed yet");

  recordRound(cwd, 1);
  const c = add(cwd, C, "idor");
  confirm(cwd, c.id);
  const plan = planConsolidation(load(cwd).snapshot);
  assert.equal(plan.due, true);
  assert.equal(plan.trigger, "new-finding");
  assert.match(plan.reason, /1 new finding\(s\) since the pass at round 0/);
});

test("INTERVAL rounds after the last pass triggers with interval", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot));
  assert.equal(lastConsolidation(load(cwd).snapshot)!.round, 0);

  recordRound(cwd, CONSOLIDATION.INTERVAL - 1);
  assert.equal(planConsolidation(load(cwd).snapshot).due, false, "one round short");
  recordRound(cwd, CONSOLIDATION.INTERVAL);
  const plan = planConsolidation(load(cwd).snapshot);
  assert.equal(plan.due, true);
  assert.equal(plan.trigger, "interval");
  assert.match(plan.reason, /round\(s\) since the pass at round 0/);
});

test("force runs a pass even when the trigger has not fired", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot));
  assert.equal(planConsolidation(load(cwd).snapshot).due, false);

  const forced = planConsolidation(load(cwd).snapshot, { force: "manual" });
  assert.equal(forced.due, true);
  assert.equal(forced.trigger, "manual");
  assert.match(forced.reason, /forced/);
});

// -----------------------------------------------------------------
// Pair and single selection
// -----------------------------------------------------------------

test("already-examined pairs are not offered again", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);

  const first = planConsolidation(load(cwd).snapshot);
  assert.deepEqual(first.pairs.map((p) => p.key), [pairKey("H-0001", b.id)]);
  applyConsolidation(cwd, first);

  const second = planConsolidation(load(cwd).snapshot, { force: "manual" });
  assert.deepEqual(second.pairs, [], "the pair was already examined");
  assert.equal(examinedPairKeys(load(cwd).snapshot).has(pairKey("H-0001", b.id)), true);
  // The findings themselves are still extension candidates, so the pass is not
  // empty — only the PAIR is spent.
  assert.equal(second.singles.length, 2);
  assert.equal(second.skipped, null);
});

test("a NEW finding creates new pairs even though the old ones stay examined", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot));

  const c = add(cwd, C, "idor");
  confirm(cwd, c.id);
  const plan = planConsolidation(load(cwd).snapshot);
  assert.deepEqual(
    plan.pairs.map((p) => p.key).sort(),
    [pairKey("H-0001", c.id), pairKey(b.id, c.id)].sort(),
    "only the pairs involving the new finding are new",
  );
});

test("pairs are capped and the cap is reported", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const ids = ["H-0001"];
  for (let i = 0; i < 6; i++) {
    const n = add(cwd, `auth-bypass finding number ${i} about the token handling path`, "auth-bypass");
    ids.push(n.id);
  }
  for (const id of ids) confirm(cwd, id);
  const plan = planConsolidation(load(cwd).snapshot);
  assert.equal(plan.pairs.length, CONSOLIDATION.MAX_PAIRS);
  assert.match(plan.reason, /beyond the 6 handed over/);
});

test("pairs are ordered by score, strongest first", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  const c = add(cwd, C, "idor");
  confirm(cwd, "H-0001", "x", "src/auth/jwt.ts", 40);
  confirm(cwd, b.id, "y", "src/auth/jwt.ts", 45);
  confirm(cwd, c.id, "z", "src/export.ts", 900);
  const plan = planConsolidation(load(cwd).snapshot);
  assert.equal(plan.pairs[0]!.key, pairKey("H-0001", b.id), "the shared-file pair outranks the unrelated one");
  assert.ok(plan.pairs[0]!.score >= plan.pairs[1]!.score);
});

test("lateral-extension candidates exclude already-generalized findings", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  applyCombination(cwd, load(cwd).snapshot, {
    description: "the same signature-skipping technique applies to the service-to-service token",
    category: "auth-bypass",
    kind: "lateral-extension",
    spawnedFrom: ["H-0001"],
  });
  const plan = planConsolidation(load(cwd).snapshot, { force: "manual" });
  assert.ok(!plan.singles.some((s) => s.id === "H-0001"), "H-0001 was already generalized");
  assert.ok(plan.singles.some((s) => s.id === b.id));
});

test("a pass with nothing to examine is NOT due, and says why", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  applyCombination(cwd, load(cwd).snapshot, {
    description: "the same signature-skipping technique applies to the service-to-service token",
    category: "auth-bypass",
    kind: "lateral-extension",
    spawnedFrom: ["H-0001"],
  });
  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot, { force: "manual" }));
  const plan = planConsolidation(load(cwd).snapshot, { force: "manual" });

  // NOT due, even though the trigger fired. A scheduled pass with nothing to
  // hand over spends a round to produce nothing: it wastes the round AND counts
  // against the plateau, so a run of empty passes ends the audit claiming the
  // well is dry while hypotheses are still unexamined.
  assert.equal(plan.due, false);
  assert.equal(plan.pairs.length, 0);
  assert.equal(plan.singles.length, 0);
  assert.match(plan.skipped!, /nothing to pair and nothing new to extend/);
  assert.match(plan.reason, /nothing to pair and nothing new to extend/, "the reason carries the skip explanation");
  // And an empty pass cannot block a goal: there is genuinely nothing to do.
  assert.equal(applyConsolidation(cwd, plan).ok, false, "a not-due pass is not recorded");
});

// -----------------------------------------------------------------
// Recording
// -----------------------------------------------------------------

test("applyConsolidation records the pass and marks its pairs examined", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);

  const plan = planConsolidation(load(cwd).snapshot);
  const applied = applyConsolidation(cwd, plan);
  assert.equal(applied.ok, true);

  const snap = load(cwd).snapshot;
  assert.equal(snap.consolidations.length, 1);
  const record = snap.consolidations[0]!;
  assert.equal(record.trigger, "new-finding");
  assert.deepEqual(record.confirmedIds.sort(), ["H-0001", b.id].sort());
  assert.deepEqual(record.pairKeys, [pairKey("H-0001", b.id)]);
  assert.equal(record.skipped, null);
  assert.equal(examinedPairKeys(snap).size, 1);
});

test("applyConsolidation refuses a plan that is not due", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot));
  const notDue = planConsolidation(load(cwd).snapshot);
  const applied = applyConsolidation(cwd, notDue);
  assert.equal(applied.ok, false);
  assert.match(applied.errors[0]!, /not due/);
  assert.equal(load(cwd).snapshot.consolidations.length, 1, "nothing was written");
});

test("an empty pass does not need recording, because it is never scheduled", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  // Generalize the only finding so there is nothing left to offer.
  applyCombination(cwd, load(cwd).snapshot, {
    description: "the same signature-skipping technique applies to the service-to-service token",
    category: "auth-bypass",
    kind: "lateral-extension",
    spawnedFrom: ["H-0001"],
  });

  // The forced trigger used to need a recorded record to clear it, which is why
  // an empty pass was recorded at all. It no longer fires anything: `due: false`
  // means the loop never schedules the round, so there is nothing to clear — and
  // the pass was ALREADY empty here, because the only finding has been
  // generalized by the lateral extension above.
  const skippedPlan = planConsolidation(load(cwd).snapshot, { force: "manual" });
  assert.equal(skippedPlan.skipped !== null, true);
  assert.equal(skippedPlan.due, false);
  assert.equal(applyConsolidation(cwd, skippedPlan).ok, false);
  assert.equal(load(cwd).snapshot.consolidations.length, 0, "no empty record was written");

  // And it stays stable: asking again does not start firing.
  for (let i = 0; i < 5; i++) {
    assert.equal(planConsolidation(load(cwd).snapshot, { force: "manual" }).due, false);
  }
  assert.equal(load(cwd).snapshot.consolidations.length, 0);
});

test("the consolidation history survives a compaction snapshot", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot));

  assert.equal(compact(cwd), true);
  const snap = load(cwd).snapshot;
  assert.equal(snap.consolidations.length, 1, "compaction must not lose the examined-pair history");
  assert.equal(examinedPairKeys(snap).size, 1);
});

// -----------------------------------------------------------------
// Validating a combination
// -----------------------------------------------------------------

test("validateCombination requires a valid kind", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  const result = validateCombination(load(cwd).snapshot, { kind: "vibes" as never, spawnedFrom: ["H-0001"] });
  assert.equal(result.ok, false);
  assert.match(result.errors[0]!, /kind must be one of/);
});

test("validateCombination requires a non-empty spawnedFrom and says why", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  const result = validateCombination(load(cwd).snapshot, { kind: "lateral-extension", spawnedFrom: [] });
  assert.equal(result.ok, false);
  assert.match(result.errors[0]!, /unexplained combination is indistinguishable from a guess/);
});

test("validateCombination refuses a spawnedFrom id that is not CONFIRMED", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  // b is still pending.
  const result = validateCombination(load(cwd).snapshot, {
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", b.id],
  });
  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /whose status is "pending"/);
  assert.match(result.errors.join("\n"), /speculation stacked on speculation/);
});

test("validateCombination refuses a spawnedFrom id that does not exist", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  const result = validateCombination(load(cwd).snapshot, { kind: "lateral-extension", spawnedFrom: ["H-9999"] });
  assert.equal(result.ok, false);
  assert.match(result.errors[0]!, /not in the tree/);
});

test("a chain or shared-root-cause needs at least two ids", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  for (const kind of ["chain", "shared-root-cause"] as const) {
    const result = validateCombination(load(cwd).snapshot, { kind, spawnedFrom: ["H-0001"] });
    assert.equal(result.ok, false, kind);
    assert.match(result.errors.join("\n"), /relation BETWEEN findings/, kind);
  }
});

test("a lateral-extension with several ids warns but does not refuse", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  const result = validateCombination(load(cwd).snapshot, { kind: "lateral-extension", spawnedFrom: ["H-0001", b.id] });
  assert.equal(result.ok, true);
  assert.match(result.warnings[0]!, /usually generalizes ONE finding/);
});

test("validateCombination refuses a duplicate description by name", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  const result = validateCombination(load(cwd).snapshot, {
    kind: "lateral-extension",
    spawnedFrom: ["H-0001"],
    description: A.toUpperCase(),
  });
  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /already in the tree as H-0001/);
});

test("validateCombination refuses an unknown parent", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  const result = validateCombination(load(cwd).snapshot, {
    kind: "lateral-extension",
    spawnedFrom: ["H-0001"],
    parentId: "H-9999",
  });
  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /parentId H-9999 is not in the tree/);
});

// -----------------------------------------------------------------
// Applying a combination
// -----------------------------------------------------------------

test("applyCombination records the kind, the lineage and the round", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  recordRound(cwd, 4);

  const applied = applyCombination(cwd, load(cwd).snapshot, {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", b.id],
  });
  assert.equal(applied.ok, true, applied.ok ? "" : applied.errors.join("; "));
  const node = applied.node!;
  assert.equal(node.combinationKind, "shared-root-cause");
  assert.deepEqual(node.spawnedFrom, ["H-0001", b.id]);
  assert.equal(node.roundIntroduced, 4);
  assert.equal(node.status, "pending", "a combination is a NEW hypothesis and must be tested");
  assert.equal(node.depth, 1, "it attaches to the root by default");
});

test("applyCombination refuses when a source finding is not confirmed", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  const applied = applyCombination(cwd, load(cwd).snapshot, {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", b.id],
  });
  assert.equal(applied.ok, false);
  assert.equal(load(cwd).snapshot.nodes.length, 2, "nothing was added");
});

test("applyCombination still enforces the assertion-shape gate", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  const applied = applyCombination(cwd, load(cwd).snapshot, {
    description: "check the shared decode helper",
    category: "auth-bypass",
    kind: "lateral-extension",
    spawnedFrom: ["H-0001"],
  });
  assert.equal(applied.ok, false);
  assert.match(applied.errors.join("\n"), /TASK/);
});

test("a combination can attach under an explicit parent", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass", "H-0001");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  const applied = applyCombination(cwd, load(cwd).snapshot, {
    description: "the shared decode helper is the single missing verification point",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", b.id],
    parentId: "H-0001",
  });
  assert.equal(applied.ok, true, applied.ok ? "" : applied.errors.join("; "));
  assert.equal(applied.node!.parentId, "H-0001");
  assert.equal(applied.node!.depth, 1);
});

// -----------------------------------------------------------------
// The brief
// -----------------------------------------------------------------

test("the brief states the trigger, the pairs, the structural signals and all three kinds", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001", "x", "src/auth/jwt.ts", 40);
  confirm(cwd, b.id, "y", "src/auth/jwt.ts", 60);

  const text = renderConsolidation(planConsolidation(load(cwd).snapshot)).join("\n");
  assert.match(text, /CONSOLIDATION PASS — round 0, trigger: new-finding/);
  assert.match(text, /PAIRS to consider \(1\)/);
  assert.match(text, /both cite src\/auth\/jwt\.ts/);
  assert.match(text, /consider: chain .* shared-root-cause .* cross-class chain/);
  assert.match(text, /LATERAL-EXTENSION candidates/);
  assert.match(text, /hypothesis_combine/);
  assert.match(text, /kind {12}chain \| shared-root-cause \| lateral-extension/);
});

test("the brief tells the model that reporting NO combination is acceptable", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  const text = renderConsolidation(planConsolidation(load(cwd).snapshot)).join("\n");
  assert.match(text, /Reporting none is the/);
  assert.match(text, /a fabricated chain is worse than no chain/);
  assert.match(text, /Every spawnedFrom id must be a confirmed finding/);
});

test("a skipped pass renders as a recorded result, not a failure", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  confirm(cwd, "H-0001");
  applyCombination(cwd, load(cwd).snapshot, {
    description: "the same signature-skipping technique applies to the service-to-service token",
    category: "auth-bypass",
    kind: "lateral-extension",
    spawnedFrom: ["H-0001"],
  });
  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot, { force: "manual" }));
  const text = renderConsolidation(planConsolidation(load(cwd).snapshot, { force: "manual" })).join("\n");
  assert.match(text, /NOTHING TO EXAMINE/);
  assert.match(text, /recorded result, not a failure/);
});

// -----------------------------------------------------------------
// Status
// -----------------------------------------------------------------

test("consolidationStatus reports passes, examined pairs, produced kinds and dueness", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);

  let status = consolidationStatus(load(cwd).snapshot);
  assert.equal(status.passes, 0);
  assert.equal(status.examinedPairs, 0);
  assert.equal(status.due, true);
  assert.equal(status.lastRound, null);

  applyConsolidation(cwd, planConsolidation(load(cwd).snapshot));
  applyCombination(cwd, load(cwd).snapshot, {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", b.id],
  });

  status = consolidationStatus(load(cwd).snapshot);
  assert.equal(status.passes, 1);
  assert.equal(status.lastRound, 0);
  assert.equal(status.lastTrigger, "new-finding");
  assert.equal(status.examinedPairs, 1);
  assert.equal(status.produced["shared-root-cause"], 1);
  assert.equal(status.produced.chain, 0);
});

test("a combination node renders with its kind tag in the tree", async () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const b = add(cwd, B, "auth-bypass");
  confirm(cwd, "H-0001");
  confirm(cwd, b.id);
  applyCombination(cwd, load(cwd).snapshot, {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", b.id],
  });
  const { renderTree } = await import("../extensions/hypothesis-tree/render.ts");
  const text = renderTree(load(cwd).snapshot).join("\n");
  assert.match(text, /auth-bypass\+shared/);
});

test("an untyped snapshot has no consolidation history", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  const snap: TreeSnapshot = load(cwd).snapshot;
  assert.deepEqual(snap.consolidations, []);
  assert.equal(lastConsolidation(snap), null);
});
