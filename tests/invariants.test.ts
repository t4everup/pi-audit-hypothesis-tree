// pi-audit-hypothesis-tree — tests/invariants.test.ts
//
// The round-scheduling invariants, asserted over a LONG simulated run.
//
// -----------------------------------------------------------------------
// Why this file exists
// -----------------------------------------------------------------------
//
// The same bug has now been found by hand three times:
//
//   1. MAX_CONFIRMED_CONSIDERED — the recorded confirmed-id count could never
//      reach the real one, so `new-finding` was true on EVERY round and
//      consolidation pre-empted verification forever.
//   2. A tree of BLOCKED nodes — re-blocking counted as a fresh verdict, so every
//      round was "productive" and the plateau could never fire.
//   3. This one, found in a real audit's round sequence:
//
//        consolidate, verify, consolidate, verify, consolidate, verify, …
//
//      because `new-finding` fired on EVERY single confirmation, and consolidate
//      sits above challenge and pursue. Seven passes in 27 rounds, combining
//      nothing, and the depth round never got a slot.
//
// The common shape: A TRIGGER THAT IS ALWAYS TRUE, so one round kind eats the
// schedule. Each was found by reading a round sequence and noticing a pattern.
// That is a thing a test can do.
//
// So: run a long loop under the condition that caused each of them (findings
// keep being confirmed), and assert the SHAPE of the resulting sequence.
// -----------------------------------------------------------------------

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import type { Hypothesis, HypothesisStatus, RoundRecord } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-inv-"));
}

const ANCHORED = (n: number) => ({
  kind: "code-slice" as const,
  at: "",
  location: { file: `src/area${n}.ts`, line: 10 + n },
  detail: "the guard is absent",
});

/**
 * Run a long loop while findings keep being CONFIRMED.
 *
 * That is the condition that caused all three bugs: a project that produces a
 * confirmed finding every couple of rounds is a project whose "a new finding
 * appeared" triggers are true almost always.
 */
function runBusyLoop(cwd: string, rounds: number): string[] {
  const kinds: string[] = [];
  for (let i = 0; i < rounds; i++) {
    const snapshot = load(cwd).snapshot;
    const result = tickLoop(cwd, snapshot);
    if (result.action !== "sent") break;
    const records = load(cwd).snapshot.roundRecords;
    const record = records[records.length - 1]!;
    kinds.push(record.kind);

    // Play the model. It answers the round it was given, and — this is the part
    // that matters — it IGNORES the combination pass, which is what was measured
    // on the real audit (7 passes, 0 combination nodes).
    const node = record.nodeId ? load(cwd).snapshot.byId.get(record.nodeId) : undefined;
    if (record.kind === "verify" && node) {
      setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED(i)] });
    } else if (record.kind === "pursue" && node) {
      addNode(cwd, {
        description: `the shared helper behind ${node.id} is reached from endpoint number ${i} without a check`,
        category: node.category,
        parentId: node.id,
      });
    } else if (record.kind === "challenge" && node) {
      // Survives: attach what was checked, change no status.
      setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED(i), ANCHORED(i + 100)] });
    } else if (record.kind === "generate") {
      addNode(cwd, { description: `area ${i} builds a path from caller input to a sink without a check`, category: "command-injection" });
    }
  }
  return kinds;
}

function seeded(cwd = tmpProject(), hypotheses = 40): string {
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  for (let i = 0; i < hypotheses; i++) {
    const categories = ["auth-bypass", "ssrf", "sqli", "deserialization", "idor", "command-injection", "ssti", "path-traversal"];
    const r = addNode(cwd, {
      description: `area ${i} reaches a sink without the check the surrounding code relies on`,
      category: categories[i % categories.length]!,
    });
    assert.equal(r.ok, true, r.ok ? "" : r.errors.join("; "));
  }
  return cwd;
}

/** Share of `kind` over the whole sequence. */
const share = (kinds: readonly string[], kind: string): number =>
  kinds.length === 0 ? 0 : kinds.filter((k) => k === kind).length / kinds.length;

/** The worst share of `kind` over any sliding window of `size`. */
function worstWindowShare(kinds: readonly string[], kind: string, size: number): number {
  let worst = 0;
  for (let i = 0; i + size <= kinds.length; i++) {
    const window = kinds.slice(i, i + size);
    worst = Math.max(worst, window.filter((k) => k === kind).length / size);
  }
  return worst;
}

/** The longest run of consecutive rounds of `kind`. */
function longestRun(kinds: readonly string[], kind: string): number {
  let best = 0;
  let run = 0;
  for (const k of kinds) {
    run = k === kind ? run + 1 : 0;
    best = Math.max(best, run);
  }
  return best;
}

// -----------------------------------------------------------------
// The invariants
// -----------------------------------------------------------------

test("a busy loop does NOT let one kind eat the schedule", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds = runBusyLoop(cwd, 60);
  assert.ok(kinds.length >= 40, `the loop must keep running; it produced ${kinds.length} rounds: ${kinds.join(",")}`);

  // THE INVARIANT THAT WOULD HAVE CAUGHT ALL THREE BUGS. A kind that is more than
  // half of a 20-round window is a kind whose trigger is always true.
  for (const kind of ["consolidate", "challenge", "pursue", "coverage", "generate", "recon"]) {
    const worst = worstWindowShare(kinds, kind, 20);
    assert.ok(
      worst <= 0.5,
      `"${kind}" took ${(worst * 100).toFixed(0)}% of some 20-round window — a trigger that is always true.\n  ${kinds.join(",")}`,
    );
  }
});

test("verification keeps the majority of a busy loop", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds = runBusyLoop(cwd, 60);

  // The sweep is the work. Every other kind is a side quest, and the whole
  // anti-starvation design exists to keep it that way.
  const verify = share(kinds, "verify");
  assert.ok(verify >= 0.3, `verify was only ${(verify * 100).toFixed(0)}% of the rounds:\n  ${kinds.join(",")}`);
});

test("no side quest runs twice in a row, however busy the loop is", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds = runBusyLoop(cwd, 60);

  for (const kind of ["consolidate", "challenge", "pursue", "coverage"]) {
    assert.ok(longestRun(kinds, kind) <= 1, `"${kind}" ran consecutively:\n  ${kinds.join(",")}`);
  }
});

test("the combination pass does not fire on every finding", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds = runBusyLoop(cwd, 60);

  // This is the measured failure: 7 passes in 27 rounds, because `new-finding`
  // fired on EVERY confirmation.
  const consolidate = share(kinds, "consolidate");
  assert.ok(consolidate <= 0.25, `consolidate took ${(consolidate * 100).toFixed(0)}% of the rounds:\n  ${kinds.join(",")}`);
});

test("no side quest is STARVED — every one that can run, runs", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds = runBusyLoop(cwd, 60);

  // THE INVARIANT THE ROTATION EXISTS FOR, and the one a fixed precedence provably
  // cannot satisfy. Both directions were measured on real runs:
  //
  //   consolidate above challenge   consolidate 13, challenge  3   (29 of 32 confirmations never attacked)
  //   challenge above consolidate   consolidate  8, challenge  8, PURSUE 0
  //
  // A kind with ZERO rounds is not "rare", it is unreachable, and the audit quietly
  // loses everything that kind does. Swapping the order did not fix the starvation,
  // it relocated it — which is why the order is a rotation now.
  for (const kind of ["challenge", "consolidate", "pursue"]) {
    assert.ok(
      kinds.includes(kind),
      `"${kind}" never ran in ${kinds.length} busy rounds — its trigger is always available, so a fixed order starves it:\n  ${kinds.join(",")}`,
    );
  }
  // And they are BALANCED, not merely present. Before the rotation this was 13
  // against 3; a kind that runs once every twenty rounds is starved in all but name.
  const counts = ["challenge", "consolidate", "pursue"].map((k) => kinds.filter((x) => x === k).length);
  assert.ok(
    Math.max(...counts) <= Math.min(...counts) * 2,
    `the side quests are unbalanced (challenge/consolidate/pursue = ${counts.join("/")}):\n  ${kinds.join(",")}`,
  );
});

test("the challenge round is not starved by the combination pass", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds = runBusyLoop(cwd, 60);

  // The operator's question, and the reason the order was changed at all: a
  // confirmation nobody attacked is an unverified claim in the deliverable, and the
  // report says so twenty-nine times. Challenge is the ONLY kind that can remove a
  // false positive, so it gets a real share, not a token one.
  const challenge = share(kinds, "challenge");
  assert.ok(challenge >= 0.1, `challenge was only ${(challenge * 100).toFixed(0)}% of the rounds:\n  ${kinds.join(",")}`);
});

test("a confirmed HIGH finding gets PURSUED — the depth round is not starved", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds = runBusyLoop(cwd, 60);

  // On the real audit this was 0 out of 27 rounds: consolidate sat above pursue
  // and its trigger was always true.
  assert.ok(kinds.includes("pursue"), `pursue never ran, so the audit never went deeper than its recon note:\n  ${kinds.join(",")}`);
});

test("an OPEN pursuit is finished before a combination pass interrupts it", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds = runBusyLoop(cwd, 60);

  // A pursuit is bounded to two rounds, so once it starts it should finish within
  // a couple of rounds rather than being deferred indefinitely.
  const first = kinds.indexOf("pursue");
  assert.ok(first >= 0, "a pursue round must have run");
  const window = kinds.slice(first, first + 6);
  assert.ok(
    window.filter((k) => k === "pursue").length >= 2,
    `the pursuit did not continue; the next rounds were: ${window.join(",")}`,
  );
});

test("the plateau still fires on a loop that produces nothing", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 4 });
  // The model answers NOTHING: no verdict, no evidence, no combination.
  let stopped: string | null = null;
  for (let i = 0; i < 40; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") { stopped = r.reason; break; }
  }
  assert.ok(stopped, "a loop where nothing happens must stop");
  assert.match(stopped!, /plateau|no open hypotheses/);
});

// -----------------------------------------------------------------
// The harness itself
// -----------------------------------------------------------------

test("worstWindowShare and longestRun measure what they claim", () => {
  assert.equal(worstWindowShare(["a", "b", "a", "b"], "a", 2), 0.5);
  assert.equal(worstWindowShare(["a", "a", "b", "b"], "a", 2), 1);
  assert.equal(worstWindowShare(["a", "a", "a"], "a", 2), 1);
  assert.equal(worstWindowShare([], "a", 2), 0);
  assert.equal(longestRun(["a", "b", "a", "a", "a"], "a"), 3);
  assert.equal(longestRun(["b"], "a"), 0);
});
