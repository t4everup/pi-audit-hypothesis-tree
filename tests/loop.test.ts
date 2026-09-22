// pi-audit-hypothesis-tree — tests/loop.test.ts
//
// Pins stage 5: the completion contract is mechanical, the round engine cannot
// stack rounds, the loop bounds itself, and the findings ledger is readable and
// append-only.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, createTree, getNode, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { applyCombination, applyConsolidation, planConsolidation } from "../extensions/hypothesis-tree/combination.ts";
import { applyNodePatch } from "../extensions/hypothesis-tree/tree.ts";
import { hasBeenChallenged } from "../extensions/hypothesis-tree/types.ts";
import { currentRunRounds, nextChallengeCandidate, nextPursueTarget, renderChallengeBrief } from "../extensions/hypothesis-tree/loop.ts";
import { saveSettings } from "../extensions/hypothesis-tree/settings.ts";
import { renderReport } from "../extensions/hypothesis-tree/report.ts";
import {
  LOOP_DEFAULTS,
  appendFindingsLedger,
  buildContract,
  contractMet,
  describeContract,
  evaluateRound,
  findingsLedgerPath,
  pauseLoop,
  renderLoopStatus,
  renderRoundBrief,
  renderRoundSummary,
  renderWidget,
  resumeLoop,
  startLoop,
  stopLoop,
  tickLoop,
} from "../extensions/hypothesis-tree/loop.ts";
import { recordSegmentOutcome, submitRecon } from "../extensions/hypothesis-tree/recon.ts";
import type { Hypothesis, RoundRecord } from "../extensions/hypothesis-tree/types.ts";


/**
 * A confirmed finding only counts toward a contract when its evidence is
 * anchored in code — a verdict resting on an argument is the model's opinion.
 * These tests therefore confirm with a real code-slice at a real location.
 */
/**
 * Round kinds that do not advance the breadth-first sweep.
 *
 * Duplicated from loop.ts on purpose: this is the invariant the test asserts, so
 * importing the implementation's own list would make the test agree with a bug
 * in that list rather than catch it.
 */
const SIDE_QUEST_KINDS: readonly string[] = ["consolidate", "challenge", "pursue"];

function ANCHORED(detail: string) {
  return { kind: "code-slice" as const, at: "", location: { file: "src/auth.ts", line: 1 }, detail };
}

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-loop-"));
}

const A = "the login handler accepts a JWT without verifying its signature";

/** A recon note long enough to chunk, with distinct paragraphs. */
const RECON_NOTE = [
  "The project is a small Node service. It exposes three HTTP routes under /api: login, refresh and export, and it consumes one queue topic named order.created.",
  "Authentication is a JWT bearer token. The middleware under src/auth/ decodes the token and attaches the payload to the request, and the routes read the payload directly.",
  "The export route returns records selected by an id taken from the query string. I could not find an ownership check between the id and the caller in the time available.",
  "The queue consumer deserializes the message body with a generic parser. I did not read the parser itself, so I cannot say whether it restricts the types it will construct.",
].join("\n\n");

function add(cwd: string, description: string, category: string, parentId?: string): Hypothesis {
  const result = addNode(cwd, { description, category, ...(parentId ? { parentId } : {}) });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result.ok ? result.value.node : (undefined as never);
}

/** A tree with a root and two children, nothing confirmed. */
function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, A, { category: "auth-bypass" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  add(cwd, "the refresh handler accepts a JWT without verifying its signature", "auth-bypass");
  add(cwd, "the export endpoint returns records the caller does not own", "idor");
  return cwd;
}

function start(cwd: string, over: Partial<Parameters<typeof startLoop>[2]> = {}) {
  const result = startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: A, ...over });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result;
}

function roundRecord(cwd: string, round: number): RoundRecord {
  const record = load(cwd).snapshot.roundRecords.find((r) => r.round === round);
  assert.ok(record, `round ${round} must be recorded`);
  return record!;
}

// -----------------------------------------------------------------
// The contract
// -----------------------------------------------------------------

test("the default contract is one confirmed finding", () => {
  assert.deepEqual(buildContract({}), {
    minConfirmed: 1,
    minSeverity: "high",
    requireConsolidated: true,
    requireArtifact: true,
    requireReproduced: false,
    requireChallenged: true,
    // OFF by default: this clause constrains the WRITING rather than the
    // evidence. A finding can be true and well-evidenced while nobody has yet
    // worked out what an attacker gains, and the report says "not assessed"
    // either way — this only decides whether that gap may END an audit.
    requireImpact: false,
    requireExploitable: false,
    requirePreAuth: false,
  });
});

test("describeContract names every clause", () => {
  assert.match(describeContract(null), /runs until stopped/);
  assert.equal(
    describeContract(buildContract({})),
    "at least 1 confirmed finding(s), at severity >= high, each anchored in real code (not reasoning alone), each having SURVIVED an attempt to refute it, with no combination pass pending",
  );
  assert.match(describeContract(buildContract({ confirmed: 2, severity: "high" })), /at least 2 confirmed finding\(s\), at severity >= high/);
  assert.match(describeContract(buildContract({ category: ["idor", "ssrf"] })), /in idor or ssrf/);
  assert.match(describeContract(buildContract({ requireReproduced: true })), /each reproduced by a command/);
});

test("the contract is not met with no confirmed findings", () => {
  const cwd = seeded();
  const evaluation = contractMet(load(cwd).snapshot, buildContract({}));
  assert.equal(evaluation.met, false);
  assert.match(evaluation.detail[0]!, /0\/1 qualifying confirmed finding/);
});

test("confirming a finding meets the default contract once consolidation is up to date", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("no verify()")] });
  // A combination pass is now due, and the default contract requires it done.
  assert.equal(contractMet(load(cwd).snapshot, buildContract({})).met, false);
  assert.match(contractMet(load(cwd).snapshot, buildContract({})).detail.join("\n"), /combination pass is still pending/);

  assert.equal(contractMet(load(cwd).snapshot, buildContract({ requireConsolidated: false, requireChallenged: false })).met, true);
});

test("a severity clause is not satisfied by UNRATED findings, and says so", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { evidence: [ANCHORED("no verify()")] });
  const evaluation = contractMet(load(cwd).snapshot, buildContract({ severity: "high", requireConsolidated: false, requireChallenged: false }));
  assert.equal(evaluation.met, false);
  assert.match(evaluation.detail.join("\n"), /0 at severity >= high/);
  assert.match(evaluation.detail.join("\n"), /carry no severity yet — they are NOT counted as low/);
});

test("a severity clause is satisfied by a rating at or above the floor", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", {
    severity: "critical",
    evidence: [ANCHORED("no verify()")],
  });
  const evaluation = contractMet(load(cwd).snapshot, buildContract({ severity: "high", requireConsolidated: false, requireChallenged: false }));
  assert.equal(evaluation.met, true, evaluation.detail.join("; "));
});

test("a severity floor below the rating fails", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "low", evidence: [ANCHORED("x")] });
  assert.equal(contractMet(load(cwd).snapshot, buildContract({ severity: "high", requireConsolidated: false })).met, false);
});

test("a category clause only counts findings in those classes", () => {
  const cwd = seeded();
  const snap = load(cwd).snapshot;
  const auth = snap.nodes.find((n) => n.category === "auth-bypass")!;
  const idor = snap.nodes.find((n) => n.category === "idor")!;
  setStatus(cwd, auth.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  setStatus(cwd, idor.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });

  const idorOnly = contractMet(load(cwd).snapshot, buildContract({ confirmed: 2, category: ["idor"], requireConsolidated: false, requireChallenged: false }));
  assert.equal(idorOnly.met, false, "only one finding is in scope");
  const both = contractMet(load(cwd).snapshot, buildContract({ confirmed: 2, requireConsolidated: false, requireChallenged: false }));
  assert.equal(both.met, true);
});

// -----------------------------------------------------------------
// Starting, pausing, resuming, stopping
// -----------------------------------------------------------------

test("startLoop refuses without a tree and names the fix", () => {
  const cwd = tmpProject();
  const result = startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: A });
  assert.equal(result.ok, false);
  assert.match(result.errors[0]!, /no hypothesis tree/);
});

test("a /loop has no contract; a /goal has one and a round cap", () => {
  const cwd = seeded();
  start(cwd, { kind: "loop" });
  const loop = load(cwd).snapshot.loop!;
  assert.equal(loop.contract, null);
  assert.equal(loop.maxRounds, LOOP_DEFAULTS.LOOP_MAX_ROUNDS);
  assert.equal(loop.plateauWindow, LOOP_DEFAULTS.LOOP_PLATEAU);

  const cwd2 = seeded();
  start(cwd2, { kind: "goal", contract: buildContract({ confirmed: 1 }) });
  const goal = load(cwd2).snapshot.loop!;
  assert.equal(goal.contract?.minConfirmed, 1);
  assert.equal(goal.maxRounds, LOOP_DEFAULTS.GOAL_MAX_ROUNDS);
  assert.equal(goal.plateauWindow, LOOP_DEFAULTS.GOAL_PLATEAU);
});

test("startLoop refuses to start a second loop while one is RUNNING", () => {
  const cwd = seeded();
  start(cwd);
  const again = startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: A });
  assert.equal(again.ok, false);
  assert.equal(again.resumed, undefined, "a running loop is not resumed — there is nothing to do but watch it");
  assert.match(again.errors[0]!, /already RUNNING/);
  // The refusal must name the command that works, not just state the state.
  assert.match(again.errors[0]!, /\/loop status to watch it/);
  assert.match(again.errors[0]!, /\/loop pause to stop the clock/);
});

test("startLoop RESUMES a paused loop instead of refusing", () => {
  const cwd = seeded();
  start(cwd);
  tickLoop(cwd, load(cwd).snapshot);
  pauseLoop(cwd, load(cwd).snapshot, "hold");

  // "start" is the word a person types when they want the audit to go again.
  const again = startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: A });
  assert.equal(again.ok, true, again.errors.join("; "));
  assert.equal(again.resumed, true);
  assert.equal(again.loop!.status, "running");
  assert.equal(again.loop!.round, 1, "the round number carries over — nothing was reset");
  assert.equal(again.loop!.pausedReason, undefined, "the pause reason is cleared");
});

test("startLoop resumes when no objective is given at all", () => {
  const cwd = seeded();
  start(cwd);
  pauseLoop(cwd, load(cwd).snapshot, "hold");
  // `/goal start` with no argument: the existing objective is the only one in play.
  const again = startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "" });
  assert.equal(again.ok, true, again.errors.join("; "));
  assert.equal(again.resumed, true);
  assert.equal(again.loop!.objective, A, "the original objective is kept");
});

test("a paused loop with a DIFFERENT objective is refused, not silently resumed", () => {
  const cwd = seeded();
  start(cwd);
  pauseLoop(cwd, load(cwd).snapshot, "hold");
  const again = startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "a completely different audit" });
  assert.equal(again.ok, false, "resuming would silently keep the old objective");
  assert.match(again.errors[0]!, /DIFFERENT objective/);
  assert.match(again.errors[0]!, /\/loop resume/);
  assert.match(again.errors[0]!, /\/loop stop/);
  assert.equal(load(cwd).snapshot.loop!.status, "paused", "the tree and the loop are untouched");
});

test("a paused /loop is not resumed by /goal start, and vice versa", () => {
  const cwd = seeded();
  start(cwd);
  pauseLoop(cwd, load(cwd).snapshot, "hold");
  const asGoal = startLoop(cwd, load(cwd).snapshot, { kind: "goal", objective: A });
  assert.equal(asGoal.ok, false, "a kind change is a different audit, not a continuation");
  assert.match(asGoal.errors[0]!, /a PAUSED \/loop exists/);
  assert.match(asGoal.errors[0]!, /\/loop resume/);
});

test("resuming through startLoop honours the round cap the same way resume does", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: A, maxRounds: 1 });
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot); // hits the cap and stops
  assert.equal(load(cwd).snapshot.loop!.status, "stopped");
  // A STOPPED loop is replaced, not resumed, so this starts cleanly.
  const again = startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: A, maxRounds: 5 });
  assert.equal(again.ok, true, again.errors.join("; "));
  assert.equal(again.resumed, undefined);
  assert.equal(again.loop!.round, 0, "a fresh start begins at round 0");
  assert.equal(again.loop!.maxRounds, 5);
});

test("a stopped loop can be replaced by a new one", () => {
  const cwd = seeded();
  start(cwd);
  stopLoop(cwd, load(cwd).snapshot, "done");
  const again = startLoop(cwd, load(cwd).snapshot, { kind: "goal", objective: A });
  assert.equal(again.ok, true, again.ok ? "" : again.errors.join("; "));
});

test("pause and resume move the status and reset the stall counter", () => {
  const cwd = seeded();
  start(cwd);
  const paused = pauseLoop(cwd, load(cwd).snapshot, "lunch");
  assert.equal(paused.ok, true);
  assert.equal(load(cwd).snapshot.loop!.status, "paused");
  assert.equal(load(cwd).snapshot.loop!.pausedReason, "lunch");

  const resumed = resumeLoop(cwd, load(cwd).snapshot);
  assert.equal(resumed.ok, true);
  assert.equal(load(cwd).snapshot.loop!.status, "running");
  assert.equal(load(cwd).snapshot.loop!.pausedReason, undefined, "the pause reason is cleared on resume");
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 0);
});

test("pausing twice is refused, and stopping twice is refused", () => {
  const cwd = seeded();
  start(cwd);
  assert.equal(pauseLoop(cwd, load(cwd).snapshot, "x").ok, true);
  assert.equal(pauseLoop(cwd, load(cwd).snapshot, "x").ok, false);
  assert.equal(stopLoop(cwd, load(cwd).snapshot, "y").ok, true);
  assert.equal(stopLoop(cwd, load(cwd).snapshot, "y").ok, false);
});

test("a completed /goal cannot be resumed", () => {
  const cwd = seeded();
  start(cwd, { kind: "goal", contract: buildContract({ requireConsolidated: false, requireChallenged: false }) });
  // Round 1 is scheduled because the contract is not met yet.
  const first = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(first.action, "sent", first.reason);

  // The model confirms the finding during the round.
  setStatus(cwd, first.nodeId!, "confirmed", {
    severity: "high",
    evidence: [{ kind: "code-slice", at: "", location: { file: "src/auth.ts", line: 1 }, detail: "decode(token)" }],
  });

  const second = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(second.action, "complete", second.reason);
  assert.match(second.reason, /contract satisfied/);
  assert.equal(load(cwd).snapshot.loop!.status, "complete");

  const resumed = resumeLoop(cwd, load(cwd).snapshot);
  assert.equal(resumed.ok, false);
  assert.match(resumed.errors[0]!, /already met its contract/);
});

test("a /goal whose contract is ALREADY satisfied completes on the first tick", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { kind: "goal", contract: buildContract({ requireConsolidated: false, requireChallenged: false }) });
  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.action, "complete");
  assert.equal(load(cwd).snapshot.roundRecords.length, 0, "no round was needed");
});

// -----------------------------------------------------------------
// Round evaluation
// -----------------------------------------------------------------

test("a round that reached a verdict is produced", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  const record: RoundRecord = {
    round: 1, at: "", kind: "verify", nodeId: node.id,
    nodeStatusAtStart: "pending", nodeEvidenceAtStart: 0, confirmedAtStart: 0, nodeCountAtStart: 0, summary: [],
  };
  const before = evaluateRound(load(cwd).snapshot, record);
  assert.equal(before.produced, false);
  assert.match(before.detail, /no verdict and no new evidence/);

  setStatus(cwd, node.id, "rejected", { evidence: [{ kind: "code-slice", at: "", detail: "verify() is called" }] });
  const after = evaluateRound(load(cwd).snapshot, record);
  assert.equal(after.verdictReached, true);
  assert.equal(after.produced, true);
  assert.match(after.detail, /→ rejected \(1 evidence entry\/entries\)/);
});

test("a round that only added evidence is produced but not a verdict", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  const record: RoundRecord = {
    round: 1, at: "", kind: "verify", nodeId: node.id,
    nodeStatusAtStart: "pending", nodeEvidenceAtStart: 0, confirmedAtStart: 0, nodeCountAtStart: 0, summary: [],
  };
  // `testing`, not `blocked`: blocked is RESOLVED (see isResolved) and would make
  // this a verdict round, which is the opposite of what this test is about.
  setStatus(cwd, node.id, "testing", { evidence: [ANCHORED("x")] });
  const outcome = evaluateRound(load(cwd).snapshot, record);
  assert.equal(outcome.verdictReached, false);
  assert.equal(outcome.evidenceAdded, true);
  assert.equal(outcome.produced, true);
  assert.match(outcome.detail, /gained evidence but no verdict yet/);
});

test("BLOCKED counts as progress — honesty must not be punished as idleness", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  const record: RoundRecord = {
    round: 1, at: "", kind: "verify", nodeId: node.id,
    nodeStatusAtStart: "pending", nodeEvidenceAtStart: 0, confirmedAtStart: 0, nodeCountAtStart: 0, summary: [],
  };
  // The real shape of it: the code facts were established, and the answer turns
  // on something the source cannot show (a deployment config, a live daemon).
  setStatus(cwd, node.id, "blocked", { reason: "needs a running instance to settle reachability", evidence: [ANCHORED("x")] });
  const outcome = evaluateRound(load(cwd).snapshot, record);
  assert.equal(outcome.verdictReached, true, "blocked is a recorded judgement, not nothing");
  assert.equal(outcome.produced, true);
  assert.match(outcome.detail, /cannot be settled from the source alone/);
  assert.match(outcome.detail, /counted as progress, not as nothing/);
});

test("eight honest blocked verdicts do not end the audit as a plateau", () => {
  const cwd = seeded();
  const nodes: Hypothesis[] = [];
  for (let i = 0; i < 9; i++) nodes.push(add(cwd, `the endpoint number ${i} may reach the sink without a role check`, "auth-bypass"));
  start(cwd, { plateauWindow: 8 });

  let blockedCount = 0;
  for (let i = 0; i < 9; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") {
      assert.fail(`the loop stopped after ${blockedCount} blocked verdicts: ${r.reason}`);
    }
    setStatus(cwd, r.nodeId!, "blocked", { reason: "needs the deployment config", evidence: [ANCHORED("x")] });
    blockedCount++;
  }
  assert.equal(blockedCount, 9);
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 0, "not one blocked verdict counted against the plateau");
});

test("a consolidate round is judged by whether anything was COMBINED", () => {
  const cwd = seeded();
  const record: RoundRecord = {
    round: 1, at: "", kind: "consolidate", nodeId: null,
    nodeStatusAtStart: null, nodeEvidenceAtStart: 0, confirmedAtStart: 0,
    // The baseline must be the CURRENT count, or "the tree grew" is true for the
    // tree that already existed.
    nodeCountAtStart: load(cwd).snapshot.nodes.length, summary: [],
  };
  const empty = evaluateRound(load(cwd).snapshot, record);
  assert.equal(empty.produced, false);
  assert.match(empty.detail, /nothing was combined/);
  assert.match(empty.detail, /backed off/, "and it says what that costs the next pass");

  // A finding confirmed while the pass ran is progress, but it is NOT the pass's
  // own output — the pass hands over candidates and the model combines them.
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { evidence: [ANCHORED("x")] });
  const confirmedDuring = evaluateRound(load(cwd).snapshot, record);
  assert.equal(confirmedDuring.produced, true);
  assert.match(confirmedDuring.detail, /a finding was confirmed during the pass/);

  // What the pass actually produced: a new node.
  const before = load(cwd).snapshot.nodes.length;
  add(cwd, "the same signature-skipping technique applies to the service-to-service token", "auth-bypass");
  const combined = evaluateRound(load(cwd).snapshot, { ...record, nodeCountAtStart: before - 1 });
  assert.equal(combined.produced, true);
  assert.match(combined.detail, /produced 2 new combination\(s\)/);
});

test("a round whose node vanished does not claim progress", () => {
  const cwd = seeded();
  const record: RoundRecord = {
    round: 1, at: "", kind: "verify", nodeId: "H-9999",
    nodeStatusAtStart: "pending", nodeEvidenceAtStart: 0, confirmedAtStart: 0, nodeCountAtStart: 0, summary: [],
  };
  const outcome = evaluateRound(load(cwd).snapshot, record);
  assert.equal(outcome.produced, false);
  assert.match(outcome.detail, /no longer in the tree/);
});

// -----------------------------------------------------------------
// The tick
// -----------------------------------------------------------------

test("a tick with no loop is idle and writes nothing", () => {
  const cwd = seeded();
  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.action, "idle");
  assert.equal(load(cwd).snapshot.roundRecords.length, 0);
});

test("a tick on a paused or stopped loop does not advance it", () => {
  const cwd = seeded();
  start(cwd);
  pauseLoop(cwd, load(cwd).snapshot, "x");
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "paused");
  assert.equal(load(cwd).snapshot.roundRecords.length, 0);

  stopLoop(cwd, load(cwd).snapshot, "y");
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "stopped");
});

test("the first tick schedules a round, records it, and returns a brief", () => {
  const cwd = seeded();
  start(cwd);
  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.action, "sent");
  assert.equal(result.round, 1);
  assert.ok(result.nodeId);
  assert.ok(result.brief);
  assert.match(result.brief, /\[AUDIT ROUND 1 — VERIFY\]/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.round, 1);
  assert.equal(snap.loop!.awaitingRound, 1, "the anti-stacking fence is set");
  assert.equal(snap.roundRecords.length, 1);
  assert.equal(snap.roundRecords[0]!.nodeId, result.nodeId);
  assert.equal(snap.selections.length, 1, "the scheduler recorded the pick");
});

test("the second tick evaluates the first round before scheduling the next", () => {
  const cwd = seeded();
  start(cwd);
  tickLoop(cwd, load(cwd).snapshot);
  const first = roundRecord(cwd, 1);

  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.action, "sent");
  assert.equal(result.round, 2);
  assert.equal(result.previous!.round, 1);
  assert.equal(result.previous!.produced, false, "nothing was examined between the two ticks");
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 1);
  assert.equal(load(cwd).snapshot.loop!.awaitingRound, 2);
  assert.equal(first.nodeId !== null, true);
});

test("a productive round resets the stall counter", () => {
  const cwd = seeded();
  start(cwd);
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot); // round 1 evaluated as unproductive
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 1);

  // Now make round 2 productive.
  const record = roundRecord(cwd, 2);
  setStatus(cwd, record.nodeId!, "rejected", { evidence: [{ kind: "code-slice", at: "", detail: "verify() is called" }] });
  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.previous!.produced, true);
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 0, "progress resets the plateau");
});

test("the plateau stops the loop with a reason that says the well looks dry", () => {
  const cwd = seeded();
  start(cwd, { plateauWindow: 2 });
  // Three ticks with no model action: round 1 unproductive, round 2
  // unproductive, then the plateau fires.
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "sent");
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "sent");
  const third = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(third.action, "stopped");
  assert.match(third.reason, /plateau/);
  assert.match(third.reason, /the well looks dry/);
  assert.equal(load(cwd).snapshot.loop!.status, "stopped");
});

test("the round cap stops the loop", () => {
  const cwd = seeded();
  start(cwd, { maxRounds: 2, plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot);
  const third = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(third.action, "stopped");
  assert.match(third.reason, /round cap reached \(2\)/);
});

test("a due combination pass pre-empts verification and the round kind says so", () => {
  const cwd = seeded();
  const nodes = load(cwd).snapshot.nodes.filter((n) => n.status === "pending");
  setStatus(cwd, nodes[0]!.id, "confirmed", { evidence: [ANCHORED("x")] });
  setStatus(cwd, nodes[1]!.id, "confirmed", { evidence: [ANCHORED("y")] });
  start(cwd, { plateauWindow: 99 });

  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.action, "sent");
  assert.equal(roundRecord(cwd, 1).kind, "consolidate");
  assert.match(result.brief!, /COMBINATION round/);
  assert.match(result.brief!, /CONSOLIDATION PASS/);
  assert.equal(load(cwd).snapshot.consolidations.length, 1, "the pass was recorded by the tick");
});

test("the loop stops when no open hypotheses remain and recon is exhausted", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  setStatus(cwd, "H-0001", "rejected", { evidence: [{ kind: "code-slice", at: "", detail: "verify() is called" }] });
  // Recon already ran and every segment is closed, so there is nothing left to
  // generate from either — the escalation has nowhere to go.
  const submitted = submitRecon(cwd, RECON_NOTE);
  assert.equal(submitted.ok, true, submitted.ok ? "" : submitted.errors.join("; "));
  for (const segment of submitted.segments!) {
    assert.equal(recordSegmentOutcome(cwd, segment.id, "nothing-found", { note: "read it; no attack surface" }).ok, true);
  }
  start(cwd, { plateauWindow: 99 });
  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.action, "stopped", result.reason);
  assert.match(result.reason, /no open hypotheses remain/);
});

test("with no work and no recon, the loop reads the project instead of stopping", () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  setStatus(cwd, "H-0001", "rejected", { evidence: [{ kind: "code-slice", at: "", detail: "verify() is called" }] });
  start(cwd, { plateauWindow: 99 });
  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.action, "sent");
  assert.match(result.brief!, /\[AUDIT ROUND 1 — RECON\]/);
  assert.equal(roundRecord(cwd, 1).kind, "recon");
});

test("dryRun prepares a round without setting the fence", () => {
  const cwd = seeded();
  start(cwd);
  const result = tickLoop(cwd, load(cwd).snapshot, { dryRun: true });
  assert.equal(result.action, "sent");
  assert.ok(result.brief);
  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.awaitingRound, null, "a dry run must not claim a round is in flight");
  assert.equal(snap.loop!.round, 0, "and must not advance the round counter");
  assert.equal(snap.roundRecords.length, 1, "but the round itself is recorded");
});

test("a missing round record clears the fence instead of inventing an outcome", () => {
  const cwd = seeded();
  start(cwd);
  tickLoop(cwd, load(cwd).snapshot);
  assert.equal(load(cwd).snapshot.loop!.awaitingRound, 1);
  // Simulate a lost record by pointing the fence at a round that does not exist.
  const loop = load(cwd).snapshot.loop!;
  const { writeLoop } = require("../extensions/hypothesis-tree/loop.ts") as typeof import("../extensions/hypothesis-tree/loop.ts");
  writeLoop(cwd, { ...loop, awaitingRound: 99 });
  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(result.action, "sent");
  assert.equal(result.previous, null, "no outcome is invented for a lost round");
});

// -----------------------------------------------------------------
// The brief and the summary
// -----------------------------------------------------------------

test("the brief names the node, the reasons, and the exact tool calls", () => {
  const cwd = seeded();
  start(cwd);
  const result = tickLoop(cwd, load(cwd).snapshot);
  const brief = result.brief!;
  assert.match(brief, /\[AUDIT ROUND 1 — VERIFY\]/);
  assert.match(brief, /Audit loop: /);
  assert.match(brief, /YOUR NODE: H-\d+ — "/);
  assert.match(brief, /The scheduler picked it because:/);
  assert.match(brief, /score: novelty/);
  assert.match(brief, /1\. Decide which MECHANICAL fact would refute this assertion/);
  assert.match(brief, /2\. Call hypothesis_verify on H-\d+ with those probes/);
  assert.match(brief, /a grep probe REQUIRES expectation/);
  assert.match(brief, /3\. Call hypothesis_record with the verdict/);
  assert.match(brief, /one counterexample refutes/);
  assert.match(brief, /never record "confirmed" from a surviving grep alone/);
  assert.match(brief, /4\. If the verdict raises a NEW question, call hypothesis_add/);
  assert.match(brief, /Then stop\. The next round is scheduled automatically/);
});

test("a /goal brief states the contract and the gap", () => {
  const cwd = seeded();
  start(cwd, { kind: "goal", contract: buildContract({ confirmed: 2, severity: "high" }) });
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;
  assert.match(brief, /Contract: at least 2 confirmed finding\(s\), at severity >= high/);
  assert.match(brief, /0\/2 qualifying confirmed finding\(s\)/);
});

test("the round summary is readable and carries the numbers a reader needs", () => {
  const cwd = seeded();
  start(cwd, { kind: "goal" });
  const result = tickLoop(cwd, load(cwd).snapshot);
  const text = result.summary!.join("\n");
  assert.match(text, /ROUND 1 — verify H-\d+/);
  assert.match(text, /node: "/);
  assert.match(text, /auth-bypass · depth \d+ · \d+ evidence · status testing/);
  assert.match(text, /tree: 3 nodes · 0 confirmed · 0 rejected · 3 open · depth \d+/);
  assert.match(text, /combinations: 0 pass\(es\), 0 pair\(s\) examined/);
  assert.match(text, /contract: at least 1 confirmed finding\(s\)/);
  assert.match(text, /stall: 0\/5 · round cap 20/);
  assert.match(text, /next: hypothesis_verify H-\d+ → hypothesis_record/);
});

test("a later summary reports the previous round's outcome", () => {
  const cwd = seeded();
  start(cwd);
  tickLoop(cwd, load(cwd).snapshot);
  const second = tickLoop(cwd, load(cwd).snapshot);
  assert.match(second.summary!.join("\n"), /last round: H-\d+ produced no verdict and no new evidence/);
});

// -----------------------------------------------------------------
// The findings ledger
// -----------------------------------------------------------------

test("the ledger is written per round, contains the findings and a tree snapshot, and is append-only", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", {
    severity: "high",
    evidence: [{ kind: "code-slice", at: "", detail: "decode(token)", location: { file: "src/auth/jwt.ts", line: 57 } }],
  });
  start(cwd, { plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot);

  const text = fs.readFileSync(findingsLedgerPath(cwd), "utf-8");
  assert.match(text, /## Round 1 — /);
  assert.match(text, /## Round 2 — /);
  assert.match(text, /### Confirmed findings \(1\)/);
  assert.match(text, /\[high\] \*\*H-\d+\*\*/);
  assert.match(text, /src\/auth\/jwt\.ts:57/);
  assert.match(text, /### Tree snapshot \(3 nodes\)/);
  // Append-only: round 1's entry is still present after round 2 was written.
  assert.ok(text.indexOf("## Round 1") < text.indexOf("## Round 2"));
});

test("the ledger reports 'none yet' rather than an empty section", () => {
  const cwd = seeded();
  start(cwd);
  tickLoop(cwd, load(cwd).snapshot);
  const text = fs.readFileSync(findingsLedgerPath(cwd), "utf-8");
  assert.match(text, /### Confirmed findings \(0\)\n\n_none yet_/);
});

test("appendFindingsLedger reports a write failure instead of pretending", () => {
  const cwd = tmpProject();
  // A directory where the ledger file should be.
  fs.mkdirSync(findingsLedgerPath(cwd), { recursive: true });
  const ok = appendFindingsLedger(cwd, load(cwd).snapshot, 1, ["x"]);
  assert.equal(ok, false);
});

test("the ledger records a combination node with its lineage", () => {
  const cwd = seeded();
  const snap = load(cwd).snapshot;
  const auth = snap.nodes.find((n) => n.category === "auth-bypass")!;
  const idor = snap.nodes.find((n) => n.category === "idor")!;
  setStatus(cwd, auth.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  setStatus(cwd, idor.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });
  const combined = applyCombination(cwd, load(cwd).snapshot, {
    description: "the two handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: [auth.id, idor.id],
  });
  assert.equal(combined.ok, true, combined.ok ? "" : combined.errors.join("; "));

  start(cwd, { plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);

  // The tree snapshot marks it as an inference even while it is still pending.
  let text = fs.readFileSync(findingsLedgerPath(cwd), "utf-8");
  assert.match(text, /auth-bypass\+shared/, "the tree snapshot must mark a combination node");

  // Once confirmed, the findings list carries the lineage.
  setStatus(cwd, combined.node!.id, "confirmed", {
    severity: "high",
    evidence: [{ kind: "code-slice", at: "", detail: "one shared decode helper" }],
  });
  tickLoop(cwd, load(cwd).snapshot);
  text = fs.readFileSync(findingsLedgerPath(cwd), "utf-8");
  assert.match(text, new RegExp(`\\(shared-root-cause of ${auth.id}\\+${idor.id}\\)`), text.slice(-2000));
});

// -----------------------------------------------------------------
// Status and widget
// -----------------------------------------------------------------

test("the status block reports the loop, the contract gap and the recent rounds", () => {
  const cwd = seeded();
  start(cwd, { kind: "goal" });
  tickLoop(cwd, load(cwd).snapshot);
  const text = renderLoopStatus(load(cwd).snapshot).join("\n");
  assert.match(text, /Audit goal: RUNNING — /);
  assert.match(text, /round 1\/20 · stall 0\/5 · round 1 in flight/);
  assert.match(text, /contract: at least 1 confirmed finding\(s\).* — not met/);
  assert.match(text, /recent rounds:/);
  assert.match(text, /r1 verify H-\d+ — ROUND 1 — verify H-\d+/);
});

test("the status block explains how to start when there is no loop", () => {
  const cwd = seeded();
  const text = renderLoopStatus(load(cwd).snapshot).join("\n");
  assert.match(text, /No audit loop/);
  assert.match(text, /\/goal "<objective>"/);
  assert.match(text, /\/loop /);
});

test("the widget is three lines at most and shows the loop is alive", () => {
  const cwd = seeded();
  start(cwd, { kind: "goal" });
  tickLoop(cwd, load(cwd).snapshot);
  const lines = renderWidget(load(cwd).snapshot)!;
  assert.ok(lines.length <= 3, `widget must stay small: ${lines.join(" | ")}`);
  assert.match(lines[0]!, /hypothesis ▶ goal round 1\/20 · 0 confirmed · 0 rejected · 3 open/);
  assert.match(lines[1]!, /in flight: round 1/);
  assert.match(lines[2]!, /contract open:/);
});

test("there is no widget without a loop", () => {
  assert.equal(renderWidget(load(seeded()).snapshot), null);
});

test("a stopped loop's widget shows the stop glyph", () => {
  const cwd = seeded();
  start(cwd);
  stopLoop(cwd, load(cwd).snapshot, "done");
  assert.match(renderWidget(load(cwd).snapshot)![0]!, /■/);
});

// -----------------------------------------------------------------
// The acceptance criterion: N rounds, readable summaries
// -----------------------------------------------------------------

test("/loop runs N rounds and every round summary is readable", () => {
  const cwd = seeded();
  // A rich tree so the loop has work for several rounds.
  for (let i = 0; i < 5; i++) {
    add(cwd, `auth-bypass hypothesis number ${i} about the token handling path`, "auth-bypass");
  }
  start(cwd, { plateauWindow: 99 });
  const summaries: string[] = [];
  for (let i = 0; i < 6; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    assert.equal(result.action, "sent", `round ${i + 1}: ${result.action} — ${result.reason}`);
    summaries.push(result.summary!.join("\n"));
  }

  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.round, 6);
  assert.equal(snap.roundRecords.length, 6);
  assert.equal(snap.selections.length, 6, "six rounds means six scheduler picks");

  // Every summary is readable: a header, the tree line, and a next step.
  summaries.forEach((text, index) => {
    assert.match(text, new RegExp(`ROUND ${index + 1} — `), text);
    assert.match(text, /tree: \d+ nodes · \d+ confirmed · \d+ rejected · \d+ open · depth \d+/, text);
    assert.match(text, /next: /, text);
    assert.ok(text.split("\n").length >= 5, `round ${index + 1} summary is too thin:\n${text}`);
  });

  // And the ledger has one section per round.
  const ledger = fs.readFileSync(findingsLedgerPath(cwd), "utf-8");
  for (let i = 1; i <= 6; i++) assert.match(ledger, new RegExp(`## Round ${i} — `), `ledger is missing round ${i}`);
});

test("the anti-rabbit-hole limits hold across a driven loop", () => {
  const cwd = seeded();
  let parent = "H-0001";
  for (let i = 0; i < 7; i++) {
    const child = add(cwd, `chain level ${i} does not validate the audience claim at all`, "auth-bypass", parent);
    parent = child.id;
  }
  start(cwd, { plateauWindow: 99 });
  const picked: string[] = [];
  for (let i = 0; i < 8; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    if (result.action !== "sent") break;
    if (result.nodeId) picked.push(result.nodeId);
  }
  const snap = load(cwd).snapshot;
  let run = 0;
  let maxRun = 0;
  for (let i = 1; i < picked.length; i++) {
    const prev = getNode(snap, picked[i - 1]!)!;
    const cur = getNode(snap, picked[i]!)!;
    const descended = cur.depth > prev.depth;
    run = descended ? run + 1 : 0;
    maxRun = Math.max(maxRun, run);
  }
  assert.ok(maxRun <= 3, `the driven loop must respect MAX_CONSECUTIVE_DEPTH: ${picked.join(" -> ")}`);
});

test("the loop survives a reload — state is durable, not in-memory", () => {
  const cwd = seeded();
  start(cwd, { kind: "goal", plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot);

  // A fresh load, as a new process would do.
  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.kind, "goal");
  assert.equal(snap.loop!.status, "running");
  assert.equal(snap.loop!.round, 2);
  assert.equal(snap.loop!.awaitingRound, 2);
  assert.equal(snap.roundRecords.length, 2);
  assert.equal(snap.roundRecords[1]!.round, 2);
  assert.ok(snap.roundRecords[1]!.summary.length >= 5);
});

test("per-round summaries survive compaction", () => {
  const cwd = seeded();
  start(cwd, { plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot);
  const { compact } = require("../extensions/hypothesis-tree/store.ts") as typeof import("../extensions/hypothesis-tree/store.ts");
  assert.equal(compact(cwd), true);
  const snap = load(cwd).snapshot;
  assert.equal(snap.roundRecords.length, 2, "compaction must not lose the round history");
  assert.equal(snap.loop!.round, 2);
  assert.equal(snap.loop!.awaitingRound, 2);
});

// -----------------------------------------------------------------
// The round cap is durable — resume must not pretend to move it
// -----------------------------------------------------------------
//
// Field bug (2026-09-21, Centreon Web): a `/goal` with maxRounds=3 stopped at
// "round cap reached (3)". `/goal resume` reported success, ticked, and hit the
// cap again in the same call — status back to stopped, ZERO rounds sent. The
// user saw a resume message and no progress, which is worse than a refusal.

test("resume is REFUSED when the round cap is already reached, and names the fix", () => {
  const cwd = seeded();
  start(cwd, { maxRounds: 2, plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot);
  const stopped = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(stopped.action, "stopped");
  assert.match(stopped.reason, /round cap reached \(2\)/);

  const resumed = resumeLoop(cwd, load(cwd).snapshot);
  assert.equal(resumed.ok, false, "resuming past a reached cap does nothing, so it must refuse");
  const text = resumed.ok ? "" : resumed.errors.join("\n");
  assert.match(text, /round cap \(2\) is already reached at round 2/);
  assert.match(text, /would stop again immediately and send no round/);
  assert.match(text, /\/loop resume maxRounds=12/, "the exact command is named");
  assert.match(text, /\/loop start "<objective>" maxRounds=12/);
  assert.equal(load(cwd).snapshot.loop!.status, "stopped", "nothing changed");
});

test("resume maxRounds=<n> raises the cap and continues IN PLACE", () => {
  const cwd = seeded();
  start(cwd, { maxRounds: 2, plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot);
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "stopped");

  const resumed = resumeLoop(cwd, load(cwd).snapshot, { maxRounds: 5 });
  assert.equal(resumed.ok, true, resumed.ok ? "" : resumed.errors.join("; "));
  assert.match(resumed.message!, /Round cap raised to 5/);

  const loop = load(cwd).snapshot.loop!;
  assert.equal(loop.status, "running");
  assert.equal(loop.maxRounds, 5);
  assert.equal(loop.round, 2, "the round counter is preserved — this is the same audit");
  assert.equal(loop.stallRounds, 0);

  // And the next tick actually sends a round instead of re-stopping.
  const next = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(next.action, "sent", next.reason);
  assert.equal(next.round, 3);
});

test("raising the cap to the SAME value is refused, not silently accepted", () => {
  const cwd = seeded();
  start(cwd, { maxRounds: 1, plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "stopped");
  const resumed = resumeLoop(cwd, load(cwd).snapshot, { maxRounds: 1 });
  assert.equal(resumed.ok, false, "the same cap is still reached");
});

test("a PLATEAU stop still resumes in place — only the cap is unresumable", () => {
  const cwd = seeded();
  start(cwd, { plateauWindow: 1, maxRounds: 99 });
  tickLoop(cwd, load(cwd).snapshot); // round 1
  const stopped = tickLoop(cwd, load(cwd).snapshot); // round 1 evaluated unproductive -> plateau
  assert.equal(stopped.action, "stopped");
  assert.match(stopped.reason, /plateau/);

  const resumed = resumeLoop(cwd, load(cwd).snapshot);
  assert.equal(resumed.ok, true, "resume resets stallRounds, so a plateau genuinely recovers");
  assert.equal(load(cwd).snapshot.loop!.status, "running");
  const next = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(next.action, "sent");
});

test("/goal resume maxRounds=<n> is parsed from the command line", async () => {
  const cwd = tmpProject();
  createTree(cwd, A, { category: "auth-bypass" });
  add(cwd, "the refresh handler accepts a JWT without verifying its signature", "auth-bypass");
  start(cwd, { maxRounds: 1, plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "stopped");

  // The harness in command.test.ts is not available here; drive resumeLoop with
  // the parsed flag the handler would pass.
  const refused = resumeLoop(cwd, load(cwd).snapshot);
  assert.equal(refused.ok, false);
  const raised = resumeLoop(cwd, load(cwd).snapshot, { maxRounds: 9 });
  assert.equal(raised.ok, true);
  assert.equal(load(cwd).snapshot.loop!.maxRounds, 9);
});

// -----------------------------------------------------------------
// The challenge round — the answer to "a false positive ends the audit"
// -----------------------------------------------------------------
//
// A confirmation is a hypothesis too. Without an attempt to refute it, the
// model's first confident judgement is permanent: it satisfies a /goal contract
// (so the audit stops on a false positive) and it sits in a /loop's report as a
// finding nobody ever attacked.
//
// Round order after a confirmation is consolidate -> challenge -> verify: the
// combination pass is a forced trigger, so it always goes first.

/** Tick until the newest round record has the wanted kind. */
function tickUntilKind(cwd: string, kind: string, max = 8): ReturnType<typeof tickLoop> {
  for (let i = 0; i < max; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    if (result.action !== "sent") return result;
    const records = load(cwd).snapshot.roundRecords;
    if (records[records.length - 1]?.kind === kind) return result;
  }
  throw new Error(`never reached a ${kind} round`);
}

test("a confirmed finding is challenged before the goal may complete", () => {
  const cwd = seeded();
  start(cwd, { kind: "goal", contract: buildContract({ requireConsolidated: false }) });
  const first = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(first.action, "sent");

  // The model confirms a HIGH finding anchored in code — everything the
  // contract asks for EXCEPT that nobody has tried to refute it.
  setStatus(cwd, first.nodeId!, "confirmed", {
    severity: "high",
    evidence: [{ kind: "code-slice", at: "", location: { file: "src/auth.ts", line: 1 }, detail: "decode(token)" }],
  });
  assert.equal(
    contractMet(load(cwd).snapshot, buildContract({ requireConsolidated: false })).met,
    false,
    "an unchallenged confirmation must not close a goal",
  );

  // The next round is not completion: it is the challenge.
  const challenge = tickUntilKind(cwd, "challenge");
  assert.equal(challenge.nodeId, first.nodeId);
  assert.match(challenge.brief!, /\[AUDIT ROUND \d+ — CHALLENGE\]/);
  assert.match(challenge.brief!, /Your job this round is to REFUTE it/);
  assert.equal(
    load(cwd).snapshot.byId.get(first.nodeId!)!.challengedRound,
    challenge.round,
    "the attempt is recorded before the round runs",
  );

  // Surviving it now satisfies the contract.
  assert.equal(contractMet(load(cwd).snapshot, buildContract({ requireConsolidated: false })).met, true);
});

test("a refuted finding is removed and the audit continues", () => {
  const cwd = seeded();
  start(cwd, { kind: "loop", plateauWindow: 99 });
  const first = tickLoop(cwd, load(cwd).snapshot);
  const target = first.nodeId!;
  setStatus(cwd, target, "confirmed", {
    severity: "high",
    evidence: [{ kind: "code-slice", at: "", location: { file: "src/auth.ts", line: 1 }, detail: "x" }],
  });
  tickUntilKind(cwd, "challenge");

  // The challenge turn finds the guard that makes it false.
  setStatus(cwd, target, "rejected", {
    reason: "the parent controller applies denyAccessUnlessGranted in its constructor",
    evidence: [{ kind: "code-slice", at: "", location: { file: "src/parent.ts", line: 20 }, detail: "denyAccessUnlessGranted" }],
  });
  const after = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(after.previous!.kind, "challenge");
  assert.match(after.previous!.detail, /was REFUTED by the challenge — a false positive removed/);
  assert.equal(after.previous!.produced, true, "removing a false positive is progress");
  assert.equal(load(cwd).snapshot.byId.get(target)!.status, "rejected");
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 0);
});

test("surviving a challenge needs evidence, and counts as progress", () => {
  const cwd = seeded();
  start(cwd, { kind: "loop", plateauWindow: 99 });
  const first = tickLoop(cwd, load(cwd).snapshot);
  const target = first.nodeId!;
  setStatus(cwd, target, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  tickUntilKind(cwd, "challenge");

  // The model could not refute it and says what it checked.
  const node = load(cwd).snapshot.byId.get(target)!;
  applyNodePatch(cwd, target, { evidence: [...node.evidence, ANCHORED("the parent has no guard")] }, "");
  const third = tickLoop(cwd, load(cwd).snapshot);
  assert.match(third.previous!.detail, /survived the challenge/);
  assert.equal(third.previous!.produced, true);
  assert.equal(load(cwd).snapshot.byId.get(target)!.status, "confirmed", "it keeps its status");
});

test("a challenge that records nothing is unproductive", () => {
  const cwd = seeded();
  start(cwd, { kind: "loop", plateauWindow: 99 });
  const first = tickLoop(cwd, load(cwd).snapshot);
  setStatus(cwd, first.nodeId!, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  tickUntilKind(cwd, "challenge");
  // The invariant, not an absolute number: an unproductive round adds exactly one
  // to the stall. Hardcoding the total made this test break every time the round
  // precedence changed, which says nothing about whether the behaviour is right.
  const before = load(cwd).snapshot.loop!.stallRounds;
  const third = tickLoop(cwd, load(cwd).snapshot);
  assert.match(third.previous!.detail, /challenged but nothing was recorded either way/);
  assert.equal(third.previous!.produced, false);
  assert.equal(load(cwd).snapshot.loop!.stallRounds, before + 1);
});

test("nextChallengeCandidate is worst-first and one shot per finding", () => {
  const cwd = seeded();
  const low = add(cwd, "the health probe discloses the build identifier without authentication", "info-disclosure");
  const high = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  setStatus(cwd, low.id, "confirmed", { severity: "low", evidence: [ANCHORED("x")] });
  setStatus(cwd, high.id, "confirmed", { severity: "critical", evidence: [ANCHORED("y")] });

  // Worst first: a false CRITICAL costs more than a false LOW.
  assert.equal(nextChallengeCandidate(load(cwd).snapshot, 1)!.id, high.id);
  applyNodePatch(cwd, high.id, { challengedRound: 1 }, "");
  assert.equal(nextChallengeCandidate(load(cwd).snapshot, 2)!.id, low.id);
  applyNodePatch(cwd, low.id, { challengedRound: 2 }, "");
  assert.equal(nextChallengeCandidate(load(cwd).snapshot, 3), null, "both are challenged");
});

test("the challenge cadence is enforced once the first one has run", () => {
  const cwd = seeded();
  const a = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  setStatus(cwd, a.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { kind: "loop", plateauWindow: 99 });
  tickUntilKind(cwd, "challenge");
  const challengeRound = load(cwd).snapshot.roundRecords.filter((r) => r.kind === "challenge")[0]!.round;

  // A NEW confirmation is not attacked immediately — the cadence holds.
  const b = add(cwd, "the queue consumer deserializes without a type allowlist", "deserialization");
  setStatus(cwd, b.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });
  assert.equal(
    nextChallengeCandidate(load(cwd).snapshot, challengeRound + 1),
    null,
    "too soon after the last challenge",
  );
  assert.equal(
    nextChallengeCandidate(load(cwd).snapshot, challengeRound + LOOP_DEFAULTS.CHALLENGE_INTERVAL)!.id,
    b.id,
  );
});

test("reopening and re-confirming a finding makes it challengeable again", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  applyNodePatch(cwd, node.id, { challengedRound: 4 }, "");
  assert.equal(hasBeenChallenged(load(cwd).snapshot.byId.get(node.id)!), true);

  setStatus(cwd, node.id, "pending", { reason: "new evidence contradicts it" });
  assert.equal(
    hasBeenChallenged(load(cwd).snapshot.byId.get(node.id)!),
    false,
    "leaving confirmed clears the challenge record",
  );

  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });
  assert.equal(
    nextChallengeCandidate(load(cwd).snapshot, 99)!.id,
    node.id,
    "a re-confirmation is a NEW claim and gets attacked again",
  );
});

test("the challenge round does not pre-empt a due combination pass", () => {
  const cwd = seeded();
  const a = add(cwd, "the login handler trusts the alg header without pinning the algorithm", "auth-bypass");
  const b = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  setStatus(cwd, a.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  setStatus(cwd, b.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });
  start(cwd, { kind: "loop", plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot); // round 1: the forced pass
  tickLoop(cwd, load(cwd).snapshot); // round 2: blocked from side quests — a verify
  tickLoop(cwd, load(cwd).snapshot); // round 3: the challenge
  const kinds = load(cwd).snapshot.roundRecords.map((r) => r.kind);
  assert.equal(kinds[0], "consolidate", "the forced pass wins");
  // Side quests never run back to back, so the challenge waits one round. That
  // is the rule that keeps verification from being squeezed out.
  assert.equal(kinds[1], "verify", "never two side quests in a row");
  assert.equal(kinds[2], "challenge", "then the challenge");
});

test("the challenge brief quotes the finding and forbids a safe re-confirmation", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", {
    severity: "high",
    reason: "the firewall has an empty access_control and this controller has no guard",
    evidence: [ANCHORED("x")],
  });
  const brief = renderChallengeBrief(load(cwd).snapshot.byId.get(node.id)!, "audit", 7);
  assert.match(brief, /\[AUDIT ROUND 7 — CHALLENGE\]/);
  assert.match(brief, /was CONFIRMED earlier in this audit/);
  assert.match(brief, /the firewall has an empty access_control/);
  assert.match(brief, /Find the check, guard, middleware, framework default, or caller/);
  assert.match(brief, /Attack the REACHABILITY assumption/);
  assert.match(brief, /hypothesis_record H-0001 rejected/);
  assert.match(brief, /Do NOT re-confirm it to be safe/);
});

test("the report says which findings have been attacked and which have not", () => {
  const cwd = seeded();
  const attacked = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, attacked.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  applyNodePatch(cwd, attacked.id, { challengedRound: 3 }, "");
  const unattacked = add(cwd, "the queue consumer deserializes without a type allowlist", "deserialization");
  setStatus(cwd, unattacked.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });

  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /\*\*Challenge: SURVIVED\*\* — round 3 tried to refute this and failed/);
  assert.match(text, /\*\*Challenge: NEVER ATTACKED\*\*/);
  assert.match(text, /\*\*1\/2 of them have been ATTACKED\*\*/);
  assert.match(text, /an unchallenged confirmation is the auditor agreeing with itself/);
});

// -----------------------------------------------------------------
// The starvation bug: >MAX_CONFIRMED_CONSIDERED findings, forever-combine
// -----------------------------------------------------------------
//
// Observed on a real run: a tree with 13 confirmed findings and 12 UNEXAMINED
// hypotheses spent 8+ consecutive rounds on `combine`, then stopped claiming
// "the well looks dry". The cause was that `confirmedIds` recorded the CAPPED
// working set (12) rather than every confirmed id (13), so the "new finding
// since the last pass" trigger was true on every single round.

test("an audit past MAX_CONFIRMED_CONSIDERED does not loop on combine forever", () => {
  const cwd = seeded();
  const cap = 12; // CONSOLIDATION.MAX_CONFIRMED_CONSIDERED
  const ids: string[] = [];
  for (let i = 0; i < cap + 1; i++) {
    const node = add(cwd, `the endpoint number ${i} reaches the sink without a role check`, "auth-bypass");
    setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
    ids.push(node.id);
  }
  assert.equal(load(cwd).snapshot.nodes.filter((n) => n.status === "confirmed").length, cap + 1);

  start(cwd, { plateauWindow: 99 });
  const kinds: string[] = [];
  for (let i = 0; i < 6; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const recs = load(cwd).snapshot.roundRecords;
    kinds.push(recs[recs.length - 1]!.kind);
  }
  const consolidates = kinds.filter((k) => k === "consolidate").length;
  // Not "at most one": the interval trigger legitimately schedules a re-pass
  // every CONSOLIDATION.INTERVAL rounds. The bug was EVERY round, forever, which
  // starved verification completely.
  assert.ok(consolidates < kinds.length / 2, `combine must not dominate; got ${kinds.join(",")}`);
  assert.ok(kinds.includes("verify"), `verification must get rounds; got ${kinds.join(",")}`);
  assert.ok(!/consolidate,consolidate/.test(kinds.join(",")), `no back-to-back combine; got ${kinds.join(",")}`);
});

test("the pass records EVERY confirmed id, not the capped working set", () => {
  const cwd = seeded();
  const cap = 12;
  for (let i = 0; i < cap + 3; i++) {
    const node = add(cwd, `the endpoint number ${i} reaches the sink without a role check`, "auth-bypass");
    setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  }
  const plan = planConsolidation(load(cwd).snapshot, { force: "manual" });
  assert.equal(plan.confirmed.length, cap, "the working set is capped");
  assert.equal(plan.confirmedIds.length, cap + 3, "but the RECORDED set is not — this is what broke");

  applyConsolidation(cwd, plan);
  const record = load(cwd).snapshot.consolidations.at(-1)!;
  assert.equal(record.confirmedIds.length, cap + 3);

  // Which is what stops the trigger from being permanently true.
  const after = planConsolidation(load(cwd).snapshot);
  assert.equal(after.due, false, "no new finding, no interval reached");
  assert.match(after.reason, /not due/);
});

test("a periodic pass does not starve verification", () => {
  const cwd = seeded();
  const a = add(cwd, "the login handler trusts the alg header without pinning the algorithm", "auth-bypass");
  const b = add(cwd, "the webhook receiver accepts a payload without checking its signature", "auth-bypass");
  setStatus(cwd, a.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  setStatus(cwd, b.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });

  start(cwd, { plateauWindow: 99 });
  const kinds: string[] = [];
  for (let i = 0; i < 9; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const recs = load(cwd).snapshot.roundRecords;
    kinds.push(recs[recs.length - 1]!.kind);
  }
  const verify = kinds.filter((k) => k === "verify").length;
  const consolidate = kinds.filter((k) => k === "consolidate").length;
  // A re-pass every CONSOLIDATION.INTERVAL rounds is by design; verification
  // must still get the majority of the rounds.
  assert.ok(verify > consolidate, `verify must dominate; got ${kinds.join(",")}`);
  assert.ok(verify >= 3, `verify must get real work; got ${kinds.join(",")}`);
});

test("a pass with NOTHING to hand over is never scheduled at all", () => {
  const cwd = seeded();
  const only = add(cwd, "the login handler trusts the alg header without pinning the algorithm", "auth-bypass");
  setStatus(cwd, only.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  // Generalize it so there is nothing left to pair and nothing left to extend.
  applyCombination(cwd, load(cwd).snapshot, {
    description: "the same signature-skipping technique applies to the service-to-service token",
    category: "auth-bypass",
    kind: "lateral-extension",
    spawnedFrom: [only.id],
  });
  assert.equal(planConsolidation(load(cwd).snapshot).due, false);

  start(cwd, { plateauWindow: 99 });
  const kinds: string[] = [];
  for (let i = 0; i < 6; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const recs = load(cwd).snapshot.roundRecords;
    kinds.push(recs[recs.length - 1]!.kind);
  }
  assert.equal(kinds.filter((k) => k === "consolidate").length, 0, `an empty pass must never be scheduled; got ${kinds.join(",")}`);
  assert.ok(kinds.includes("verify"), kinds.join(","));
});

// -----------------------------------------------------------------
// Cross-lifecycle round numbers
// -----------------------------------------------------------------

test("a restarted loop does not evaluate the PREVIOUS run's round", () => {
  const cwd = seeded();
  start(cwd, { plateauWindow: 99 });
  const first = tickLoop(cwd, load(cwd).snapshot); // round 1, productive (verdict recorded)
  setStatus(cwd, first.nodeId!, "rejected", { reason: "no", evidence: [ANCHORED("x")] });
  tickLoop(cwd, load(cwd).snapshot); // evaluates round 1: productive, stall 0

  // Stop and start a NEW run over the same tree. The counter restarts at 1.
  stopLoop(cwd, load(cwd).snapshot, "restart");
  start(cwd, { plateauWindow: 99 });
  const r1 = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(r1.round, 1, "the new run numbers from 1");

  // The new run's round 1 must be judged on ITS OWN record, which is empty — not
  // on the old run's round 1, which had produced a verdict.
  const r2 = tickLoop(cwd, load(cwd).snapshot);
  assert.match(r2.previous!.detail, /no verdict and no new evidence/, "the new run's round 1 was empty");
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 1, "and the stall climbs from it");
});

test("currentRunRounds separates the two runs", () => {
  const cwd = seeded();
  start(cwd, { plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot);
  const runOne = currentRunRounds(load(cwd).snapshot).length;
  stopLoop(cwd, load(cwd).snapshot, "restart");
  start(cwd, { plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);

  const snap = load(cwd).snapshot;
  assert.equal(snap.roundRecords.length, 3, "the ledger keeps all three");
  assert.equal(currentRunRounds(snap).length, 1, "but this run has exactly one");
});

test("the challenge cadence is not suppressed by a previous run's challenge", () => {
  const cwd = seeded();
  const node = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { plateauWindow: 99 });
  // Run the first challenge in run one.
  let sawChallenge = false;
  for (let i = 0; i < 4 && !sawChallenge; i++) {
    tickLoop(cwd, load(cwd).snapshot);
    sawChallenge = load(cwd).snapshot.roundRecords.some((r) => r.kind === "challenge");
  }
  assert.equal(sawChallenge, true, "run one challenged it");

  // A new confirmation in a NEW run must be attackable immediately, not after
  // waiting for a cadence measured against the old run's round numbers.
  stopLoop(cwd, load(cwd).snapshot, "restart");
  start(cwd, { plateauWindow: 99 });
  const fresh = add(cwd, "the queue consumer deserializes without a type allowlist", "deserialization");
  setStatus(cwd, fresh.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });
  assert.equal(nextChallengeCandidate(load(cwd).snapshot, 1)!.id, fresh.id);
});

// -----------------------------------------------------------------
// PURSUE — depth, and the starvation it must not cause
// -----------------------------------------------------------------
//
// Every other round moves to a SIBLING. A tree built that way is wide and
// shallow (measured on a real audit: 29 nodes at depth 1, 8 at 2, 1 at 3), and a
// finding is rarely one endpoint — a missing check is usually missing in a shared
// helper the whole surface inherits.

test("a high finding is pursued for depth", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { plateauWindow: 99 });

  const pursue = tickUntilKind(cwd, "pursue");
  assert.equal(pursue.nodeId, node.id);
  assert.match(pursue.brief!, /\[AUDIT ROUND \d+ — PURSUE\]/);
  assert.match(pursue.brief!, /This one stays on a single CONFIRMED/);
  assert.match(pursue.brief!, /WHAT ELSE does this root cause imply/);
  assert.match(pursue.brief!, /WHO CALLS this/);
  assert.match(pursue.brief!, /HOW FAR does it go/);
  assert.match(pursue.brief!, /WHAT does it combine with/);
  assert.match(pursue.brief!, new RegExp(`hypothesis_add with parentId=${node.id}`));
  // The budget is spent on PREPARE, so a crash cannot re-pursue forever.
  assert.equal(load(cwd).snapshot.byId.get(node.id)!.pursueSpent, 1);
});

test("pursue NEVER runs two rounds in a row, whatever is due", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { plateauWindow: 999 });

  const kinds: string[] = [];
  for (let i = 0; i < 16; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const recs = load(cwd).snapshot.roundRecords;
    kinds.push(recs[recs.length - 1]!.kind);
  }
  // THE HARD INVARIANT. A round kind that can pre-empt every other kind
  // eventually does exactly that — that is how the combination bug starved
  // verification — so the side quests share one rule: never two in a row.
  for (let i = 1; i < kinds.length; i++) {
    const both = SIDE_QUEST_KINDS.includes(kinds[i - 1]!) && SIDE_QUEST_KINDS.includes(kinds[i]!);
    assert.equal(both, false, `two side quests in a row at ${i}: ${kinds.join(",")}`);
  }
  // And the consequence: verification keeps the majority.
  const verify = kinds.filter((k) => k === "verify").length;
  assert.ok(verify >= kinds.length / 3, `verify must not be starved; got ${kinds.join(",")}`);
});

test("the pursue budget is a ceiling — a finding is pursued at most N times", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { plateauWindow: 999 });

  let pursues = 0;
  for (let i = 0; i < 30; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const recs = load(cwd).snapshot.roundRecords;
    if (recs[recs.length - 1]!.kind === "pursue") {
      pursues++;
      // Simulate the model producing a child each time, so the pursuit stays
      // productive and the budget is the ONLY thing that stops it.
      addNode(cwd, {
        description: `the shared helper behind ${node.id} is reached from endpoint number ${pursues} without a check`,
        category: "auth-bypass",
        parentId: node.id,
      });
    }
  }
  assert.equal(pursues, 2, `the default budget is 2, got ${pursues}`);
  assert.equal(load(cwd).snapshot.byId.get(node.id)!.pursueSpent, 2);
});

test("a pursue round that adds nothing CLOSES the pursuit instead of spending the budget", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { plateauWindow: 999 });

  // Round 1: the model adds nothing.
  tickUntilKind(cwd, "pursue");
  const after = tickLoop(cwd, load(cwd).snapshot);
  assert.match(after.previous!.detail, /produced no new hypothesis/);
  assert.match(after.previous!.detail, /this lead looks exhausted/);
  assert.equal(after.previous!.produced, false);
  assert.equal(load(cwd).snapshot.byId.get(node.id)!.pursueSpent, 2, "closed, not left at 1");

  // So it is never offered again.
  assert.equal(nextPursueTarget(load(cwd).snapshot, 99, 2), null);
});

test("a pursue round that adds a child is productive and keeps the stall at zero", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { plateauWindow: 999 });

  tickUntilKind(cwd, "pursue");
  addNode(cwd, {
    description: "the same missing check applies to every handler extending the shared base controller",
    category: "auth-bypass",
    parentId: node.id,
  });
  const after = tickLoop(cwd, load(cwd).snapshot);
  assert.match(after.previous!.detail, /1 new hypothesis\(es\) derived from it/);
  assert.equal(after.previous!.produced, true);
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 0);
});

test("only findings at HIGH or worse are pursued", () => {
  const cwd = seeded();
  const low = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, low.id, "confirmed", { severity: "low", evidence: [ANCHORED("x")] });
  assert.equal(nextPursueTarget(load(cwd).snapshot, 3, 2), null, "depth is the expensive round");

  const high = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  setStatus(cwd, high.id, "confirmed", { severity: "critical", evidence: [ANCHORED("y")] });
  assert.equal(nextPursueTarget(load(cwd).snapshot, 3, 2)!.id, high.id);
});

test("pursueRounds=0 switches the round off entirely", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "critical", evidence: [ANCHORED("x")] });
  assert.equal(nextPursueTarget(load(cwd).snapshot, 3, 0), null);

  saveSettings(cwd, { pursueRounds: 0 });
  start(cwd, { plateauWindow: 99 });
  const kinds: string[] = [];
  for (let i = 0; i < 8; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const recs = load(cwd).snapshot.roundRecords;
    kinds.push(recs[recs.length - 1]!.kind);
  }
  assert.equal(kinds.filter((k) => k === "pursue").length, 0, kinds.join(","));
});

test("reopening and re-confirming a finding gives it a FRESH pursuit budget", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  applyNodePatch(cwd, node.id, { pursueSpent: 2 }, "");
  assert.equal(nextPursueTarget(load(cwd).snapshot, 9, 2), null, "budget spent");

  setStatus(cwd, node.id, "pending", { reason: "new evidence contradicts it" });
  assert.equal(load(cwd).snapshot.byId.get(node.id)!.pursueSpent, 0, "cleared on leaving confirmed");
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("y")] });
  assert.equal(nextPursueTarget(load(cwd).snapshot, 9, 2)!.id, node.id, "a re-confirmation is a NEW claim");
});

test("an open pursuit is finished before a new one starts", () => {
  const cwd = seeded();
  const a = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  const b = add(cwd, "the webhook receiver accepts a payload without checking its signature", "auth-bypass");
  setStatus(cwd, a.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  setStatus(cwd, b.id, "confirmed", { severity: "critical", evidence: [ANCHORED("y")] });

  // Nothing pursued yet: worst first.
  assert.equal(nextPursueTarget(load(cwd).snapshot, 3, 2)!.id, b.id);
  applyNodePatch(cwd, b.id, { pursueSpent: 1 }, "");
  // b is mid-pursuit, so it stays the target even though `a` is unpursued —
  // hopping after one round is the breadth-first behaviour pursue exists to fix.
  assert.equal(nextPursueTarget(load(cwd).snapshot, 5, 2)!.id, b.id);
  applyNodePatch(cwd, b.id, { pursueSpent: 2 }, "");
  assert.equal(nextPursueTarget(load(cwd).snapshot, 7, 2)!.id, a.id, "then the next one");
});

test("the pursue round never fires when there is nothing at HIGH to pursue", () => {
  const cwd = seeded();
  start(cwd, { plateauWindow: 99 });
  const kinds: string[] = [];
  for (let i = 0; i < 5; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const recs = load(cwd).snapshot.roundRecords;
    kinds.push(recs[recs.length - 1]!.kind);
  }
  assert.equal(kinds.filter((k) => k === "pursue").length, 0, kinds.join(","));
});

test("a pursue round that adds a child is productive and keeps the stall at zero", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });
  start(cwd, { plateauWindow: 999 });

  tickUntilKind(cwd, "pursue");
  addNode(cwd, {
    description: "the same missing check applies to every handler extending the shared base controller",
    category: "auth-bypass",
    parentId: node.id,
  });
  const after = tickLoop(cwd, load(cwd).snapshot);
  assert.match(after.previous!.detail, /1 new hypothesis\(es\) derived from it/);
  assert.equal(after.previous!.produced, true);
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 0);
});

test("the report lists what the depth work produced", () => {
  const cwd = seeded();
  // A NEW node, not the seeded root: the root already has two children, so it
  // could never show the "never pursued" case this test starts with.
  const node = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED("x")] });

  // Nothing pursued yet: the report says so rather than showing an empty list.
  assert.match(renderReport(load(cwd).snapshot, null, { language: "zh" }), /_未追索。这一条只有它自己/);

  addNode(cwd, {
    description: "the shared base controller skips the role check for every handler that extends it",
    category: "auth-bypass",
    parentId: node.id,
    attackVector: {
      entrypoint: "POST /api/x",
      technique: "shared helper",
      path: [{ detail: "the sink", location: { file: "src/Base.php", line: 12 } }],
      impact: "接管所有继承该基类的接口",
    },
  });
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /#### 衍生假设（追索产出，1 条）/);
  assert.match(text, /the shared base controller skips the role check/);
  assert.match(text, /`src\/Base\.php:12`/, "a reader must be able to open the line");
  assert.match(text, /广度靠枚举，深度靠这个/);
  // And the child's tier is labelled in the reader's language, like everything
  // else in the scaffolding.
  assert.doesNotMatch(text, /REASONING ONLY/);
  assert.match(text, /仅推理/);
});

// -----------------------------------------------------------------
// A tree full of BLOCKED nodes must still stop
// -----------------------------------------------------------------
//
// `blocked` counts as progress (an honest "I cannot settle this from the source"
// is a real examination). But `isOpen("blocked")` is also TRUE, so a blocked node
// is still a scheduling candidate — which meant a tree where every node was
// blocked would cycle through them forever, each re-block counted as a fresh
// verdict, and the plateau could never fire. That is the "keeps working, never
// switches, never stops" failure, and it is worth a test of its own.

test("re-blocking an already-blocked node is NOT progress", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  const record: RoundRecord = {
    round: 1, at: "", kind: "verify", nodeId: node.id,
    // The baseline is the status BEFORE the selection moved it to testing.
    nodeStatusAtStart: "blocked", nodeEvidenceAtStart: 1, confirmedAtStart: 0,
    nodeCountAtStart: 2, summary: [],
  };
  setStatus(cwd, node.id, "blocked", { reason: "needs a running instance", evidence: [ANCHORED("x")] });
  const outcome = evaluateRound(load(cwd).snapshot, record);
  assert.equal(outcome.verdictReached, false, "blocked → blocked is not a new verdict");
  assert.equal(outcome.produced, false);
});

test("the FIRST block of a pending node IS progress", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  const record: RoundRecord = {
    round: 1, at: "", kind: "verify", nodeId: node.id,
    nodeStatusAtStart: "pending", nodeEvidenceAtStart: 0, confirmedAtStart: 0,
    nodeCountAtStart: 2, summary: [],
  };
  setStatus(cwd, node.id, "blocked", { reason: "needs a running instance", evidence: [ANCHORED("x")] });
  const outcome = evaluateRound(load(cwd).snapshot, record);
  assert.equal(outcome.verdictReached, true);
  assert.equal(outcome.produced, true);
});

test("a tree where EVERY node is blocked reaches the plateau instead of spinning", () => {
  const cwd = seeded();
  // Block every hypothesis before the loop starts.
  for (const n of load(cwd).snapshot.nodes.filter((x) => x.status === "pending")) {
    setStatus(cwd, n.id, "blocked", { reason: "cannot settle from the source", evidence: [ANCHORED("x")] });
  }
  start(cwd, { plateauWindow: 4 });

  const kinds: string[] = [];
  let stopped: string | null = null;
  for (let i = 0; i < 20; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") { stopped = r.reason; break; }
    const recs = load(cwd).snapshot.roundRecords;
    kinds.push(recs[recs.length - 1]!.kind);
  }
  assert.ok(stopped, `the loop must stop; it ran ${kinds.length} rounds instead`);
  assert.match(stopped!, /plateau|no open hypotheses/);
  assert.ok(kinds.length <= 6, `it must stop quickly, not spin; ran ${kinds.length}: ${kinds.join(",")}`);
});

test("the status baseline is the one BEFORE the selection moved it to testing", () => {
  const cwd = seeded();
  // Block EVERYTHING, so the scheduler has nothing but blocked nodes to choose
  // from and the one it picks is the one under test.
  for (const n of load(cwd).snapshot.nodes.filter((x) => x.status === "pending")) {
    setStatus(cwd, n.id, "blocked", { reason: "waiting", evidence: [ANCHORED("x")] });
  }
  start(cwd, { plateauWindow: 99 });
  const r = tickLoop(cwd, load(cwd).snapshot);
  const rec = load(cwd).snapshot.roundRecords.find((x) => x.round === r.round)!;
  assert.ok(rec.nodeId, "a blocked node was selected");
  // applySelection moves it to `testing`; the record must still say what it WAS.
  assert.equal(rec.nodeStatusAtStart, "blocked", "not the post-selection 'testing'");
  assert.equal(load(cwd).snapshot.byId.get(rec.nodeId!)!.status, "testing");
});
