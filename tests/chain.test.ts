// pi-audit-hypothesis-tree — tests/chain.test.ts
//
// Pins EXPLOITATION CHAINS: a confirmed sink that is usable only if something
// else holds.
//
// The shape this exists for, from a real audit:
//
//   H-0039  ScheduledTask.a(byte[]) calls new ObjectInputStream(...).readObject()
//           with no ObjectInputFilter, and the bytes come from three BYTEA
//           columns of Scheduled_Tasks — CONFIRMED, the code says so
//   H-0040  can anything write schedule_data BEFORE authentication?
//
// H-0039 is not speculation. It is a confirmed sink that is exploitable ONLY IF
// H-0040 holds. Before this, the report presented it exactly like a working RCE,
// and nothing ever prompted anyone to go and test the gate.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, applyNodePatch, createTree, getNode, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { buildContract, contractMet, startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import { renderReport } from "../extensions/hypothesis-tree/report.ts";
import { buildContext, planNextRound, scoreCandidate } from "../extensions/hypothesis-tree/scheduler.ts";
import { chainState, gatesOf } from "../extensions/hypothesis-tree/types.ts";
import type { Evidence, Hypothesis } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-chain-"));
}

function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

function add(cwd: string, description: string, category: string, requires?: string[]): Hypothesis {
  const result = addNode(cwd, { description, category, ...(requires ? { requires } : {}) });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result.ok ? result.value.node : (undefined as never);
}

const ANCHORED: Evidence = {
  kind: "code-slice",
  at: "",
  location: { file: "src/ScheduledTask.java", line: 88 },
  detail: "new ObjectInputStream(new ByteArrayInputStream(data)).readObject()",
};

/** The sink, confirmed, gated on writability of the columns. */
function deserSink(cwd: string, requires?: string[]): Hypothesis {
  const node = add(
    cwd,
    "ScheduledTask.a(byte[]) calls readObject() with no ObjectInputFilter, and its bytes come from the schedule_data/task_data/task_results BYTEA columns",
    "deserialization",
    requires,
  );
  setStatus(cwd, node.id, "confirmed", {
    severity: "high",
    evidence: [ANCHORED],
    reason: "the gadget libraries are all on the classpath (commons-collections-3.2, commons-beanutils-1.8.3, spring 3.1.2, hibernate3)",
  });
  return node;
}

const chainOf = (cwd: string, id: string) => chainState(getNode(load(cwd).snapshot, id)!, (x) => load(cwd).snapshot.byId.get(x));

// -----------------------------------------------------------------
// The derivation
// -----------------------------------------------------------------

test("a confirmed sink with an UNVERIFIED gate is gated, not usable", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);

  const chain = chainOf(cwd, sink.id);
  assert.equal(chain.state, "gated");
  assert.deepEqual(chain.pending, [gate.id]);
  assert.equal(getNode(load(cwd).snapshot, sink.id)!.status, "confirmed", "the sink itself IS confirmed");
});

test("confirming the gate makes the whole chain READY", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);
  assert.equal(chainOf(cwd, sink.id).state, "gated");

  setStatus(cwd, gate.id, "confirmed", { severity: "critical", evidence: [ANCHORED] });
  const chain = chainOf(cwd, sink.id);
  assert.equal(chain.state, "chain-ready");
  assert.deepEqual(chain.confirmed, [gate.id]);
});

test("a REFUTED gate BREAKS the chain rather than leaving it open", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);

  setStatus(cwd, gate.id, "rejected", { reason: "the column is only written by an admin-authenticated scheduled job", evidence: [ANCHORED] });
  const chain = chainOf(cwd, sink.id);
  // NOT "gated": a broken link cannot come good, and saying "gated" would imply
  // it might. The sink is still real; the entry is not.
  assert.equal(chain.state, "broken");
  assert.deepEqual(chain.refuted, [gate.id]);
});

test("several gates: ready only when ALL of them are confirmed", () => {
  const cwd = seeded();
  const a = add(cwd, "the schedule_data column can be written before authentication", "auth-bypass");
  const b = add(cwd, "the attacker can reach the scheduled task dispatcher with no session", "auth-bypass");
  const sink = deserSink(cwd, [a.id, b.id]);

  setStatus(cwd, a.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  assert.equal(chainOf(cwd, sink.id).state, "gated", "one gate is not enough");
  setStatus(cwd, b.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  assert.equal(chainOf(cwd, sink.id).state, "chain-ready");
});

test("a gate that is not in the tree makes the chain gated and names it", () => {
  const cwd = seeded();
  const sink = add(cwd, "the scheduled task deserializes attacker-controlled bytes", "deserialization");
  // Bypass validation deliberately: this is the state a tree is in when a node
  // was referenced and then removed, or when a snapshot predates the gate.
  applyNodePatch(cwd, sink.id, { requires: [] }, "");
  const direct = chainState({ requires: ["H-9999"] }, (id) => load(cwd).snapshot.byId.get(id));
  assert.equal(direct.state, "gated");
  assert.deepEqual(direct.missing, ["H-9999"]);
});

test("a finding nobody asked about is UNASSESSED, not standalone", () => {
  const cwd = seeded();
  const node = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass");
  // No `requires` at all means NOBODY ASKED. Reporting that as "stands alone" is
  // the same error as reporting "no impact recorded" as "no impact".
  assert.equal(chainOf(cwd, node.id).state, "unassessed");
});

test("an explicit EMPTY requires means the gates were assessed and there are none", () => {
  const cwd = seeded();
  const node = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass", []);
  assert.equal(chainOf(cwd, node.id).state, "standalone");
});

test("recorded preconditions that never became gates are UNTRACKED", () => {
  const cwd = seeded();
  const node = add(cwd, "the server fetches a URL the caller supplies", "ssrf");
  applyNodePatch(
    cwd,
    node.id,
    { attackVector: { entrypoint: "POST /import", technique: "caller-supplied URL", path: [{ detail: "fetches it" }], preconditions: ["是否有回显通道未评估"] } },
    "",
  );
  // The model wrote the uncertainty down as PROSE. Nothing will ever test it.
  assert.equal(chainOf(cwd, node.id).state, "untracked");
});

// -----------------------------------------------------------------
// Validation — the checks that keep chainState decidable
// -----------------------------------------------------------------

test("requires refuses an id that is not in the tree", () => {
  const cwd = seeded();
  const result = addNode(cwd, {
    description: "the scheduled task deserializes attacker-controlled bytes",
    category: "deserialization",
    requires: ["H-9999"],
  });
  assert.equal(result.ok, false);
  assert.match(result.ok ? "" : result.errors[0]!, /which is not in the tree/);
  assert.match(result.ok ? "" : result.errors[0]!, /an untracked precondition is prose that never gets tested/);
});

test("requires refuses the scope node — a boundary cannot be confirmed", () => {
  const cwd = seeded();
  const scopeId = load(cwd).snapshot.rootId;
  const result = addNode(cwd, {
    description: "the scheduled task deserializes attacker-controlled bytes",
    category: "deserialization",
    requires: [scopeId],
  });
  assert.equal(result.ok, false);
  assert.match(result.ok ? "" : result.errors[0]!, /SCOPE node/);
});

test("requires refuses a self-reference", () => {
  const cwd = seeded();
  const node = add(cwd, "the scheduled task deserializes attacker-controlled bytes", "deserialization");
  const patched = applyNodePatch(cwd, node.id, { requires: [node.id] }, "");
  assert.equal(patched.ok, false);
  assert.match(patched.ok ? "" : patched.errors[0]!, /gates itself/);
});

test("requires refuses a cycle", () => {
  const cwd = seeded();
  const a = add(cwd, "the scheduled task deserializes attacker-controlled bytes", "deserialization");
  const b = add(cwd, "the dispatcher can be reached with no session", "auth-bypass", [a.id]);
  // a requires b, and b already requires a.
  const patched = applyNodePatch(cwd, a.id, { requires: [b.id] }, "");
  assert.equal(patched.ok, false);
  assert.match(patched.ok ? "" : patched.errors[0]!, /cycle/);
});

test("requires refuses the same gate twice", () => {
  const cwd = seeded();
  const gate = add(cwd, "the schedule_data column can be written before authentication", "auth-bypass");
  const result = addNode(cwd, {
    description: "the scheduled task deserializes attacker-controlled bytes",
    category: "deserialization",
    requires: [gate.id, gate.id],
  });
  assert.equal(result.ok, false);
  assert.match(result.ok ? "" : result.errors[0]!, /same gate twice/);
});

test("an empty requires array REMOVES the gates", () => {
  const cwd = seeded();
  const gate = add(cwd, "the schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);
  assert.equal(chainOf(cwd, sink.id).state, "gated");
  // The finding turned out to stand alone.
  assert.equal(applyNodePatch(cwd, sink.id, { requires: [] }, "").ok, true);
  assert.equal(chainOf(cwd, sink.id).state, "standalone");
});

// -----------------------------------------------------------------
// The gate is the most valuable hypothesis in the tree
// -----------------------------------------------------------------

test("a gate of a CONFIRMED finding outranks a novel hypothesis", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  deserSink(cwd, [gate.id]);
  const fresh = add(cwd, "the export endpoint returns records the caller does not own", "idor");

  const snap = load(cwd).snapshot;
  const context = buildContext(snap, 5);
  const gateScore = scoreCandidate(getNode(snap, gate.id)!, context);
  const freshScore = scoreCandidate(getNode(snap, fresh.id)!, context);

  assert.ok(gateScore.gateBoost > 0, "the gate is recognised");
  assert.ok(freshScore.gateBoost === 0, "the unrelated node is not");
  // Both are unexamined, so the difference is the gate boost alone.
  assert.ok(
    gateScore.total > freshScore.total,
    `verifying the gate is what turns a confirmed sink into an exploit; gate ${gateScore.total} must beat novel ${freshScore.total}`,
  );

  const decision = planNextRound(snap, { round: 5 });
  assert.equal(decision.selected?.id, gate.id, "and the scheduler actually picks it");
});

test("a gate of an UNCONFIRMED finding gets no boost", () => {
  const cwd = seeded();
  const gate = add(cwd, "the schedule_data column can be written before authentication", "auth-bypass");
  // The dependent finding is NOT confirmed, so its gate is just another node.
  add(cwd, "the scheduled task deserializes attacker-controlled bytes", "deserialization", [gate.id]);

  const snap = load(cwd).snapshot;
  assert.equal(scoreCandidate(getNode(snap, gate.id)!, buildContext(snap, 5)).gateBoost, 0);
});

test("a gate of an already chain-READY finding gets no boost", () => {
  const cwd = seeded();
  const gate = add(cwd, "the schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);
  setStatus(cwd, gate.id, "confirmed", { severity: "critical", evidence: [ANCHORED] });
  assert.equal(chainOf(cwd, sink.id).state, "chain-ready");

  // The gate is resolved; there is nothing left to convert.
  const other = add(cwd, "the export endpoint returns records the caller does not own", "idor");
  const snap = load(cwd).snapshot;
  const context = buildContext(snap, 6);
  assert.equal(scoreCandidate(getNode(snap, gate.id)!, context).gateBoost, 0);
  void other;
});

test("gatesOf finds every dependent of a node", () => {
  const cwd = seeded();
  const gate = add(cwd, "the schedule_data column can be written before authentication", "auth-bypass");
  const a = deserSink(cwd, [gate.id]);
  const b = add(cwd, "the export path also deserializes the same column", "deserialization", [gate.id]);
  const dependents = gatesOf(load(cwd).snapshot, gate.id).map((n) => n.id).sort();
  assert.deepEqual(dependents, [a.id, b.id].sort());
});

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

test("a gated finding is reported as NOT usable, with its gate named", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);

  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*攻击链:\*\*/);
  assert.match(text, /\*\*攻击链未成立\*\* —— 还需要这些前提成立/);
  assert.match(text, new RegExp(`… \\*\\*${gate.id}\\*\\*`), "the open gate is marked");
  assert.match(text, /sink 是真的，但路还没打通/);
  // And the summary counts it as unusable.
  assert.match(text, /\*\*0\/1\*\* \|/);
  assert.match(text, /其中 1\/1 条的利用前提尚未验证/);
  assert.match(text, /不要当作可用漏洞上报/);
});

test("a chain-ready finding says so", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);
  setStatus(cwd, gate.id, "confirmed", { severity: "critical", evidence: [ANCHORED] });

  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*攻击链成立\*\* —— 所有前提已确认/);
  assert.match(text, /这一条可以实际利用/);
  assert.match(text, new RegExp(`✓ \\*\\*${gate.id}\\*\\*`));
});

test("a broken chain says the sink is real but the entry is not", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);
  setStatus(cwd, gate.id, "rejected", { reason: "admin-only writer", evidence: [ANCHORED] });

  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*攻击链已断\*\*/);
  assert.match(text, /sink 仍然真实，但入口不成立/);
  assert.match(text, new RegExp(`✗ \\*\\*${gate.id}\\*\\*`));
  void sink;
});

test("an unassessed finding says so instead of claiming it stands alone", () => {
  const cwd = seeded();
  const node = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass");
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*攻击链:\*\*/);
  assert.match(text, /\*\*利用前提未评估\*\*/);
  assert.match(text, /\*\*这不等于它不需要依赖。\*\*/);
  assert.match(text, /响应是否回显/, "and it names what to ask");
  // It must NOT be counted as usable.
  assert.match(text, /\| \*\*可实际利用（攻击链完整）\*\* \| \*\*0\/1\*\* \|/);
  assert.match(text, /\| \*\*利用前提未评估\*\* \| 1\/1 \|/);
  assert.match(text, /其中 1\/1 条的利用前提从未被评估/);
});

test("a deliberately standalone finding has no chain block at all", () => {
  const cwd = seeded();
  const node = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass", []);
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.doesNotMatch(text, /\*\*攻击链:\*\*/);
  assert.match(text, /\| \*\*可实际利用（攻击链完整）\*\* \| \*\*1\/1\*\* \|/);
  assert.match(text, /每条确认发现都标了攻击链状态/);
});

test("recorded-but-untracked preconditions are called out, and not counted as usable", () => {
  const cwd = seeded();
  const node = add(cwd, "the server fetches a caller-supplied URL and returns the parsed body", "ssrf");
  applyNodePatch(
    cwd,
    node.id,
    { attackVector: { entrypoint: "POST /import", technique: "caller-supplied URL", path: [{ detail: "fetches it" }], preconditions: ["是否有回显通道未评估", "file:// 是否在白名单里未评估"] } },
    "",
  );
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*前提未跟踪\*\*/);
  assert.match(text, /记录了 2 个前置条件，但\*\*没有任何一条被变成假设\*\*/);
  assert.match(text, /- 是否有回显通道未评估/);
  assert.match(text, /这条发现现在读起来像是可用的，而它可能不是/);
  assert.match(text, /\| \*\*可实际利用（攻击链完整）\*\* \| \*\*0\/1\*\* \|/);
});

test("the chain block is in English for an English report", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  deserSink(cwd, [gate.id]);
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /\*\*Chain:\*\*/);
  assert.match(text, /\*\*CHAIN NOT READY\*\*/);
});

// -----------------------------------------------------------------
// The contract
// -----------------------------------------------------------------

test("requireExploitable refuses a gated finding as a finish line", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  const sink = deserSink(cwd, [gate.id]);
  applyNodePatch(cwd, sink.id, { challengedRound: 1 }, "");
  applyNodePatch(cwd, gate.id, { challengedRound: 1 }, "");

  // The default contract counts the confirmed SINK, gates and all.
  const lenient = buildContract({ requireConsolidated: false });
  assert.equal(lenient.requireExploitable, false);
  assert.equal(contractMet(load(cwd).snapshot, lenient).met, true);

  // requireExploitable demands a finding that can actually be used.
  const strict = buildContract({ requireConsolidated: false, requireExploitable: true });
  const evaluation = contractMet(load(cwd).snapshot, strict);
  assert.equal(evaluation.met, false, "a gated sink is not a usable finding");
  assert.ok(evaluation.detail.some((d) => /chain not ready|excluded/i.test(d)), evaluation.detail.join(" | "));

  // Confirming the gate satisfies it.
  setStatus(cwd, gate.id, "confirmed", { severity: "critical", evidence: [ANCHORED] });
  assert.equal(contractMet(load(cwd).snapshot, strict).met, true);
});

test("the loop schedules the gate instead of another novel hypothesis", () => {
  const cwd = seeded();
  const gate = add(cwd, "the Scheduled_Tasks.schedule_data column can be written before authentication", "auth-bypass");
  deserSink(cwd, [gate.id]);
  for (let i = 0; i < 6; i++) add(cwd, `the endpoint number ${i} returns records the caller does not own`, "idor");

  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  // Round 1 is the forced combination pass (a finding was just confirmed), so
  // what matters is which node the first VERIFY round picks.
  const seen: string[] = [];
  let picked: string | null = null;
  for (let i = 0; i < 5; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const recs = load(cwd).snapshot.roundRecords;
    const rec = recs[recs.length - 1]!;
    seen.push(`${rec.kind}:${rec.nodeId ?? "-"}`);
    if (rec.kind === "verify" && rec.nodeId) { picked = rec.nodeId; break; }
  }
  assert.equal(
    picked,
    gate.id,
    `the gate comes first — it is what converts the sink into an exploit. Saw: ${seen.join(" ")}`,
  );
});
