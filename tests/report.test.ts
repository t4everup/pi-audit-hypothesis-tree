// pi-audit-hypothesis-tree — tests/report.test.ts
//
// Pins the deliverable: the verification tier (how well a verdict is
// supported), the contract's tier gate, and the audit report.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, applyNodePatch, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { applyCombination } from "../extensions/hypothesis-tree/combination.ts";
import { buildContract, contractMet, startLoop } from "../extensions/hypothesis-tree/loop.ts";
import { reportPath, renderReport, writeReport } from "../extensions/hypothesis-tree/report.ts";
import { meetsTier, tierLabel, tierRank, verificationTier } from "../extensions/hypothesis-tree/types.ts";
import type { AttackVector, Evidence, Hypothesis } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-report-"));
}

const A = "the login handler accepts a JWT without verifying its signature";

function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

function add(cwd: string, description: string, category: string): Hypothesis {
  const result = addNode(cwd, { description, category });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result.ok ? result.value.node : (undefined as never);
}

const ARGUMENT: Evidence = { kind: "reasoning", at: "", detail: "it looks wrong" };
const ANCHORED: Evidence = { kind: "code-slice", at: "", location: { file: "src/auth.ts", line: 57 }, detail: "decode(token)" };
const REPRODUCED: Evidence = { kind: "command-output", at: "", command: "curl -sS /api/x", detail: "HTTP 200 with the record" };

function withEvidence(evidence: Evidence[]): Pick<Hypothesis, "evidence"> {
  return { evidence };
}

// -----------------------------------------------------------------
// The verification tier
// -----------------------------------------------------------------

test("the tier is derived from the evidence, never declared", () => {
  assert.equal(verificationTier(withEvidence([])), "reasoning-only");
  assert.equal(verificationTier(withEvidence([ARGUMENT])), "reasoning-only");
  assert.equal(verificationTier(withEvidence([ANCHORED])), "static");
  assert.equal(verificationTier(withEvidence([ARGUMENT, ANCHORED])), "static");
  assert.equal(verificationTier(withEvidence([ANCHORED, REPRODUCED])), "reproduced");
});

test("a command-output with no command does not count as reproduced", () => {
  // The command is what makes it re-runnable; without it the output is a claim.
  assert.equal(verificationTier(withEvidence([{ kind: "command-output", at: "", detail: "HTTP 200" }])), "reasoning-only");
});

test("a code-slice with no location does not count as anchored", () => {
  assert.equal(verificationTier(withEvidence([{ kind: "code-slice", at: "", detail: "decode(token)" }])), "reasoning-only");
});

test("tiers compare by strength", () => {
  assert.ok(tierRank("reproduced") > tierRank("static"));
  assert.ok(tierRank("static") > tierRank("reasoning-only"));
  assert.equal(meetsTier("reproduced", "static"), true);
  assert.equal(meetsTier("static", "reproduced"), false);
  assert.match(tierLabel("reasoning-only"), /an opinion, not a finding/);
  assert.match(tierLabel("static"), /not reproduced/);
  assert.match(tierLabel("reproduced"), /a command was run/);
});

// -----------------------------------------------------------------
// The contract's tier gate — the "trustworthy" half
// -----------------------------------------------------------------

test("the default contract demands a HIGH-or-worse finding anchored in code", () => {
  const contract = buildContract({});
  assert.equal(contract.minSeverity, "high", "a security audit means high severity, not any severity");
  assert.equal(contract.requireArtifact, true, "a verdict resting on an argument is not a finding");
  assert.equal(contract.requireReproduced, false, "reproduction needs allowCommandProbes, so it is opt-in");
});

test("a confirmed finding backed only by an argument does NOT satisfy the contract", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "critical", evidence: [ARGUMENT] });
  const evaluation = contractMet(load(cwd).snapshot, buildContract({ requireConsolidated: false, requireChallenged: false }));
  assert.equal(evaluation.met, false, "an opinion must not close an audit");
  assert.match(evaluation.detail.join("\n"), /0\/1 qualifying confirmed finding/);
  assert.match(evaluation.detail.join("\n"), /excluded: reasoning only, no artifact/);
});

test("an anchored finding satisfies the artifact gate", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  const evaluation = contractMet(load(cwd).snapshot, buildContract({ requireConsolidated: false, requireChallenged: false }));
  assert.equal(evaluation.met, true, evaluation.detail.join("; "));
});

test("requireReproduced excludes a merely static finding", () => {
  const cwd = seeded();
  const staticNode = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, staticNode.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  const staticOnly = contractMet(load(cwd).snapshot, buildContract({ requireConsolidated: false, requireReproduced: true, requireChallenged: false }));
  assert.equal(staticOnly.met, false);
  assert.match(staticOnly.detail.join("\n"), /excluded: not reproduced by a command/);

  const reproducedNode = add(cwd, "the queue consumer deserializes without a type allowlist", "deserialization");
  setStatus(cwd, reproducedNode.id, "confirmed", { severity: "high", evidence: [REPRODUCED] });
  const reproduced = contractMet(load(cwd).snapshot, buildContract({ requireConsolidated: false, requireReproduced: true, requireChallenged: false }));
  assert.equal(reproduced.met, true, reproduced.detail.join("; "));
});

test("the default contract is not met by an UNRATED confirmed finding", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { evidence: [ANCHORED] });
  const evaluation = contractMet(load(cwd).snapshot, buildContract({ requireConsolidated: false, requireChallenged: false }));
  assert.equal(evaluation.met, false);
  assert.match(evaluation.detail.join("\n"), /carry no severity yet/);
});

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

function buildScenario(): string {
  const cwd = seeded();
  const confirmed = add(cwd, "the refresh handler accepts a JWT without verifying its signature", "auth-bypass");
  const refuted = add(cwd, "the export endpoint returns records the caller does not own", "idor");
  const open = add(cwd, "the webhook fetcher follows redirects to internal addresses", "ssrf");
  const opinion = add(cwd, "the session cookie is issued without the Secure flag", "misconfiguration");
  setStatus(cwd, confirmed.id, "confirmed", {
    severity: "high",
    reason: "the refresh path calls decode() and never verify(); established by reading both files",
    evidence: [ANCHORED, { ...ANCHORED, location: { file: "src/refresh.ts", line: 12 } }],
  });
  setStatus(cwd, refuted.id, "rejected", {
    reason: "owner_id is compared before the record is returned",
    evidence: [{ kind: "code-slice", at: "", location: { file: "src/export.ts", line: 88 }, detail: "owner_id is compared" }],
  });
  setStatus(cwd, opinion.id, "confirmed", {
    severity: "high",
    reason: "the cookie is set without the Secure attribute",
    evidence: [ARGUMENT],
  });
  void open;
  return cwd;
}

test("the report leads with the run's outcome and its counts", () => {
  const cwd = buildScenario();
  startLoop(cwd, load(cwd).snapshot, { kind: "goal", objective: "audit", plateauWindow: 99 });
  const text = renderReport(load(cwd).snapshot, load(cwd).snapshot.loop, { language: "en" });
  assert.match(text, /^# Code audit report/);
  assert.match(text, /- \*\*Run\*\*: goal · running/);
  assert.match(text, /\| Hypotheses recorded \| 4 \|/);
  assert.match(text, /\| \*\*Confirmed\*\* \| 2 \|/);
  // The count is split by the contract's severity floor, so a report for a "high"
  // goal cannot read as though the target was met. Both findings in this scenario
  // ARE at target, so there is no below-target row at all.
  assert.match(text, /\| \*\*Confirmed \(at target: >= high\)\*\* \| \*\*2\*\* \|/);
  assert.doesNotMatch(text, /Confirmed \(below high/);
  assert.match(text, /\| Rejected \(ruled out\) \| 1 \|/);
});

test("the report prints the verification tier of every confirmed finding", () => {
  const cwd = buildScenario();
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /0 reproduced \(a command was run and re-runnable\)/);
  assert.match(text, /1 static \(anchored in code, not reproduced\)/);
  assert.match(text, /1 reasoning only — \*\*these are opinions, not findings\*\*/);
  assert.match(text, /\*\*Verification:\*\* STATIC \(anchored in code, not reproduced\)/);
  assert.match(text, /\*\*Verification:\*\* REASONING ONLY \(no artifact — an opinion, not a finding\)/);
  assert.match(text, /Treat it as a lead to check, never as a confirmed vulnerability/);
});

test("the report puts confirmed findings worst-first and shows the assertion and the auditor's own scope statement", () => {
  const cwd = buildScenario();
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /### 1\. H-0002 — HIGH — auth-bypass/);
  assert.match(text, /\*\*Assertion\.\*\* The `refresh` handler|the refresh handler accepts a JWT/);
  assert.match(text, /\*\*The auditor's own statement of scope\*\*/);
  assert.match(text, /^> /m, "the reason is quoted, not paraphrased");
});

test("the report says a tree that refuted nothing is a gap, not a clean result", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /## Ruled out \(0\)/);
  assert.match(text, /A tree that only confirms has not been testing anything/);
});

test("the report lists what was NOT examined, in the scheduler's order", () => {
  const cwd = buildScenario();
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  // Four hypotheses: one confirmed+anchored, one refuted, one confirmed on an
  // argument (which the contract excludes but the report still shows), and one
  // never examined.
  assert.match(text, /## Not examined \(1\)/);
  assert.match(text, /Nothing here is a claim either way/);
  assert.match(text, /H-0004/);
  assert.doesNotMatch(text, /## Not examined \(1\)[\s\S]*H-0002/, "a confirmed finding is not listed as unexamined");
});

test("the report states plainly what it does not claim", () => {
  const cwd = buildScenario();
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /## What this report does NOT claim/);
  assert.match(text, /It is not a penetration test/);
  assert.match(text, /Absence of a finding is not absence of a vulnerability/);
  assert.match(text, /Severity is the auditor's judgement/);
});

test("the location prefers the attack vector's SINK, not the first evidence entry", () => {
  const cwd = seeded();
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "pending")!;
  const vector: AttackVector = {
    entrypoint: "POST /api/login",
    technique: "alg=none",
    path: [
      { detail: "send the token", location: { file: "src/api/login.ts", line: 40 } },
      { detail: "the verifier accepts it", location: { file: "src/auth/jwt.ts", line: 88 } },
    ],
  };
  const result = addNode(cwd, { description: "the verifier trusts the alg header", category: "auth-bypass", attackVector: vector });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  setStatus(cwd, result.ok ? result.value.node.id : node.id, "confirmed", {
    severity: "high",
    // A background grep in a dependency comes FIRST in the evidence; the
    // location must not be taken from it.
    evidence: [{ kind: "code-slice", at: "", location: { file: "vendor/x/y.php", line: 3 }, detail: "noise" }],
  });
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /\*\*Location:\*\* `src\/auth\/jwt\.ts:88`/, "the sink, not the noise");
  assert.doesNotMatch(text, /\*\*Location:\*\* `vendor/);
});

test("the report is written in place and reports a failure instead of pretending", () => {
  const cwd = buildScenario();
  const written = writeReport(cwd, load(cwd).snapshot, null, { language: "en" });
  assert.equal(written.ok, true, written.errors.join("; "));
  assert.equal(written.path, reportPath(cwd));
  assert.match(fs.readFileSync(written.path, "utf-8"), /^# Code audit report/);

  const blocked = tmpProject();
  fs.mkdirSync(reportPath(blocked), { recursive: true });
  assert.equal(writeReport(blocked, load(blocked).snapshot, null, { language: "en" }).ok, false);
});

test("a combination-produced finding carries its lineage into the report", () => {
  const cwd = seeded();
  const a = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass");
  const b = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  setStatus(cwd, a.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  setStatus(cwd, b.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  const combined = applyCombination(cwd, load(cwd).snapshot, {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: [a.id, b.id],
  });
  assert.equal(combined.ok, true, combined.ok ? "" : combined.errors.join("; "));
  setStatus(cwd, combined.node!.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /\*\*Derived by combination\.\*\* shared-root-cause of H-0002 \+ H-0003/);
});

test("an empty tree still produces a usable report", () => {
  const cwd = tmpProject();
  createTree(cwd, "the project rooted at cwd", { nodeKind: "scope" });
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /^# Code audit report/);
  assert.match(text, /\| Hypotheses recorded \| 0 \|/);
  assert.match(text, /\*\*No finding was confirmed\.\*\*/);
  assert.match(text, /That is a result, not a failure/);
  assert.match(text, /_None\._/);
});

test("the report is derived from state — no model summary is invented", () => {
  const cwd = buildScenario();
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /No summary here is model-generated — every line is derived from the recorded state/);
});

// -----------------------------------------------------------------
// #4: the report splits confirmed findings at the target severity
// -----------------------------------------------------------------
//
// A real run produced 7 confirmed findings of which 3 were `info`, all in ONE
// list — so a report for a "pre-auth HIGH" goal read as though the target had been
// met.

test("findings below the contract floor are a SEPARATE section", () => {
  const cwd = seeded();
  const high = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  const info = add(cwd, "the login page leaks the build identifier in a header", "info-disclosure");
  const evidence = [{ kind: "code-slice" as const, at: "", location: { file: "src/a.ts", line: 1 }, detail: "x" }];
  setStatus(cwd, high.id, "confirmed", { severity: "high", evidence });
  setStatus(cwd, info.id, "confirmed", { severity: "info", evidence });
  startLoop(cwd, load(cwd).snapshot, { kind: "goal", objective: "audit", contract: buildContract({ severity: "high" }) });

  const text = renderReport(load(cwd).snapshot, load(cwd).snapshot.loop, { language: "zh" });
  assert.match(text, /## 已确认发现（达标：≥ high，1 条）/);
  assert.match(text, /## 已确认发现（未达标：低于 high 或未评级，1 条）/);
  assert.match(text, /这 1 条是\*\*真实但低于目标等级\*\*的发现/);
  assert.match(text, /\| \*\*已确认（达标 ≥ high）\*\* \| \*\*1\*\* \|/);
  assert.match(text, /\| 已确认（低于 high 或未评级） \| 1 \|/);
  // The `info` finding is still THERE — it is real — just not mixed in.
  assert.match(text, /the login page leaks the build identifier/);
});

test("with no contract the floor is medium, so a /loop still splits", () => {
  const cwd = seeded();
  const med = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  const low = add(cwd, "the health probe discloses the build identifier without authentication", "info-disclosure");
  const evidence = [{ kind: "code-slice" as const, at: "", location: { file: "src/a.ts", line: 1 }, detail: "x" }];
  setStatus(cwd, med.id, "confirmed", { severity: "medium", evidence });
  setStatus(cwd, low.id, "confirmed", { severity: "low", evidence });
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit" });

  const text = renderReport(load(cwd).snapshot, load(cwd).snapshot.loop, { language: "en" });
  assert.match(text, /## Confirmed findings \(at target: >= medium, 1\)/);
  assert.match(text, /## Confirmed findings \(below medium, or unrated: 1\)/);
});

test("an UNRATED finding counts as below target, not as low", () => {
  const cwd = seeded();
  const node = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  setStatus(cwd, node.id, "confirmed", { evidence: [{ kind: "code-slice", at: "", location: { file: "src/a.ts", line: 1 }, detail: "x" }] });
  startLoop(cwd, load(cwd).snapshot, { kind: "goal", objective: "audit", contract: buildContract({ severity: "high" }) });
  const text = renderReport(load(cwd).snapshot, load(cwd).snapshot.loop, { language: "en" });
  assert.match(text, /below high, or unrated: 1/);
  assert.match(text, /Nothing reached the target severity/);
});

test("the report shows the written refutation attempt, and says when there is none", () => {
  const cwd = seeded();
  const a = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  const b = add(cwd, "the export endpoint returns records the caller does not own", "idor");
  const evidence = [{ kind: "code-slice" as const, at: "", location: { file: "src/a.ts", line: 1 }, detail: "x" }];
  setStatus(cwd, a.id, "confirmed", { severity: "high", evidence });
  setStatus(cwd, b.id, "confirmed", { severity: "high", evidence });
  applyNodePatch(cwd, a.id, { refutation: { at: "", attempt: "grepped the parent class for a guard; none exists" } }, "");

  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /\*\*Refutation attempt \(written\):\*\* grepped the parent class for a guard; none exists/);
  // And the one with nothing behind it says so.
  assert.match(text, /\*\*Refutation attempt: NONE\*\*/);
  assert.match(text, /It is the auditor agreeing with itself/);
});
