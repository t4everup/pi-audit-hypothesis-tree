// pi-audit-hypothesis-tree — tests/finding-dossier.test.ts
//
// Pins the shape of a finding in the report: the three sections every finding
// carries, what they say when they are EMPTY, and the fact that the report is
// written in the operator's language while the findings are quoted verbatim.
//
// The empty cases are the reason this file exists. "No impact recorded" and
// "no impact" are different claims, and a report that silently drops the section
// lets the reader assume the second.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, applyNodePatch, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { buildContract, contractMet, startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import { dossierOf, renderReport, writeReport } from "../extensions/hypothesis-tree/report.ts";
import { DEFAULT_SETTINGS, loadSettings, saveSettings, settingsPath } from "../extensions/hypothesis-tree/settings.ts";
import { REPORT_LANGUAGES, reportStrings, severityLabel } from "../extensions/hypothesis-tree/reportText.ts";
import type { AttackVector, Evidence, Hypothesis } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-dossier-"));
}

function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

function add(cwd: string, description: string, attackVector?: AttackVector): Hypothesis {
  const result = addNode(cwd, { description, category: "auth-bypass", ...(attackVector ? { attackVector } : {}) });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result.ok ? result.value.node : (undefined as never);
}

const ANCHORED: Evidence = {
  kind: "code-slice",
  at: "",
  location: { file: "src/api/gorgone.ts", line: 66 },
  detail: "public function sendCommand(Request $request) {",
};
const RAN: Evidence = {
  kind: "command-output",
  at: "",
  command: "curl -sS -X POST http://target/api/gorgone/command",
  detail: "HTTP/1.1 200 OK\n{\"result\":\"ok\"}",
};

function fullVector(): AttackVector {
  return {
    entrypoint: "POST /api/gorgone/command",
    technique: "未鉴权的 Gorgone 命令转发",
    path: [
      { detail: "防火墙只声明 security: true，access_control 为空", location: { file: "config/packages/security.yaml", line: 12 } },
      { detail: "控制器直接转发命令", location: { file: "src/api/gorgone.ts", line: 66 } },
      { detail: "到达 GorgoneService::send", location: { file: "src/service/gorgone.ts", line: 95 } },
    ],
    impact: "以 Gorgone 的权限在任意被管主机上执行命令，进而接管中心节点",
    payload: "{\"command\":\"whoami\"}",
    preconditions: ["api 防火墙未做 IP 限制"],
  };
}

function confirmed(cwd: string, node: Hypothesis, evidence: Evidence[], severity: Hypothesis["severity"] = "high"): void {
  setStatus(cwd, node.id, "confirmed", { severity, evidence });
}

// -----------------------------------------------------------------
// The three sections are always present
// -----------------------------------------------------------------

test("every confirmed finding carries the call chain, the impact and the PoC", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);

  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /#### 调用链/);
  assert.match(text, /#### 可利用干什么/);
  assert.match(text, /#### PoC 验证/);

  // The chain is the vector's path, numbered, with locations a reader can open.
  // In a FENCE now: the file:line sits on its own line so the chain scans down
  // one column, and a multi-line step detail cannot leak out and break the
  // markdown around it.
  assert.match(text, /^1\. config\/packages\/security\.yaml:12$/m);
  assert.match(text, /^   防火墙只声明 security: true/m);  assert.match(text, /^2\. src\/api\/gorgone\.ts:66$/m);
  assert.match(text, /^3\. src\/service\/gorgone\.ts:95$/m);
  assert.match(text, /^入口  POST \/api\/gorgone\/command$/m);
  assert.match(text, /^手法  未鉴权的 Gorgone 命令转发$/m);
  assert.match(text, /^载荷  \{"command":"whoami"\}$/m);
  assert.match(text, /^前置条件  api 防火墙未做 IP 限制$/m);

  // The impact is the auditor's own sentence, not a restatement of the technique.
  assert.match(text, /以 Gorgone 的权限在任意被管主机上执行命令/);
});

test("a missing impact says NOT ASSESSED and explains the difference", () => {
  const cwd = seeded();
  const vector = fullVector();
  delete (vector as { impact?: string }).impact;
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", vector);
  confirmed(cwd, node, [ANCHORED]);

  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /_未评估影响。/);
  assert.match(text, /这不是「没有影响」，而是「没有评估」/);
  // And the section is still there: a reader must be able to see the gap.
  assert.match(text, /#### 可利用干什么/);
});

test("a finding with no attack vector at all says so without claiming unreachable", () => {
  const cwd = seeded();
  const node = add(cwd, "the export endpoint returns records the caller does not own");
  confirmed(cwd, node, [ANCHORED]);

  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /_未记录调用链。/);
  assert.match(text, /「还不知道怎么到达」和「不可达」是两件不同的事/);
  assert.match(text, /_未评估影响。/);
});

test("the PoC section reflects what was actually executed", () => {
  const cwd = seeded();
  const reproduced = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, reproduced, [ANCHORED, RAN]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /状态  已复现 —— 下面的命令真的运行过，可重跑/);
  assert.match(text, /^命令  curl -sS -X POST http:\/\/target\/api\/gorgone\/command$/m);
  assert.match(text, /^输出$/m);
  assert.doesNotMatch(text, /状态  静态证据，未复现/);
});

test("a static-only finding says nothing was executed, and what a PoC would need", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /状态  静态证据，未复现 —— 下面的代码锚点是发现的基础，但没有运行任何东西/);
  assert.match(text, /^锚点  src\/api\/gorgone\.ts:66$/m);
});

test("a finding with no artifact is marked as an opinion, not a vulnerability", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [{ kind: "reasoning", at: "", detail: "看起来不对" }]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /状态  没有物证 —— 只有论证，没有代码锚点，也没有运行过任何命令/);
  assert.match(text, /必须先验证  没有代码锚点也没有运行过任何命令——在验证之前它不是发现，是线索/);
  assert.match(text, /1 条仅推理——\*\*这些是观点，不是发现\*\*/);
});

// -----------------------------------------------------------------
// The dossier count
// -----------------------------------------------------------------

test("dossierOf counts PRESENCE, not quality", () => {
  const cwd = seeded();
  const complete = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, complete, [ANCHORED]);
  assert.deepEqual(dossierOf(load(cwd).snapshot.byId.get(complete.id)!), {
    chain: true,
    impact: true,
    poc: true,
    complete: true,
  });

  // A chain with no locations is still "present" — the tool cannot judge whether
  // a chain is any good, only whether the auditor wrote one down.
  const noLocations = add(cwd, "the export endpoint returns records the caller does not own", {
    entrypoint: "GET /api/export",
    technique: "missing ownership filter",
    path: [{ detail: "no location given" }],
    impact: "read another tenant's records",
  });
  confirmed(cwd, noLocations, [ANCHORED]);
  assert.equal(dossierOf(load(cwd).snapshot.byId.get(noLocations.id)!).complete, true);
});

test("the summary counts complete dossiers and warns about the rest", () => {
  const cwd = seeded();
  const a = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  const b = add(cwd, "the export endpoint returns records the caller does not own", {
    entrypoint: "GET /api/export",
    technique: "missing ownership filter",
    path: [{ detail: "no filter", location: { file: "src/api/export.ts", line: 20 } }],
  });
  confirmed(cwd, a, [ANCHORED]);
  confirmed(cwd, b, [ANCHORED]);

  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*1\/2 条发现具备完整档案\*\*/);
  assert.match(text, /缺失不是「没有影响」，而是「没有评估」/);
});

test("an empty impact is not an impact", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", {
    ...fullVector(),
    impact: "   ",
  });
  confirmed(cwd, node, [ANCHORED]);
  assert.equal(dossierOf(load(cwd).snapshot.byId.get(node.id)!).impact, false);
  assert.match(renderReport(load(cwd).snapshot, null, { language: "zh" }), /_未评估影响。/);
});

// -----------------------------------------------------------------
// Language
// -----------------------------------------------------------------

test("zh is the default, and every string exists in both languages", () => {
  assert.equal(DEFAULT_SETTINGS.reportLanguage, "zh");
  const zh = reportStrings("zh");
  const en = reportStrings("en");
  assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort(), "a missing translation must fail the build, not the report");
  for (const key of Object.keys(zh) as (keyof typeof zh)[]) {
    const a = zh[key];
    const b = en[key];
    if (typeof a === "string") assert.equal(typeof b, "string", `${key} must be a string in both`);
    else if (Array.isArray(a)) assert.equal((b as unknown[]).length, a.length, `${key} must have the same number of lines`);
    else assert.equal(typeof b, "function", `${key} must be a formatter in both`);
  }
});

test("the same finding renders in either language with the model's text untouched", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);
  const snap = load(cwd).snapshot;

  const zh = renderReport(snap, null, { language: "zh" });
  const en = renderReport(snap, null, { language: "en" });
  assert.match(zh, /# 代码审计报告/);
  assert.match(en, /# Code audit report/);
  for (const text of [zh, en]) {
    // The assertion, the impact and the evidence are QUOTED, never translated:
    // a report that paraphrases its own evidence is laundering it.
    assert.match(text, /the gorgone command endpoint forwards without a role check/);
    assert.match(text, /以 Gorgone 的权限在任意被管主机上执行命令/);
    assert.match(text, /public function sendCommand\(Request \$request\) \{/);
  }
});

test("severity is labelled in the reader's language", () => {
  assert.equal(severityLabel("high", "zh"), "高危");
  assert.equal(severityLabel("critical", "zh"), "严重");
  assert.equal(severityLabel(undefined, "zh"), "未评级");
  assert.equal(severityLabel("high", "en"), "HIGH");
  assert.equal(severityLabel(undefined, "en"), "UNRATED");
});

test("the reportLanguage setting round-trips and rejects a typo", () => {
  const cwd = seeded();
  assert.equal(loadSettings(cwd).settings.reportLanguage, "zh", "defaults");
  assert.equal(saveSettings(cwd, { reportLanguage: "en" }).ok, true);
  assert.equal(loadSettings(cwd).settings.reportLanguage, "en", "from file");

  const bad = saveSettings(cwd, { reportLanguage: "cn" as never });
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0]!, /reportLanguage must be one of: zh, en/);
  assert.equal(loadSettings(cwd).settings.reportLanguage, "en", "the bad write changed nothing");
  assert.deepEqual(REPORT_LANGUAGES, ["zh", "en"]);
});

test("an unreadable settings file falls back to Chinese rather than crashing", () => {
  const cwd = seeded();
  fs.writeFileSync(settingsPath(cwd), "{ not json", "utf-8");
  const loaded = loadSettings(cwd);
  assert.equal(loaded.settings.reportLanguage, "zh");
  assert.ok(loaded.error);
});

test("writeReport honours the language it is given", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);
  const written = writeReport(cwd, load(cwd).snapshot, null, { language: "en" });
  assert.equal(written.ok, true, written.errors.join("; "));
  assert.match(fs.readFileSync(path.join(cwd, ".pi-hypothesis", "REPORT.md"), "utf-8"), /^# Code audit report/);
});

// -----------------------------------------------------------------
// The report renders the impact section for a hand-built tree too
// -----------------------------------------------------------------

test("the report renders all three sections even when nothing is confirmed", () => {
  const cwd = seeded();
  add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /## 已确认 \(0\)/);
  assert.match(text, /_无。_/);
  assert.match(text, /没有确认任何漏洞/);
  // The unexamined list still shows where the vector would take an attacker.
  assert.match(text, /→ POST \/api\/gorgone\/command/);
});

// -----------------------------------------------------------------
// The contract clause
// -----------------------------------------------------------------

test("requireImpact is off by default and gates the contract when on", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", {
    ...fullVector(),
    impact: undefined,
  });
  confirmed(cwd, node, [ANCHORED]);
  applyNodePatch(cwd, node.id, { challengedRound: 1 }, "");
  const snap = () => load(cwd).snapshot;

  const lenient = buildContract({ requireConsolidated: false });
  assert.equal(lenient.requireImpact, false);
  assert.equal(contractMet(snap(), lenient).met, true, "an unassessed impact does not block a default goal");

  const strict = buildContract({ requireConsolidated: false, requireImpact: true });
  const evaluation = contractMet(snap(), strict);
  assert.equal(evaluation.met, false);
  assert.match(evaluation.detail[0]!, /excluded: not yet challenged|0\/1 qualifying/);

  // Filling the impact in unblocks it.
  applyNodePatch(cwd, node.id, { attackVector: { ...fullVector() } }, "");
  assert.equal(contractMet(load(cwd).snapshot, strict).met, true);
});

test("describeContract names the impact clause only when it is on", () => {
  const { describeContract } = require("../extensions/hypothesis-tree/loop.ts") as typeof import("../extensions/hypothesis-tree/loop.ts");
  assert.doesNotMatch(describeContract(buildContract({})), /what an attacker gains/);
  assert.match(describeContract(buildContract({ requireImpact: true })), /each stating what an attacker gains/);
});

// -----------------------------------------------------------------
// Skills
// -----------------------------------------------------------------
//
// pi puts a skill LIST in the system prompt and expects the model to read a
// SKILL.md when the task matches. Its own docs warn that models often do not —
// and a round brief makes that worse, because the brief is a complete procedure,
// so the model has no reason to go looking for a second set of instructions.

test("every brief tells the model to consult a matching skill", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", fullVector());
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;
  assert.match(brief, /## 技能（skills）/);
  assert.match(brief, /先 read 它的 SKILL\.md/);
  assert.match(brief, /当作「\*\*找什么\*\*」/);
});

test("the brief keeps the skill's PROCESS from overwriting the extension's", () => {
  // A skill written for the same job carries its own node labels, its own status
  // vocabulary and its own quotas. A model holding both produces a tree the
  // tools cannot read, so the split is stated explicitly.
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", fullVector());
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;

  assert.match(brief, /节点编号用工具返回的 `H-xxxx`/);
  assert.match(brief, /不要用技能自创的/);
  assert.match(brief, /状态词只用 `hypothesis_record` 支持的那几个/);
  assert.match(brief, /忽略它的流程部分/);
  assert.match(brief, /反钻牛角尖的硬限制/);
  assert.match(brief, /不要为了读技能浪费一轮/);
});

test("the skill guidance is in English for an English project", () => {
  const cwd = seeded();
  saveSettings(cwd, { reportLanguage: "en" });
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", fullVector());
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;
  assert.match(brief, /## Skills/);
  assert.match(brief, /read its SKILL\.md first/);
  assert.match(brief, /do NOT use a skill's own `H1\.2\.3` labels/);
  assert.match(brief, /ignore the process half/);
});

test("the skill guidance rides in EVERY kind of brief, not just verify", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", fullVector());
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  // Round 1 is a verify; force a consolidate by confirming a finding.
  const first = tickLoop(cwd, load(cwd).snapshot);
  assert.match(first.brief!, /## 技能/);
  const node = load(cwd).snapshot.nodes.find((n) => n.nodeKind !== "scope")!;
  confirmed(cwd, node, [ANCHORED]);
  const second = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(load(cwd).snapshot.roundRecords[1]!.kind, "consolidate");
  assert.match(second.brief!, /## 技能/, "the combine brief carries it too");
});

// -----------------------------------------------------------------
// 是否需要验证 — the triage question
// -----------------------------------------------------------------
//
// The tier says how STRONG the evidence is. This section says what to DO about
// it, which is the different question a reader triaging a report actually has:
// which of these can I act on, and which are still claims?
//
// Everything in it is DERIVED. The tool never decides whether a finding is good
// enough — it only says what is still missing.

test("a reproduced finding says it needs NO verification", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED, RAN]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /#### 是否需要验证/);
  assert.match(text, /不需要  已经运行过命令并留下了可重跑的输出/);
  assert.doesNotMatch(text, /^怎么验证$/m, "there is nothing left to verify");
});

test("a static finding says YES and names the concrete next step", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /需要  代码路径读懂了，但从未触发过——静态证据证明不了可达性/);
  // The actionable half, built from the vector the auditor already recorded
  // rather than invented here.
  assert.match(text, /怎么验证/);
  assert.match(text, /对真实实例发送 POST \/api\/gorgone\/command/);
  assert.match(text, /载荷  \{"command":"whoami"\}/);
});

test("a reasoning-only finding says it MUST be verified before it counts as one", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check");
  confirmed(cwd, node, [{ kind: "reasoning", at: "", detail: "看起来不对" }]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /必须先验证  没有代码锚点也没有运行过任何命令——在验证之前它不是发现，是线索/);
  // With no vector to point at, the next step is the cheapest one that would
  // change anything: confirm the code location even exists.
  assert.match(text, /先 read 它声称的代码位置，确认它真的存在/);
});

test("a static finding with no vector is told to complete the chain first", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check");
  confirmed(cwd, node, [ANCHORED]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /从入口开始读代码，把调用链补到 sink/);
});

test("a finding nobody has attacked says so in the verification section too", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);
  assert.match(
    renderReport(load(cwd).snapshot, null, { language: "zh" }),
    /且尚未被对抗复核攻击过——这是审计员在附和自己/,
  );

  applyNodePatch(cwd, node.id, { challengedRound: 3 }, "");
  const after = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.doesNotMatch(after, /且尚未被对抗复核攻击过/);
});

test("a blocked finding is told what it is waiting on instead of being told to verify", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  setStatus(cwd, node.id, "blocked", {
    reason: "needs a running instance to settle whether the daemon is reachable",
    evidence: [ANCHORED],
  });
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  // A blocked finding is not a confirmed one, so it is not in the confirmed
  // section at all — but the phrasing is pinned here for when it is reopened.
  assert.doesNotMatch(text, /#### 是否需要验证/);
});

test("the verification section is in English for an English report", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /#### Does it need verification\?/);
  assert.match(text, /YES  the code path was read but never triggered/);
  assert.match(text, /how to verify/);
});

test("the evidence section does not repeat what the PoC section already showed", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  // ANCHORED is the code-slice, and the PoC section is its readable form. The
  // evidence section used to print the same source twice, which is the single
  // biggest waste in the file.
  assert.doesNotMatch(text, /\*\*证据/, "nothing left over, so no section at all");
  assert.equal(text.split("public function sendCommand").length - 1, 1, "the anchor appears exactly once");
});

test("evidence the PoC section could not show still gets listed", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [
    ANCHORED,
    { kind: "reasoning", at: "", detail: "security.yaml 的 access_control 为空数组" },
  ]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*证据（2 条）\*\*/);
  assert.match(text, /- \*\*reasoning\*\* — security\.yaml 的 access_control 为空数组/);
});
