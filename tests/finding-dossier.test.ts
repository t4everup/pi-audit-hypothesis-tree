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
import { buildContract, contractMet } from "../extensions/hypothesis-tree/loop.ts";
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
  assert.match(text, /1\. `config\/packages\/security\.yaml:12` — 防火墙只声明/);
  assert.match(text, /2\. `src\/api\/gorgone\.ts:66` — 控制器直接转发命令/);
  assert.match(text, /3\. `src\/service\/gorgone\.ts:95` — 到达 GorgoneService::send/);
  assert.match(text, /- 入口: `POST \/api\/gorgone\/command`/);
  assert.match(text, /- 手法: 未鉴权的 Gorgone 命令转发/);
  assert.match(text, /- 载荷: `\{"command":"whoami"\}`/);
  assert.match(text, /- 前置条件: api 防火墙未做 IP 限制/);

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
  assert.match(text, /\*\*已复现。\*\*/);
  assert.match(text, /复现命令: `curl -sS -X POST http:\/\/target\/api\/gorgone\/command`/);
  assert.match(text, /在项目根目录重跑上面的命令即可自行确认/);
  assert.doesNotMatch(text, /静态证据，未复现/);
});

test("a static-only finding says nothing was executed, and what a PoC would need", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [ANCHORED]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*静态证据，未复现。\*\*/);
  assert.match(text, /需要一次真实的请求或一次真实的调用/);
});

test("a finding with no artifact is marked as an opinion, not a vulnerability", () => {
  const cwd = seeded();
  const node = add(cwd, "the gorgone command endpoint forwards without a role check", fullVector());
  confirmed(cwd, node, [{ kind: "reasoning", at: "", detail: "看起来不对" }]);
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*没有物证。\*\*/);
  assert.match(text, /\*\*不要把它当作漏洞\*\*/);
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
