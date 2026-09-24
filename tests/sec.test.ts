// pi-audit-hypothesis-tree — tests/sec.test.ts
//
// `/loopSEC` — the mode with no hypothesis tree.
//
// The point of these tests is the TRADE: what this mode drops (the assertion gate,
// the verdict, the tier, the falsification attempt, the challenge round) and the one
// thing it keeps (an artifact on every finding). A test that only checked "it
// records findings" would pass on a version that had quietly kept the assertion gate
// and on a version that had dropped the artifact rule.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { pauseLoop, resumeLoop, startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import { saveSettings } from "../extensions/hypothesis-tree/settings.ts";
import {
  appendSecLedger,
  recordFinding,
  renderSecDigBrief,
  renderSecFindings,
  renderSecReport,
  secCitedFiles,
  secCoverage,
  secLedgerPath,
  secReportPath,
  submitSecRecon,
  updateFinding,
  validateFinding,
  writeSecReport,
} from "../extensions/hypothesis-tree/sec.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-sec-"));
}

/** A project with real files, so the coverage walk has something to find. */
function seeded(cwd = tmpProject()): string {
  for (const [rel, body] of [
    ["src/http/server.c", "int main(void) { return 0; }\n"],
    ["src/util/shell.c", "void run_cmd(char *c) { system(c); }\n"],
    ["src/auth/session.c", "int check_auth(void) { return 1; }\n"],
    ["src/handlers/upload.c", "void up(void) { fopen(name, \"w\"); }\n"],
    ["src/cfg/parse.c", "void parse(void) { }\n"],
    ["docs/README.md", "# docs\n"],
    // NOT `vendor/` — that is in PROBE_SKIP_DIRS on purpose (a dependency tree is
    // not the audited surface, and walking it spends the file budget before the
    // project's own code is reached). Four files so the directory clears
    // COVERAGE.MIN_FILES_FOR_GAP and shows up as a real gap.
    ["tools/a.c", "int a(void) { return 1; }\n"],
    ["tools/b.c", "int b(void) { return 1; }\n"],
    ["tools/c.c", "int c(void) { return 1; }\n"],
    ["tools/d.c", "int d(void) { return 1; }\n"],
  ] as const) {
    const abs = path.join(cwd, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, body, "utf-8");
  }
  return cwd;
}

const NOTE = [
  "一个 C 语言写的嵌入式 Web 服务，源码在 src/ 下，约 400 个文件。入口是 src/http/server.c 的 main()，监听 80 端口，所有请求经 router 分发。",
  "认证在 src/auth/session.c 的 check_auth()，但 router 里有一张表把部分路径标为公开。",
  "文件上传在 src/handlers/upload.c，把 multipart 的 filename 直接拼进 fopen()。",
  "命令执行在 src/util/shell.c 的 run_cmd()，用 system() 拼接字符串。",
].join("\n\n");

function startSec(cwd: string, objective = "挖掘认证前rce漏洞", plateauWindow = 99) {
  const result = startLoop(cwd, load(cwd).snapshot, { kind: "sec", objective, plateauWindow });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result;
}

// -----------------------------------------------------------------
// The one rule this mode keeps
// -----------------------------------------------------------------

test("a finding with no artifact is REFUSED — the only rule /loopSEC keeps", () => {
  const cwd = seeded();
  const refused = recordFinding(cwd, { title: "某处有命令注入", category: "rce" });
  assert.equal(refused.ok, false);
  const message = refused.ok ? "" : refused.errors.join(" ");
  assert.match(message, /needs an artifact/);
  // And it says WHY, because the reason is the whole design of the mode.
  assert.match(message, /the ONLY thing\s+a reader can check|ONLY thing/);
  assert.equal(load(cwd).snapshot.findings.length, 0, "nothing was recorded");
});

test("a location OR an evidence excerpt is enough, and both is better", () => {
  const cwd = seeded();
  const byLocation = recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1 });
  assert.equal(byLocation.ok, true, byLocation.ok ? "" : byLocation.errors.join("; "));
  const byEvidence = recordFinding(cwd, { title: "upload 把 filename 拼进 fopen", category: "path-traversal", evidence: "src/handlers/upload.c:1\n  fopen(name, \"w\");" });
  assert.equal(byEvidence.ok, true, byEvidence.ok ? "" : byEvidence.errors.join("; "));
  assert.equal(load(cwd).snapshot.findings.length, 2);
});

test("a file without a line is refused rather than silently given line 1", () => {
  const cwd = seeded();
  const result = validateFinding({ title: "x", category: "rce", file: "src/a.c" });
  assert.equal(result.ok, false);
  assert.match(result.ok ? "" : result.errors.join(" "), /line/);
});

test("an update may not leave a finding with no artifact", () => {
  const cwd = seeded();
  const created = recordFinding(cwd, { title: "x", category: "rce", evidence: "src/a.c:1 system(c)" });
  assert.equal(created.ok, true);
  const id = created.ok ? created.value.id : "";
  // A patch that sets an empty evidence string does not clear it, so this must
  // still be allowed — the check is on the RESULT, not on the patch.
  const ok = updateFinding(cwd, id, { severity: "high" });
  assert.equal(ok.ok, true);
  const missing = updateFinding(cwd, "F-9999", { severity: "high" });
  assert.equal(missing.ok, false, "an unknown id is refused");
});

// -----------------------------------------------------------------
// What this mode drops
// -----------------------------------------------------------------

test("NO assertion gate — a noun phrase is a perfectly good finding title", () => {
  const cwd = seeded();
  // In hypothesis mode this exact string is refused: it has no truth value.
  const result = recordFinding(cwd, {
    title: "src/diag/ 下的调试端点",
    category: "info-disclosure",
    file: "src/diag/debug.c",
    line: 12,
  });
  assert.equal(result.ok, true, "the assertion gate must NOT apply here");
});

test("a sec run creates NO hypothesis tree", () => {
  const cwd = seeded();
  const started = startSec(cwd);
  assert.equal(started.ok, true, started.ok ? "" : started.errors.join("; "));
  const snapshot = load(cwd).snapshot;
  assert.equal(snapshot.rootId, "", "a sec run has no tree to create");
  assert.equal(snapshot.nodes.length, 0);
  assert.equal(snapshot.loop!.kind, "sec", "and the loop survived the store round trip");
});

test("the sec loop is not refused for having no tree, but /loop still is", () => {
  const cwd = seeded();
  const loop = startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit" });
  assert.equal(loop.ok, false, "/loop still needs a tree");
  assert.match(loop.ok ? "" : loop.errors.join(" "), /no hypothesis tree/);
});

// -----------------------------------------------------------------
// The briefs
// -----------------------------------------------------------------

test("round 1 is RECON and the dig brief carries the note, the findings and the unread set", () => {
  const cwd = seeded();
  startSec(cwd);
  const first = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(first.action, "sent");
  assert.match(first.brief!, /^\[SEC ROUND 1 — RECON\]/);
  assert.match(first.brief!, /THIS IS THE ONLY RECON PASS/);

  assert.equal(submitSecRecon(cwd, NOTE).ok, true);
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high" });

  const second = tickLoop(cwd, load(cwd).snapshot);
  assert.match(second.brief!, /^\[SEC ROUND 2 — DIG\]/);
  const brief = second.brief!;
  assert.match(brief, /YOUR NOTE FROM THE RECON PASS/);
  assert.match(brief, /嵌入式 Web 服务/, "the note is carried verbatim");
  assert.match(brief, /FOUND SO FAR \(1\)/);
  assert.match(brief, /F-0001 \[high\] rce/);
  assert.match(brief, /src\/util\/shell\.c:1/);
  assert.match(brief, /NOT READ YET/);
  assert.match(brief, /tools\s+\(4 file\(s\)/, "the untouched subtree is named — this is where the breadth comes from");
  assert.match(brief, /UNREAD/, "and it says a directory with no finding is not clean");
  assert.match(brief, /no assertion gate/, "and it says what the rule is instead");
});

test("the dig brief says recording NOTHING is legitimate", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;
  // Without this line the model optimises for looking productive, which in a mode
  // with no verification is the worst possible incentive.
  assert.match(brief, /Recording nothing is a\s+legitimate outcome/);
});

// -----------------------------------------------------------------
// The plateau
// -----------------------------------------------------------------

test("a sec round that records nothing is unproductive, and the plateau fires", () => {
  const cwd = seeded();
  // The plateau window has to be set at START. Calling startLoop a second time to
  // change it is refused (a loop is already running), so the window stayed at 99
  // and the test measured nothing — which is exactly how it failed the first time.
  startSec(cwd, "挖掘认证前rce漏洞", 3);
  submitSecRecon(cwd, NOTE);

  // The model answers nothing for several rounds.
  let stopped: string | null = null;
  for (let i = 0; i < 20; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    if (result.action !== "sent") {
      stopped = result.reason;
      break;
    }
  }
  assert.ok(stopped, "a run where nothing is ever recorded must stop");
  assert.match(stopped!, /plateau/);
  assert.match(stopped!, /no new evidence/);
});

test("a round that records a finding RESETS the stall counter", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 3);
  submitSecRecon(cwd, NOTE);

  tickLoop(cwd, load(cwd).snapshot);
  tickLoop(cwd, load(cwd).snapshot);
  assert.ok(load(cwd).snapshot.loop!.stallRounds > 0, "two empty rounds stall");
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1 });
  tickLoop(cwd, load(cwd).snapshot);
  assert.equal(load(cwd).snapshot.loop!.stallRounds, 0, "a finding is progress");
});

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

test("the report LEADS with what this mode does not have", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high", preAuth: true });

  const report = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop);
  const caveat = report.indexOf("先读这一段");
  const findings = report.indexOf("## 发现");
  assert.ok(caveat > 0, "the caveat is present");
  assert.ok(caveat < findings, "and it comes BEFORE the findings, not after them");
  for (const missing of ["没有验证等级", "没有证伪尝试", "没有对抗复核", "没有等级核查", "没有断言门禁"]) {
    assert.ok(report.includes(missing), `the report must name what is missing: ${missing}`);
  }
  assert.match(report, /每条发现都带物证/, "and what IS enforced");
  // Every finding says so on its own line too, not only in the preamble.
  assert.match(report, /未经验证/);
  assert.match(report, /认证前可达/);
});

test("the report defaults to Chinese and follows reportLanguage when set", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high" });

  // The default, with no options at all — the operator's preference is Chinese and a
  // report that comes out English until told otherwise is a setting that looks broken.
  const zh = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop, {
    coverageReport: secCoverage(load(cwd).snapshot, cwd),
  });
  assert.match(zh, /^# \/loopSEC — 发现$/m);
  assert.match(zh, /## 先读这一段/);
  assert.match(zh, /## 概览/);
  assert.match(zh, /## 覆盖/);
  assert.match(zh, /## 发现（1）/);
  assert.match(zh, /高危/, "the severity label is translated too");

  const en = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop, {
    language: "en",
    coverageReport: secCoverage(load(cwd).snapshot, cwd),
  });
  assert.match(en, /^# \/loopSEC — findings$/m);
  assert.match(en, /## READ THIS FIRST/);
  assert.match(en, /## Summary/);
  assert.match(en, /## Findings \(1\)/);
  assert.match(en, /HIGH/);

  // writeSecReport reads the setting itself, so a caller cannot forget it.
  saveSettings(cwd, { reportLanguage: "en" });
  const written = writeSecReport(cwd, load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.equal(written.ok, true, written.ok ? "" : written.errors.join("; "));
  assert.match(fs.readFileSync(written.ok ? written.value : "", "utf-8"), /## READ THIS FIRST/);
  saveSettings(cwd, { reportLanguage: "zh" });
  writeSecReport(cwd, load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.match(fs.readFileSync(secReportPath(cwd), "utf-8"), /## 先读这一段/);
});

test("a finding with no severity is listed, and counted separately from the rated ones", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "一条还没判级的", category: "other", file: "src/a.c", line: 1 });
  const report = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.match(report, /\*\*未评级的\*\*/);
  assert.match(report, /未评级/);
});

test("an unassessed preAuth is NOT counted as pre-auth", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1, preAuth: true });
  recordFinding(cwd, { title: "b", category: "rce", file: "src/b.c", line: 1 });
  const report = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.match(report, /无需认证可达 \| 1 \|/);
  assert.match(report, /\*\*认证要求未评估\*\* \| 1 \|/);
});

test("the report is written to its OWN file, so it cannot overwrite the hypothesis report", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  assert.match(secReportPath(cwd), /SEC-REPORT\.md$/);
  assert.match(secLedgerPath(cwd), /SEC-FINDINGS\.md$/);
  assert.notEqual(path.basename(secReportPath(cwd)), "REPORT.md");
});

// -----------------------------------------------------------------
// Coverage, without hypotheses
// -----------------------------------------------------------------

test("coverage counts the files a FINDING cites, not the files a node cites", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/util/shell.c", line: 1 });
  recordFinding(cwd, { title: "b", category: "rce", evidence: "see src/handlers/upload.c:77 and src/cfg/parse.c:3" });
  const cited = secCitedFiles(load(cwd).snapshot);
  assert.ok(cited.has("src/util/shell.c"), "the location counts");
  assert.ok(cited.has("src/handlers/upload.c"), "and a `file:line` inside an evidence excerpt counts too");
  assert.ok(cited.has("src/cfg/parse.c"));
  const report = secCoverage(load(cwd).snapshot, cwd);
  assert.equal(report.citedFiles, 3);
  assert.ok(report.projectFiles! >= 9, "the walk found the project");
  assert.ok(report.gaps.some((g) => g.dir.includes("tools")), `tools/ is untouched: ${JSON.stringify(report.gaps)}`);
});

// -----------------------------------------------------------------
// The store round trip — the allowlist lesson
// -----------------------------------------------------------------

test("every SecFinding field survives being written and read back", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, {
    title: "run_cmd 拼接 host",
    category: "rce",
    file: "src/util/shell.c",
    line: 41,
    severity: "high",
    preAuth: true,
    evidence: "41: system(cmd);",
    reasoning: "router 把 /diag/ping 标为公开",
    poc: "curl 'http://t/diag/ping?host=127.0.0.1;id'",
  });
  const back = load(cwd).snapshot.findings[0]!;
  assert.equal(back.title, "run_cmd 拼接 host");
  assert.equal(back.category, "rce");
  assert.deepEqual(back.location, { file: "src/util/shell.c", line: 41 });
  assert.equal(back.severity, "high");
  assert.equal(back.preAuth, true);
  assert.equal(back.evidence, "41: system(cmd);");
  assert.equal(back.reasoning, "router 把 /diag/ping 标为公开");
  assert.equal(back.poc, "curl 'http://t/diag/ping?host=127.0.0.1;id'");
});

test("an absent preAuth stays ABSENT across the round trip", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  const back = load(cwd).snapshot.findings[0]!;
  // Tri-state: silence must not become a claim in either direction.
  assert.equal("preAuth" in back, false, "silence stays silence");
  assert.equal("severity" in back, false, "and an unrated finding stays unrated");
});

test("a finding written to the log with NO artifact is dropped on read", () => {
  // The write path refuses one; the read path must too, or a hand-edited log puts
  // a bare claim back into the report.
  const cwd = seeded();
  startSec(cwd);
  const log = path.join(cwd, ".pi-hypothesis", "tree.jsonl");
  fs.appendFileSync(
    log,
    JSON.stringify({ type: "finding_recorded", at: new Date().toISOString(), finding: { id: "F-0001", title: "a bare claim", category: "rce", at: "", round: 1 } }) + "\n",
    "utf-8",
  );
  assert.equal(load(cwd).snapshot.findings.length, 0, "no artifact, no finding");
});

// -----------------------------------------------------------------
// The lifecycle the operator asked for
// -----------------------------------------------------------------

test("pause, resume and the round budget all work on a sec loop", () => {
  const cwd = seeded();
  startSec(cwd);
  assert.equal(pauseLoop(cwd, load(cwd).snapshot, "the operator paused it").ok, true);
  assert.equal(load(cwd).snapshot.loop!.status, "paused");
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "paused", "a paused loop sends nothing");

  assert.equal(resumeLoop(cwd, load(cwd).snapshot, { forRounds: 3 }).ok, true);
  const loop = load(cwd).snapshot.loop!;
  assert.equal(loop.status, "running");
  assert.equal(loop.pauseAfterRound, loop.round + 3, "the budget is relative to the current round");
});

test("the ledger is cumulative, so a finding is never invisible in it", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  tickLoop(cwd, load(cwd).snapshot);
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1 });
  tickLoop(cwd, load(cwd).snapshot);
  appendSecLedger(cwd, load(cwd).snapshot, load(cwd).snapshot.loop!.round, ["SEC ROUND — dig"]);

  const ledger = fs.readFileSync(secLedgerPath(cwd), "utf-8");
  // The ledger is written when the round is PREPARED, so a per-round list would
  // show every finding in NO entry. Measured before the fix: 2 findings, five
  // entries, all claiming zero.
  assert.match(ledger, /### Findings so far \(1\)/);
  assert.match(ledger, /F-0001/);
});

test("renderSecFindings shows what the run has, for `/sec tree`", () => {
  const cwd = seeded();
  startSec(cwd);
  assert.match(renderSecFindings(load(cwd).snapshot).join("\n"), /round 1 reads the project/);
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high", preAuth: true });
  const text = renderSecFindings(load(cwd).snapshot).join("\n");
  assert.match(text, /1 finding\(s\)/);
  assert.match(text, /F-0001 \[high\] rce \[pre-auth\]\s+src\/util\/shell\.c:1/);
});

// -----------------------------------------------------------------
// The brief and the report must not invent discipline
// -----------------------------------------------------------------

test("the dig brief never claims a verification tier or a challenge round", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  const brief = renderSecDigBrief(load(cwd).snapshot, "挖掘认证前rce漏洞", 2, secCoverage(load(cwd).snapshot, cwd));
  for (const lie of ["验证等级", "对抗复核", "证伪", "verification tier"]) {
    assert.equal(brief.includes(lie), false, `the brief must not promise ${lie}`);
  }
  assert.match(brief, /no assertion gate/);
});
