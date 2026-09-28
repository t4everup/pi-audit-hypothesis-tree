// pi-audit-hypothesis-tree — tests/sec.test.ts
//
// `/loopSEC` — the mode with no hypothesis tree, and the analysis engine that makes
// it more than "go and look".
//
// These tests are written against the TRADE, not the feature. A test that only
// checked "it records findings" would pass on a version that had quietly kept the
// assertion gate, and on one that had dropped the artifact rule. So they pin both
// directions, and the analysis engine's central claim gets its own test: **a round
// that examines an item and finds nothing is PROGRESS**, because the opposite is a
// plateau that stops a run which is doing exactly what it was asked to do.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { pauseLoop, resumeLoop, startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import { saveSettings } from "../extensions/hypothesis-tree/settings.ts";
import { loopCommandName } from "../extensions/hypothesis-tree/types.ts";
import {
  appendSecLedger,
  clearSurface,
  nextOpenSurface,
  recordFinding,
  recordSurface,
  renderSecAnalyzeBrief,
  renderSecFindings,
  renderSecReport,
  renderSecSurfaceBrief,
  secCitedFiles,
  secCoverage,
  secLedgerPath,
  secReportPath,
  submitSecRecon,
  surfaceProgress,
  updateFinding,
  updateSurface,
  validateFinding,
  validateSurface,
  writeSecReport,
} from "../extensions/hypothesis-tree/sec.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-sec-"));
}

/**
 * A project with real files.
 *
 * `vendor/` is deliberately NOT used for the untouched-subtree case: it is in
 * PROBE_SKIP_DIRS on purpose (a dependency tree is not the audited surface, and
 * walking it spends the file budget before the project's own code is reached), so a
 * fixture that expects it to appear as a gap is wrong.
 */
function seeded(cwd = tmpProject()): string {
  for (const [rel, body] of [
    ["src/http/server.c", "int main(void) { return 0; }\n"],
    ["src/http/router.c", '{"public": ["/diag/ping"]}\n'],
    ["src/util/shell.c", "void run_cmd(char *c) { system(c); }\n"],
    ["src/auth/session.c", "int check_auth(void) { return 1; }\n"],
    ["src/handlers/upload.c", 'void up(void) { fopen(name, "w"); }\n'],
    ["src/cfg/parse.c", "void parse(void) { }\n"],
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
  "一个 C 语言写的嵌入式 Web 服务，源码在 src/ 下。入口是 src/http/server.c 的 main()，监听 80 端口，所有请求经 src/http/router.c 分发。",
  "认证在 src/auth/session.c 的 check_auth()，但 router.c 里有一张表把部分路径标为公开。",
  "命令执行在 src/util/shell.c 的 run_cmd()，用 system() 拼接字符串。",
  "文件上传在 src/handlers/upload.c，把 multipart 的 filename 直接拼进 fopen()。",
].join("\n\n");

function startSec(cwd: string, objective = "挖掘认证前rce漏洞", plateauWindow = 99) {
  const result = startLoop(cwd, load(cwd).snapshot, { kind: "sec", objective, plateauWindow });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result;
}

/** Recon + a small surface list, the state every analyze test starts from. */
function withSurface(cwd: string, items = 3): void {
  startSec(cwd);
  assert.equal(submitSecRecon(cwd, NOTE).ok, true);
  const titles = [
    { title: "POST /diag/ping", kind: "entrypoint" as const, file: "src/http/router.c", line: 1, categories: ["rce"] },
    { title: "run_cmd() in src/util/shell.c", kind: "sink" as const, file: "src/util/shell.c", line: 1 },
    { title: "the session cookie check", kind: "boundary" as const, file: "src/auth/session.c", line: 1 },
    { title: "the upload handler", kind: "entrypoint" as const, file: "src/handlers/upload.c", line: 1 },
    { title: "the config parser", kind: "file" as const, file: "src/cfg/parse.c", line: 1 },
  ];
  for (const item of titles.slice(0, items)) {
    assert.equal(recordSurface(cwd, item).ok, true);
  }
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
  assert.match(message, /ONLY thing/);
  assert.equal(load(cwd).snapshot.findings.length, 0, "nothing was recorded");
});

test("a location OR an evidence excerpt is enough", () => {
  const cwd = seeded();
  assert.equal(recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1 }).ok, true);
  assert.equal(
    recordFinding(cwd, { title: "upload 拼 filename", category: "path-traversal", evidence: "src/handlers/upload.c:1\n  fopen(name, \"w\");" }).ok,
    true,
  );
  assert.equal(load(cwd).snapshot.findings.length, 2);
});

test("a file without a line is refused rather than silently given line 1", () => {
  const result = validateFinding({ title: "x", category: "rce", file: "src/a.c" });
  assert.equal(result.ok, false);
  assert.match(result.ok ? "" : result.errors.join(" "), /line/);
});

// -----------------------------------------------------------------
// The attack surface — the work list
// -----------------------------------------------------------------

test("a surface item needs only a title — an entrypoint has no line number", () => {
  // The whole point of an entrypoint is that it is reachable from OUTSIDE the code,
  // so demanding a file:line would exclude exactly the items that matter most.
  const cwd = seeded();
  const bare = validateSurface({ title: "POST /diag/ping" });
  assert.equal(bare.ok, true, bare.ok ? "" : bare.errors.join("; "));
  // But a file without a line is still refused, because there the line IS knowable.
  const half = validateSurface({ title: "x", file: "src/a.c" });
  assert.equal(half.ok, false);
  assert.match(half.ok ? "" : half.errors.join(" "), /line/);
});

test("enumerating the same item twice is a warning, not a refusal", () => {
  const cwd = seeded();
  const first = recordSurface(cwd, { title: "POST /diag/ping" });
  assert.equal(first.ok, true);
  const again = recordSurface(cwd, { title: "POST /diag/ping" });
  // Refusing it would make the model handle a rejection it cannot act on; a duplicate
  // is a waste, not a fault.
  assert.equal(again.ok, true);
  assert.ok(again.warnings.length > 0, "and it says so");
  assert.equal(load(cwd).snapshot.surfaces.length, 1);
});

test("the next item is the first still open, in ENUMERATION order", () => {
  const cwd = seeded();
  withSurface(cwd);
  const snapshot = load(cwd).snapshot;
  assert.equal(nextOpenSurface(snapshot)!.id, "S-0001");
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  // The order is the enumerator's judgement and nothing re-sorts it behind its back.
  assert.equal(nextOpenSurface(load(cwd).snapshot)!.id, "S-0002");
});

test("clearing an item REQUIRES a reason that names the guard", () => {
  const cwd = seeded();
  withSurface(cwd);
  const empty = clearSurface(cwd, "S-0001", "nothing found");
  assert.equal(empty.ok, false);
  const message = empty.ok ? "" : empty.errors.join(" ");
  assert.match(message, /WHICH guard/);
  assert.match(message, /absence of a reason/, "and it says why the bar exists");
  assert.equal(load(cwd).snapshot.surfaces[0]!.status, "open", "and nothing was cleared");

  const good = clearSurface(cwd, "S-0001", "check_auth() is called at router.c:88 before dispatch, and /diag/ping is not in the public table");
  assert.equal(good.ok, true, good.ok ? "" : good.errors.join("; "));
  const after = load(cwd).snapshot.surfaces[0]!;
  assert.equal(after.status, "cleared");
  assert.ok(after.examinedAt, "and the timestamp is stamped, not left to the caller");
});

test("a finding against a surface item EXAMINES that item", () => {
  const cwd = seeded();
  withSurface(cwd);
  assert.equal(
    recordFinding(cwd, {
      title: "run_cmd() 把 host 拼进 system()",
      category: "rce",
      file: "src/util/shell.c",
      line: 1,
      surfaceId: "S-0001",
    }).ok,
    true,
  );
  const item = load(cwd).snapshot.surfaces[0]!;
  // Without this the item stayed `open`, so the next round was handed the same one and
  // the model was asked to analyse a thing it had just found a bug in.
  assert.equal(item.status, "examined");
  assert.equal(item.findingId, "F-0001");
  assert.equal(nextOpenSurface(load(cwd).snapshot)!.id, "S-0002");
});

test("progress counts examined items, and a cleared one is examined", () => {
  const cwd = seeded();
  withSurface(cwd);
  assert.deepEqual(surfaceProgress(load(cwd).snapshot), { total: 3, open: 3, examined: 0, cleared: 0, productive: 0 });
  clearSurface(cwd, "S-0001", "check_auth() is called at router.c:88 before dispatch, and the route is not public");
  const p = surfaceProgress(load(cwd).snapshot);
  assert.equal(p.examined, 1);
  assert.equal(p.cleared, 1);
  assert.equal(p.open, 2);
  assert.equal(p.productive, 0, "cleared is not productive — and that is the point");
});

// -----------------------------------------------------------------
// The round flow — recon, surface, analyze
// -----------------------------------------------------------------

test("the sec loop runs recon, then surface, then analyze — and ASSIGNS the item", () => {
  const cwd = seeded();
  startSec(cwd);

  const first = tickLoop(cwd, load(cwd).snapshot);
  assert.match(first.brief!, /^\[SEC ROUND 1 — RECON\]/);

  submitSecRecon(cwd, NOTE);
  const second = tickLoop(cwd, load(cwd).snapshot);
  assert.match(second.brief!, /^\[SEC ROUND 2 — SURFACE\]/);
  assert.match(second.brief!, /LIST THEM IN THE ORDER THEY SHOULD BE EXAMINED/);
  assert.match(second.brief!, /COORDINATES, not claims/, "an item is a place, not an assertion");

  recordSurface(cwd, { title: "POST /diag/ping", kind: "entrypoint", file: "src/http/router.c", line: 1, categories: ["rce"] });
  const third = tickLoop(cwd, load(cwd).snapshot);
  assert.match(third.brief!, /^\[SEC ROUND 3 — ANALYZE S-0001\]/);
  assert.equal(load(cwd).snapshot.roundRecords.at(-1)!.kind, "analyze");
  assert.equal(load(cwd).snapshot.roundRecords.at(-1)!.surfaceId, "S-0001");
});

test("the analyze brief carries the item, the method, and the class depth axes", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;
  assert.match(brief, /THIS ROUND IS THIS ITEM/);
  assert.match(brief, /S-0001 {2}\[entrypoint\] {2}POST \/diag\/ping/);
  assert.match(brief, /src\/http\/router\.c:1/);
  // The method — the thing that makes this analysis rather than "go and look".
  assert.match(brief, /HOW TO ANALYSE/);
  assert.match(brief, /ENTRY/);
  assert.match(brief, /CONTROLLED INPUT/);
  assert.match(brief, /THE CHECK/);
  assert.match(brief, /SINK/);
  assert.match(brief, /Read the check itself/, "and it says not to trust a function's name");
  assert.match(brief, /Trace it ALL before concluding/);
  // The class knowledge, reused from ladders.ts rather than re-invented.
  assert.match(brief, /The depth axes for rce/);
  assert.match(brief, /which exact call executes/, "the ladder's own axis text");
  // And the two exits.
  assert.match(brief, /sec_finding/);
  assert.match(brief, /sec_clear/);
  assert.match(brief, /Clearing an item is a RESULT, not a failure/);
  assert.match(brief, /reason must name the guard/);
});

test("the analyze brief says do NOT switch items, and why", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;
  assert.match(brief, /Analyse THIS item all the way down/);
  assert.match(brief, /every item on the list gets a round[\s\S]{0,4}of its own/);
});

test("the analyze brief shows what has been cleared, so it is not re-examined", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;
  assert.match(brief, /^\[SEC ROUND \d+ — ANALYZE S-0002\]/, "the cleared item is skipped");
  assert.match(brief, /ALREADY CLEARED/);
  assert.match(brief, /S-0001/);
  assert.match(brief, /check_auth\(\) runs at router\.c:88/, "and the reason is carried, not just the id");
});

test("a surface round is only reached when every item has been examined", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  tickLoop(cwd, load(cwd).snapshot);
  assert.equal(load(cwd).snapshot.roundRecords.at(-1)!.kind, "analyze");
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  const next = tickLoop(cwd, load(cwd).snapshot);
  // The list is the enumerator's, so when it is exhausted the right move is to
  // enumerate again with what the analysis revealed — not to stop.
  assert.match(next.brief!, /^\[SEC ROUND \d+ — SURFACE\]/);
});

// -----------------------------------------------------------------
// THE FIX THAT MATTERS: examining an item is PROGRESS
// -----------------------------------------------------------------

test("a round that EXAMINES an item and finds nothing is PROGRESS, not a plateau slot", () => {
  const cwd = seeded();
  // A plateau window of 3. Before this fix, three careful rounds that each read the
  // code, traced the flow and correctly concluded "guarded" would stop the run.
  startSec(cwd, "挖掘认证前rce漏洞", 3);
  submitSecRecon(cwd, NOTE);
  for (const title of ["a", "b", "c", "d", "e"]) {
    recordSurface(cwd, { title: `item ${title}`, kind: "file", file: "src/cfg/parse.c", line: 1 });
  }

  // Five rounds, each clearing its item, finding nothing.
  for (let i = 0; i < 5; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    assert.equal(result.action, "sent", `round ${i + 1} must be sent: ${result.reason}`);
    const item = nextOpenSurface(load(cwd).snapshot);
    assert.ok(item, "an item must still be open");
    clearSurface(cwd, item!.id, "check_auth() runs at router.c:88 before dispatch and this path is not in the public table");
  }

  const loop = load(cwd).snapshot.loop!;
  assert.equal(loop.status, "running", "five productive rounds must NOT have stopped the run");
  assert.equal(loop.stallRounds, 0, "examining an item resets the stall counter");
  assert.equal(surfaceProgress(load(cwd).snapshot).examined, 5);
});

test("a round that examines NOTHING is unproductive, and the plateau fires", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 3);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "one item", kind: "file", file: "src/cfg/parse.c", line: 1 });

  // The model answers nothing at all: the item is never cleared, no finding lands.
  let stopped: string | null = null;
  for (let i = 0; i < 12; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    if (result.action !== "sent") {
      stopped = result.reason;
      break;
    }
  }
  assert.ok(stopped, "a run where nothing is ever examined must stop");
  assert.match(stopped!, /plateau/);
});

test("a surface round that enumerates nothing is unproductive", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 2);
  submitSecRecon(cwd, NOTE);
  // No items are ever recorded, so every round is a surface round that adds nothing.
  let stopped: string | null = null;
  for (let i = 0; i < 8; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    if (result.action !== "sent") {
      stopped = result.reason;
      break;
    }
  }
  assert.ok(stopped, "an enumeration that adds nothing must eventually stop the run");
  assert.match(stopped!, /plateau/);
});

test("the round summary says how much of the surface has been examined", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  tickLoop(cwd, load(cwd).snapshot);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  tickLoop(cwd, load(cwd).snapshot);
  const ledger = fs.readFileSync(secLedgerPath(cwd), "utf-8");
  // The ledger is written when the round is PREPARED, so it carries the round's
  // assignment and the progress at that moment — which is how a reader can see the
  // analysis advancing rather than only the findings appearing.
  assert.match(ledger, /SEC ROUND 1 — analyse S-0001/);
  assert.match(ledger, /0\/2 examined/);
  assert.match(ledger, /SEC ROUND 2 — analyse S-0002/);
  assert.match(ledger, /1\/2 examined/, "the second round knows the first one cleared an item");
});

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

test("the report LEADS with what this mode does not have", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  // A finding is needed for the per-finding caveat line to exist at all.
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high" });
  const report = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop);
  const caveat = report.indexOf("先读这一段");
  const findings = report.indexOf("## 发现");
  assert.ok(caveat > 0, "the caveat is present");
  assert.ok(caveat < findings, "and it comes BEFORE the findings, not after them");
  for (const missing of ["没有验证等级", "没有证伪尝试", "没有对抗复核", "没有等级核查", "没有断言门禁"]) {
    assert.ok(report.includes(missing), `the report must name what is missing: ${missing}`);
  }
  assert.match(report, /每条发现都带物证/);
  assert.match(report, /未经验证/);
});

test("the report shows the attack surface and how much of it was examined", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high", surfaceId: "S-0002" });

  const report = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.match(report, /## 攻击面/);
  assert.match(report, /\*\*攻击面上的项\*\* \| 3 \|/);
  assert.match(report, /\*\*已分析\*\* \| \*\*2\*\* \(67%\)/, "the denominator the findings cannot give on their own");
  assert.match(report, /已确认有防护 \| 1 \|/);
  assert.match(report, /产出了发现 \| 1 \|/);
  // The two lists, and they say different things.
  assert.match(report, /## 尚未分析/);
  assert.match(report, /它们不是干净的，是没看过/);
  assert.match(report, /## 已分析并确认有防护/);
  assert.match(report, /check_auth\(\) runs at router\.c:88/, "the clearance reason is printed — it is the evidence");
  // And the finding links back to where it came from.
  assert.match(report, /\*\*来自攻击面：\*\* `S-0002`/);
});

test("a run that never enumerated a surface says so instead of showing an empty table", () => {
  const cwd = seeded();
  startSec(cwd);
  const report = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.match(report, /这次运行没有枚举攻击面/);
});

test("a finding with no severity is listed, and counted separately from the rated ones", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "一条还没判级的", category: "other", file: "src/a.c", line: 1 });
  const report = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.match(report, /\*\*未评级的\*\*/);
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

test("the report defaults to Chinese and follows reportLanguage when set", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const zh = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop, {
    coverageReport: secCoverage(load(cwd).snapshot, cwd),
  });
  assert.match(zh, /^# \/loopSEC — 发现$/m);
  assert.match(zh, /## 先读这一段/);
  assert.match(zh, /## 攻击面/);
  assert.match(zh, /## 概览/);
  assert.match(zh, /## 覆盖/);
  assert.match(zh, /## 发现（0）/);

  const en = renderSecReport(load(cwd).snapshot, load(cwd).snapshot.loop, {
    language: "en",
    coverageReport: secCoverage(load(cwd).snapshot, cwd),
  });
  assert.match(en, /^# \/loopSEC — findings$/m);
  assert.match(en, /## READ THIS FIRST/);
  assert.match(en, /## Attack surface/);
  assert.match(en, /## Summary/);

  // writeSecReport reads the setting itself, so a caller cannot forget it.
  saveSettings(cwd, { reportLanguage: "en" });
  const written = writeSecReport(cwd, load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.equal(written.ok, true, written.ok ? "" : written.errors.join("; "));
  assert.match(fs.readFileSync(secReportPath(cwd), "utf-8"), /## READ THIS FIRST/);
  saveSettings(cwd, { reportLanguage: "zh" });
  writeSecReport(cwd, load(cwd).snapshot, load(cwd).snapshot.loop);
  assert.match(fs.readFileSync(secReportPath(cwd), "utf-8"), /## 先读这一段/);
});

test("the report is written to its OWN file, so it cannot overwrite the hypothesis report", () => {
  const cwd = seeded();
  startSec(cwd);
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
  assert.ok(cited.has("src/util/shell.c"));
  assert.ok(cited.has("src/handlers/upload.c"), "a `file:line` inside an evidence excerpt counts too");
  const report = secCoverage(load(cwd).snapshot, cwd);
  assert.equal(report.citedFiles, 3);
  assert.ok(report.projectFiles! >= 9);
  assert.ok(report.gaps.some((g) => g.dir.includes("tools")), `tools/ is untouched: ${JSON.stringify(report.gaps)}`);
});

// -----------------------------------------------------------------
// The store round trip — the allowlist lesson, twice over
// -----------------------------------------------------------------

test("every SecFinding field survives being written and read back", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
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
    surfaceId: "S-0001",
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
  assert.equal(back.surfaceId, "S-0001");
});

test("every SecSurface field survives being written and read back", () => {
  const cwd = seeded();
  startSec(cwd);
  recordSurface(cwd, {
    title: "POST /diag/ping",
    kind: "entrypoint",
    file: "src/http/router.c",
    line: 88,
    categories: ["rce", "command-injection"],
  });
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  updateSurface(cwd, "S-0001", { findingId: "F-0001" });
  const back = load(cwd).snapshot.surfaces[0]!;
  assert.equal(back.kind, "entrypoint");
  assert.equal(back.title, "POST /diag/ping");
  assert.deepEqual(back.location, { file: "src/http/router.c", line: 88 });
  assert.deepEqual(back.categories, ["rce", "command-injection"]);
  assert.equal(back.status, "cleared");
  assert.match(back.clearedReason!, /check_auth\(\)/);
  assert.ok(back.examinedAt, "examinedAt survives the allowlist");
  assert.equal(back.findingId, "F-0001");
});

test("an absent preAuth stays ABSENT across the round trip", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  const back = load(cwd).snapshot.findings[0]!;
  assert.equal("preAuth" in back, false, "silence stays silence");
  assert.equal("severity" in back, false, "and an unrated finding stays unrated");
});

test("a finding written to the log with NO artifact is dropped on read", () => {
  const cwd = seeded();
  startSec(cwd);
  fs.appendFileSync(
    path.join(cwd, ".pi-hypothesis", "tree.jsonl"),
    JSON.stringify({
      type: "finding_recorded",
      at: new Date().toISOString(),
      finding: { id: "F-0001", title: "a bare claim", category: "rce", at: "", round: 1 },
    }) + "\n",
    "utf-8",
  );
  assert.equal(load(cwd).snapshot.findings.length, 0, "no artifact, no finding");
});

test("a surface item written with no title is dropped on read", () => {
  const cwd = seeded();
  startSec(cwd);
  fs.appendFileSync(
    path.join(cwd, ".pi-hypothesis", "tree.jsonl"),
    JSON.stringify({ type: "surface_recorded", at: new Date().toISOString(), surface: { id: "S-0001", at: "", round: 1, title: "" } }) + "\n",
    "utf-8",
  );
  assert.equal(load(cwd).snapshot.surfaces.length, 0);
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
  withSurface(cwd, 1);
  tickLoop(cwd, load(cwd).snapshot);
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1 });
  tickLoop(cwd, load(cwd).snapshot);
  appendSecLedger(cwd, load(cwd).snapshot, load(cwd).snapshot.loop!.round, ["SEC ROUND — analyze"]);
  const ledger = fs.readFileSync(secLedgerPath(cwd), "utf-8");
  assert.match(ledger, /### Findings so far \(1\)/);
  assert.match(ledger, /F-0001/);
});

test("renderSecFindings shows the surface AND the findings, for `/loopsec tree`", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  const text = renderSecFindings(load(cwd).snapshot).join("\n");
  assert.match(text, /Attack surface: 0\/2 examined/);
  assert.match(text, /S-0001 \[entrypoint\] POST \/diag\/ping/);
  assert.match(text, /No findings recorded yet\./, "a work list with no findings is the normal early state");
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high", preAuth: true });
  const after = renderSecFindings(load(cwd).snapshot).join("\n");
  assert.match(after, /F-0001 \[high\] rce \[pre-auth\]\s+src\/util\/shell\.c:1/);
});

test("the surface and analyze briefs never claim a verification tier or a challenge round", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const snapshot = load(cwd).snapshot;
  const surface = renderSecSurfaceBrief(snapshot, "挖掘认证前rce漏洞", 2);
  const analyze = renderSecAnalyzeBrief(snapshot, "挖掘认证前rce漏洞", 3, snapshot.surfaces[0]!);
  for (const text of [surface, analyze]) {
    for (const lie of ["验证等级", "对抗复核", "证伪", "verification tier"]) {
      assert.equal(text.includes(lie), false, `the brief must not promise ${lie}`);
    }
  }
  assert.match(analyze, /no assertion gate|COORDINATES|sec_clear/);
});

test("an update may not leave a finding with no artifact", () => {
  const cwd = seeded();
  const created = recordFinding(cwd, { title: "x", category: "rce", evidence: "src/a.c:1 system(c)" });
  assert.equal(created.ok, true);
  const id = created.ok ? created.value.id : "";
  assert.equal(updateFinding(cwd, id, { severity: "high" }).ok, true);
  assert.equal(updateFinding(cwd, "F-9999", { severity: "high" }).ok, false, "an unknown id is refused");
});

test("NO assertion gate — a noun phrase is a perfectly good finding title", () => {
  const cwd = seeded();
  // In hypothesis mode this exact string is refused: it has no truth value.
  assert.equal(
    recordFinding(cwd, { title: "src/diag/ 下的调试端点", category: "info-disclosure", file: "src/cfg/parse.c", line: 1 }).ok,
    true,
  );
});

test("a sec run creates NO hypothesis tree", () => {
  const cwd = seeded();
  startSec(cwd);
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
// The long-run shape of the analysis engine
// -----------------------------------------------------------------
//
// Stress-tested over 200 rounds before these were written, because the question
// "does `enumerate -> analyse xN -> enumerate` GROW or does it spin?" cannot be
// answered by reading the code. Measured: no item was ever enumerated twice, the
// run never went idle, and a model that swept ONE item per surface round still
// produced 12 findings over 200 rounds.
//
// The share of rounds spent enumerating is `1/(k+1)` for a sweep of k items, and that
// is the MODEL's rate rather than the loop's structure — so what is pinned here is
// that the loop keeps making progress and does not thrash, not a particular share.

test("a long run never re-enumerates a place it already has", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 8);
  submitSecRecon(cwd, NOTE);

  let seq = 0;
  for (let i = 0; i < 60; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    assert.equal(result.action, "sent", `round ${i + 1} stopped early: ${result.reason}`);
    const rec = load(cwd).snapshot.roundRecords.at(-1)!;
    if (rec.kind === "surface") {
      // A model that sweeps two places per surface round.
      for (let k = 0; k < 2; k++) {
        seq++;
        recordSurface(cwd, { title: `area ${seq} reaches a sink without the guard the code relies on`, kind: "file", file: "src/cfg/parse.c", line: 1 });
      }
    } else if (rec.kind === "analyze" && rec.surfaceId) {
      clearSurface(cwd, rec.surfaceId, "check_auth() runs at router.c:88 before dispatch and this path is not in the public table");
    }
  }

  const snap = load(cwd).snapshot;
  const titles = snap.surfaces.map((s) => s.title);
  assert.equal(titles.length, new Set(titles).size, "an item was enumerated twice — the loop is spinning");
  assert.equal(surfaceProgress(snap).open, 0, "every enumerated item gets analysed");
  assert.ok(snap.surfaces.length >= 30, `the surface must grow; it reached ${snap.surfaces.length}`);

  // The invariant is ASYMMETRIC, and it has to be: `analyze` dominating is the point
  // (it is the work), so what is pinned is that the ENUMERATION never takes the tier.
  // Its share is 1/(k+1) for a sweep of k items, so a two-item sweep measures 33% and
  // the one-item worst case lands on exactly 50% — the boundary this codebase uses for
  // "a trigger that is always true".
  const secRounds = snap.roundRecords.filter((r) => r.findingCountAtStart !== undefined);
  const surfaceShare = secRounds.filter((r) => r.kind === "surface").length / secRounds.length;
  assert.ok(surfaceShare <= 0.5, `enumeration took ${(surfaceShare * 100).toFixed(0)}% of the rounds`);
  const analyzeShare = secRounds.filter((r) => r.kind === "analyze").length / secRounds.length;
  assert.ok(analyzeShare >= 0.5, `analysis is the work and must keep the majority; it took ${(analyzeShare * 100).toFixed(0)}%`);
});

test("an analyze round that reveals a new place can record it without a surface round", () => {
  // The improvement the stress test pointed at: tracing one path is how you find the
  // next one, and a place noticed but not recorded is a place the run never returns to.
  const cwd = seeded();
  withSurface(cwd, 1);
  const brief = tickLoop(cwd, load(cwd).snapshot).brief!;
  assert.match(brief, /if the analysis reveals a NEW place/);
  assert.match(brief, /sec_surface` it right now/);
  assert.match(brief, /keeps the list growing without spending a\s+whole round on enumeration/);
});

// -----------------------------------------------------------------
// The command name is NOT the kind
// -----------------------------------------------------------------

test("the kind stays `sec` while the command is `/loopsec`", () => {
  // The two are different things and conflating them is a one-way door: the kind is
  // what the log stores, and `normalizeLoopState` DROPS an unknown one — so renaming
  // the kind would make every existing run unreadable. The command name is a UI
  // surface. Mapping it in one place is what stops the twenty hint strings from
  // assuming the two are equal.
  assert.equal(loopCommandName("sec"), "loopsec");
  assert.equal(loopCommandName("goal"), "goal");
  assert.equal(loopCommandName("loop"), "loop");
});

test("a loop started as kind `sec` still reads back after a round trip", () => {
  const cwd = seeded();
  startSec(cwd);
  const loop = load(cwd).snapshot.loop!;
  assert.equal(loop.kind, "sec", "the stored kind must not follow the command name");
  assert.equal(tickLoop(cwd, load(cwd).snapshot).action, "sent", "and the loop still drives");
});
