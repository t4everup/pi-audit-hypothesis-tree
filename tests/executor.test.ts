// pi-audit-hypothesis-tree — tests/executor.test.ts
//
// Pins the verification executor: every probe is a FALSIFICATION ATTEMPT, the
// aggregation is asymmetric (one counterexample refutes), every probe is
// bounded, and the executor never changes a status.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { DEFAULT_SETTINGS, loadSettings, saveSettings, settingsPath } from "../extensions/hypothesis-tree/settings.ts";
import {
  type ExecFn,
  looksCatastrophic,
  regexError,
  renderOutcome,
  runGrepProbe,
  runLocationProbe,
  runVerification,
  truncateOutput,
  verificationRefusal,
  walkProject,
} from "../extensions/hypothesis-tree/executor.ts";
import type { Hypothesis } from "../extensions/hypothesis-tree/types.ts";

const AT = "2026-01-01T00:00:00.000Z";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-exec-"));
}

function write(cwd: string, rel: string, body: string): void {
  const abs = path.join(cwd, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, body, "utf-8");
}

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
    createdAt: AT,
    lastTouchedAt: AT,
    score: 0,
    spawnedFrom: [],
    roundIntroduced: 0,
    timesSelected: 0,
    lastSelectedRound: null,
    ...over,
  };
}

const S = { ...DEFAULT_SETTINGS, allowCommandProbes: true, locationContext: 2 };

// -----------------------------------------------------------------
// Bounds helpers
// -----------------------------------------------------------------

test("truncateOutput keeps the HEAD and the TAIL, and says how much it dropped", () => {
  const text = "A".repeat(100) + "MIDDLE" + "Z".repeat(100);
  const out = truncateOutput(text, 60);
  assert.ok(out.startsWith("A"), "the head survives");
  assert.ok(out.endsWith("Z"), "the tail survives — that is where a test runner puts the failure");
  assert.match(out, /character\(s\) omitted/);
  assert.ok(out.length < text.length);
});

test("truncateOutput leaves a short string untouched", () => {
  assert.equal(truncateOutput("short", 100), "short");
});

test("looksCatastrophic refuses the classic nested-quantifier shapes", () => {
  for (const bad of ["(a+)+", "(\\w*)*", "(a+)*b", "(x{1,})*", "(a|a)*"]) {
    assert.ok(looksCatastrophic(bad), `should refuse: ${bad}`);
  }
});

test("looksCatastrophic accepts ordinary patterns", () => {
  for (const good of ["verify\\(", "jwt\\.verify", "function\\s+\\w+\\(", "(get|post)", "a+b*c?"]) {
    assert.equal(looksCatastrophic(good), null, `should accept: ${good}`);
  }
});

test("looksCatastrophic refuses an over-long pattern", () => {
  assert.match(looksCatastrophic("a".repeat(501))!, /longer than 500/);
});

test("regexError reports an invalid pattern", () => {
  assert.ok(regexError("([", true));
  assert.equal(regexError("verify\\(", true), null);
});

// -----------------------------------------------------------------
// walkProject bounds
// -----------------------------------------------------------------

test("walkProject skips the dependency and state directories", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "x");
  write(cwd, "node_modules/pkg/index.js", "x");
  write(cwd, ".git/HEAD", "x");
  write(cwd, ".pi-hypothesis/tree.jsonl", "x");
  write(cwd, "dist/bundle.js", "x");
  const found = walkProject(cwd, undefined, S).files.map((f) => path.relative(cwd, f).replace(/\\/g, "/"));
  assert.deepEqual(found, ["src/a.ts"], `the audit must not probe its own state or dependencies: ${found.join(", ")}`);
});

test("walkProject refuses a subPath outside the project", () => {
  const cwd = tmpProject();
  const result = walkProject(cwd, "../elsewhere", S);
  assert.equal(result.files.length, 0);
  assert.match(result.reason, /outside the project root/);
});

test("walkProject honours the file budget", () => {
  const cwd = tmpProject();
  for (let i = 0; i < 10; i++) write(cwd, `src/f${i}.ts`, "x");
  const result = walkProject(cwd, undefined, { ...S, maxFilesScanned: 3 });
  assert.equal(result.files.length, 3);
  assert.equal(result.truncated, true);
  assert.match(result.reason, /3-file budget/);
});

// -----------------------------------------------------------------
// location probe — the anti-fabrication gate
// -----------------------------------------------------------------

test("a location probe that exists SURVIVES and captures the slice with its coordinate", () => {
  const cwd = tmpProject();
  write(cwd, "src/auth/jwt.ts", "line1\nline2\nconst payload = decode(token)\nline4\nline5\n");
  const result = runLocationProbe(cwd, { kind: "location", file: "src/auth/jwt.ts", line: 3 }, S, AT);
  assert.equal(result.outcome, "survived");
  assert.match(result.summary, /exists \(5 lines\)/);
  assert.equal(result.evidence.length, 1);
  assert.deepEqual(result.evidence[0]!.location, { file: "src/auth/jwt.ts", line: 3 });
  assert.match(result.evidence[0]!.detail, /> {6}3 \| const payload = decode\(token\)/, "the target line is marked");
  assert.match(result.evidence[0]!.detail, / {6}2 \| line2/, "context is included");
});

test("a missing file FALSIFIES a 'present' prediction", () => {
  const cwd = tmpProject();
  const result = runLocationProbe(cwd, { kind: "location", file: "src/nope.ts", line: 1 }, S, AT);
  assert.equal(result.outcome, "falsified");
  assert.match(result.summary, /does not exist/);
  assert.equal(result.evidence.length, 0, "a missing file produces no artifact");
});

test("a missing file SURVIVES an 'absent' prediction", () => {
  const cwd = tmpProject();
  const result = runLocationProbe(cwd, { kind: "location", file: "src/nope.ts", line: 1, expectation: "absent" }, S, AT);
  assert.equal(result.outcome, "survived");
});

test("a line past the end of the file FALSIFIES the citation", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "one\ntwo\n");
  const result = runLocationProbe(cwd, { kind: "location", file: "src/a.ts", line: 900 }, S, AT);
  assert.equal(result.outcome, "falsified");
  assert.match(result.summary, /past the end of the file \(2 lines\)/);
});

test("a location outside the project is REFUSED as inconclusive", () => {
  const cwd = tmpProject();
  const result = runLocationProbe(cwd, { kind: "location", file: "../outside.ts", line: 1 }, S, AT);
  assert.equal(result.outcome, "inconclusive");
  assert.match(result.summary, /outside the project root/);
});

test("every location result states what it does NOT establish", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "x\n");
  const result = runLocationProbe(cwd, { kind: "location", file: "src/a.ts", line: 1 }, S, AT);
  assert.match(result.establishes, /does not establish/);
});

// -----------------------------------------------------------------
// grep probe
// -----------------------------------------------------------------

test("a grep that matches SURVIVES a 'present' prediction and records the coordinate", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "const x = 1;\nverify(token, key)\n");
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "verify\\(", expectation: "present" }, S, AT);
  assert.equal(result.outcome, "survived");
  assert.match(result.summary, /matched 1 line\(s\) in 1 file\(s\)/);
  assert.deepEqual(result.evidence[0]!.location, { file: "src/a.ts", line: 2 });
  assert.match(result.evidence[0]!.detail, /src\/a\.ts:2: verify\(token, key\)/);
});

test("a grep that matches nothing FALSIFIES a 'present' prediction", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "const x = 1;\n");
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "verify\\(", expectation: "present" }, S, AT);
  assert.equal(result.outcome, "falsified");
  assert.match(result.summary, /matched nothing/);
  assert.equal(result.evidence.length, 0);
});

test("a grep that matches nothing SURVIVES an 'absent' prediction", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "const x = 1;\n");
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "verify\\(", expectation: "absent" }, S, AT);
  assert.equal(result.outcome, "survived");
});

test("a grep that matches FALSIFIES an 'absent' prediction", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "verify(token, key)\n");
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "verify\\(", expectation: "absent" }, S, AT);
  assert.equal(result.outcome, "falsified");
});

test("a grep is case-insensitive by default and case-sensitive on request", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "VERIFY(token)\n");
  assert.equal(runGrepProbe(cwd, { kind: "grep", pattern: "verify", expectation: "present" }, S, AT).outcome, "survived");
  assert.equal(
    runGrepProbe(cwd, { kind: "grep", pattern: "verify", expectation: "present", ignoreCase: false }, S, AT).outcome,
    "falsified",
  );
});

test("a grep honours the match cap and says it stopped at the budget", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", Array.from({ length: 30 }, (_, i) => `verify(x${i})`).join("\n"));
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "verify\\(", expectation: "present" }, { ...S, maxGrepMatches: 5 }, AT);
  assert.match(result.summary, /matched 5 line\(s\)/);
  assert.match(result.summary, /scan stopped at the budget/);
});

test("a grep skips binary files", () => {
  const cwd = tmpProject();
  fs.writeFileSync(path.join(cwd, "blob.bin"), Buffer.from([0x00, 0x01, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79]));
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "verify", expectation: "present" }, S, AT);
  assert.equal(result.outcome, "falsified", "a NUL byte means the file is not text");
});

test("a catastrophic pattern is REFUSED before it runs", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "x\n");
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "(a+)+", expectation: "present" }, S, AT);
  assert.equal(result.outcome, "inconclusive");
  assert.match(result.summary, /pattern refused/);
  assert.match(result.errors[0]!, /nested quantifier/);
});

test("an invalid pattern is REFUSED as inconclusive, not as a falsification", () => {
  const cwd = tmpProject();
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "([", expectation: "present" }, S, AT);
  assert.equal(result.outcome, "inconclusive");
  assert.match(result.summary, /does not compile/);
});

test("a grep restricted to a subPath only scans that subtree", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "verify(x)\n");
  write(cwd, "other/b.ts", "verify(y)\n");
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "verify\\(", expectation: "present", subPath: "src" }, S, AT);
  assert.match(result.summary, /matched 1 line\(s\) in 1 file\(s\)/);
  assert.match(result.evidence[0]!.detail, /src\/a\.ts/);
  assert.doesNotMatch(result.evidence[0]!.detail, /other\/b\.ts/);
});

test("a grep subPath outside the project is refused", () => {
  const cwd = tmpProject();
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "x", expectation: "present", subPath: ".." }, S, AT);
  assert.equal(result.outcome, "inconclusive");
  assert.match(result.summary, /nothing scanned/);
});

test("every grep result states that a pattern match is not a data flow", () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "verify(x)\n");
  const result = runGrepProbe(cwd, { kind: "grep", pattern: "verify", expectation: "present" }, S, AT);
  assert.match(result.establishes, /not a data flow/);
});

// -----------------------------------------------------------------
// command probe — consent gate and bounds
// -----------------------------------------------------------------

function fakeExec(over: { stdout?: string; stderr?: string; code?: number; throws?: string } = {}): ExecFn {
  return async () => {
    if (over.throws) throw new Error(over.throws);
    return { stdout: over.stdout ?? "", stderr: over.stderr ?? "", code: over.code ?? 0 };
  };
}

test("a command probe is REFUSED when the project has not opted in", async () => {
  const cwd = tmpProject();
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "command", command: "npm", args: ["test"] }],
    settings: { ...S, allowCommandProbes: false },
    exec: fakeExec(),
    at: AT,
  });
  assert.equal(outcome.results[0]!.outcome, "inconclusive");
  assert.match(outcome.results[0]!.summary, /refused: command probes are disabled/);
  assert.match(outcome.results[0]!.errors[0]!, /allowCommandProbes/);
});

test("a command probe is REFUSED when no exec surface exists", async () => {
  const cwd = tmpProject();
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "command", command: "npm" }],
    settings: S,
    at: AT,
  });
  assert.equal(outcome.results[0]!.outcome, "inconclusive");
  assert.match(outcome.results[0]!.summary, /no exec surface/);
});

test("a command that exits zero SURVIVES the default expectation", async () => {
  const cwd = tmpProject();
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "command", command: "npm", args: ["test"] }],
    settings: S,
    exec: fakeExec({ stdout: "42 passing", code: 0 }),
    at: AT,
  });
  assert.equal(outcome.results[0]!.outcome, "survived");
  assert.match(outcome.results[0]!.summary, /exit 0 \(expected zero\)/);
  const evidence = outcome.evidence[0]!;
  assert.equal(evidence.kind, "command-output");
  assert.equal(evidence.command, "npm test", "the command is recorded so the output is reproducible");
  assert.match(evidence.detail, /42 passing/);
});

test("a command that exits nonzero FALSIFIES a 'zero' expectation", async () => {
  const cwd = tmpProject();
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "command", command: "npm", args: ["test"] }],
    settings: S,
    exec: fakeExec({ stderr: "3 failing", code: 1 }),
    at: AT,
  });
  assert.equal(outcome.results[0]!.outcome, "falsified");
  assert.match(outcome.evidence[0]!.detail, /3 failing/);
});

test("a command expectation of 'nonzero' inverts the sense", async () => {
  const cwd = tmpProject();
  const survived = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "command", command: "curl", expectation: "nonzero" }],
    settings: S,
    exec: fakeExec({ code: 7 }),
    at: AT,
  });
  assert.equal(survived.results[0]!.outcome, "survived");
});

test("a timed-out command is INCONCLUSIVE and still records what happened", async () => {
  const cwd = tmpProject();
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "command", command: "sleep", args: ["999"] }],
    settings: S,
    exec: fakeExec({ throws: "command timed out after 1000ms" }),
    at: AT,
  });
  assert.equal(outcome.results[0]!.outcome, "inconclusive");
  assert.match(outcome.results[0]!.summary, /timed out/);
  assert.equal(outcome.evidence.length, 1, "a timeout is itself evidence worth keeping");
});

test("an empty command is refused", async () => {
  const cwd = tmpProject();
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "command", command: "   " }],
    settings: S,
    exec: fakeExec(),
    at: AT,
  });
  assert.equal(outcome.results[0]!.outcome, "inconclusive");
  assert.match(outcome.results[0]!.summary, /empty command/);
});

// -----------------------------------------------------------------
// Aggregation — the falsification rule
// -----------------------------------------------------------------

test("ONE counterexample refutes, even alongside surviving probes", async () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "const x = 1;\n");
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [
      { kind: "grep", pattern: "const", expectation: "present" }, // survives
      { kind: "grep", pattern: "verify\\(", expectation: "present" }, // falsified
      { kind: "location", file: "src/a.ts", line: 1 }, // survives
    ],
    settings: S,
    at: AT,
  });
  assert.equal(outcome.suggestedVerdict, "rejected");
  assert.match(outcome.counterexample!, /matched nothing/);
  assert.match(outcome.rationale.join("\n"), /One counterexample refutes/);
  assert.match(outcome.rationale.join("\n"), /suggestion only/);
});

test("all probes surviving suggests CONFIRMED, and says support is not proof", async () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "verify(x)\n");
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [
      { kind: "grep", pattern: "verify", expectation: "present" },
      { kind: "location", file: "src/a.ts", line: 1 },
    ],
    settings: S,
    at: AT,
  });
  assert.equal(outcome.suggestedVerdict, "confirmed");
  assert.equal(outcome.counterexample, null);
  assert.match(outcome.rationale.join("\n"), /Support is not proof/);
});

test("all probes inconclusive suggests INCONCLUSIVE and asks for more", async () => {
  const cwd = tmpProject();
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "location", file: "src/missing.ts", line: 1, expectation: "absent" }],
    settings: S,
    at: AT,
  });
  // 'absent' + missing file = survived, so this one is a survival; use a
  // genuinely inconclusive probe instead.
  assert.equal(outcome.suggestedVerdict, "confirmed");
  const refused = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "command", command: "x" }],
    settings: { ...S, allowCommandProbes: false },
    at: AT,
  });
  assert.equal(refused.suggestedVerdict, "inconclusive");
  assert.equal(refused.needsMoreProbes, true);
  assert.match(refused.rationale.join("\n"), /More probes are needed/);
});

test("no probes at all is inconclusive, never a silent pass", async () => {
  const cwd = tmpProject();
  const outcome = await runVerification({ projectRoot: cwd, node: node(), probes: [], settings: S, at: AT });
  assert.equal(outcome.suggestedVerdict, "inconclusive");
  assert.equal(outcome.hasQuotableEvidence, false);
  assert.match(outcome.rationale[0]!, /No probes were supplied/);
});

test("the outcome carries every probe's evidence flattened", async () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "verify(x)\n");
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [
      { kind: "grep", pattern: "verify", expectation: "present" },
      { kind: "location", file: "src/a.ts", line: 1 },
    ],
    settings: S,
    at: AT,
  });
  assert.equal(outcome.evidence.length, 2);
  assert.equal(outcome.hasQuotableEvidence, true);
  assert.ok(outcome.evidence.every((e) => e.at === AT), "evidence is timestamped");
});

// -----------------------------------------------------------------
// The executor never decides
// -----------------------------------------------------------------

test("a node that already has a verdict is refused re-verification", () => {
  assert.match(verificationRefusal(node({ status: "confirmed" }))!, /already has the verdict "confirmed"/);
  assert.match(verificationRefusal(node({ status: "rejected" }))!, /reopen it/);
  assert.equal(verificationRefusal(node({ status: "pending" })), null);
  assert.equal(verificationRefusal(node({ status: "testing" })), null);
  assert.equal(verificationRefusal(node({ status: "blocked" })), null);
});

test("runVerification does not touch any status — it returns a suggestion only", async () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "x\n");
  const target = node({ status: "testing" });
  const outcome = await runVerification({
    projectRoot: cwd,
    node: target,
    probes: [{ kind: "grep", pattern: "x", expectation: "present" }],
    settings: S,
    at: AT,
  });
  assert.equal(outcome.suggestedVerdict, "confirmed");
  assert.equal(target.status, "testing", "the node object is untouched");
  assert.equal(target.evidence.length, 0, "the executor does not attach either — the caller does");
});

test("renderOutcome states the suggestion, the rationale and that it does not decide", async () => {
  const cwd = tmpProject();
  write(cwd, "src/a.ts", "verify(x)\n");
  const outcome = await runVerification({
    projectRoot: cwd,
    node: node(),
    probes: [{ kind: "grep", pattern: "verify", expectation: "present" }],
    settings: S,
    at: AT,
  });
  const text = renderOutcome(outcome).join("\n");
  assert.match(text, /verification of H-0001: suggested CONFIRMED/);
  assert.match(text, /evidence entry\/entries produced/);
  assert.match(text, /The executor does not decide/);
});

// -----------------------------------------------------------------
// Settings
// -----------------------------------------------------------------

test("command probes are OFF by default", () => {
  assert.equal(DEFAULT_SETTINGS.allowCommandProbes, false);
});

test("settings default when the file is absent, and report the source", () => {
  const cwd = tmpProject();
  const loaded = loadSettings(cwd);
  assert.equal(loaded.source, "defaults");
  assert.equal(loaded.settings.allowCommandProbes, false);
});

test("saveSettings round-trips and preserves unknown keys", () => {
  const cwd = tmpProject();
  fs.mkdirSync(path.dirname(settingsPath(cwd)), { recursive: true });
  fs.writeFileSync(settingsPath(cwd), JSON.stringify({ allowCommandProbes: false, futureKey: "keep me" }), "utf-8");
  const saved = saveSettings(cwd, { allowCommandProbes: true });
  assert.equal(saved.ok, true);
  assert.equal(loadSettings(cwd).settings.allowCommandProbes, true);
  const raw = JSON.parse(fs.readFileSync(settingsPath(cwd), "utf-8"));
  assert.equal(raw.futureKey, "keep me", "a key this build does not know must survive a write");
});

test("saveSettings rejects an unknown key and a wrong type", () => {
  const cwd = tmpProject();
  assert.equal(saveSettings(cwd, { nonsense: 1 } as never).ok, false);
  assert.equal(saveSettings(cwd, { allowCommandProbes: "yes" as never }).ok, false);
  assert.equal(saveSettings(cwd, { maxGrepMatches: "many" as never }).ok, false);
});

test("a corrupt settings file falls back to defaults AND reports the corruption", () => {
  const cwd = tmpProject();
  fs.mkdirSync(path.dirname(settingsPath(cwd)), { recursive: true });
  fs.writeFileSync(settingsPath(cwd), "{ not json", "utf-8");
  const loaded = loadSettings(cwd);
  assert.equal(loaded.source, "defaults");
  assert.equal(loaded.settings.allowCommandProbes, false);
  assert.match(loaded.error!, /not valid JSON/);
});

test("numeric settings are clamped to sane bounds", () => {
  const cwd = tmpProject();
  saveSettings(cwd, { maxGrepMatches: 999_999, locationContext: -5, commandTimeoutMs: 1 });
  const loaded = loadSettings(cwd).settings;
  assert.ok(loaded.maxGrepMatches <= 5_000);
  assert.ok(loaded.locationContext >= 0);
  assert.ok(loaded.commandTimeoutMs >= 1_000);
});
