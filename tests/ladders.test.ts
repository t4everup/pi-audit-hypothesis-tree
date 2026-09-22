// pi-audit-hypothesis-tree — tests/ladders.test.ts
//
// Pins the per-class exploitation ladders.
//
// The gap this closes, from a real scenario: an SSRF was confirmed — the server
// fetches a caller-directed URL, file:// included, exfiltrated indirectly through
// the parsed result — and "whether there is an echo channel" was never assessed.
//
// The axes a model happens not to think of are the axes nobody asks about, and an
// unasked axis is not a gap the report can see. The ladder is the smallest amount
// of domain knowledge that closes it: not how to exploit anything, just the
// questions, phrased so a "no" is as useful as a "yes".

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import { LADDERS, ladderFor, ladderSummary, renderLadder } from "../extensions/hypothesis-tree/ladders.ts";
import { HYPOTHESIS_CATEGORIES } from "../extensions/hypothesis-tree/types.ts";
import type { Evidence } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-ladder-"));
}

function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

const ANCHORED: Evidence = { kind: "code-slice", at: "", location: { file: "src/a.java", line: 1 }, detail: "x" };

// -----------------------------------------------------------------
// Coverage — every class gets a ladder, curated or generic
// -----------------------------------------------------------------

test("EVERY category gets a ladder — absence of knowledge is not absence of a question", () => {
  for (const category of HYPOTHESIS_CATEGORIES) {
    const ladder = ladderFor(category);
    assert.ok(ladder.axes.length > 0, `${category} must have at least one axis`);
    assert.ok(ladder.keyAxis.length > 0, `${category} must name a decisive axis`);
  }
});

test("a class with no curated ladder falls back rather than returning nothing", () => {
  // `dependency-risk` is deliberately not curated.
  assert.equal(LADDERS["dependency-risk"], undefined);
  const fallback = ladderFor("dependency-risk");
  assert.ok(fallback.axes.length >= 3);
  assert.match(fallback.keyAxis, /WHAT IT DEPENDS ON/);
});

test("the curated ladders cover the pre-auth high-severity classes", () => {
  for (const category of [
    "ssrf",
    "deserialization",
    "command-injection",
    "path-traversal",
    "arbitrary-file-read",
    "arbitrary-file-write",
    "file-upload",
    "xxe",
    "sqli",
    "ssti",
    "auth-bypass",
    "idor",
    "privilege-escalation",
    "info-disclosure",
    "hardcoded-secret",
    "open-redirect",
    "race-condition",
    "rce",
    "misconfiguration",
  ] as const) {
    assert.ok(LADDERS[category], `${category} must be curated`);
  }
});

// -----------------------------------------------------------------
// The axes that were missing
// -----------------------------------------------------------------

test("the SSRF ladder names the echo channel as the decisive axis", () => {
  const ladder = ladderFor("ssrf");
  // The user's exact gap: "是否有回显通道未评估".
  assert.match(ladder.keyAxis, /ECHO CHANNEL/);
  assert.match(ladder.keyAxis, /reflected/);
  const axes = ladder.axes.join("\n");
  for (const axis of ["ECHO CHANNEL", "PROTOCOL ALLOWLIST", "file://", "gopher://", "REDIRECTS", "169.254.169.254", "BLIND EXFIL"]) {
    assert.ok(axes.includes(axis), `the SSRF ladder must name ${axis}`);
  }
});

test("the deserialization ladder names the gadget chain as decisive", () => {
  const ladder = ladderFor("deserialization");
  assert.match(ladder.keyAxis, /GADGET CHAIN/);
  const axes = ladder.axes.join("\n");
  for (const axis of ["ObjectInputFilter", "classpath", "readObject", "ENTRY PRECONDITION"]) {
    assert.ok(axes.includes(axis), `must name ${axis}`);
  }
});

test("the auth-bypass ladder attacks the assumption that a controller alone settles it", () => {
  const axes = ladderFor("auth-bypass").axes.join("\n");
  for (const axis of ["GLOBAL ENFORCEMENT", "ENTRY POINT", "ROUTE ALIASES", "NORMALIZATION", "THE SAME CLASS", "DEFAULT DENY"]) {
    assert.ok(axes.includes(axis), `must name ${axis}`);
  }
});

test("the path-traversal ladder leads with read-versus-write", () => {
  const ladder = ladderFor("path-traversal");
  assert.match(ladder.keyAxis, /READ OR WRITE/);
  assert.match(ladder.keyAxis, /RCE/);
});

test("every axis is a question that can be answered NO", () => {
  for (const [category, ladder] of Object.entries(LADDERS)) {
    for (const axis of ladder!.axes) {
      // An axis phrased as an instruction ("check X") invites a checklist tick;
      // one phrased as a question can be settled either way, which is the point.
      assert.doesNotMatch(axis, /^(check|verify|look|test|find)\b/i, `${category}: "${axis}" reads as a task, not a question`);
      assert.ok(axis.length > 20, `${category}: "${axis}" is too short to be specific`);
    }
  }
});

// -----------------------------------------------------------------
// It reaches the two moments where the model can still act
// -----------------------------------------------------------------

test("the pursue brief carries the ladder for the finding's class", () => {
  const cwd = seeded();
  const node = addNode(cwd, { description: "服务端直接按外部实体指示发起出站请求，未限制协议，含 file:// 读本机文件", category: "ssrf" });
  setStatus(cwd, node.ok ? node.value.node.id : "?", "confirmed", { severity: "high", evidence: [ANCHORED] });
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });

  let brief: string | null = null;
  for (let i = 0; i < 6 && !brief; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (!r.brief) break;
    if (r.brief.includes("— PURSUE]")) brief = r.brief;
  }
  assert.ok(brief, "a pursue round must have run on a confirmed HIGH finding");
  assert.match(brief!, /## The depth axes for ssrf/);
  assert.match(brief!, /ECHO CHANNEL/);
  assert.match(brief!, /An axis you cannot settle becomes a GATE hypothesis/);
  assert.match(brief!, /hypothesis_vector H-\d+ requires=\[\.\.\.\]/, "and it says how to link them");
});

test("the challenge brief carries the ladder — the axes are what to attack", () => {
  const cwd = seeded();
  const node = addNode(cwd, { description: "服务端直接按外部实体指示发起出站请求，未限制协议，含 file:// 读本机文件", category: "ssrf" });
  setStatus(cwd, node.ok ? node.value.node.id : "?", "confirmed", { severity: "high", evidence: [ANCHORED] });
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });

  let brief: string | null = null;
  for (let i = 0; i < 6 && !brief; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (!r.brief) break;
    if (r.brief.includes("— CHALLENGE]")) brief = r.brief;
  }
  assert.ok(brief, "a challenge round must have run");
  assert.match(brief!, /## The depth axes for ssrf/);
});

test("the confirmation nudge carries the ladder", () => {
  const cwd = seeded();
  const node = addNode(cwd, { description: "服务端直接按外部实体指示发起出站请求，未限制协议，含 file:// 读本机文件", category: "ssrf" });
  assert.equal(node.ok, true);
  const text = renderLadder("ssrf", node.ok ? node.value.node.id : "H-0002");
  assert.match(text, /The depth axes for ssrf/);
  assert.match(text, /Prose is recorded, printed, and then tested by nothing/);
  assert.match(text, /hypothesis_vector H-0002 requires=\[\.\.\.\]/);
});

test("the ladder renders in Chinese for a Chinese project", () => {
  const text = renderLadder("ssrf", "H-0002", "zh");
  assert.match(text, /## ssrf 的深度轴/);
  assert.match(text, /没有 settle 的轴，就变成一条 gate 假设/);
  assert.match(text, /ECHO CHANNEL/, "the axis names stay English — they are the technical terms");
});

test("ladderSummary is a one-liner for a tool response", () => {
  const summary = ladderSummary("ssrf");
  assert.match(summary, /depth axes for ssrf/);
  assert.match(summary, /ECHO CHANNEL/);
  assert.equal(summary.split("\n").length, 1);
});

// -----------------------------------------------------------------
// It is knowledge, not a mandate
// -----------------------------------------------------------------

test("the ladder does not tell the model what to conclude", () => {
  const text = renderLadder("ssrf", "H-0002");
  // Every axis must be answerable either way. A ladder that only made sense if
  // the answer were "yes" would manufacture the finding it claims to test.
  assert.doesNotMatch(text, /\b(must be vulnerable|will be exploitable|confirm that)\b/i);
  assert.match(text, /"no" is as useful an answer as "yes"/);
});
