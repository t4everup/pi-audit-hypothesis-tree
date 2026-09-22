// pi-audit-hypothesis-tree — tests/recon.test.ts
//
// Pins stage 6: the audit of an UNFAMILIAR project. A scope node is a boundary
// rather than a claim, the recon note is chunked mechanically into segments,
// coverage is the denominator that ends the generation phase, and an attack
// vector is a field on the hypothesis.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, createTree, getNode, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { planNextRound } from "../extensions/hypothesis-tree/scheduler.ts";
import { startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import {
  RECON,
  chunkNote,
  closedSegmentIds,
  describeVector,
  hypothesesForSegment,
  nextOpenSegment,
  reconNotePath,
  recordSegmentOutcome,
  renderCoverage,
  renderReconBrief,
  renderSegmentBrief,
  segmentById,
  segmentCoverage,
  segmentIdFor,
  splitParagraphs,
  submitRecon,
  vectorCoverage,
} from "../extensions/hypothesis-tree/recon.ts";
import { isSchedulable, validateAttackVector, validateHypothesisInput } from "../extensions/hypothesis-tree/types.ts";
import type { AttackVector, Hypothesis } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-recon-"));
}

const NOTE = [
  "The project is a small Node service. It exposes three HTTP routes under /api: login, refresh and export, and it consumes one queue topic named order.created.",
  "Authentication is a JWT bearer token. The middleware under src/auth/ decodes the token and attaches the payload to the request, and the routes read the payload directly.",
  "The export route returns records selected by an id taken from the query string. I could not find an ownership check between the id and the caller in the time available.",
  "The queue consumer deserializes the message body with a generic parser. I did not read the parser itself, so I cannot say whether it restricts the types it will construct.",
  "There is no CSRF protection on the refresh route, which is a cookie-authenticated POST.",
  "Configuration is read from environment variables at boot; I did not find any secret in the repository.",
].join("\n\n");

function seeded(): string {
  const cwd = tmpProject();
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

function add(cwd: string, description: string, category: string, over: { segmentId?: string; attackVector?: AttackVector } = {}): Hypothesis {
  const result = addNode(cwd, { description, category, ...over });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result.ok ? result.value.node : (undefined as never);
}

// -----------------------------------------------------------------
// The scope node kind
// -----------------------------------------------------------------

test("a scope root is exempt from the assertion gate; a hypothesis root is not", () => {
  const cwd = tmpProject();
  // "audit this project" is not a claim, and a falsification tree must not be
  // rooted in the one node that can never be falsified.
  const scope = createTree(cwd, "audit this project", { nodeKind: "scope" });
  assert.equal(scope.ok, true, scope.ok ? "" : scope.errors.join("; "));
  assert.equal(scope.ok && scope.value.root.nodeKind, "scope");

  const cwd2 = tmpProject();
  const bad = createTree(cwd2, "audit this project", { nodeKind: "hypothesis" });
  assert.equal(bad.ok, false);
  assert.match(bad.ok ? "" : bad.errors.join("\n"), /TASK|truth value/);
});

test("nodeKind defaults to hypothesis, so /hypothesis new is unchanged", () => {
  const cwd = tmpProject();
  const created = createTree(cwd, "the login handler accepts a JWT without verifying its signature", { category: "auth-bypass" });
  assert.equal(created.ok, true);
  assert.equal(created.ok && created.value.root.nodeKind, "hypothesis");
});

test("a scope node is NOT schedulable — it has no truth value", () => {
  const cwd = seeded();
  const snap = load(cwd).snapshot;
  const root = getNode(snap, "H-0001")!;
  assert.equal(isSchedulable(root), false);
  assert.equal(planNextRound(snap).selected, null, "the scheduler must not offer the scope node");

  const hypothesis = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass");
  assert.equal(isSchedulable(getNode(load(cwd).snapshot, hypothesis.id)!), true);
  assert.equal(planNextRound(load(cwd).snapshot).selected?.id, hypothesis.id);
});

test("a scope node is not counted as pending work", async () => {
  const cwd = seeded();
  add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass");
  const { summarize } = await import("../extensions/hypothesis-tree/tree.ts");
  const summary = summarize(load(cwd).snapshot);
  assert.equal(summary.scopeNodes, 1);
  assert.equal(summary.nodes, 2);
  assert.equal(summary.byStatus.pending, 1, "only the hypothesis is pending");
});

// -----------------------------------------------------------------
// Paragraph splitting
// -----------------------------------------------------------------

test("paragraphs split on blank lines", () => {
  assert.deepEqual(splitParagraphs("one\n\ntwo\n\n\nthree"), ["one", "two", "three"]);
  assert.deepEqual(splitParagraphs("only one"), ["only one"]);
  assert.deepEqual(splitParagraphs(""), []);
  assert.deepEqual(splitParagraphs("\n\n\n"), []);
});

test("a fenced code block is kept intact even when it contains blank lines", () => {
  // The regression this guards: a naive split would cut the block in half and
  // hand the model a segment that starts in the middle of a function.
  const note = ["before", "", "```js", "function f() {", "", "  return 1;", "}", "```", "", "after"].join("\n");
  const paragraphs = splitParagraphs(note);
  assert.equal(paragraphs.length, 3, paragraphs.join(" || "));
  assert.match(paragraphs[1]!, /```js[\s\S]*return 1[\s\S]*```/, "the whole fence survives as one paragraph");
  assert.deepEqual(paragraphs, ["before", "```js\nfunction f() {\n\n  return 1;\n}\n```", "after"]);
});

test("a tilde fence is tracked the same way", () => {
  const note = ["a", "", "~~~", "", "~~~", "", "b"].join("\n");
  assert.equal(splitParagraphs(note).length, 3);
});

// -----------------------------------------------------------------
// Segment identity and chunking
// -----------------------------------------------------------------

test("segment ids are content AND position derived", () => {
  assert.equal(segmentIdFor(0, "hello"), segmentIdFor(0, "hello"), "stable for the same input");
  assert.notEqual(segmentIdFor(0, "hello"), segmentIdFor(0, "hello!"), "content changes the id");
  assert.notEqual(segmentIdFor(0, "hello"), segmentIdFor(1, "hello"), "position changes the id");
  assert.match(segmentIdFor(3, "x"), /^S-003-[0-9a-f]{8}$/);
});

test("chunkNote groups paragraphs N at a time and keeps a short tail", () => {
  const six = ["p1", "p2", "p3", "p4", "p5", "p6"].join("\n\n");
  const segments = chunkNote(six, { paragraphsPerSegment: 4 });
  assert.equal(segments.length, 2);
  assert.equal(segments[0]!.paragraphs, 4);
  assert.equal(segments[1]!.paragraphs, 2, "the tail is kept, not dropped");
  assert.equal(segments[0]!.text, "p1\n\np2\n\np3\n\np4");
});

test("the paragraph count is clamped to the design's 3-5 range", () => {
  const nine = Array.from({ length: 9 }, (_, i) => `p${i}`).join("\n\n");
  assert.equal(chunkNote(nine, { paragraphsPerSegment: 1 })[0]!.paragraphs, RECON.MIN_PARAGRAPHS_PER_SEGMENT);
  assert.equal(chunkNote(nine, { paragraphsPerSegment: 99 })[0]!.paragraphs, RECON.MAX_PARAGRAPHS_PER_SEGMENT, "clamped at the top of the range");
  assert.equal(chunkNote(nine, { paragraphsPerSegment: 99 }).length, 2, "9 paragraphs at 5 per segment is 5 + 4");
  assert.equal(RECON.MIN_PARAGRAPHS_PER_SEGMENT, 3);
  assert.equal(RECON.MAX_PARAGRAPHS_PER_SEGMENT, 5);
});

test("chunkNote on an empty note yields nothing", () => {
  assert.deepEqual(chunkNote(""), []);
});

// -----------------------------------------------------------------
// Submitting recon
// -----------------------------------------------------------------

test("a recon note that is too short to describe a project is refused", () => {
  const cwd = seeded();
  const result = submitRecon(cwd, "it is a web app");
  assert.equal(result.ok, false);
  assert.match(result.errors[0]!, /too short to describe a project/);
  assert.equal(load(cwd).snapshot.segments.length, 0, "nothing was recorded");
});

test("submitRecon records the segments and writes the note for humans", () => {
  const cwd = seeded();
  const result = submitRecon(cwd, NOTE);
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  assert.ok(result.segments!.length >= 2);
  const snap = load(cwd).snapshot;
  assert.equal(snap.segments.length, result.segments!.length);
  assert.ok(snap.reconAt);
  assert.equal(fs.readFileSync(reconNotePath(cwd), "utf-8").trim(), NOTE);
});

// -----------------------------------------------------------------
// Coverage — the denominator
// -----------------------------------------------------------------

test("coverage starts at zero and names the open segments", () => {
  const cwd = seeded();
  submitRecon(cwd, NOTE);
  const coverage = segmentCoverage(load(cwd).snapshot);
  assert.equal(coverage.covered, 0);
  assert.equal(coverage.open.length, coverage.total);
  assert.equal(nextOpenSegment(load(cwd).snapshot)!.id, coverage.open[0]);
});

test("a hypothesis carrying a segmentId closes that segment", () => {
  const cwd = seeded();
  const submitted = submitRecon(cwd, NOTE);
  const first = submitted.segments![0]!.id;
  add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass", { segmentId: first });

  const coverage = segmentCoverage(load(cwd).snapshot);
  assert.equal(coverage.covered, 1);
  assert.ok(!coverage.open.includes(first));
  assert.equal(closedSegmentIds(load(cwd).snapshot).has(first), true);
});

test("an explicit nothing-found closes a segment, and REQUIRES a note", () => {
  const cwd = seeded();
  const first = submitRecon(cwd, NOTE).segments![0]!.id;
  const refused = recordSegmentOutcome(cwd, first, "nothing-found", {});
  assert.equal(refused.ok, false);
  assert.match(refused.errors[0]!, /indistinguishable from not looking/);

  const ok = recordSegmentOutcome(cwd, first, "nothing-found", { note: "read the boot sequence; no external input" });
  assert.equal(ok.ok, true);
  assert.equal(segmentCoverage(load(cwd).snapshot).covered, 1);
});

test("an unknown segment id is accepted by the ledger but changes nothing about coverage", () => {
  const cwd = seeded();
  submitRecon(cwd, NOTE);
  const before = segmentCoverage(load(cwd).snapshot).covered;
  recordSegmentOutcome(cwd, "S-999-deadbeef", "nothing-found", { note: "x" });
  assert.equal(segmentCoverage(load(cwd).snapshot).covered, before);
});

test("coverage is complete once every segment is closed", () => {
  const cwd = seeded();
  const submitted = submitRecon(cwd, NOTE);
  for (const segment of submitted.segments!) {
    recordSegmentOutcome(cwd, segment.id, "nothing-found", { note: "read it; no attack surface" });
  }
  const coverage = segmentCoverage(load(cwd).snapshot);
  assert.equal(coverage.covered, coverage.total);
  assert.deepEqual(coverage.open, []);
  assert.equal(nextOpenSegment(load(cwd).snapshot), null);
});

test("editing the note re-opens ONLY the segments whose text changed", () => {
  const cwd = seeded();
  const submitted = submitRecon(cwd, NOTE);
  for (const segment of submitted.segments!) {
    recordSegmentOutcome(cwd, segment.id, "nothing-found", { note: "read it" });
  }
  assert.equal(segmentCoverage(load(cwd).snapshot).open.length, 0);

  // Change the FIRST paragraph only.
  const edited = NOTE.replace("small Node service", "small Deno service");
  const again = submitRecon(cwd, edited);
  assert.equal(again.ok, true);
  const coverage = segmentCoverage(load(cwd).snapshot);
  assert.equal(coverage.open.length, 1, `only the changed segment re-opened: ${coverage.open.join(", ")}`);
  assert.equal(coverage.open[0], again.segments![0]!.id);
  assert.notEqual(again.segments![0]!.id, submitted.segments![0]!.id, "the id changed because the content did");
  assert.equal(again.segments![1]!.id, submitted.segments![1]!.id, "the untouched segment kept its id, so it stays covered");
});

// -----------------------------------------------------------------
// Attack vectors
// -----------------------------------------------------------------

const VECTOR: AttackVector = {
  entrypoint: "POST /api/login",
  technique: "alg=none JWT forgery",
  path: [
    { detail: "send a token whose header says alg=none", location: { file: "src/auth/jwt.ts", line: 41 } },
    { detail: "the verifier accepts the unsigned token", location: { file: "src/auth/jwt.ts", line: 88 } },
  ],
  payload: '{"alg":"none","typ":"JWT"}.{"sub":"admin"}.',
  preconditions: ["the login route is reachable without credentials"],
};

test("validateAttackVector requires an entrypoint and a technique", () => {
  assert.equal(validateAttackVector(undefined).ok, true, "an absent vector is legal — it means 'not yet known'");
  const missing = validateAttackVector({ path: [] } as Partial<AttackVector>);
  assert.equal(missing.ok, false);
  assert.match(missing.errors.join("\n"), /entrypoint is required/);
  assert.match(missing.errors.join("\n"), /technique is required/);
  assert.equal(validateAttackVector(VECTOR).ok, true);
});

test("validateAttackVector rejects a path step with no detail", () => {
  const bad = validateAttackVector({ entrypoint: "x", technique: "y", path: [{ detail: "" }] });
  assert.equal(bad.ok, false);
  assert.match(bad.errors.join("\n"), /path\[0\] needs a detail/);
});

test("a vector survives the store round trip", () => {
  const cwd = seeded();
  const node = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass", { attackVector: VECTOR });
  const reloaded = getNode(load(cwd).snapshot, node.id)!;
  assert.deepEqual(reloaded.attackVector, VECTOR);
});

test("describeVector names the entrypoint, technique, step count and preconditions", () => {
  const text = describeVector(VECTOR);
  assert.match(text, /POST \/api\/login · alg=none JWT forgery · 2 step\(s\)/);
  assert.match(text, /needs the login route is reachable without credentials/);
});

test("vectorCoverage counts hypotheses with and without a vector", () => {
  const cwd = seeded();
  add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass", { attackVector: VECTOR });
  add(cwd, "the export endpoint returns records the caller does not own", "idor");
  const coverage = vectorCoverage(load(cwd).snapshot);
  assert.equal(coverage.withVector, 1);
  assert.equal(coverage.withoutVector, 1, "an absent vector means 'unknown', and it is counted as such");
});

test("hypothesesForSegment returns exactly that segment's output", () => {
  const cwd = seeded();
  const first = submitRecon(cwd, NOTE).segments![0]!.id;
  const second = submitRecon(cwd, NOTE).segments![1]!.id;
  const a = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass", { segmentId: first });
  add(cwd, "the export endpoint returns records the caller does not own", "idor", { segmentId: second });
  assert.deepEqual(hypothesesForSegment(load(cwd).snapshot, first).map((n) => n.id), [a.id]);
});

// -----------------------------------------------------------------
// Briefs
// -----------------------------------------------------------------

test("the recon brief asks for prose, names what to cover, and forbids hypothesising", () => {
  const text = renderReconBrief(load(seeded()).snapshot, "audit the login flow");
  assert.match(text, /\[AUDIT ROUND 1 — RECON\]/);
  assert.match(text, /Audit objective: audit the login flow/);
  assert.match(text, /There is no hypothesis tree yet/);
  assert.match(text, /what the project IS/);
  assert.match(text, /ENTRYPOINTS/);
  assert.match(text, /TRUST BOUNDARIES/);
  assert.match(text, /what you could NOT work out/);
  assert.match(text, /call hypothesis_recon/);
  assert.match(text, /WRITE IT AS PARAGRAPHS/);
  assert.match(text, /Do NOT write hypotheses yet/);
});

test("the segment brief quotes the segment and asks for vectors as a FIELD", () => {
  const cwd = seeded();
  const submitted = submitRecon(cwd, NOTE);
  const segment = submitted.segments![0]!;
  const text = renderSegmentBrief(load(cwd).snapshot, segment, "audit the login flow", segmentCoverage(load(cwd).snapshot));
  assert.match(text, new RegExp(`GENERATE from segment ${segment.id}`));
  assert.match(text, /Segment 1 of \d+/);
  assert.match(text, new RegExp(segment.text.slice(0, 40).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(text, /hypothesis_add with:/);
  assert.match(text, /attackVector {4}\{ entrypoint, path:/);
  assert.match(text, /It is a FIELD on the\s+hypothesis, not a separate node/);
  assert.match(text, /hypothesis_cover_segment/);
  assert.match(text, /Derive only what THIS segment supports/);
});

test("renderCoverage reports 'not run' before recon, then the denominator", () => {
  const cwd = seeded();
  assert.match(renderCoverage(load(cwd).snapshot), /recon: not run yet/);
  const submitted = submitRecon(cwd, NOTE);
  assert.match(renderCoverage(load(cwd).snapshot), /recon: 0\/\d+ segment\(s\) covered \(0%\)/);
  for (const segment of submitted.segments!) recordSegmentOutcome(cwd, segment.id, "nothing-found", { note: "read it" });
  assert.match(renderCoverage(load(cwd).snapshot), /generation complete/);
});

test("segmentById finds a segment and returns undefined for an unknown id", () => {
  const cwd = seeded();
  const first = submitRecon(cwd, NOTE).segments![0]!;
  assert.equal(segmentById(load(cwd).snapshot, first.id)!.text, first.text);
  assert.equal(segmentById(load(cwd).snapshot, "S-999-deadbeef"), undefined);
});

// -----------------------------------------------------------------
// The full flow: bootstrap → recon → generate → verify
// -----------------------------------------------------------------

test("a /goal on an unfamiliar project runs recon, then generate, then verify", () => {
  const cwd = tmpProject();
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true);
  const started = startLoop(cwd, load(cwd).snapshot, { kind: "goal", objective: "audit the login flow", plateauWindow: 99 });
  assert.equal(started.ok, true, started.ok ? "" : started.errors.join("; "));

  // Round 1 — RECON.
  const round1 = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(round1.action, "sent");
  assert.equal(round1.brief!.includes("[AUDIT ROUND 1 — RECON]"), true);
  assert.equal(load(cwd).snapshot.roundRecords[0]!.kind, "recon");

  // The model submits its notes.
  const submitted = submitRecon(cwd, NOTE);
  assert.equal(submitted.ok, true);
  const segments = submitted.segments!;

  // Round 2 — GENERATE from the first segment.
  const round2 = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(round2.action, "sent");
  assert.equal(round2.segmentId, segments[0]!.id);
  assert.equal(load(cwd).snapshot.roundRecords[1]!.kind, "generate");
  assert.match(round2.brief!, new RegExp(`GENERATE from segment ${segments[0]!.id}`));

  // The model adds a hypothesis with a vector, which closes the segment.
  const hypothesis = add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass", {
    segmentId: segments[0]!.id,
    attackVector: VECTOR,
  });
  assert.equal(segmentCoverage(load(cwd).snapshot).covered, 1);

  // Close the remaining segments explicitly.
  for (const segment of segments.slice(1)) {
    recordSegmentOutcome(cwd, segment.id, "nothing-found", { note: "read it; no attack surface" });
  }
  assert.deepEqual(segmentCoverage(load(cwd).snapshot).open, []);

  // Round 3 — GENERATION IS DONE, so the loop moves to verification of the
  // hypothesis the recon produced.
  const round3 = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(round3.action, "sent");
  assert.equal(round3.nodeId, hypothesis.id);
  assert.equal(load(cwd).snapshot.roundRecords[2]!.kind, "verify");
  assert.match(round3.brief!, /\[AUDIT ROUND 3 — VERIFY\]/);
  assert.match(round3.brief!, /YOUR NODE: H-0002/);
});

test("the recon round is judged by whether a note was submitted", () => {
  const cwd = tmpProject();
  createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);

  // Nothing submitted: the next tick reports an unproductive recon round.
  const unproductive = tickLoop(cwd, load(cwd).snapshot);
  assert.match(unproductive.previous!.detail, /no recon note was submitted/);
  assert.equal(unproductive.previous!.produced, false);
});

test("the generate round is judged by whether its segment closed", () => {
  const cwd = tmpProject();
  createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  tickLoop(cwd, load(cwd).snapshot);
  submitRecon(cwd, NOTE);
  tickLoop(cwd, load(cwd).snapshot); // round 2: generate

  // Round 3 evaluates round 2, whose segment produced nothing and stayed open.
  const result = tickLoop(cwd, load(cwd).snapshot);
  assert.match(result.previous!.detail, /produced no hypotheses and was not closed/);
  assert.equal(result.previous!.produced, false);
});

test("recon state survives a compaction", async () => {
  const cwd = seeded();
  const submitted = submitRecon(cwd, NOTE);
  add(cwd, "the login handler accepts a JWT without verifying its signature", "auth-bypass", {
    segmentId: submitted.segments![0]!.id,
    attackVector: VECTOR,
  });
  const { compact } = await import("../extensions/hypothesis-tree/store.ts");
  assert.equal(compact(cwd), true);
  const snap = load(cwd).snapshot;
  assert.equal(snap.segments.length, submitted.segments!.length);
  assert.ok(snap.reconAt);
  assert.equal(segmentCoverage(snap).covered, 1);
  assert.ok(getNode(snap, "H-0002")!.attackVector, "the vector survives too");
});

// -----------------------------------------------------------------
// The recon brief states the STAKES
// -----------------------------------------------------------------
//
// Measured on a real Centreon audit: 16 paragraphs -> 4 segments -> 4 generation
// rounds -> 23 hypotheses, and 92% of every hypothesis that audit ever recorded
// came from those 4 windows. Nothing came from anywhere else, because generation
// is segment-driven and nothing later goes back and reads an area the note did not
// mention.
//
// The brief said "every later hypothesis is derived from it" without saying
// "and there is no second pass", which reads as one step among several.

test("the recon brief says it is the ONLY recon pass", () => {
  const cwd = seeded();
  const brief = renderReconBrief(load(cwd).snapshot, "audit the project");
  assert.match(brief, /THIS IS THE ONLY RECON PASS, AND IT SETS THE CEILING/);
  assert.match(brief, /nothing later goes back and reads a subsystem this/);
  assert.match(brief, /the number of segments you write here is the number of\s+windows this audit will ever look through/);
});

test("the recon brief states the measured consequence", () => {
  const cwd = seeded();
  const brief = renderReconBrief(load(cwd).snapshot, "audit the project");
  // A concrete number from a real run, not an assertion about importance.
  assert.match(brief, /16 paragraphs became 4 segments/);
  assert.match(brief, /92% of every\s+hypothesis that audit ever recorded came from those 4 windows/);
  assert.match(brief, /\*\*A part of the project absent from this note is a part nothing will look at\.\*\*/);
});

test("the recon brief says granularity is not a budget", () => {
  const cwd = seeded();
  const brief = renderReconBrief(load(cwd).snapshot, "audit the project");
  assert.match(brief, /COVER THE WHOLE PROJECT, AND BE GENEROUS/);
  assert.match(brief, /GRANULARITY, not the BUDGET/);
  assert.match(brief, /not sixteen for the lot/);
});

test("the recon brief asks for the areas NOT looked at, by name", () => {
  const cwd = seeded();
  const brief = renderReconBrief(load(cwd).snapshot, "audit the project");
  assert.match(brief, /Name what you did NOT look at/);
  // The reason silence is the wrong answer: it is ambiguous.
  assert.match(brief, /silence is indistinguishable from/);
});

test("the recon brief still forbids writing hypotheses", () => {
  const cwd = seeded();
  const brief = renderReconBrief(load(cwd).snapshot, "audit the project");
  // The added pressure must not turn the recon round into a guessing round.
  assert.match(brief, /Do NOT write hypotheses yet/);
  assert.match(brief, /a hypothesis written before\s+the project has been read is a guess/);
});

test("the recon brief still explains the chunking", () => {
  const cwd = seeded();
  const brief = renderReconBrief(load(cwd).snapshot, "audit the project");
  assert.match(brief, /split into segments of 3–5 paragraphs/);
  assert.match(brief, /one coherent\s+thought about one part of the project/);
});
