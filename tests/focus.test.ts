// pi-audit-hypothesis-tree — tests/focus.test.ts
//
// Pins `focus=` — the operator's scope, as a PREFERENCE.
//
// Measured on a real audit: the objective was "find pre-auth RCE", and 7 of the 9
// never-examined hypotheses were auth-bypass. The objective's wording steered the
// recon, the recon steered generation, and nothing ever narrowed it.
//
// It is deliberately NOT a filter. A pre-auth RCE is routinely reached by chaining
// a finding from some other class, and refusing the other class would make exactly
// that chain unfindable.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { submitRecon } from "../extensions/hypothesis-tree/recon.ts";

/** A recon note long enough to pass the minimum, chunked into segments. */
const NOTE = Array.from({ length: 6 }, (_, i) =>
  `Paragraph ${i}: this part of the project has an entrypoint, a trust boundary, and a data flow that I read carefully enough to describe in a sentence.`,
).join("\n\n");
import { renderFocus, startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import { buildContext, planNextRound, scoreCandidate } from "../extensions/hypothesis-tree/scheduler.ts";
import { SCORE_WEIGHTS } from "../extensions/hypothesis-tree/scheduler.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-focus-"));
}

function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

function add(cwd: string, description: string, category: string): string {
  const r = addNode(cwd, { description, category });
  assert.equal(r.ok, true, r.ok ? "" : r.errors.join("; "));
  return r.ok ? r.value.node.id : "";
}

// -----------------------------------------------------------------
// It is carried, and it survives
// -----------------------------------------------------------------

test("the loop carries the focus, and it survives the ledger", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99, focus: ["ssrf", "deserialization"] });
  assert.deepEqual(load(cwd).snapshot.loop!.focus, ["ssrf", "deserialization"]);
});

test("no focus means no focus — the field is absent, not empty", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  assert.equal(load(cwd).snapshot.loop!.focus, undefined);
});

// -----------------------------------------------------------------
// It is a BIAS, not a filter
// -----------------------------------------------------------------

test("a focus class outscores an identical node outside it", () => {
  const cwd = seeded();
  const inside = add(cwd, "the importer fetches a caller-supplied URL without a protocol allowlist", "ssrf");
  const outside = add(cwd, "the export endpoint returns records the caller does not own", "idor");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99, focus: ["ssrf"] });

  const snap = load(cwd).snapshot;
  const context = buildContext(snap, 3);
  const a = scoreCandidate(snap.byId.get(inside)!, context);
  const b = scoreCandidate(snap.byId.get(outside)!, context);
  assert.equal(a.focusBoost, SCORE_WEIGHTS.focusBoost);
  assert.equal(b.focusBoost, 0);
  assert.ok(a.total > b.total, `focus ${a.total} must beat non-focus ${b.total}`);
});

test("a node OUTSIDE the focus is still scheduled when nothing inside it is due", () => {
  const cwd = seeded();
  // Nothing in the focus exists at all.
  add(cwd, "the export endpoint returns records the caller does not own", "idor");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99, focus: ["ssrf"] });

  const decision = planNextRound(load(cwd).snapshot, { round: 3 });
  assert.ok(decision.selected, "the idor node must still be selectable — a filter would refuse it");
  assert.equal(load(cwd).snapshot.byId.get(decision.selected!.id)!.category, "idor");
});

test("the boost is a preference, not a guarantee — a gate still outranks it", () => {
  const cwd = seeded();
  const gate = add(cwd, "the schedule_data column can be written before authentication", "auth-bypass");
  const sink = addNode(cwd, {
    description: "the scheduled task deserializes attacker-controlled bytes with no filter",
    category: "deserialization",
    requires: [gate],
  });
  assert.equal(sink.ok, true);
  const { setStatus } = require("../extensions/hypothesis-tree/tree.ts") as typeof import("../extensions/hypothesis-tree/tree.ts");
  setStatus(cwd, sink.ok ? sink.value.node.id : "?", "confirmed", {
    severity: "critical",
    evidence: [{ kind: "code-slice", at: "", location: { file: "src/a.java", line: 1 }, detail: "x" }],
  });
  // The run is scoped to ssrf; the gate is auth-bypass.
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99, focus: ["ssrf"] });

  const snap = load(cwd).snapshot;
  const context = buildContext(snap, 4);
  const g = scoreCandidate(snap.byId.get(gate)!, context);
  assert.equal(g.focusBoost, 0, "the gate is outside the focus");
  assert.equal(g.gateBoost, SCORE_WEIGHTS.gateBoost);
  // Confirming the gate is what turns a confirmed sink into an exploit. That
  // outranks the operator's stated scope, and it should.
  assert.ok(g.gateBoost > SCORE_WEIGHTS.focusBoost);
});

// -----------------------------------------------------------------
// The brief states it
// -----------------------------------------------------------------

test("renderFocus says it is a preference, and says what to do with the rest", () => {
  const text = renderFocus(["ssrf", "deserialization"]);
  assert.match(text, /THIS RUN IS SCOPED TO: ssrf, deserialization/);
  assert.match(text, /If you find something in another class, RECORD it/);
  assert.match(text, /a pre-auth RCE is often reached by chaining a finding from somewhere else/);
  assert.match(text, /do not\s+spend this round on it/);
});

test("EVERY kind of brief carries the focus — not just verify", () => {
  const cwd = seeded();
  const sub = submitRecon(cwd, NOTE, { paragraphsPerSegment: 3 });
  assert.equal(sub.ok, true, sub.ok ? "" : sub.errors.join("; "));
  add(cwd, "the importer fetches a caller-supplied URL without a protocol allowlist", "ssrf");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999, focus: ["ssrf"] });

  // THE REGRESSION. The focus was pushed inside renderRoundBrief AFTER the five
  // early returns, so it reached the verify brief and NOTHING ELSE — including
  // not generate, which is the only round where it could reduce the work rather
  // than just reorder it.
  const seen = new Set<string>();
  const missing: string[] = [];
  for (let i = 0; i < 14; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent" || !r.brief) break;
    const rec = load(cwd).snapshot.roundRecords.at(-1)!;
    seen.add(rec.kind);
    if (!/THIS RUN IS SCOPED TO: ssrf/.test(r.brief)) missing.push(rec.kind);
    if (rec.kind === "generate" && rec.segmentId) {
      addNode(cwd, { description: `segment ${rec.segmentId.slice(-4)} reaches a sink without the check the code relies on`, category: "ssrf", segmentId: rec.segmentId });
    }
    if (rec.kind === "verify" && rec.nodeId) {
      setStatus(cwd, rec.nodeId, "confirmed", { severity: "high", evidence: [{ kind: "code-slice", at: "", location: { file: "src/a.ts", line: 1 }, detail: "x" }] });
    }
  }
  assert.ok(seen.has("generate"), `generate must have run; saw ${[...seen].join(",")}`);
  assert.deepEqual(missing, [], `these briefs did NOT carry the focus: ${missing.join(",")}`);
});

test("a run with no focus carries no such line", () => {
  const cwd = seeded();
  add(cwd, "the importer fetches a caller-supplied URL without a protocol allowlist", "ssrf");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  assert.doesNotMatch(tickLoop(cwd, load(cwd).snapshot).brief!, /THIS RUN IS SCOPED TO/);
});
