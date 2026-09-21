// pi-audit-hypothesis-tree — tests/store.test.ts
//
// Pins the persistence layer: append-only JSONL, crash-tolerant folding,
// append-only compaction, and the exFAT constraints (no hard links, no
// atomic rename, no held descriptor).

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  COMPACT_AFTER_EVENTS,
  type TreeEvent,
  appendEvent,
  applyPatch,
  compact,
  compactIfNeeded,
  descriptionKey,
  emptySnapshot,
  eventsSinceSnapshot,
  foldEvents,
  load,
  parseEvents,
  repairTornTail,
  serializeEvent,
  treeDir,
  treeLogPath,
} from "../extensions/hypothesis-tree/store.ts";
import type { Hypothesis } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-store-"));
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
    createdAt: "2026-01-01T00:00:00.000Z",
    lastTouchedAt: "2026-01-01T00:00:00.000Z",
    score: 0,
    spawnedFrom: [],
    roundIntroduced: 0,
    timesSelected: 0,
    lastSelectedRound: null,
    ...over,
  };
}

const CREATED: TreeEvent = { type: "tree_created", at: "2026-01-01T00:00:00.000Z", treeId: "T-abc12345", objective: node().description };

// -----------------------------------------------------------------
// Serialization
// -----------------------------------------------------------------

test("one record is one JSON object terminated by exactly one newline", () => {
  const line = serializeEvent(CREATED);
  assert.equal(line.endsWith("\n"), true);
  assert.equal(line.indexOf("\n"), line.length - 1, "no embedded newline");
  assert.deepEqual(JSON.parse(line.trim()), CREATED);
});

// -----------------------------------------------------------------
// parseEvents — torn vs malformed vs unknown
// -----------------------------------------------------------------

test("a clean log parses with no torn and no malformed lines", () => {
  const text = serializeEvent(CREATED) + serializeEvent({ type: "node_added", at: "t", node: node() });
  const parsed = parseEvents(text);
  assert.equal(parsed.events.length, 2);
  assert.equal(parsed.torn, 0);
  assert.equal(parsed.malformed, 0);
  assert.equal(parsed.unknown, 0);
});

test("a final line with no newline is counted as TORN, not malformed", () => {
  // A crash mid-append: the last record has no terminating newline.
  const text = serializeEvent(CREATED) + '{"type":"node_added","at":"t","node":{"id":"H-0001"';
  const parsed = parseEvents(text);
  assert.equal(parsed.events.length, 1, "the complete record survives");
  assert.equal(parsed.torn, 1);
  assert.equal(parsed.malformed, 0, "a torn tail must not be reported as corruption");
});

test("a complete but unparseable line is MALFORMED, distinct from torn", () => {
  const text = serializeEvent(CREATED) + "{ not json\n";
  const parsed = parseEvents(text);
  assert.equal(parsed.events.length, 1);
  assert.equal(parsed.torn, 0);
  assert.equal(parsed.malformed, 1);
});

test("a complete line with an unrecognized event type is UNKNOWN, not corruption", () => {
  // A newer writer must not look like a damaged file.
  const text = serializeEvent(CREATED) + JSON.stringify({ type: "future_event", at: "t" }) + "\n";
  const parsed = parseEvents(text);
  assert.equal(parsed.events.length, 1);
  assert.equal(parsed.unknown, 1);
  assert.equal(parsed.malformed, 0);
});

test("blank lines are skipped without counting as anything", () => {
  const text = serializeEvent(CREATED) + "\n\n" + serializeEvent({ type: "round_recorded", at: "t", round: 1 });
  const parsed = parseEvents(text);
  assert.equal(parsed.events.length, 2);
  assert.equal(parsed.torn + parsed.malformed + parsed.unknown, 0);
});

test("an empty or missing log is not an error", () => {
  const parsed = parseEvents("");
  assert.deepEqual(parsed.events, []);
  assert.equal(parsed.torn + parsed.malformed + parsed.unknown, 0);
});

// -----------------------------------------------------------------
// foldEvents
// -----------------------------------------------------------------

test("fold reconstructs the tree and the root", () => {
  const snap = foldEvents([CREATED, { type: "node_added", at: "t1", node: node() }]);
  assert.equal(snap.treeId, "T-abc12345");
  assert.equal(snap.rootId, "H-0001");
  assert.equal(snap.nodes.length, 1);
  assert.equal(snap.objective, node().description);
});

test("latest record wins per node id", () => {
  const snap = foldEvents([
    CREATED,
    { type: "node_added", at: "t1", node: node() },
    { type: "node_updated", at: "t2", id: "H-0001", patch: { status: "confirmed" } },
  ]);
  assert.equal(snap.nodes.length, 1);
  assert.equal(snap.nodes[0]!.status, "confirmed");
  assert.equal(snap.updatedAt, "t2");
});

test("a status-only patch must NOT reset the other fields to parser defaults", () => {
  // The regression this guards: the normalizer supplies defaults for absent
  // keys, so a value-based merge would reset category to "other", severity to
  // pending, and evidence to [] on every status change.
  const snap = foldEvents([
    CREATED,
    { type: "node_added", at: "t1", node: node({ category: "ssrf", evidence: [{ kind: "reasoning", at: "t1", detail: "x" }] }) },
    { type: "node_updated", at: "t2", id: "H-0001", patch: { status: "confirmed" } },
  ]);
  const n = snap.nodes[0]!;
  assert.equal(n.status, "confirmed");
  assert.equal(n.category, "ssrf", "category survives a status-only patch");
  assert.equal(n.evidence.length, 1, "evidence survives a status-only patch");
  assert.equal(n.description, node().description, "description survives");
  assert.equal(n.parentId, null, "parentId survives");
});

test("an update for a node the log never added is ignored, not invented", () => {
  const snap = foldEvents([CREATED, { type: "node_updated", at: "t", id: "H-9999", patch: { status: "confirmed" } }]);
  assert.equal(snap.nodes.length, 0);
});

test("maxNodeSeq tracks the highest id so ids are never reused", () => {
  const snap = foldEvents([
    CREATED,
    { type: "node_added", at: "t", node: node({ id: "H-0007" }) },
    { type: "node_added", at: "t", node: node({ id: "H-0002", parentId: "H-0007", depth: 1, description: "another assertion that is long enough" }) },
  ]);
  assert.equal(snap.maxNodeSeq, 7);
});

test("rounds is monotonic across the log", () => {
  const snap = foldEvents([
    CREATED,
    { type: "round_recorded", at: "t", round: 3 },
    { type: "round_recorded", at: "t", round: 1 },
  ]);
  assert.equal(snap.rounds, 3, "a late-arriving lower round must not rewind the counter");
});

test("a snapshot REPLACES the folded state and events after it fold on top", () => {
  const snap = foldEvents([
    CREATED,
    { type: "node_added", at: "t1", node: node() },
    { type: "node_updated", at: "t2", id: "H-0001", patch: { status: "confirmed" } },
    {
      type: "snapshot",
      at: "t3",
      snapshot: {
        treeId: "T-abc12345",
        objective: node().description,
        rootId: "H-0001",
        nodes: [node({ status: "confirmed" })],
        maxNodeSeq: 1,
        rounds: 2,
        compactions: 1,
        selections: [],
        consolidations: [],
        loop: null,
        roundRecords: [],
        segments: [],
        segmentRecords: [],
        reconAt: null,
      },
    },
    { type: "node_updated", at: "t4", id: "H-0001", patch: { status: "rejected", statusReason: "disproved" } },
  ]);
  assert.equal(snap.compactions, 1);
  assert.equal(snap.rounds, 2);
  assert.equal(snap.nodes.length, 1);
  assert.equal(snap.nodes[0]!.status, "rejected", "an event after the snapshot still wins");
});

// -----------------------------------------------------------------
// applyPatch
// -----------------------------------------------------------------

test("applyPatch honours the presence set when given one", () => {
  const prev = node({ category: "ssrf" });
  const patched = applyPatch(prev, { category: "other", status: "confirmed" }, new Set(["status"]));
  assert.equal(patched.category, "ssrf", "a key absent from the raw patch must not win");
  assert.equal(patched.status, "confirmed");
});

test("applyPatch with no presence set lets every defined field win", () => {
  const patched = applyPatch(node({ category: "ssrf" }), { category: "other" });
  assert.equal(patched.category, "other");
});

// -----------------------------------------------------------------
// I/O + crash recovery
// -----------------------------------------------------------------

test("appendEvent creates the directory tree and load reads it back", () => {
  const cwd = tmpProject();
  assert.equal(appendEvent(cwd, CREATED), true);
  assert.equal(fs.existsSync(treeLogPath(cwd)), true);
  const { snapshot, torn } = load(cwd);
  assert.equal(snapshot.treeId, "T-abc12345");
  assert.equal(torn, 0);
});

test("a missing log loads as an empty tree, never a throw", () => {
  const cwd = tmpProject();
  const { snapshot, readError } = load(cwd);
  assert.equal(readError, undefined);
  assert.deepEqual(snapshot.nodes, []);
  assert.equal(snapshot.rootId, "");
});

test("a torn tail is skipped and reported, and the surviving records still load", () => {
  const cwd = tmpProject();
  appendEvent(cwd, CREATED);
  appendEvent(cwd, { type: "node_added", at: "t", node: node() });
  // Simulate a crash mid-append.
  fs.appendFileSync(treeLogPath(cwd), '{"type":"node_added","at":"t","node":{"id":"H-00', "utf-8");

  const { snapshot, torn } = load(cwd);
  assert.equal(torn, 1);
  assert.equal(snapshot.tornLines, 1);
  assert.equal(snapshot.nodes.length, 1, "everything before the torn tail is intact");
});

test("repairTornTail drops only the partial record and is idempotent", () => {
  const cwd = tmpProject();
  appendEvent(cwd, CREATED);
  fs.appendFileSync(treeLogPath(cwd), "garbage-with-no-newline", "utf-8");

  const first = repairTornTail(cwd);
  assert.equal(first.repaired, true);
  assert.ok(first.droppedBytes > 0);
  assert.equal(load(cwd).torn, 0);
  assert.equal(load(cwd).snapshot.treeId, "T-abc12345", "the complete record survives");

  const second = repairTornTail(cwd);
  assert.equal(second.repaired, false);
  assert.equal(second.reason, "clean tail");
});

test("repairTornTail leaves a clean log byte-identical", () => {
  const cwd = tmpProject();
  appendEvent(cwd, CREATED);
  const before = fs.readFileSync(treeLogPath(cwd), "utf-8");
  repairTornTail(cwd);
  assert.equal(fs.readFileSync(treeLogPath(cwd), "utf-8"), before);
});

test("repairTornTail on a missing log is a no-op", () => {
  const cwd = tmpProject();
  const result = repairTornTail(cwd);
  assert.equal(result.repaired, false);
  assert.equal(result.reason, "no log");
});

test("an unreadable log reports readError instead of pretending to be empty", () => {
  const cwd = tmpProject();
  // A directory where the log file should be: existsSync true, readFileSync throws.
  fs.mkdirSync(treeLogPath(cwd), { recursive: true });
  const { snapshot, readError } = load(cwd);
  assert.ok(readError, "the failure must be reported");
  assert.equal(snapshot.nodes.length, 0);
});

// -----------------------------------------------------------------
// Compaction (append-only)
// -----------------------------------------------------------------

test("compact appends a snapshot and does not truncate the log", () => {
  const cwd = tmpProject();
  appendEvent(cwd, CREATED);
  appendEvent(cwd, { type: "node_added", at: "t1", node: node() });
  appendEvent(cwd, { type: "node_updated", at: "t2", id: "H-0001", patch: { status: "confirmed" } });
  const before = fs.readFileSync(treeLogPath(cwd), "utf-8");

  assert.equal(compact(cwd), true);

  const after = fs.readFileSync(treeLogPath(cwd), "utf-8");
  assert.ok(after.startsWith(before), "the log is only ever appended to");
  const { snapshot } = load(cwd);
  assert.equal(snapshot.compactions, 1);
  assert.equal(snapshot.nodes.length, 1);
  assert.equal(snapshot.nodes[0]!.status, "confirmed", "state is preserved across compaction");
});

test("compact refuses a log with no tree and refuses a redundant snapshot", () => {
  const cwd = tmpProject();
  assert.equal(compact(cwd), false, "no tree to snapshot");
  appendEvent(cwd, CREATED);
  appendEvent(cwd, { type: "node_added", at: "t", node: node() });
  assert.equal(compact(cwd), true);
  assert.equal(compact(cwd), false, "nothing new since the last snapshot");
});

test("eventsSinceSnapshot resets after a snapshot and counts forward again", () => {
  const cwd = tmpProject();
  appendEvent(cwd, CREATED);
  appendEvent(cwd, { type: "node_added", at: "t", node: node() });
  assert.equal(eventsSinceSnapshot(cwd), 2);
  compact(cwd);
  assert.equal(eventsSinceSnapshot(cwd), 0);
  appendEvent(cwd, { type: "node_updated", at: "t2", id: "H-0001", patch: { status: "confirmed" } });
  assert.equal(eventsSinceSnapshot(cwd), 1);
});

test("compactIfNeeded only fires past the threshold", () => {
  const cwd = tmpProject();
  appendEvent(cwd, CREATED);
  appendEvent(cwd, { type: "node_added", at: "t", node: node() });
  assert.equal(compactIfNeeded(cwd, 100), false);
  assert.equal(compactIfNeeded(cwd, 2), true);
  assert.equal(load(cwd).snapshot.compactions, 1);
});

test("the default compaction threshold is a positive bound", () => {
  assert.ok(Number.isInteger(COMPACT_AFTER_EVENTS) && COMPACT_AFTER_EVENTS > 10);
});

// -----------------------------------------------------------------
// exFAT constraints — the requirement that must not silently regress
// -----------------------------------------------------------------

test("the store never uses a hard link, a rename, or a copy (exFAT EISDIR source)", () => {
  const src = fs.readFileSync("extensions/hypothesis-tree/store.ts", "utf-8");
  // Strip comments so the module's own explanation of these calls does not
  // trip the check.
  const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  for (const forbidden of ["renameSync", "linkSync", "copyFileSync", "fs.link(", "fs.rename("]) {
    assert.ok(!code.includes(forbidden), `store.ts must not call ${forbidden} — a non-journaling volume returns EISDIR/EPERM on it`);
  }
  assert.ok(code.includes("appendFileSync"), "the only writer is an append");
  assert.ok(!/openSync/.test(code), "no descriptor is held open (a held handle is what a non-NTFS volume locks on)");
});

test("the state directory lives under the audited project", () => {
  assert.equal(treeDir("/proj"), path.join("/proj", ".pi-hypothesis"));
  assert.equal(treeLogPath("/proj"), path.join("/proj", ".pi-hypothesis", "tree.jsonl"));
});

// -----------------------------------------------------------------
// descriptionKey
// -----------------------------------------------------------------

test("descriptionKey is stable across punctuation and case noise", () => {
  const a = descriptionKey("The login handler does NOT validate the JWT signature.");
  const b = descriptionKey("the login  handler does not validate the jwt signature");
  assert.equal(a, b);
});

test("descriptionKey separates genuinely different assertions", () => {
  assert.notEqual(
    descriptionKey("the login handler does not validate the jwt signature"),
    descriptionKey("the refresh handler does not validate the jwt signature"),
  );
});

test("emptySnapshot is inert", () => {
  const snap = emptySnapshot();
  assert.equal(snap.rootId, "");
  assert.deepEqual(snap.nodes, []);
  assert.equal(snap.byId.size, 0);
});
