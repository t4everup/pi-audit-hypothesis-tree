// pi-audit-hypothesis-tree — tests/notes.test.ts
//
// Pins operator input into a running loop: the two kinds of note, the delivery
// record, the brief splice, and the live report.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { compact, load } from "../extensions/hypothesis-tree/store.ts";
import { loadSettings, saveSettings } from "../extensions/hypothesis-tree/settings.ts";
import { addNode, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { tickLoop, withNotes, startLoop, renderLoopStatus } from "../extensions/hypothesis-tree/loop.ts";
import { renderReport } from "../extensions/hypothesis-tree/report.ts";
import {
  NOTES_PER_BRIEF,
  appendNote,
  hasPendingNotes,
  markNotesDelivered,
  operatorNotePath,
  pendingNotes,
  renderNotesSection,
  renderNotesStatus,
  renderOperatorSummary,
  writeOperatorMirror,
} from "../extensions/hypothesis-tree/notes.ts";
import type { Evidence, Hypothesis } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-notes-"));
}

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

const ANCHORED: Evidence = { kind: "code-slice", at: "", location: { file: "src/auth.ts", line: 57 }, detail: "decode(token)" };

// -----------------------------------------------------------------
// Recording
// -----------------------------------------------------------------

test("an empty note is refused rather than delivered as a blank section", () => {
  const cwd = seeded();
  for (const text of ["", "   ", "\n\t "]) {
    const result = appendNote(cwd, load(cwd).snapshot, text);
    assert.equal(result.ok, false, `"${text}" should be refused`);
    assert.match(result.errors[0]!, /empty/);
  }
  assert.equal(load(cwd).snapshot.notes.length, 0, "nothing was recorded");
});

test("notes get sequential ids and survive a reload", () => {
  const cwd = seeded();
  appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2", { pinned: true });
  appendNote(cwd, load(cwd).snapshot, "look at the queue consumer this round");

  // A fresh load re-folds the ledger — this is the durability claim.
  const notes = load(cwd).snapshot.notes;
  assert.equal(notes.length, 2);
  assert.equal(notes[0]!.id, "N-001");
  assert.equal(notes[1]!.id, "N-002");
  assert.equal(notes[0]!.pinned, true);
  assert.equal(notes[1]!.pinned, false);
  assert.equal(notes[0]!.deliveredRound, null, "nothing is delivered until a brief carries it");
});

test("delivery is recorded, and a one-shot note is then spent", () => {
  const cwd = seeded();
  const first = appendNote(cwd, load(cwd).snapshot, "look at the queue consumer").note!;
  const pinned = appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2", { pinned: true }).note!;

  assert.deepEqual(pendingNotes(load(cwd).snapshot).map((n) => n.id).sort(), [pinned.id, first.id].sort());
  markNotesDelivered(cwd, [first.id], 4);

  const after = load(cwd).snapshot;
  assert.equal(after.notes.find((n) => n.id === first.id)!.deliveredRound, 4);
  assert.deepEqual(pendingNotes(after).map((n) => n.id), [pinned.id], "the one-shot is spent, the standing one is not");
});

test("a delivery for an unknown note is ignored, not turned into a note", () => {
  const cwd = seeded();
  markNotesDelivered(cwd, ["N-999"], 3);
  assert.equal(load(cwd).snapshot.notes.length, 0, "the note is the record; the delivery is only an annotation on it");
});

test("re-delivering does not overwrite the round that actually delivered it", () => {
  const cwd = seeded();
  const note = appendNote(cwd, load(cwd).snapshot, "look at the queue consumer").note!;
  markNotesDelivered(cwd, [note.id], 4);
  markNotesDelivered(cwd, [note.id], 9);
  assert.equal(load(cwd).snapshot.notes.find((n) => n.id === note.id)!.deliveredRound, 4);
});

test("notes are not windowed — compaction cannot lose operator input", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  for (let i = 0; i < 30; i++) appendNote(cwd, load(cwd).snapshot, `note ${i}`);

  assert.equal(compact(cwd), true, "a snapshot was written");
  const after = load(cwd).snapshot;
  assert.equal(after.notes.length, 30, "every note survives compaction");
  assert.equal(after.notes[29]!.id, "N-030", "and the sequence continues correctly");
});

// -----------------------------------------------------------------
// The section a brief carries
// -----------------------------------------------------------------

test("no notes means no section at all — never a hollow heading", () => {
  const cwd = seeded();
  assert.equal(renderNotesSection(load(cwd).snapshot), "");
  assert.equal(hasPendingNotes(load(cwd).snapshot), false);
  assert.equal(withNotes("[AUDIT ROUND 1 — VERIFY]\n\nbody", load(cwd).snapshot), "[AUDIT ROUND 1 — VERIFY]\n\nbody");
});

test("the section names the two kinds so the model can weigh them", () => {
  const cwd = seeded();
  appendNote(cwd, load(cwd).snapshot, "look at the queue consumer this round");
  appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2", { pinned: true });
  const section = renderNotesSection(load(cwd).snapshot);
  assert.match(section, /OPERATOR INPUT/);
  assert.match(section, /does not replace evidence/);
  assert.match(section, /\*\*\[standing context\]\*\* the admin API is under \/admin\/v2/);
  assert.match(section, /- look at the queue consumer this round/);
});

test("the section is capped and newest-first, so a long run cannot drown the brief", () => {
  const cwd = seeded();
  for (let i = 1; i <= NOTES_PER_BRIEF + 4; i++) appendNote(cwd, load(cwd).snapshot, `note ${i}`);
  const pending = pendingNotes(load(cwd).snapshot);
  assert.equal(pending.length, NOTES_PER_BRIEF);
  assert.equal(pending[0]!.text, `note ${NOTES_PER_BRIEF + 4}`, "the most recent instruction is the most visible");
});

test("operator input goes AFTER the round banner, not above it", () => {
  const cwd = seeded();
  appendNote(cwd, load(cwd).snapshot, "look at the queue consumer");
  const out = withNotes("[AUDIT ROUND 3 — VERIFY]\n\nbody line 1\nbody line 2", load(cwd).snapshot);
  const lines = out.split("\n");
  assert.equal(lines[0], "[AUDIT ROUND 3 — VERIFY]", "the banner still orients the model");
  assert.equal(lines[1], "");
  assert.match(lines[2]!, /OPERATOR INPUT/);
  assert.match(out, /body line 1\nbody line 2/, "the body is intact and not re-spaced");
  assert.doesNotMatch(out, /\n\n\n/, "no triple newline");
});

test("a brief with no banner still gets the notes, at the top", () => {
  const cwd = seeded();
  appendNote(cwd, load(cwd).snapshot, "look at the queue consumer");
  const out = withNotes("body without a banner", load(cwd).snapshot);
  assert.match(out, /^## OPERATOR INPUT/);
  assert.match(out, /body without a banner$/);
});

// -----------------------------------------------------------------
// End to end: the loop actually delivers it
// -----------------------------------------------------------------

test("the next round carries the note, and the round after does not", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2 — start there");

  const first = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(first.action, "sent");
  assert.match(first.brief!, /OPERATOR INPUT/);
  assert.match(first.brief!, /the admin API is under \/admin\/v2 — start there/);
  assert.equal(load(cwd).snapshot.notes[0]!.deliveredRound, first.round, "the delivery is recorded");

  const second = tickLoop(cwd, load(cwd).snapshot);
  assert.doesNotMatch(second.brief!, /OPERATOR INPUT/, "a one-shot note is not repeated");
});

test("a standing context is carried by every round", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2", { pinned: true });

  for (let i = 0; i < 3; i++) {
    const result = tickLoop(cwd, load(cwd).snapshot);
    assert.match(result.brief!, /the admin API is under \/admin\/v2/, `round ${i + 1} should carry it`);
    assert.equal(load(cwd).snapshot.notes[0]!.deliveredRound, null, "a standing note is never spent");
  }
});

test("a note added mid-run reaches the round after it, not the one in flight", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  const inFlight = tickLoop(cwd, load(cwd).snapshot);
  assert.doesNotMatch(inFlight.brief!, /OPERATOR INPUT/, "nothing had been said yet");

  appendNote(cwd, load(cwd).snapshot, "skip the SSO path, I already checked it");
  const next = tickLoop(cwd, load(cwd).snapshot);
  assert.match(next.brief!, /skip the SSO path, I already checked it/);
});

test("a dry run does not spend a note", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  appendNote(cwd, load(cwd).snapshot, "look at the queue consumer");
  tickLoop(cwd, load(cwd).snapshot, { dryRun: true });
  assert.equal(load(cwd).snapshot.notes[0]!.deliveredRound, null, "nothing was actually sent, so nothing was delivered");
});

// -----------------------------------------------------------------
// Visibility
// -----------------------------------------------------------------

test("the status line answers 'did my hint land?'", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  // Quiet when there is nothing to say: a status line that always carries an
  // "operator input: none" row trains the reader to skip that line.
  assert.doesNotMatch(renderLoopStatus(load(cwd).snapshot).join("\n"), /operator input/);

  appendNote(cwd, load(cwd).snapshot, "look at the queue consumer");
  appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2", { pinned: true });
  const status = renderLoopStatus(load(cwd).snapshot).join("\n");
  assert.match(status, /operator input: 2 note\(s\) — 1 standing, 2 waiting for the next brief/);
  assert.equal(renderNotesStatus(load(cwd).snapshot), "operator input: 2 note(s) — 1 standing, 2 waiting for the next brief");
});

test("the summary separates pending, standing and delivered", () => {
  const cwd = seeded();
  const spent = appendNote(cwd, load(cwd).snapshot, "look at the queue consumer").note!;
  appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2", { pinned: true });
  appendNote(cwd, load(cwd).snapshot, "check the export endpoint next");
  markNotesDelivered(cwd, [spent.id], 2);

  const text = renderOperatorSummary(load(cwd).snapshot);
  assert.match(text, /PENDING — the next round will carry these/);
  assert.match(text, /STANDING — carried by every round/);
  assert.match(text, /DELIVERED \(one-shot, already consumed\)/);
  assert.match(text, /N-001  round 2/);
});

test("the empty summary teaches the two verbs instead of showing nothing", () => {
  const cwd = seeded();
  const text = renderOperatorSummary(load(cwd).snapshot);
  assert.match(text, /\/loop note <text>/);
  assert.match(text, /\/loop context <text>/);
});

test("the mirror file is written where the operator can find it", () => {
  const cwd = seeded();
  appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2", { pinned: true });
  assert.equal(writeOperatorMirror(cwd, load(cwd).snapshot), true);
  const text = fs.readFileSync(operatorNotePath(cwd), "utf-8");
  assert.match(text, /# Operator input/);
  assert.match(text, /\| N-001 \| context \| every round \|/);
  assert.equal(writeOperatorMirror(cwd, load(cwd).snapshot), true, "rewriting is not an error");
});

test("the mirror is written by the loop, so it stays current without being asked", () => {
  const cwd = seeded();
  add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  appendNote(cwd, load(cwd).snapshot, "look at the queue consumer");
  tickLoop(cwd, load(cwd).snapshot);
  assert.match(fs.readFileSync(operatorNotePath(cwd), "utf-8"), /look at the queue consumer/);
});

// -----------------------------------------------------------------
// The live report
// -----------------------------------------------------------------

test("the report is written after every round, not only at the end", () => {
  const cwd = seeded();
  // The loop writes the report in the project's configured language, so pin it
  // here. This test is about WHEN the file is written, not what language it is in.
  saveSettings(cwd, { reportLanguage: "en" });
  const node = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  const first = tickLoop(cwd, load(cwd).snapshot);
  const file = path.join(cwd, ".pi-hypothesis", "REPORT.md");
  assert.equal(fs.existsSync(file), true, "the report exists mid-run");

  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  tickLoop(cwd, load(cwd).snapshot);
  const text = fs.readFileSync(file, "utf-8");
  assert.match(text, /regenerated every round while a loop is running/);
  assert.match(text, /the api dispatcher reaches the orchestration sink without a role check/);
  assert.match(text, /\| \*\*Confirmed\*\* \| 1 \|/, "the report reflects the finding, mid-run");
  // Split by the contract severity floor, so a report for a HIGH goal cannot read
  // as though the target was met.
  assert.match(text, /\| \*\*Confirmed \(at target: >= medium\)\*\* \| \*\*1\*\* \|/);
  assert.equal(first.action, "sent");
});

test("the report comes out in the project's configured language", () => {
  const cwd = seeded();
  const node = add(cwd, "the api dispatcher reaches the orchestration sink without a role check", "auth-bypass");
  // zh is the default, so a fresh project gets a Chinese report without asking.
  assert.equal(loadSettings(cwd).settings.reportLanguage, "zh");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99 });
  setStatus(cwd, node.id, "confirmed", { severity: "high", evidence: [ANCHORED] });
  tickLoop(cwd, load(cwd).snapshot);
  const zh = fs.readFileSync(path.join(cwd, ".pi-hypothesis", "REPORT.md"), "utf-8");
  assert.match(zh, /# 代码审计报告/);
  assert.match(zh, /#### 调用链/);

  // Changing the setting mid-run takes effect on the next round: a report that
  // keeps coming out in the old language is a setting that looks broken.
  saveSettings(cwd, { reportLanguage: "en" });
  tickLoop(cwd, load(cwd).snapshot);
  const en = fs.readFileSync(path.join(cwd, ".pi-hypothesis", "REPORT.md"), "utf-8");
  assert.match(en, /# Code audit report/);
  assert.doesNotMatch(en, /代码审计报告/);
});

test("the report records what the operator said and whether it landed", () => {
  const cwd = seeded();
  appendNote(cwd, load(cwd).snapshot, "the admin API is under /admin/v2", { pinned: true });
  appendNote(cwd, load(cwd).snapshot, "check the export endpoint next");
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /## Operator input \(2\)/);
  assert.match(text, /\| N-001 \| standing \| every round \| the admin API is under \/admin\/v2 \|/);
  assert.match(text, /\| N-002 \| one-shot \| \*\*not yet\*\* \| check the export endpoint next \|/);
});

test("an audit with no operator input has no operator section", () => {
  const cwd = seeded();
  assert.doesNotMatch(renderReport(load(cwd).snapshot, null, { language: "en" }), /## Operator input/);
});

test("a note containing a pipe or a newline cannot break the report table", () => {
  const cwd = seeded();
  appendNote(cwd, load(cwd).snapshot, "the endpoint is /a|b\nand it is pre-auth");
  const text = renderReport(load(cwd).snapshot, null, { language: "en" });
  assert.match(text, /the endpoint is \/a\\\|b and it is pre-auth/, "escaped and flattened onto one row");
  const row = text.split("\n").find((l) => l.startsWith("| N-001"))!;
  assert.match(row, /\\\|/, "the pipe is escaped for a markdown reader");
  // The NEWLINE is what actually breaks the table into two rows, so that is what
  // this checks. A split on "|" would count the escaped one too.
  assert.equal(text.split("\n").filter((l) => l.includes("and it is pre-auth")).length, 1, "one row, not two");
  assert.equal(text.split("\n").filter((l) => l.startsWith("| N-001")).length, 1, "exactly one row for the note");
});
