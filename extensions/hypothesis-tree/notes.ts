/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/notes.ts
 *
 * Operator input into a running loop.
 *
 * -----------------------------------------------------------------------
 * Why this exists
 * -----------------------------------------------------------------------
 *
 * An audit runs for hours, and the operator learns things while it runs: "the
 * admin API is under /admin/v2", "I already checked the SSO path, skip it",
 * "look at the queue consumer, that is where the last incident was". Without a
 * way to hand that over, the operator either stops the loop and loses its state
 * or watches it spend rounds re-deriving what they already know.
 *
 * -----------------------------------------------------------------------
 * Two kinds, because there are two kinds of information
 * -----------------------------------------------------------------------
 *
 *   NOTE (one-shot)   — "look at X this round". Delivered in the NEXT brief,
 *                       then consumed. A one-shot note that stayed forever
 *                       would drown the brief and keep pulling the audit back
 *                       to a stale instruction.
 *
 *   CONTEXT (pinned)  — "the admin API is under /admin/v2". Delivered in EVERY
 *                       brief, because it is a durable fact about the project
 *                       rather than an instruction for one round.
 *
 * Both are append-only in the same ledger as everything else, so they survive a
 * reload, and a note's delivery is RECORDED rather than inferred: a note is
 * delivered exactly once, and the record says so.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { type OperatorNote, type TreeSnapshot, clip } from "./types.js";
import { STATE_DIR_NAME, appendEvent, nowIso } from "./store.js";

export const OPERATOR_NOTE_NAME = "OPERATOR.md";

export function operatorNotePath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, OPERATOR_NOTE_NAME);
}

/** How many recent notes a brief carries, so a long run cannot swamp it. */
export const NOTES_PER_BRIEF = 8;

export interface AppendNoteResult {
  ok: boolean;
  errors: string[];
  note?: OperatorNote;
}

/**
 * Record an operator note.
 *
 * Refuses an empty one: a blank note would be delivered as a blank section and
 * read as "the operator said something" when they said nothing.
 */
export function appendNote(
  projectRoot: string,
  snapshot: TreeSnapshot,
  text: string,
  opts: { pinned?: boolean; at?: string } = {},
): AppendNoteResult {
  const body = (text ?? "").trim();
  if (!body) return { ok: false, errors: ["the note is empty — say what you want the audit to know"] };

  const at = opts.at ?? nowIso();
  const maxSeq = snapshot.notes.reduce((max, n) => {
    const m = /^N-(\d+)$/.exec(n.id);
    return m ? Math.max(max, Number(m[1])) : max;
  }, 0);
  const note: OperatorNote = {
    id: `N-${String(maxSeq + 1).padStart(3, "0")}`,
    text: body,
    pinned: opts.pinned === true,
    at,
    deliveredRound: null,
  };
  if (!appendEvent(projectRoot, { type: "operator_note_recorded", at, note })) {
    return { ok: false, errors: ["the note could not be written — nothing changed"] };
  }
  return { ok: true, errors: [], note };
}

/** Record that these notes went into a brief. */
export function markNotesDelivered(projectRoot: string, ids: readonly string[], round: number, at = nowIso()): boolean {
  let ok = true;
  for (const id of ids) {
    if (!appendEvent(projectRoot, { type: "operator_note_delivered", at, id, round })) ok = false;
  }
  return ok;
}

/**
 * The notes the next brief must carry.
 *
 * Unpinned notes are pending until delivered; pinned ones are always pending.
 * Newest first, so the most recent instruction is the most visible, and capped
 * so a long run cannot drown the brief.
 */
export function pendingNotes(snapshot: TreeSnapshot): OperatorNote[] {
  const pending = snapshot.notes.filter((n) => n.pinned || n.deliveredRound === null);
  return pending.slice(-NOTES_PER_BRIEF).reverse();
}

/** True when there is operator input the next brief has not carried yet. */
export function hasPendingNotes(snapshot: TreeSnapshot): boolean {
  return snapshot.notes.some((n) => n.pinned || n.deliveredRound === null);
}

/**
 * The section a brief carries. Empty when there is nothing to say, so an audit
 * with no operator input never grows a hollow heading.
 */
export function renderNotesSection(snapshot: TreeSnapshot): string {
  const notes = pendingNotes(snapshot);
  if (notes.length === 0) return "";
  const lines: string[] = [];
  lines.push("## OPERATOR INPUT (from the person running this audit)");
  lines.push("");
  lines.push("This is not project content and not a hypothesis — it is information from the operator.");
  lines.push("Treat it as authoritative context and use it, but it does not replace evidence.");
  lines.push("");
  for (const note of notes) {
    lines.push(`- ${note.pinned ? "**[standing context]** " : ""}${note.text.replace(/\n/g, "\n  ")}`);
  }
  return lines.join("\n");
}

/** A human-readable mirror, so the operator can see what they have told it. */
export function writeOperatorMirror(projectRoot: string, snapshot: TreeSnapshot): boolean {
  const lines: string[] = ["# Operator input", ""];
  if (snapshot.notes.length === 0) {
    lines.push("_Nothing recorded yet._", "");
    lines.push("`/loop note <text>` — delivered in the next round only.");
    lines.push("`/loop context <text>` — delivered in every round.");
  } else {
    lines.push("| id | kind | delivered | text |");
    lines.push("|---|---|---|---|");
    for (const note of snapshot.notes) {
      const kind = note.pinned ? "context" : "note";
      const delivered = note.pinned ? "every round" : note.deliveredRound === null ? "PENDING" : `round ${note.deliveredRound}`;
      lines.push(`| ${note.id} | ${kind} | ${delivered} | ${clip(note.text.replace(/\|/g, "\\|").replace(/\n/g, " "), 160)} |`);
    }
    lines.push("");
    lines.push("_Maintained automatically. `/loop context clear` removes the standing context._");
  }
  lines.push("");
  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    fs.writeFileSync(operatorNotePath(projectRoot), lines.join("\n"), "utf-8");
    return true;
  } catch {
    return false;
  }
}

/** One line for the status block. */
export function renderNotesStatus(snapshot: TreeSnapshot): string {
  if (snapshot.notes.length === 0) return "operator input: none";
  const pending = pendingNotes(snapshot).length;
  const pinned = snapshot.notes.filter((n) => n.pinned).length;
  return `operator input: ${snapshot.notes.length} note(s) — ${pinned} standing, ${pending} waiting for the next brief`;
}

/**
 * What the operator has told the audit, and what has reached the model yet.
 *
 * Shown both when `/loop note` is called with no text and by `/loop notes`,
 * because that is the question an operator has mid-run: "did my hint land?"
 */
export function renderOperatorSummary(snapshot: TreeSnapshot): string {
  if (snapshot.notes.length === 0) {
    return [
      "No operator input recorded.",
      "",
      "/loop note <text>    — delivered in the NEXT round only (an instruction)",
      "/loop context <text> — delivered in EVERY round (a standing fact)",
    ].join("\n");
  }
  const lines: string[] = [];
  const pinned = snapshot.notes.filter((n) => n.pinned);
  const oneShot = snapshot.notes.filter((n) => !n.pinned);
  const pending = oneShot.filter((n) => n.deliveredRound === null);
  lines.push(`Operator input: ${snapshot.notes.length} note(s) — ${pinned.length} standing, ${pending.length} pending delivery`);
  lines.push("");
  if (pending.length > 0) {
    lines.push("PENDING — the next round will carry these:");
    for (const note of pending) lines.push(`  ${note.id}  ${clip(note.text.replace(/\n/g, " "), 140)}`);
    lines.push("");
  }
  if (pinned.length > 0) {
    lines.push("STANDING — carried by every round:");
    for (const note of pinned) lines.push(`  ${note.id}  ${clip(note.text.replace(/\n/g, " "), 140)}`);
    lines.push("");
  }
  const delivered = oneShot.filter((n) => n.deliveredRound !== null);
  if (delivered.length > 0) {
    lines.push("DELIVERED (one-shot, already consumed):");
    for (const note of delivered) {
      lines.push(`  ${note.id}  round ${note.deliveredRound}  ${clip(note.text.replace(/\n/g, " "), 120)}`);
    }
  }
  return lines.join("\n");
}
