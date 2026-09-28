/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/sec.ts
 *
 * `/loopSEC` — give an objective, dig, get a report.
 *
 * -----------------------------------------------------------------------
 * What this mode is, and what it deliberately is not
 * -----------------------------------------------------------------------
 *
 * The hypothesis tree exists to make an audit's output TRUSTWORTHY. Every node is
 * an assertion that can be proven wrong, a verdict requires a quotable artifact, a
 * derived tier says how strong that artifact is, a challenge round attacks the
 * finding afterwards, and a refuted finding leaves the report. All of that is load
 * on every round, and it is load the operator may not want for a first pass over a
 * large codebase.
 *
 * So this mode drops it. There is no assertion gate, no verdict, no tier, no
 * falsification attempt and no challenge round — none of those can exist without
 * an assertion to attack, and a report that claimed them here would be claiming
 * discipline it does not have.
 *
 * ONE REQUIREMENT SURVIVES: a finding must carry an artifact — a `location`, an
 * `evidence` excerpt, or both. The bar is cheap (the model is reading the code, so
 * it has a `file:line`), and it is the entire difference between a triage report
 * and a list of things a model said. `validateFinding` refuses a finding with
 * neither, and `store.ts` drops one on read as well, so a hand-edited log cannot
 * put a bare claim back.
 *
 * The report therefore LEADS with what it is not. A reader who skims a list of
 * findings grouped by severity will assume the severities were checked; the report
 * says, before the first finding, that they were not.
 *
 * -----------------------------------------------------------------------
 * Where the breadth comes from, without hypotheses
 * -----------------------------------------------------------------------
 *
 * The hypothesis mode gets its breadth from recon segments: the note is chunked and
 * every chunk becomes a generation round. A dig round does not generate from a
 * segment, so this mode needs another mechanism — and it uses the one that was
 * already there and measured: **what has not been read yet**.
 *
 * `coverage.ts` computes the untouched subtrees from the files a run has cited.
 * Here the citations come from the findings instead of from hypothesis nodes, and
 * the dig brief hands the model the gap. That is the same adaptive gap the coverage
 * round uses, and it is why a `/loopSEC` run gets wider as it goes rather than
 * re-reading whatever it found first.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { STATE_DIR_NAME, appendEvent, load, nowIso } from "./store.js";
import { type Result } from "./tree.js";
import { coverageGaps, coverageHeadline, type CoverageReport } from "./coverage.js";
import { reportLanguageOf } from "./settings.js";
import { ladderFor } from "./ladders.js";
import {
  type ReportLanguage,
  type SecStrings,
  secStrings,
  severityLabel,
} from "./reportText.js";
import {
  type AuditLoopState,
  type SecFinding,
  type SecFindingPatch,
  type SecSurface,
  type SecSurfaceKind,
  type SecSurfacePatch,
  type Severity,
  type TreeSnapshot,
  SEC_SURFACE_KINDS,
  SEVERITIES,
  formatDuration,
  loopTiming,
  severityRank,
} from "./types.js";

/** The sec report's file name. Distinct from REPORT.md so the two modes coexist. */
export const SEC_REPORT_FILE = "SEC-REPORT.md";
/** The running journal, one section per round. */
export const SEC_LEDGER_FILE = "SEC-FINDINGS.md";

export function secReportPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, SEC_REPORT_FILE);
}

export function secLedgerPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, SEC_LEDGER_FILE);
}

// -----------------------------------------------------------------
// Recording
// -----------------------------------------------------------------

export interface FindingInput {
  title: string;
  category: string;
  severity?: Severity;
  preAuth?: boolean;
  file?: string;
  line?: number;
  evidence?: string;
  reasoning?: string;
  poc?: string;
  round?: number;
  /** The surface item this came out of. */
  surfaceId?: string;
}

/**
 * The one gate this mode keeps, and why it is not negotiable.
 *
 * Everything else about `/loopSEC` is free-form, but a finding with no artifact is
 * not a finding — it is a sentence. The cost of the requirement is a `file:line`
 * the model already has in hand, and the benefit is that every line of the report
 * can be opened and checked by the reader. A mode that dropped this too would
 * produce a document that looks like a security assessment and cannot be verified
 * at all.
 */
export function validateFinding(input: FindingInput): Result<FindingInput> {
  const errors: string[] = [];
  if (typeof input.title !== "string" || input.title.trim() === "") {
    errors.push("title is required — say what the finding is");
  }
  const hasLocation = typeof input.file === "string" && input.file.trim() !== "";
  const hasEvidence = typeof input.evidence === "string" && input.evidence.trim() !== "";
  if (!hasLocation && !hasEvidence) {
    errors.push(
      "a finding needs an artifact: a `file` (with `line`) or an `evidence` excerpt. " +
        "This mode has no assertion gate and no verification tier, so the artifact is the ONLY thing " +
        "a reader can check — without it the report is a list of sentences.",
    );
  }
  if (hasLocation && (typeof input.line !== "number" || !Number.isFinite(input.line) || input.line < 1)) {
    errors.push("`line` must be a 1-based line number when `file` is given");
  }
  if (typeof input.category !== "string" || input.category.trim() === "") {
    errors.push("category is required (free-form here, but it is how the report groups findings)");
  }
  return errors.length === 0 ? { ok: true, value: input, warnings: [] } : { ok: false, errors };
}

/** Next free `F-####` id. */
function nextFindingId(snapshot: TreeSnapshot): string {
  let max = 0;
  for (const f of snapshot.findings) {
    const m = /^F-(\d+)$/.exec(f.id);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `F-${String(max + 1).padStart(4, "0")}`;
}

export function recordFinding(projectRoot: string, input: FindingInput, at = nowIso()): Result<SecFinding> {
  const check = validateFinding(input);
  if (!check.ok) return { ok: false, errors: check.errors };
  const snapshot = load(projectRoot).snapshot;
  const finding: SecFinding = {
    id: nextFindingId(snapshot),
    at,
    round: typeof input.round === "number" && input.round > 0 ? input.round : snapshot.rounds,
    title: input.title.trim(),
    category: input.category.trim(),
    ...(input.severity ? { severity: input.severity } : {}),
    ...(typeof input.preAuth === "boolean" ? { preAuth: input.preAuth } : {}),
    ...(typeof input.file === "string" && input.file
      ? { location: { file: input.file, line: typeof input.line === "number" ? Math.max(1, Math.floor(input.line)) : 1 } }
      : {}),
    ...(typeof input.evidence === "string" && input.evidence ? { evidence: input.evidence } : {}),
    ...(typeof input.reasoning === "string" && input.reasoning ? { reasoning: input.reasoning } : {}),
    ...(typeof input.poc === "string" && input.poc ? { poc: input.poc } : {}),
    ...(input.surfaceId ? { surfaceId: input.surfaceId } : {}),
  };
  if (!appendEvent(projectRoot, { type: "finding_recorded", at, finding })) {
    return { ok: false, errors: ["the finding could not be written to the log"] };
  }
  // A finding recorded against a surface item EXAMINES that item. Without this the
  // item stayed `open`, so the next round was handed the same one and the model was
  // asked to analyse a thing it had just found a bug in.
  if (input.surfaceId && snapshot.surfaces.some((x) => x.id === input.surfaceId)) {
    updateSurface(projectRoot, input.surfaceId, { status: "examined", findingId: finding.id }, at);
  }
  return { ok: true, value: finding, warnings: [] };
}

export function updateFinding(projectRoot: string, id: string, patch: SecFindingPatch, at = nowIso()): Result<SecFinding> {
  const snapshot = load(projectRoot).snapshot;
  const existing = snapshot.findings.find((f) => f.id === id);
  if (!existing) return { ok: false, errors: [`${id} is not a finding in this run`] };
  // The artifact requirement holds on UPDATE too, or a patch could erase the only
  // thing a reader can check.
  const location = patch.location ?? existing.location;
  const evidence = patch.evidence ?? existing.evidence;
  if (!location && !evidence) {
    return { ok: false, errors: [`${id} would be left with no artifact — a finding needs a location or an evidence excerpt`] };
  }
  if (!appendEvent(projectRoot, { type: "finding_updated", at, id, patch })) {
    return { ok: false, errors: ["the update could not be written to the log"] };
  }
  const after = load(projectRoot).snapshot.findings.find((f) => f.id === id)!;
  return { ok: true, value: after, warnings: [] };
}

export function submitSecRecon(projectRoot: string, note: string, at = nowIso()): Result<string> {
  const text = (note ?? "").trim();
  if (text.length < 200) {
    return {
      ok: false,
      errors: [
        `the recon note must be at least 200 characters (got ${text.length}). It is the ONLY pass over the ` +
          "project, and every later round works from it plus the attack surface it enumerates.",
      ],
    };
  }
  if (!appendEvent(projectRoot, { type: "sec_recon_submitted", at, note: text })) {
    return { ok: false, errors: ["the recon note could not be written to the log"] };
  }
  return { ok: true, value: text, warnings: [] };
}

// -----------------------------------------------------------------
// The attack surface — the work list
// -----------------------------------------------------------------
//
// This is what turns "go and look" into an ANALYSIS.
//
// Without a list the loop can only hand over a note and a set of unread directories;
// there is no record of what has been looked at, no way to tell progress from
// idleness, and no way to give the model a specific target. With it:
//
//   - the loop ASSIGNS the next open item, so the analysis is systematic rather than
//     whatever the model felt like reading;
//   - `cleared` is a first-class result, so "I read this and it is guarded" counts as
//     progress and stops the next round re-reading it;
//   - the report can say examined N of M, which is the honest answer to "how much of
//     this project did the run actually analyse".
//
// The items are COORDINATES, not claims — that is what keeps this mode distinct from
// the hypothesis tree. `POST /diag/ping` is a place; "the ping handler reaches
// system() without a check" is an assertion about it. Enumerating places must not
// require asserting anything first, or the mode is back to the gate it exists to
// avoid.

export interface SurfaceInput {
  title: string;
  kind?: SecSurfaceKind;
  file?: string;
  line?: number;
  categories?: string[];
  round?: number;
}

/**
 * The surface item's own gate, and it is deliberately weak.
 *
 * A title and a kind, nothing more. A `file` is not required: the whole point of an
 * entrypoint is that it is reachable from OUTSIDE the code, so demanding a line
 * number would exclude exactly the items that matter most.
 */
export function validateSurface(input: SurfaceInput): Result<SurfaceInput> {
  const errors: string[] = [];
  if (typeof input.title !== "string" || input.title.trim() === "") {
    errors.push("title is required — say what the item is (a route, a function, a boundary)");
  }
  if (input.kind !== undefined && !(SEC_SURFACE_KINDS as readonly string[]).includes(input.kind)) {
    errors.push(`kind must be one of ${SEC_SURFACE_KINDS.join("|")}`);
  }
  if (typeof input.file === "string" && input.file.trim() !== "" && typeof input.line !== "number") {
    errors.push("`line` is required when `file` is given");
  }
  return errors.length === 0 ? { ok: true, value: input, warnings: [] } : { ok: false, errors };
}

function nextSurfaceId(snapshot: TreeSnapshot): string {
  let max = 0;
  for (const s of snapshot.surfaces) {
    const m = /^S-(\d+)$/.exec(s.id);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `S-${String(max + 1).padStart(4, "0")}`;
}

export function recordSurface(projectRoot: string, input: SurfaceInput, at = nowIso()): Result<SecSurface> {
  const check = validateSurface(input);
  if (!check.ok) return { ok: false, errors: check.errors };
  const snapshot = load(projectRoot).snapshot;
  const title = input.title.trim();
  // A duplicate is not an error — enumerating the same route twice is a waste, not a
  // fault, and refusing it would make the model handle a rejection it cannot act on.
  const existing = snapshot.surfaces.find((s) => s.title.trim() === title);
  if (existing) return { ok: true, value: existing, warnings: [`already enumerated as ${existing.id}`] };
  const surface: SecSurface = {
    id: nextSurfaceId(snapshot),
    at,
    round: typeof input.round === "number" && input.round > 0 ? input.round : snapshot.rounds,
    kind: input.kind ?? "other",
    title,
    ...(typeof input.file === "string" && input.file
      ? { location: { file: input.file, line: typeof input.line === "number" ? Math.max(1, Math.floor(input.line)) : 1 } }
      : {}),
    ...(input.categories && input.categories.length > 0 ? { categories: [...input.categories] } : {}),
    status: "open",
  };
  if (!appendEvent(projectRoot, { type: "surface_recorded", at, surface })) {
    return { ok: false, errors: ["the surface item could not be written to the log"] };
  }
  return { ok: true, value: surface, warnings: [] };
}

/**
 * Mark an item examined and CLEARED.
 *
 * The reason is required and that is the whole value of the operation. "Nothing
 * found" is not a reason — it is the absence of one. A clearance that cannot name
 * the guard it found is a clearance nobody can check, and it would let a whole area
 * be marked done on the strength of a shrug.
 */
export function clearSurface(projectRoot: string, id: string, reason: string, at = nowIso()): Result<SecSurface> {
  const text = (reason ?? "").trim();
  if (text.length < 20) {
    return {
      ok: false,
      errors: [
        `${id} cannot be cleared with "${text}" — say WHICH guard you found and where. ` +
          'A clearance that cannot name one is a clearance nobody can check, and "nothing found" is ' +
          "the absence of a reason rather than one.",
      ],
    };
  }
  return updateSurface(projectRoot, id, { status: "cleared", clearedReason: text }, at);
}

export function updateSurface(
  projectRoot: string,
  id: string,
  patch: SecSurfacePatch,
  at = nowIso(),
): Result<SecSurface> {
  const snapshot = load(projectRoot).snapshot;
  const existing = snapshot.surfaces.find((s) => s.id === id);
  if (!existing) return { ok: false, errors: [`${id} is not on this run's attack surface`] };
  const after = applySurfacePatchForCheck(existing, patch);
  if (after.status === "cleared" && !after.clearedReason) {
    return { ok: false, errors: [`${id} cannot be cleared without a reason — see clearSurface`] };
  }
  // The timestamp is STAMPED here rather than taken from the caller, and it is part
  // of the patch because that is the only way it reaches the log. An earlier version
  // built a `stamped` object, never used it, and asserted the field onto the patch
  // through `unknown` — which type-checked and did nothing at all.
  const full: SecSurfacePatch = {
    ...patch,
    ...(patch.status !== undefined && patch.status !== "open" && !existing.examinedAt ? { examinedAt: at } : {}),
  };
  if (!appendEvent(projectRoot, { type: "surface_updated", at, id, patch: full })) {
    return { ok: false, errors: ["the update could not be written to the log"] };
  }
  const written = load(projectRoot).snapshot.surfaces.find((s) => s.id === id)!;
  return { ok: true, value: written, warnings: [] };
}

/** Local mirror of the store's patch application, for the pre-write check only. */
function applySurfacePatchForCheck(surface: SecSurface, patch: SecSurfacePatch): SecSurface {
  return {
    ...surface,
    ...(patch.status !== undefined ? { status: patch.status } : {}),
    ...(patch.clearedReason !== undefined ? { clearedReason: patch.clearedReason } : {}),
    ...(patch.findingId !== undefined ? { findingId: patch.findingId } : {}),
  };
}

/**
 * The next item to analyse: the first one still `open`, in ENUMERATION order.
 *
 * Enumeration order rather than a computed priority, because the enumerator listed
 * them in the order worth checking — that judgement is the model's, and re-sorting
 * behind its back would throw it away. The surface brief says so.
 */
export function nextOpenSurface(snapshot: TreeSnapshot): SecSurface | null {
  return snapshot.surfaces.find((s) => s.status === "open") ?? null;
}

export interface SurfaceProgress {
  total: number;
  open: number;
  examined: number;
  cleared: number;
  /** Items that produced a finding. */
  productive: number;
}

export function surfaceProgress(snapshot: TreeSnapshot): SurfaceProgress {
  const total = snapshot.surfaces.length;
  const cleared = snapshot.surfaces.filter((s) => s.status === "cleared").length;
  const withFinding = snapshot.surfaces.filter((s) => s.findingId).length;
  return {
    total,
    open: snapshot.surfaces.filter((s) => s.status === "open").length,
    // "examined" counts everything that was looked at, cleared or not — it is the
    // honest denominator for "how much did this run analyse".
    examined: snapshot.surfaces.filter((s) => s.status !== "open").length,
    cleared,
    productive: withFinding,
  };
}

// -----------------------------------------------------------------
// Coverage, from findings instead of from nodes
// -----------------------------------------------------------------

/**
 * Every project-relative file a FINDING cites.
 *
 * The hypothesis version walks `attackVector.path` and `evidence`. This walks the
 * finding's location and — because a finding may carry an evidence excerpt with no
 * location — any `file:line` looking token inside that excerpt, so a paste of a
 * code slice still counts as having read the file it came from.
 */
export function secCitedFiles(snapshot: Pick<TreeSnapshot, "findings">): Set<string> {
  const cited = new Set<string>();
  const add = (file: string | undefined): void => {
    if (!file) return;
    cited.add(path.posix.normalize(file.split("\\").join("/")).replace(/^\.\//, ""));
  };
  for (const finding of snapshot.findings) {
    add(finding.location?.file);
    const text = finding.evidence ?? "";
    // `src/a.py:41` and `src/a.py:41-49` — the two shapes a pasted artifact uses.
    for (const m of text.matchAll(/([A-Za-z0-9_./-]+\.[A-Za-z0-9]+):\d+/g)) add(m[1]);
  }
  return cited;
}

export function secCoverage(snapshot: TreeSnapshot, projectRoot: string): CoverageReport {
  return coverageGaps(snapshot, projectRoot, secCitedFiles(snapshot));
}

// -----------------------------------------------------------------
// The briefs
// -----------------------------------------------------------------

/**
 * Round 1: read the project, write the note.
 *
 * Same stakes as the hypothesis recon, stated the same way, because the note is the
 * ceiling in BOTH modes — the difference is only what later rounds do with it.
 */
export function renderSecReconBrief(snapshot: TreeSnapshot, objective: string, round: number): string {
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — RECON]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  lines.push("Nothing can be dug for before the project has been read. This round produces the RECON NOTE.");
  lines.push("");
  lines.push("THIS IS THE ONLY RECON PASS, AND IT SETS THE CEILING.");
  lines.push("");
  lines.push("Every later round works from this note plus what has not been read yet. **A part of the");
  lines.push("project absent from this note is a part nothing will look at.**");
  lines.push("");
  lines.push("READ THE PROJECT. Use `ls`, `find`, `grep`, `read` — whatever the shape of the repository demands.");
  lines.push("Cover, in prose:");
  lines.push("  - what the project IS (language, framework, what it does, how it is deployed)");
  lines.push("  - its ENTRYPOINTS: HTTP routes, RPC/GraphQL, websockets, CLI verbs, scheduled jobs,");
  lines.push("    queue consumers, file uploads, deserializers, template/plugin loaders");
  lines.push("  - the TRUST BOUNDARIES: where input crosses from unauthenticated to authenticated,");
  lines.push("    and what the authentication actually checks");
  lines.push("  - where the class of bug the objective names would LIVE in this codebase");
  lines.push("  - anything you could NOT work out");
  lines.push("");
  lines.push("Write PARAGRAPHS, not one giant block. Name the files and directories you looked at.");
  lines.push("");
  lines.push("Then stop. Record it with `sec_recon`, and the next round starts digging.");
  return lines.join("\n");
}

/**
 * What has been found so far, one line each.
 *
 * Carried in EVERY sec brief, not only the analyze one: a round that re-reports a
 * finding the run already has wastes the turn, and the model cannot know what is
 * already recorded unless it is told.
 */
function renderFoundSoFar(snapshot: TreeSnapshot): string {
  const findings = snapshot.findings;
  if (findings.length === 0) {
    return "FOUND SO FAR: nothing yet.";
  }
  const lines: string[] = [`FOUND SO FAR (${findings.length}) — do NOT re-report these:`];
  for (const f of [...findings].sort(compareFinding)) {
    const where = f.location ? ` ${f.location.file}:${f.location.line}` : "";
    lines.push(`  ${f.id} [${f.severity ?? "unrated"}] ${f.category} — ${clip(f.title, 110)}${where}`);
  }
  return lines.join("\n");
}

/**
 * The depth axes for a class, in THIS mode's terms.
 *
 * `renderLadder` in ladders.ts is hypothesis-flavoured: it ends by telling the model
 * to file each unsettled axis as a `requires` gate. That is exactly the machinery
 * this mode does not have. The AXES are the valuable part and they are class
 * knowledge rather than tree machinery, so they are reused here with the instruction
 * that fits — settle each one, and an axis you cannot settle is where to keep
 * digging rather than a question mark to move past.
 */
function renderSecLadder(category: string): string {
  const ladder = ladderFor(category);
  const lines: string[] = [];
  lines.push(`### The depth axes for ${category}`);
  lines.push("");
  lines.push('Settle EACH one by reading code — "no" is as useful an answer as "yes".');
  lines.push("**An axis you cannot settle is where this round should keep digging**, not a question mark to move past.");
  lines.push("");
  lines.push("**The one that matters most — if you check only one, check this:**");
  lines.push(`  ${ladder.keyAxis}`);
  lines.push("");
  lines.push("All of them:");
  for (const axis of ladder.axes) lines.push(`  - ${axis}`);
  return lines.join("\n");
}

/**
 * Round 2: enumerate the attack surface into a WORK LIST.
 *
 * This is the round that turns the mode from "go and look" into an analysis. The
 * list is what the loop then works through one item at a time, so the ORDER the model
 * writes it in IS the plan — which is why the brief says so, and why the loop does not
 * re-sort it afterwards.
 */
export function renderSecSurfaceBrief(snapshot: TreeSnapshot, objective: string, round: number): string {
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — SURFACE]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  lines.push("--- YOUR NOTE FROM THE RECON PASS ---");
  lines.push(snapshot.secNote ?? "(no recon note was recorded)");
  lines.push("--- END OF NOTE ---");
  lines.push("");
  lines.push("Now enumerate the ATTACK SURFACE: the places in this project that an attacker can");
  lines.push("reach, and the places where something dangerous happens.");
  lines.push("");
  lines.push("  - **entrypoint** — a route, an RPC method, a CLI verb, a queue consumer, a");
  lines.push("    scheduled job, a file that gets parsed. Anything reachable from outside.");
  lines.push("  - **sink** — where something dangerous actually happens: an exec, a query, a");
  lines.push("    file write, a deserialize, a template render, a path built from input.");
  lines.push("  - **boundary** — where input crosses from unauthenticated to authenticated, and");
  lines.push("    what the check actually inspects.");
  lines.push("  - **file** — a source file worth reading closely even if you cannot yet say why.");
  lines.push("");
  lines.push("Record each with `sec_surface`. Aim for 10-30 items — enough to cover the project,");
  lines.push("few enough that each one can get a full round of its own.");
  lines.push("");
  lines.push("**LIST THEM IN THE ORDER THEY SHOULD BE EXAMINED.** The loop takes the first open");
  lines.push("item each round, so that order IS the plan — put the ones most likely to hold the");
  lines.push("objective first. Nothing re-sorts the list afterwards.");
  lines.push("");
  lines.push("**These are COORDINATES, not claims.** `POST /diag/ping` is a place. You do NOT have");
  lines.push("to say what is wrong with it yet — that is what the analyze rounds are for. Listing a");
  lines.push("place you end up clearing is not a wasted item; it is a part of the project somebody");
  lines.push("looked at and found sound.");
  lines.push("");
  lines.push("If a category is already obvious (`rce`, `sqli`, `path-traversal`, …), pass it as");
  lines.push("`categories` — the analyze round then hands you that class's depth axes.");
  return lines.join("\n");
}

/**
 * Round 3..N: work ONE item on the list, all the way down.
 *
 * The loop ASSIGNS the item, and that is the point: the analysis is systematic rather
 * than whatever the model felt like reading, and a round cannot drift onto something
 * else because it found the assigned item uninteresting.
 */
export function renderSecAnalyzeBrief(
  snapshot: TreeSnapshot,
  objective: string,
  round: number,
  item: SecSurface,
): string {
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — ANALYZE ${item.id}]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  lines.push("--- THIS ROUND IS THIS ITEM ---");
  lines.push(`  ${item.id}  [${item.kind}]  ${item.title}`);
  if (item.location) lines.push(`  at ${item.location.file}:${item.location.line}`);
  if (item.categories && item.categories.length > 0) lines.push(`  classes to check: ${item.categories.join(", ")}`);
  lines.push("--- END ---");
  lines.push("");
  lines.push(
    "**Analyse THIS item all the way down.** Do not switch to another — every item on the list gets a round",
  );
  lines.push("of its own, and one abandoned half way never gets looked at like this again.");
  lines.push("");
  lines.push("--- HOW TO ANALYSE ---");
  lines.push("Trace the **complete data flow**, one step at a time:");
  lines.push("  1. **ENTRY** — how does control reach this item? Which route, function or event hands it over?");
  lines.push("  2. **CONTROLLED INPUT** — which parts are attacker-controlled? What constrains format, length, encoding?");
  lines.push("  3. **THE CHECK** — is there validation, escaping, an auth check, a cast? **Read the check itself**,");
  lines.push("     not its name. A function called `sanitize` that concatenates is not a sanitizer.");
  lines.push("  4. **SINK** — which exact call does the dangerous thing, and is its argument built by concatenation");
  lines.push("     or passed through untouched?");
  lines.push("");
  lines.push("**Trace it ALL before concluding.** Stopping half way is guessing, and a guess written into the");
  lines.push("report is one a reader cannot tell apart from a checked conclusion.");
  lines.push("");
  for (const category of item.categories ?? []) {
    lines.push(renderSecLadder(category));
    lines.push("");
  }
  lines.push("--- ALREADY CLEARED ---");
  const cleared = snapshot.surfaces.filter((s) => s.status === "cleared");
  if (cleared.length === 0) {
    lines.push("(nothing yet)");
  } else {
    lines.push("These items have been examined and found guarded — do not re-examine them:");
    for (const s of cleared.slice(-12)) {
      lines.push(`  ${s.id}  ${clip(s.title, 80)} — ${clip(s.clearedReason ?? "", 90)}`);
    }
  }
  lines.push("");
  lines.push(renderFoundSoFar(snapshot));
  lines.push("");
  lines.push("--- TWO WAYS THIS ROUND CAN END ---");
  lines.push("**You found something** → `sec_finding`, with `surfaceId` pointing back at this item. It needs a");
  lines.push("`file`+`line` or an `evidence` excerpt.");
  lines.push("");
  lines.push("**You read it and it is guarded** → `sec_clear`, saying WHICH guard you found and where.");
  lines.push("");
  lines.push("**Clearing an item is a RESULT, not a failure.** It is the only evidence a reader has that a part of");
  lines.push("the project was looked at and found sound, and it is what stops the next round re-reading the same");
  lines.push("file. A round that finds nothing but clears an item has produced something.");
  lines.push("");
  lines.push("**The `sec_clear` reason must name the guard.** \"Nothing found\" is not a reason, it is the absence");
  lines.push("of one — a clearance that cannot say what protects the code is one nobody can check.");
  return lines.join("\n");
}

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

function clip(text: string, max: number): string {
  const t = (text ?? "").replace(/\s+/g, " ").trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

function compareFinding(a: SecFinding, b: SecFinding): number {
  const ra = a.severity ? severityRank(a.severity) : 99;
  const rb = b.severity ? severityRank(b.severity) : 99;
  if (ra !== rb) return ra - rb;
  return a.id.localeCompare(b.id);
}

export interface SecReportOptions {
  /** ISO timestamp to stamp the report with. */
  at?: string;
  coverageReport?: CoverageReport;
  /** The reader's language. Defaults to Chinese — see settings.reportLanguage. */
  language?: ReportLanguage;
}

/** Findings grouped by severity, worst first, with the unrated last. */
export function secFindingsBySeverity(snapshot: TreeSnapshot): { rated: SecFinding[]; unrated: SecFinding[] } {
  const sorted = [...snapshot.findings].sort(compareFinding);
  return { rated: sorted.filter((f) => f.severity), unrated: sorted.filter((f) => !f.severity) };
}

export function renderSecReport(
  snapshot: TreeSnapshot,
  loop: AuditLoopState | null,
  opts: SecReportOptions = {},
): string {
  const at = opts.at ?? nowIso();
  const coverage = opts.coverageReport ?? null;
  const lang: ReportLanguage = opts.language ?? "zh";
  const t = secStrings(lang);
  const lines: string[] = [];
  const findings = snapshot.findings;
  const { rated, unrated } = secFindingsBySeverity(snapshot);
  const preAuth = findings.filter((f) => f.preAuth === true).length;

  lines.push(t.title);
  lines.push("");
  lines.push(t.generatedFrom);
  lines.push("");
  lines.push(`- **${t.objective}**: \`${snapshot.objective || loop?.objective || "(none)"}\``);
  lines.push(`- **${t.generatedAt}**: ${at}`);
  if (loop) {
    lines.push(`- **${t.run}**: sec · ${loop.status} · round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : ""}`);
    const timing = loopTiming(loop, Date.parse(at) || Date.now());
    if (timing) lines.push(`- **${t.duration}**: ${formatDuration(timing.activeMs)}`);
    lines.push(`- **${t.stoppedBecause}**: ${loop.stopReason ?? loop.pausedReason ?? t.stillRunning}`);
  }
  lines.push("");

  // ---- THE CAVEAT, BEFORE THE FINDINGS ------------------------------------
  //
  // Placed here rather than at the foot, and that is deliberate. Everywhere else in
  // this extension the non-claims go last; here the reader is about to scroll a list
  // of findings GROUPED BY SEVERITY, and severity is exactly the field this mode
  // does not check. A reader who meets the caveat afterwards has already formed the
  // wrong impression.
  lines.push(t.caveatTitle);
  lines.push("");
  lines.push(t.caveatIntro);
  lines.push("");
  lines.push(`| ${t.caveatColMissing} | ${t.caveatColMeans} |`);
  lines.push("|---|---|");
  lines.push(`| ${t.caveatNoTier} | ${t.caveatNoTierWhy} |`);
  lines.push(`| ${t.caveatNoFalsification} | ${t.caveatNoFalsificationWhy} |`);
  lines.push(`| ${t.caveatNoChallenge} | ${t.caveatNoChallengeWhy} |`);
  lines.push(`| ${t.caveatNoSeverity} | ${t.caveatNoSeverityWhy} |`);
  lines.push(`| ${t.caveatNoGate} | ${t.caveatNoGateWhy} |`);
  lines.push("");
  lines.push(t.caveatEnforced);
  lines.push("");
  lines.push(t.caveatRerun);
  lines.push("");

  // ---- summary ------------------------------------------------------------
  lines.push(t.summaryTitle);
  lines.push("");
  lines.push("| | |");
  lines.push("|---|---|");
  lines.push(`| ${t.rowFindings} | ${findings.length} |`);
  for (const sev of SEVERITIES) {
    const n = rated.filter((f) => f.severity === sev).length;
    if (n > 0) lines.push(`| ${severityLabel(sev, lang)} | ${n} |`);
  }
  if (unrated.length > 0) lines.push(`| ${t.rowUnrated} | **${unrated.length}** |`);
  lines.push(`| ${t.rowPreAuth} | ${preAuth} |`);
  lines.push(`| ${t.rowPostAuth} | ${findings.filter((f) => f.preAuth === false).length} |`);
  lines.push(`| ${t.rowUnassessed} | ${findings.filter((f) => typeof f.preAuth !== "boolean").length} |`);
  lines.push(`| ${t.rowNote} | ${snapshot.secNote ? t.yes : t.no} |`);
  lines.push("");
  if (findings.length === 0) {
    lines.push(t.noFindings);
    lines.push("");
  }

  // ---- coverage -----------------------------------------------------------
  if (coverage) {
    lines.push(t.coverageTitle);
    lines.push("");
    lines.push(`| | |`);
    lines.push(`|---|---|`);
    lines.push(`| ${t.rowCited} | ${coverageHeadline(coverage, lang)} |`);
    lines.push(`| ${t.rowGapDirs} | ${coverage.gaps.length} |`);
    lines.push("");
    if (coverage.projectFiles === null) {
      lines.push(t.coverageNotMeasured(coverage.reason));
    } else if (coverage.gaps.length === 0) {
      lines.push(t.coverageNoGap);
    } else {
      lines.push(t.coverageGapNote);
      lines.push("");
      for (const gap of coverage.gaps) lines.push(t.coverageGapLine(gap.dir, gap.files));
    }
    lines.push("");
  }

  // ---- the attack surface ---------------------------------------------
  //
  // BEFORE the findings, because it is the answer to the question the findings cannot
  // answer: how much of this project did the run actually analyse. A list of findings
  // with no denominator reads as "this is what there is"; with one it reads as "this is
  // what was found in the part that was looked at".
  const progress = surfaceProgress(snapshot);
  lines.push(t.surfaceTitle);
  lines.push("");
  if (progress.total === 0) {
    lines.push(t.surfaceNone);
    lines.push("");
  } else {
    lines.push(t.surfaceIntro);
    lines.push("");
    lines.push("| | |");
    lines.push("|---|---|");
    lines.push(`| ${t.rowSurfaceTotal} | ${progress.total} |`);
    lines.push(`| ${t.rowSurfaceExamined} | **${progress.examined}** (${pct(progress.examined, progress.total)}%) |`);
    lines.push(`| ${t.rowSurfaceCleared} | ${progress.cleared} |`);
    lines.push(`| ${t.rowSurfaceProductive} | ${progress.productive} |`);
    lines.push("");
    if (progress.open === 0) {
      lines.push(t.surfaceAllExamined);
      lines.push("");
    }
  }

  // ---- the findings -------------------------------------------------------
  lines.push(t.findingsTitle(findings.length));
  lines.push("");
  if (findings.length === 0) {
    lines.push(t.noneRecorded);
    lines.push("");
  } else {
    [...rated, ...unrated].forEach((f, i) => lines.push(...renderSecFinding(f, i + 1, t, lang)));
  }

  // ---- what was not read --------------------------------------------------
  const openItems = snapshot.surfaces.filter((s) => s.status === "open");
  if (openItems.length > 0) {
    lines.push(t.surfaceOpenTitle);
    lines.push("");
    lines.push(t.surfaceOpenNote);
    lines.push("");
    for (const s of openItems) {
      lines.push(t.surfaceOpenLine(s.id, s.kind, s.title, s.location ? `${s.location.file}:${s.location.line}` : ""));
    }
    lines.push("");
  }
  const clearedItems = snapshot.surfaces.filter((s) => s.status === "cleared");
  if (clearedItems.length > 0) {
    lines.push(t.surfaceClearedTitle);
    lines.push("");
    lines.push(t.surfaceClearedNote);
    lines.push("");
    for (const s of clearedItems) lines.push(t.surfaceClearedLine(s.id, s.title, s.clearedReason ?? ""));
    lines.push("");
  }
  if (coverage && coverage.gaps.length > 0) {
    lines.push(t.notReadTitle);
    lines.push("");
    lines.push(t.notReadNote);
    lines.push("");
    for (const gap of coverage.gaps) lines.push(t.coverageGapLine(gap.dir, gap.files));
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push(t.footer);
  lines.push("");
  return lines.join("\n");
}

/** A whole-number percentage, for the examined/total ratio. */
function pct(part: number, whole: number): number {
  return whole === 0 ? 0 : Math.round((part / whole) * 100);
}

function renderSecFinding(f: SecFinding, index: number, t: SecStrings, lang: ReportLanguage): string[] {
  const lines: string[] = [];
  const sev = f.severity ? severityLabel(f.severity, lang) : t.rowUnrated.replace(/\*/g, "");
  lines.push(`### ${index}. ${f.id} — ${sev} — ${f.category}`);
  lines.push("");
  lines.push(f.title);
  lines.push("");
  if (f.location) lines.push(`${t.location} \`${f.location.file}:${f.location.line}\``);
  if (f.surfaceId) lines.push(t.surfaceItemLabel(f.surfaceId));
  lines.push(
    `${t.authRequirement} ${f.preAuth === true ? t.authPre : f.preAuth === false ? t.authPost : t.authUnassessed}`,
  );
  lines.push(t.recordedAt(f.round, f.at));
  lines.push("");
  if (f.reasoning) {
    lines.push(t.why);
    lines.push("");
    lines.push(f.reasoning);
    lines.push("");
  }
  if (f.evidence) {
    lines.push(t.evidenceLabel);
    lines.push("");
    const fence = fenceFor(f.evidence);
    lines.push(fence);
    for (const line of f.evidence.split("\n")) lines.push(line);
    lines.push(fence);
    lines.push("");
  }
  if (f.poc) {
    lines.push(t.pocLabel);
    lines.push("");
    const fence = fenceFor(f.poc);
    lines.push(fence);
    for (const line of f.poc.split("\n")) lines.push(line);
    lines.push(fence);
    lines.push("");
  }
  lines.push(t.notVerified);
  lines.push("");
  return lines;
}

/** A fence longer than anything inside it. See reportText.ts on why this matters. */
function fenceFor(text: string): string {
  let longest = 0;
  for (const m of text.match(/`+/g) ?? []) longest = Math.max(longest, m.length);
  return "`".repeat(Math.max(3, longest + 1));
}

function severityZh(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "严重";
    case "high":
      return "高危";
    case "medium":
      return "中危";
    case "low":
      return "低危";
    case "info":
      return "信息";
  }
}

/** Kept for the renderers that have no language in hand (the `/sec tree` line). */
export { severityZh };

/** A compact view of the findings, for `/sec tree`. */
export function renderSecFindings(snapshot: TreeSnapshot): string[] {
  const p = surfaceProgress(snapshot);
  const lines: string[] = [];
  if (p.total > 0) {
    lines.push(
      `Attack surface: ${p.examined}/${p.total} examined · ${p.cleared} cleared · ${p.productive} produced a finding · ${p.open} open`,
    );
    for (const s of snapshot.surfaces.filter((x) => x.status === "open").slice(0, 8)) {
      const where = s.location ? `  ${s.location.file}:${s.location.line}` : "";
      lines.push(`  ${s.id} [${s.kind}] ${clip(s.title, 80)}${where}`);
    }
    const open = p.open;
    if (open > 8) lines.push(`  … +${open - 8} more open`);
    lines.push("");
  }
  if (snapshot.findings.length === 0) {
    // The surface still has to show — a sec run with a work list and no findings is
    // the NORMAL case early on, and the old early-return here hid the one thing that
    // says whether it is working.
    lines.push(snapshot.secNote ? "No findings recorded yet." : "No recon note and no findings yet — round 1 reads the project.");
    return lines;
  }
  lines.push(`${snapshot.findings.length} finding(s):`, "");
  for (const f of [...snapshot.findings].sort(compareFinding)) {
    const where = f.location ? `  ${f.location.file}:${f.location.line}` : "  (evidence only)";
    const auth = f.preAuth === true ? " [pre-auth]" : f.preAuth === false ? " [auth]" : " [auth NOT assessed]";
    lines.push(`  ${f.id} [${f.severity ?? "unrated"}] ${f.category}${auth}${where}`);
    lines.push(`     ${clip(f.title, 100)}`);
  }
  return lines;
}

// -----------------------------------------------------------------
// Writing
// -----------------------------------------------------------------

export function writeSecReport(
  projectRoot: string,
  snapshot: TreeSnapshot,
  loop: AuditLoopState | null,
  opts: SecReportOptions = {},
): Result<string> {
  const reportPath = secReportPath(projectRoot);
  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    const text = renderSecReport(snapshot, loop, {
      ...opts,
      // Read here rather than taken from the caller, for the same reason
      // `writeReport` does: a caller that forgets the language produces an English
      // report for a Chinese operator, and the setting looks broken.
      language: opts.language ?? reportLanguageOf(projectRoot),
      coverageReport: opts.coverageReport ?? secCoverage(snapshot, projectRoot),
    });
    // Only the append-and-truncate pair this project uses everywhere: no rename,
    // no held fd, so a non-NTFS volume cannot fail the write.
    fs.writeFileSync(reportPath, text, "utf-8");
  } catch (error) {
    return { ok: false, errors: [`could not write the report: ${(error as Error).message}`] };
  }
  return { ok: true, value: reportPath, warnings: [] };
}

/**
 * Append one round to the journal.
 *
 * CUMULATIVE, like the hypothesis ledger and for the same reason: this is written
 * when the round is PREPARED, so it cannot contain the round's own output. Listing
 * only `finding.round === round` therefore printed "no finding recorded this round"
 * for every round and showed the findings in NONE of them — measured, 2 findings and
 * five entries all claiming zero.
 *
 * The full list also makes the journal readable on its own: a reader can see what
 * the run knew at each point without diffing consecutive entries.
 */
export function appendSecLedger(
  projectRoot: string,
  snapshot: TreeSnapshot,
  round: number,
  summary: readonly string[],
  at = nowIso(),
): boolean {
  const findings = [...snapshot.findings].sort(compareFinding);
  const body: string[] = [];
  body.push("");
  body.push(`## Round ${round} — ${at}`);
  body.push("");
  const fence = fenceFor(summary.join("\n"));
  body.push(fence);
  body.push(...summary);
  body.push(fence);
  body.push("");
  body.push(`### Findings so far (${findings.length})`);
  body.push("");
  if (findings.length === 0) {
    body.push("_none yet_");
  } else {
    for (const f of findings) {
      const where = f.location ? ` — ${f.location.file}:${f.location.line}` : "";
      const when = f.round > 0 ? ` (r${f.round})` : "";
      body.push(`- [${f.severity ?? "unrated"}] **${f.id}** ${f.title} — ${f.category}${where}${when}`);
    }
  }
  body.push("");
  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    fs.appendFileSync(secLedgerPath(projectRoot), body.join("\n"), "utf-8");
    return true;
  } catch {
    return false;
  }
}

/**
 * The skill guidance is NOT appended here.
 *
 * `loop.ts` owns brief assembly — it appends the operator's notes, the run's scope,
 * the output requirements and the skill guidance to every brief in every mode, in
 * one place. Doing it here as well would apply it twice in sec mode and would put
 * the same decision in two files.
 */
export function secRoundBrief(snapshot: TreeSnapshot, objective: string, round: number): string {
  if (snapshot.secNote === null) return renderSecReconBrief(snapshot, objective, round);
  const item = nextOpenSurface(snapshot);
  if (!item) return renderSecSurfaceBrief(snapshot, objective, round);
  return renderSecAnalyzeBrief(snapshot, objective, round, item);
}
