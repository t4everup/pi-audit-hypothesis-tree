/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/recon.ts
 *
 * Stage 6: turning an unknown project into a tree of hypotheses.
 *
 * -----------------------------------------------------------------------
 * Why the audit cannot start with a hypothesis
 * -----------------------------------------------------------------------
 *
 * Stages 1–5 all assume a tree already exists. But the normal case is the
 * opposite: you are handed a repository you have never read, and you cannot
 * write "the login handler accepts a JWT without verifying its signature" until
 * you have found the login handler.
 *
 * So the audit starts with RECON: the model reads the project and writes prose —
 * what it is, where the entrypoints are, what the trust boundaries look like.
 * That prose is then chunked into segments, and each segment becomes the input
 * for one hypothesis-generation round.
 *
 * -----------------------------------------------------------------------
 * Why the MODEL'S NOTES are chunked, not the source
 * -----------------------------------------------------------------------
 *
 * Chunking the raw source is the obvious idea and it is worse in every way that
 * matters:
 *
 *   - A file or a line range can split a function in half, so a hypothesis
 *     derived from the fragment is guessing about code the model never saw
 *     whole. A paragraph boundary is where the MODEL stopped a thought, so
 *     every segment is semantically complete.
 *   - Coverage would be meaningless. "We have read 340 of 500 files" says
 *     nothing about whether the interesting ones were understood.
 *   - It does not terminate in practice. A 500-file repository is 500 rounds at
 *     one segment per round; a recon note is three to eight segments, so the
 *     generation phase is three to eight rounds and then the real work starts.
 *
 * The chunking itself is mechanical — blank-line-separated paragraphs, grouped
 * N at a time, with fenced code blocks kept intact. The extension owns that;
 * the model owns what the paragraphs SAY.
 *
 * -----------------------------------------------------------------------
 * Coverage is the denominator
 * -----------------------------------------------------------------------
 *
 * "When is generation finished" needs a mechanical answer, or the phase never
 * ends: a model can always invent another hypothesis, and "the well is dry"
 * would be indistinguishable from "the model stopped trying". `segmentCoverage`
 * is that answer — and a segment closed with `nothing-found` is a RESULT, not a
 * failure, exactly like a skipped consolidation pass.
 */

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  type AttackVector,
  type Hypothesis,
  type ReconSegment,
  type SegmentCoverage,
  type SegmentOutcome,
  type SegmentRecord,
  type TreeSnapshot,
  clip,
} from "./types.js";
import { STATE_DIR_NAME, appendEvent, nowIso } from "./store.js";

// -----------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------

export const RECON = {
  /**
   * Paragraphs per segment.
   *
   * The design calls for 3–5; 4 is the middle. Below 3 the segments are too
   * thin to carry an attack surface, above 5 a segment spans several unrelated
   * parts of the project and the hypotheses it produces drift.
   */
  PARAGRAPHS_PER_SEGMENT: 4,
  MIN_PARAGRAPHS_PER_SEGMENT: 3,
  MAX_PARAGRAPHS_PER_SEGMENT: 5,
  /** A note shorter than this cannot describe a project. */
  MIN_NOTE_CHARS: 200,
} as const;

export const RECON_NOTE_NAME = "recon.md";

export function reconNotePath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, RECON_NOTE_NAME);
}

// -----------------------------------------------------------------
// Chunking
// -----------------------------------------------------------------

/**
 * Split a note into paragraphs, keeping fenced code blocks intact.
 *
 * A code block routinely contains blank lines, and a naive `split(/\n\s*\n/)`
 * would cut it in half — handing the model a segment that starts in the middle
 * of a function and a second that starts with a stray closing fence. Fences are
 * therefore tracked, and blank lines inside one are not boundaries.
 */
export function splitParagraphs(note: string): string[] {
  const lines = note.split(/\r?\n/);
  const paragraphs: string[] = [];
  let current: string[] = [];
  let fence: string | null = null;

  const flush = (): void => {
    const text = current.join("\n").trim();
    if (text) paragraphs.push(text);
    current = [];
  };

  for (const line of lines) {
    const fenceMatch = /^\s*(```|~~~)/.exec(line);
    if (fenceMatch) {
      const marker = fenceMatch[1]!;
      if (fence === null) fence = marker;
      else if (fence === marker) fence = null;
      current.push(line);
      continue;
    }
    if (fence === null && line.trim() === "") {
      flush();
      continue;
    }
    current.push(line);
  }
  flush();
  return paragraphs;
}

/** Content+position identity, so an edited note re-opens only what changed. */
export function segmentIdFor(index: number, text: string): string {
  const hash = createHash("sha256").update(text).digest("hex").slice(0, 8);
  return `S-${String(index).padStart(3, "0")}-${hash}`;
}

export interface ChunkOptions {
  /** Paragraphs per segment; clamped to [MIN, MAX]. */
  paragraphsPerSegment?: number;
}

/**
 * Group paragraphs into segments.
 *
 * The LAST segment may be shorter than the minimum: a note whose paragraph
 * count is not a multiple of N would otherwise lose its tail, and dropping the
 * model's closing remarks is exactly where it tends to say "and the thing I
 * could not work out was …".
 */
export function chunkNote(note: string, opts: ChunkOptions = {}): ReconSegment[] {
  const per = Math.min(
    RECON.MAX_PARAGRAPHS_PER_SEGMENT,
    Math.max(RECON.MIN_PARAGRAPHS_PER_SEGMENT, Math.floor(opts.paragraphsPerSegment ?? RECON.PARAGRAPHS_PER_SEGMENT)),
  );
  const paragraphs = splitParagraphs(note);
  const segments: ReconSegment[] = [];
  for (let i = 0; i < paragraphs.length; i += per) {
    const group = paragraphs.slice(i, i + per);
    const text = group.join("\n\n");
    const index = segments.length;
    segments.push({ id: segmentIdFor(index, text), index, paragraphs: group.length, text, hash: segmentIdFor(index, text).split("-")[2]! });
  }
  return segments;
}

// -----------------------------------------------------------------
// Coverage
// -----------------------------------------------------------------

/** Segment ids that have been closed (produced something or explicitly empty). */
export function closedSegmentIds(snapshot: TreeSnapshot): Set<string> {
  const closed = new Set<string>();
  for (const record of snapshot.segmentRecords) closed.add(record.segmentId);
  // A hypothesis that names a segment closes it even if no outcome record was
  // written — the model may have called hypothesis_add without the outcome
  // bookkeeping, and treating that segment as open would re-ask forever.
  for (const node of snapshot.nodes) if (node.segmentId) closed.add(node.segmentId);
  return closed;
}

export function segmentCoverage(snapshot: TreeSnapshot): SegmentCoverage {
  const closed = closedSegmentIds(snapshot);
  const open = snapshot.segments.filter((s) => !closed.has(s.id)).map((s) => s.id);
  return {
    total: snapshot.segments.length,
    covered: snapshot.segments.length - open.length,
    open,
  };
}

/** The next segment to hand over, or null when coverage is complete. */
export function nextOpenSegment(snapshot: TreeSnapshot): ReconSegment | null {
  const closed = closedSegmentIds(snapshot);
  return snapshot.segments.find((s) => !closed.has(s.id)) ?? null;
}

export function segmentById(snapshot: TreeSnapshot, id: string): ReconSegment | undefined {
  return snapshot.segments.find((s) => s.id === id);
}

// -----------------------------------------------------------------
// Mutations
// -----------------------------------------------------------------

export interface SubmitReconResult {
  ok: boolean;
  errors: string[];
  segments?: ReconSegment[];
}

/**
 * Record a recon submission.
 *
 * The note is written to `.pi-hypothesis/recon.md` as well as logged, because a
 * human reviewing the audit needs to read the prose the tree was derived from —
 * the JSONL holds the segments, but the note is what the model actually wrote.
 *
 * The write is in place (no temp+rename), matching the store's exFAT discipline.
 */
export function submitRecon(projectRoot: string, note: string, opts: ChunkOptions & { at?: string } = {}): SubmitReconResult {
  const text = (note ?? "").trim();
  if (text.length < RECON.MIN_NOTE_CHARS) {
    return {
      ok: false,
      errors: [
        `the recon note is too short to describe a project (${text.length} chars, minimum ${RECON.MIN_NOTE_CHARS}). ` +
          `Write what you actually found: what the project is, its entrypoints, its trust boundaries, and what you could not work out.`,
      ],
    };
  }
  const segments = chunkNote(text, opts);
  if (segments.length === 0) return { ok: false, errors: ["the recon note produced no segments — it appears to be blank"] };

  const at = opts.at ?? nowIso();
  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    fs.writeFileSync(reconNotePath(projectRoot), text + "\n", "utf-8");
  } catch {
    // The note file is for humans; the durable record is the event below.
  }
  if (!appendEvent(projectRoot, { type: "recon_submitted", at, note: text, segments })) {
    return { ok: false, errors: ["the recon note could not be written — the tree is unchanged"] };
  }
  return { ok: true, errors: [], segments };
}

/**
 * Close a segment.
 *
 * `nothing-found` REQUIRES a note, for the same reason a blocked hypothesis
 * requires a reason: "we looked and there was nothing" and "we did not look"
 * must not be the same record.
 */
export function recordSegmentOutcome(
  projectRoot: string,
  segmentId: string,
  outcome: SegmentOutcome,
  opts: { hypothesisIds?: string[]; note?: string; at?: string } = {},
): { ok: boolean; errors: string[] } {
  if (!segmentId) return { ok: false, errors: ["segmentId is required"] };
  if (outcome === "nothing-found" && !(opts.note ?? "").trim()) {
    return {
      ok: false,
      errors: ["outcome 'nothing-found' needs a note saying what you examined — otherwise it is indistinguishable from not looking"],
    };
  }
  const record: SegmentRecord = {
    segmentId,
    at: opts.at ?? nowIso(),
    outcome,
    hypothesisIds: opts.hypothesisIds ?? [],
    ...(opts.note ? { note: opts.note } : {}),
  };
  if (!appendEvent(projectRoot, { type: "segment_recorded", at: record.at, record })) {
    return { ok: false, errors: ["the segment outcome could not be written — the tree is unchanged"] };
  }
  return { ok: true, errors: [] };
}

// -----------------------------------------------------------------
// Attack vectors
// -----------------------------------------------------------------

/** One line describing a vector, for the tree view and the ledger. */
export function describeVector(vector: AttackVector): string {
  const steps = vector.path.length > 0 ? ` · ${vector.path.length} step(s)` : "";
  const pre = vector.preconditions && vector.preconditions.length > 0 ? ` · needs ${vector.preconditions.join("; ")}` : "";
  return `${vector.entrypoint} · ${vector.technique}${steps}${pre}`;
}

/** How many hypotheses carry a vector — the generation phase's real output. */
export function vectorCoverage(snapshot: TreeSnapshot): { withVector: number; withoutVector: number } {
  const hypotheses = snapshot.nodes.filter((n) => n.nodeKind !== "scope");
  const withVector = hypotheses.filter((n) => n.attackVector).length;
  return { withVector, withoutVector: hypotheses.length - withVector };
}

/** Hypotheses that came from a given segment. */
export function hypothesesForSegment(snapshot: TreeSnapshot, segmentId: string): Hypothesis[] {
  return snapshot.nodes.filter((n) => n.segmentId === segmentId);
}

// -----------------------------------------------------------------
// Briefs
// -----------------------------------------------------------------

/** The recon round: read the project, write prose, submit it. */
export function renderReconBrief(snapshot: TreeSnapshot, objective: string): string {
  const lines: string[] = [];
  lines.push("[AUDIT ROUND 1 — RECON]");
  lines.push("");
  lines.push(`Audit objective: ${objective}`);
  lines.push("");
  lines.push("There is no hypothesis tree yet, and none can be written before the project has been read.");
  lines.push("This round produces the RECON NOTE that every later hypothesis is derived from.");
  lines.push("");
  // THE STAKES, and they were not stated before.
  //
  // Measured on a real Centreon audit: 16 paragraphs -> 4 segments -> 4 generation
  // rounds -> 23 hypotheses, and 92% of EVERY hypothesis that audit ever recorded
  // came from those 4 windows. Nothing came from anywhere else — generation is
  // segment-driven, and nothing later goes back and reads an area the note did not
  // mention. A brief that says "every later hypothesis is derived from it" without
  // saying "and there is no second pass" reads as one step among several.
  lines.push("THIS IS THE ONLY RECON PASS, AND IT SETS THE CEILING.");
  lines.push("");
  lines.push("The note is split into segments, and each segment is ONE generation round. Generation");
  lines.push("is where hypotheses come from — nothing later goes back and reads a subsystem this");
  lines.push("note does not mention. So the number of segments you write here is the number of");
  lines.push("windows this audit will ever look through.");
  lines.push("");
  lines.push("**A part of the project absent from this note is a part nothing will look at.**");
  lines.push("");
  lines.push("Measured on a real audit: 16 paragraphs became 4 segments, and 92% of every");
  lines.push("hypothesis that audit ever recorded came from those 4 windows. The note was the");
  lines.push("whole ceiling, and it was written in one turn.");
  lines.push("");
  lines.push("READ THE PROJECT. Use `ls`, `find`, `grep`, `read` — whatever the shape of the repository demands.");
  lines.push("Cover, in prose:");
  lines.push("  - what the project IS (language, framework, what it does)");
  lines.push("  - its ENTRYPOINTS: HTTP routes, RPC/GraphQL, websockets, CLI verbs, scheduled jobs,");
  lines.push("    queue consumers, file uploads, deserializers, template/plugin loaders");
  lines.push("  - its TRUST BOUNDARIES: where authentication and authorization happen, and where");
  lines.push("    they visibly do NOT");
  lines.push("  - its DATA FLOWS you can already see: what reaches what");
  lines.push("  - what you could NOT work out, and what you would need to work it out");
  lines.push("");
  lines.push("Then call hypothesis_recon with that prose.");
  lines.push("");
  lines.push("WRITE IT AS PARAGRAPHS. The note is split into segments of 3–5 paragraphs, and each");
  lines.push("segment becomes one hypothesis-generation round. So one paragraph should be one coherent");
  lines.push("thought about one part of the project — not one sentence, and not the whole subsystem.");
  lines.push("");
  lines.push("COVER THE WHOLE PROJECT, AND BE GENEROUS. One paragraph per coherent thought is the");
  lines.push("GRANULARITY, not the BUDGET: a large application is many paragraphs, not one per");
  lines.push("subsystem and not sixteen for the lot. A thin note is not a cheap audit — it is a");
  lines.push("narrow one, and the narrowness is invisible in the report.");
  lines.push("");
  lines.push("Name what you did NOT look at. \"I did not read the plugin loader\" is a paragraph, and");
  lines.push("it is far better than silence: silence is indistinguishable from \"I looked and there");
  lines.push("was nothing there\", and only one of those is true.");
  lines.push("");
  lines.push("Do NOT write hypotheses yet. This round is observation only: a hypothesis written before");
  lines.push("the project has been read is a guess, and the whole point of the tree is that every node");
  lines.push("is something that could be proven wrong by evidence you have actually looked at.");
  lines.push("");
  lines.push("Then stop. The next round will hand you the first segment.");
  return lines.join("\n");
}

/** One generate round: turn one segment into hypotheses + attack vectors. */
export function renderSegmentBrief(
  snapshot: TreeSnapshot,
  segment: ReconSegment,
  objective: string,
  coverage: SegmentCoverage,
): string {
  const lines: string[] = [];
  lines.push(`[AUDIT ROUND — GENERATE from segment ${segment.id}]`);
  lines.push("");
  lines.push(`Audit objective: ${objective}`);
  lines.push(`Segment ${segment.index + 1} of ${coverage.total} (${segment.paragraphs} paragraph(s)); ${coverage.covered} already covered.`);
  lines.push("");
  lines.push("This is YOUR segment of the recon note:");
  lines.push("");
  lines.push("---");
  lines.push(segment.text);
  lines.push("---");
  lines.push("");
  lines.push("Turn it into HYPOTHESES and ATTACK VECTORS.");
  lines.push("");
  lines.push("A hypothesis is a falsifiable claim about the codebase — \"the login handler accepts a");
  lines.push("JWT without verifying its signature\", not \"check the JWT validation\". The store refuses");
  lines.push("task-shaped text, so phrase it as something evidence could prove WRONG.");
  lines.push("");
  lines.push("An attack vector is how an attacker would actually get there: the entrypoint, the chain of");
  lines.push("steps to the sink, the technique, and any payload or precondition. It is a FIELD on the");
  lines.push("hypothesis, not a separate node.");
  lines.push("");
  lines.push("For each hypothesis call hypothesis_add with:");
  lines.push("  description     the falsifiable claim");
  lines.push("  category        the class (auth-bypass, idor, sqli, ssrf, path-traversal, deserialization, …)");
  lines.push(`  segmentId       "${segment.id}"`);
  lines.push("  attackVector    { entrypoint, path: [{ location?, detail }], technique, payload?, preconditions? }");
  lines.push("");
  lines.push("Rules:");
  lines.push("  - Derive only what THIS segment supports. Do not reach for the whole project.");
  lines.push("  - A claim you cannot connect to a location or a flow is at best a weak hypothesis — say so");
  lines.push("    by leaving the vector's path short rather than inventing steps.");
  lines.push("  - If the segment genuinely contains no attack surface, call hypothesis_cover_segment with");
  lines.push(`    segmentId="${segment.id}" and a note saying what you examined. That is a RESULT, not a`);
  lines.push("    failure, and it is what keeps coverage honest.");
  lines.push("  - Do not re-add a hypothesis that is already in the tree: the store refuses it and names");
  lines.push("    the existing node.");
  lines.push("");
  lines.push("Then stop. The next segment (or the first verification round) follows automatically.");
  return lines.join("\n");
}

/** One-line coverage summary for the status block. */
export function renderCoverage(snapshot: TreeSnapshot): string {
  const coverage = segmentCoverage(snapshot);
  if (snapshot.reconAt === null) return "recon: not run yet (the first round reads the project)";
  if (coverage.total === 0) return "recon: submitted, but it produced no segments";
  const vectors = vectorCoverage(snapshot);
  const pct = Math.round((coverage.covered / coverage.total) * 100);
  return (
    `recon: ${coverage.covered}/${coverage.total} segment(s) covered (${pct}%)` +
    ` · ${vectors.withVector} hypothesis(es) carry an attack vector` +
    (coverage.open.length > 0 ? ` · next ${coverage.open[0]}` : " · generation complete")
  );
}

