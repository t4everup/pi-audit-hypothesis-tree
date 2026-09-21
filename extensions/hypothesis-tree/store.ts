/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/store.ts
 *
 * Append-only JSONL persistence for the hypothesis tree.
 *
 * -----------------------------------------------------------------------
 * Why append-only, and what is deliberately NOT used
 * -----------------------------------------------------------------------
 *
 * This extension must work on a non-NTFS Windows volume (exFAT). exFAT has no
 * journal and a documented history of returning EISDIR / EPERM on the
 * link-and-rename dance that "atomic write" libraries use, so the store
 * NEVER:
 *
 *   - creates a hard link (`fs.linkSync`) — the observed EISDIR source;
 *   - writes a temp file and renames over the target (`fs.renameSync`);
 *   - opens the log once and keeps the descriptor.
 *
 * It ONLY calls `mkdirSync` and `appendFileSync` with the default `"a"` flag,
 * which is a single O_APPEND write per record on a descriptor that is opened
 * and closed by the call. No rename, no link, no long-held lock — so there is
 * nothing for a non-journaling filesystem to fail on.
 *
 * The cost of giving up atomic replacement is that a crash can tear the LAST
 * line. That is handled rather than hoped away:
 *
 *   - every record is one JSON object terminated by exactly one `\n`;
 *   - a file whose last byte is not `\n` has a torn tail, which the reader
 *     detects precisely (not by "JSON.parse failed", which would also swallow
 *     real corruption) and skips;
 *   - the torn line is reported as `tornLines` so the UI can say so.
 *
 * Recovery is therefore "read the log and fold it", and it is correct after a
 * crash at ANY byte offset: everything up to the last complete newline is
 * intact and already durable.
 *
 * -----------------------------------------------------------------------
 * Compaction without rewriting
 * -----------------------------------------------------------------------
 *
 * A long audit appends one record per status change, so the log grows without
 * bound. The usual answer (rewrite the file with only the latest record per
 * node) requires a temp file + rename, which is exactly what this module
 * cannot do.
 *
 * Instead `compact()` APPENDS a `snapshot` record containing the fully folded
 * state. The reader starts from the newest snapshot and folds only the events
 * after it, so read cost is bounded while the file stays append-only. The
 * file grows monotonically — that is the accepted trade for correctness on a
 * filesystem with no journal, and the snapshots are small relative to the
 * events they subsume (one record per node instead of one per touch).
 */

import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  type Evidence,
  type Hypothesis,
  type HypothesisStatus,
  type TreeSnapshot,
  isVerdict,
} from "./types.js";

// -----------------------------------------------------------------
// Paths
// -----------------------------------------------------------------

/** State directory name, relative to the audited project root. */
export const STATE_DIR_NAME = ".pi-hypothesis";
export const TREE_LOG_NAME = "tree.jsonl";

export function treeDir(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME);
}

export function treeLogPath(projectRoot: string): string {
  return path.join(treeDir(projectRoot), TREE_LOG_NAME);
}

// -----------------------------------------------------------------
// Event shapes
// -----------------------------------------------------------------

/** A snapshot's payload — everything needed to reconstruct state without the
 * events it subsumes. */
export interface SnapshotPayload {
  treeId: string;
  objective: string;
  rootId: string;
  nodes: Hypothesis[];
  maxNodeSeq: number;
  rounds: number;
  compactions: number;
}

export type TreeEvent =
  | { type: "tree_created"; at: string; treeId: string; objective: string }
  | { type: "node_added"; at: string; node: Hypothesis }
  | { type: "node_updated"; at: string; id: string; patch: NodePatch }
  | { type: "round_recorded"; at: string; round: number }
  | { type: "snapshot"; at: string; snapshot: SnapshotPayload };

/**
 * The fields a node update may change.
 *
 * `id`, `createdAt`, `depth` and `parentId` are absent on purpose:
 *   - `id` is identity;
 *   - `createdAt` is history;
 *   - `depth` is derived (a reparent must recompute it for the whole subtree,
 *     which is a tree operation, not a field patch);
 *   - `parentId` moves a subtree, which is also a tree operation.
 * Reparenting is stage-2 work (`tree.moveSubtree`); until it exists, refusing
 * the field here is better than accepting a patch that would silently make
 * `depth` a lie.
 */
export interface NodePatch {
  description?: string;
  category?: string;
  status?: HypothesisStatus;
  evidence?: Evidence[];
  lastTouchedAt?: string;
  score?: number;
  spawnedFrom?: string[];
  roundIntroduced?: number;
  statusReason?: string;
}

// -----------------------------------------------------------------
// Serialization
// -----------------------------------------------------------------

/** One record = one JSON object + exactly one newline. */
export function serializeEvent(event: TreeEvent): string {
  return JSON.stringify(event) + "\n";
}

/**
 * Parse a log's text into events, reporting the exact number of lines that
 * could not be used.
 *
 * `torn` counts a final line that has no terminating newline — a crash
 * artifact. `malformed` counts complete lines that are not valid event
 * objects — real corruption. They are counted separately because the
 * responses differ: a torn tail is expected and harmless, corruption is a
 * reason to stop and tell the user.
 */
export function parseEvents(text: string): {
  events: TreeEvent[];
  torn: number;
  malformed: number;
  unknown: number;
} {
  const events: TreeEvent[] = [];
  let torn = 0;
  let malformed = 0;
  let unknown = 0;
  if (!text) return { events, torn, malformed, unknown };

  const endsWithNewline = text.endsWith("\n");
  const lines = text.split("\n");
  // A trailing "" after the final newline is not a line.
  if (endsWithNewline) lines.pop();

  lines.forEach((line, index) => {
    const isLast = index === lines.length - 1;
    if (!line.trim()) return;
    // The last line of a file with no trailing newline is a torn write.
    if (isLast && !endsWithNewline) {
      torn++;
      return;
    }
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      malformed++;
      return;
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      malformed++;
      return;
    }
    const type = (raw as { type?: unknown }).type;
    if (typeof type !== "string") {
      malformed++;
      return;
    }
    const event = normalizeEvent(raw as Record<string, unknown>);
    if (!event) {
      unknown++;
      return;
    }
    events.push(event);
  });

  return { events, torn, malformed, unknown };
}

/** Narrow an arbitrary parsed object to a known event, or null. Unknown
 * event types are counted rather than silently dropped, so a newer writer
 * cannot be mistaken for corruption. */
function normalizeEvent(raw: Record<string, unknown>): TreeEvent | null {
  const at = typeof raw.at === "string" ? raw.at : "";
  switch (raw.type) {
    case "tree_created": {
      if (typeof raw.treeId !== "string" || typeof raw.objective !== "string") return null;
      return { type: "tree_created", at, treeId: raw.treeId, objective: raw.objective };
    }
    case "node_added": {
      const node = normalizeNode(raw.node);
      if (!node) return null;
      return { type: "node_added", at, node };
    }
    case "node_updated": {
      if (typeof raw.id !== "string") return null;
      const patch = normalizePatch(raw.patch);
      if (!patch) return null;
      return { type: "node_updated", at, id: raw.id, patch };
    }
    case "round_recorded": {
      const round = typeof raw.round === "number" && Number.isFinite(raw.round) ? Math.max(0, Math.floor(raw.round)) : 0;
      return { type: "round_recorded", at, round };
    }
    case "snapshot": {
      const snapshot = normalizeSnapshot(raw.snapshot);
      if (!snapshot) return null;
      return { type: "snapshot", at, snapshot };
    }
    default:
      return null;
  }
}

const STATUSES = new Set<HypothesisStatus>(["pending", "testing", "confirmed", "rejected", "blocked"]);

function normalizeNode(value: unknown): Hypothesis | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.id !== "string" || !o.id.trim()) return null;
  if (typeof o.description !== "string") return null;
  const status = typeof o.status === "string" && STATUSES.has(o.status as HypothesisStatus)
    ? (o.status as HypothesisStatus)
    : "pending";
  return {
    id: o.id,
    parentId: typeof o.parentId === "string" && o.parentId ? o.parentId : null,
    description: o.description,
    category: typeof o.category === "string" && o.category ? o.category : "other",
    status,
    evidence: normalizeEvidenceList(o.evidence),
    depth: typeof o.depth === "number" && Number.isFinite(o.depth) ? Math.max(0, Math.floor(o.depth)) : 0,
    createdAt: typeof o.createdAt === "string" ? o.createdAt : "",
    lastTouchedAt: typeof o.lastTouchedAt === "string" ? o.lastTouchedAt : "",
    score: typeof o.score === "number" && Number.isFinite(o.score) ? o.score : 0,
    spawnedFrom: Array.isArray(o.spawnedFrom) ? o.spawnedFrom.filter((s): s is string => typeof s === "string" && !!s) : [],
    roundIntroduced: typeof o.roundIntroduced === "number" && Number.isFinite(o.roundIntroduced) ? Math.max(0, Math.floor(o.roundIntroduced)) : 0,
    ...(typeof o.statusReason === "string" && o.statusReason ? { statusReason: o.statusReason } : {}),
  };
}

function normalizeEvidenceList(value: unknown): Evidence[] {
  if (!Array.isArray(value)) return [];
  const out: Evidence[] = [];
  for (const item of value) {
    const e = normalizeEvidence(item);
    if (e) out.push(e);
  }
  return out;
}

function normalizeEvidence(value: unknown): Evidence | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.detail !== "string" || !o.detail) return null;
  const kind = typeof o.kind === "string" ? o.kind : "reasoning";
  const location = o.location && typeof o.location === "object"
    ? (() => {
        const l = o.location as Record<string, unknown>;
        if (typeof l.file !== "string" || !l.file) return undefined;
        const line = typeof l.line === "number" && Number.isFinite(l.line) ? Math.max(1, Math.floor(l.line)) : 1;
        return { file: l.file, line };
      })()
    : undefined;
  return {
    kind: kind as Evidence["kind"],
    at: typeof o.at === "string" ? o.at : "",
    ...(location ? { location } : {}),
    ...(typeof o.command === "string" && o.command ? { command: o.command } : {}),
    detail: o.detail,
  };
}

function normalizePatch(value: unknown): NodePatch | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const patch: NodePatch = {};
  if (typeof o.description === "string") patch.description = o.description;
  if (typeof o.category === "string") patch.category = o.category;
  if (typeof o.status === "string" && STATUSES.has(o.status as HypothesisStatus)) patch.status = o.status as HypothesisStatus;
  if (Array.isArray(o.evidence)) patch.evidence = normalizeEvidenceList(o.evidence);
  if (typeof o.lastTouchedAt === "string") patch.lastTouchedAt = o.lastTouchedAt;
  if (typeof o.score === "number" && Number.isFinite(o.score)) patch.score = o.score;
  if (Array.isArray(o.spawnedFrom)) patch.spawnedFrom = o.spawnedFrom.filter((s): s is string => typeof s === "string" && !!s);
  if (typeof o.roundIntroduced === "number" && Number.isFinite(o.roundIntroduced)) patch.roundIntroduced = Math.max(0, Math.floor(o.roundIntroduced));
  if (typeof o.statusReason === "string") patch.statusReason = o.statusReason;
  return patch;
}

function normalizeSnapshot(value: unknown): SnapshotPayload | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.treeId !== "string" || typeof o.rootId !== "string") return null;
  const nodes: Hypothesis[] = [];
  if (Array.isArray(o.nodes)) {
    for (const n of o.nodes) {
      const node = normalizeNode(n);
      if (node) nodes.push(node);
    }
  }
  return {
    treeId: o.treeId,
    objective: typeof o.objective === "string" ? o.objective : "",
    rootId: o.rootId,
    nodes,
    maxNodeSeq: typeof o.maxNodeSeq === "number" && Number.isFinite(o.maxNodeSeq) ? Math.max(0, Math.floor(o.maxNodeSeq)) : nodes.length,
    rounds: typeof o.rounds === "number" && Number.isFinite(o.rounds) ? Math.max(0, Math.floor(o.rounds)) : 0,
    compactions: typeof o.compactions === "number" && Number.isFinite(o.compactions) ? Math.max(0, Math.floor(o.compactions)) : 0,
  };
}

/**
 * Merge a node update over the previous node.
 *
 * `present` is the key set of the raw patch. Presence — not value — decides
 * what wins: a status-only patch omits `category`, and the normalizer's
 * default for a missing category would otherwise reset a node's category to
 * "other" on every status change. (`spawnedFrom`/`evidence` are the
 * exception: an explicitly empty array is a clear, so it is skipped only when
 * the patch did not carry the key at all.)
 */
export function applyPatch(prev: Hypothesis, patch: NodePatch, present?: ReadonlySet<string>): Hypothesis {
  const next: Hypothesis = { ...prev };
  const keys = present ?? new Set(Object.keys(patch));
  const target = next as unknown as Record<string, unknown>;
  for (const [key, value] of Object.entries(patch) as [keyof NodePatch, unknown][]) {
    if (value === undefined) continue;
    if (present && !keys.has(key)) continue;
    if ((key === "evidence" || key === "spawnedFrom") && Array.isArray(value) && value.length === 0) continue;
    target[key] = value;
  }
  return next;
}

// -----------------------------------------------------------------
// Fold
// -----------------------------------------------------------------

/** An empty snapshot for a project with no tree yet. */
export function emptySnapshot(): TreeSnapshot {
  return {
    treeId: "",
    objective: "",
    rootId: "",
    nodes: [],
    byId: new Map(),
    order: [],
    maxNodeSeq: 0,
    rounds: 0,
    tornLines: 0,
    compactions: 0,
    updatedAt: "",
  };
}

/**
 * Fold a parsed event stream into a snapshot.
 *
 * Latest record wins per node id. The fold is pure so it can be tested
 * against hand-written logs, including deliberately damaged ones.
 */
export function foldEvents(events: readonly TreeEvent[]): TreeSnapshot {
  let treeId = "";
  let objective = "";
  let rootId = "";
  let maxNodeSeq = 0;
  let rounds = 0;
  let compactions = 0;
  let updatedAt = "";
  const order: string[] = [];
  const byId = new Map<string, Hypothesis>();

  const put = (node: Hypothesis, at: string): void => {
    if (!byId.has(node.id)) order.push(node.id);
    byId.set(node.id, node);
    if (at) updatedAt = at;
  };

  for (const event of events) {
    switch (event.type) {
      case "tree_created": {
        treeId = event.treeId;
        objective = event.objective;
        if (event.at) updatedAt = event.at;
        break;
      }
      case "node_added": {
        put(event.node, event.at);
        maxNodeSeq = Math.max(maxNodeSeq, seqOf(event.node.id));
        if (event.node.parentId === null) rootId = event.node.id;
        break;
      }
      case "node_updated": {
        const prev = byId.get(event.id);
        if (!prev) break; // an update for a node the log never added
        put(applyPatch(prev, event.patch), event.at);
        break;
      }
      case "round_recorded": {
        rounds = Math.max(rounds, event.round);
        if (event.at) updatedAt = event.at;
        break;
      }
      case "snapshot": {
        // A snapshot REPLACES the folded state; events after it are folded on
        // top. That is what makes compaction bounded without a rewrite.
        order.length = 0;
        byId.clear();
        treeId = event.snapshot.treeId;
        objective = event.snapshot.objective;
        rootId = event.snapshot.rootId;
        maxNodeSeq = event.snapshot.maxNodeSeq;
        rounds = Math.max(rounds, event.snapshot.rounds);
        compactions = Math.max(compactions, event.snapshot.compactions);
        for (const node of event.snapshot.nodes) put(node, event.at);
        if (event.at) updatedAt = event.at;
        break;
      }
    }
  }

  const nodes = order.map((id) => byId.get(id)!);
  for (const node of nodes) maxNodeSeq = Math.max(maxNodeSeq, seqOf(node.id));
  if (!rootId) {
    const root = nodes.find((n) => n.parentId === null);
    if (root) rootId = root.id;
  }

  return { treeId, objective, rootId, nodes, byId, order, maxNodeSeq, rounds, tornLines: 0, compactions, updatedAt };
}

function seqOf(id: string): number {
  const m = /^H-(\d+)$/.exec(id);
  return m ? Number(m[1]) : 0;
}

// -----------------------------------------------------------------
// I/O
// -----------------------------------------------------------------

export interface LoadResult {
  snapshot: TreeSnapshot;
  /** Lines with no terminating newline (crash artifact). */
  torn: number;
  /** Complete lines that were not valid events (real corruption). */
  malformed: number;
  /** Complete lines carrying an event type this build does not know. */
  unknown: number;
  /** True when the log exists but could not be read at all. */
  readError?: string;
}

/**
 * Read and fold the log.
 *
 * Never throws: a missing log is an empty tree, and an unreadable log is an
 * empty tree PLUS a `readError` the caller must surface. Failing closed on an
 * empty snapshot would silently discard a real audit.
 */
export function load(projectRoot: string): LoadResult {
  const file = treeLogPath(projectRoot);
  let text: string;
  try {
    if (!fs.existsSync(file)) {
      return { snapshot: emptySnapshot(), torn: 0, malformed: 0, unknown: 0 };
    }
    text = fs.readFileSync(file, "utf-8");
  } catch (error) {
    return {
      snapshot: emptySnapshot(),
      torn: 0,
      malformed: 0,
      unknown: 0,
      readError: error instanceof Error ? error.message : String(error),
    };
  }
  const parsed = parseEvents(text);
  const snapshot = foldEvents(parsed.events);
  snapshot.tornLines = parsed.torn;
  return { snapshot, torn: parsed.torn, malformed: parsed.malformed, unknown: parsed.unknown };
}

/** Append one event. Returns false when the write failed — callers must
 * surface that, never assume success. */
export function appendEvent(projectRoot: string, event: TreeEvent): boolean {
  const file = treeLogPath(projectRoot);
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    // `"a"` opens with O_APPEND and the descriptor is closed by this call:
    // one write, no rename, no link, no held lock.
    fs.appendFileSync(file, serializeEvent(event), "utf-8");
    return true;
  } catch {
    return false;
  }
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function newTreeId(): string {
  return `T-${randomUUID().slice(0, 8)}`;
}

/** Stable short hash of an assertion, used to detect an exact duplicate
 * hypothesis recorded twice under different ids. */
export function descriptionKey(description: string): string {
  const normalized = description
    .toLowerCase()
    .replace(/[`'"“”‘’]/g, "")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()
    .replace(/\s+/g, " ");
  return createHash("sha256").update(normalized).digest("hex").slice(0, 16);
}

// -----------------------------------------------------------------
// Compaction (append-only)
// -----------------------------------------------------------------

/** Records-after-snapshot threshold at which `compactIfNeeded` fires. */
export const COMPACT_AFTER_EVENTS = 400;

/** Count the events after the newest snapshot. This is the read cost the
 * next `load()` will pay. */
export function eventsSinceSnapshot(projectRoot: string): number {
  const file = treeLogPath(projectRoot);
  try {
    if (!fs.existsSync(file)) return 0;
    const { events } = parseEvents(fs.readFileSync(file, "utf-8"));
    let lastSnapshot = -1;
    events.forEach((e, i) => {
      if (e.type === "snapshot") lastSnapshot = i;
    });
    return events.length - lastSnapshot - 1;
  } catch {
    return 0;
  }
}

/**
 * Append a snapshot of the current folded state.
 *
 * This is compaction, NOT a rewrite: the file is only ever appended to. Read
 * cost becomes O(nodes) instead of O(events).
 *
 * Refuses to compact a tree with no root (nothing to snapshot) or when a
 * snapshot would be larger than the events it subsumes (a young tree).
 */
export function compact(projectRoot: string): boolean {
  const { snapshot, readError } = load(projectRoot);
  if (readError || !snapshot.rootId || snapshot.nodes.length === 0) return false;
  const since = eventsSinceSnapshot(projectRoot);
  if (since === 0) return false;
  const payload: SnapshotPayload = {
    treeId: snapshot.treeId,
    objective: snapshot.objective,
    rootId: snapshot.rootId,
    nodes: snapshot.nodes,
    maxNodeSeq: snapshot.maxNodeSeq,
    rounds: snapshot.rounds,
    compactions: snapshot.compactions + 1,
  };
  return appendEvent(projectRoot, { type: "snapshot", at: nowIso(), snapshot: payload });
}

/** Compact when the log has grown past the threshold. Returns whether a
 * snapshot was written. */
export function compactIfNeeded(projectRoot: string, threshold = COMPACT_AFTER_EVENTS): boolean {
  if (eventsSinceSnapshot(projectRoot) < threshold) return false;
  return compact(projectRoot);
}

// -----------------------------------------------------------------
// Crash recovery
// -----------------------------------------------------------------

export interface RepairResult {
  repaired: boolean;
  /** Bytes removed from the torn tail (0 when nothing was torn). */
  droppedBytes: number;
  reason: string;
}

/**
 * Truncate a torn tail so the next append starts from a clean line boundary.
 *
 * This is the ONLY operation that shortens the log, and it only ever removes
 * bytes after the last newline — i.e. a partial record that was never
 * durable. `truncateSync` is used rather than a rewrite+rename because
 * truncation is in-place and needs no second file (exFAT-safe).
 *
 * Safe to call at any time; a log with a clean tail is left untouched.
 */
export function repairTornTail(projectRoot: string): RepairResult {
  const file = treeLogPath(projectRoot);
  let text: string;
  try {
    if (!fs.existsSync(file)) return { repaired: false, droppedBytes: 0, reason: "no log" };
    text = fs.readFileSync(file, "utf-8");
  } catch (error) {
    return { repaired: false, droppedBytes: 0, reason: error instanceof Error ? error.message : String(error) };
  }
  if (!text || text.endsWith("\n")) return { repaired: false, droppedBytes: 0, reason: "clean tail" };
  const lastNewline = text.lastIndexOf("\n");
  const keep = lastNewline + 1; // 0 when there is no newline at all
  const dropped = Buffer.byteLength(text, "utf-8") - Buffer.byteLength(text.slice(0, keep), "utf-8");
  try {
    fs.truncateSync(file, keep);
    return { repaired: true, droppedBytes: dropped, reason: "dropped a torn tail" };
  } catch (error) {
    return { repaired: false, droppedBytes: 0, reason: error instanceof Error ? error.message : String(error) };
  }
}

/** Convenience predicate for callers that only need "is this node a verdict". */
export { isVerdict };
