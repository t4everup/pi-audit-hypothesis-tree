/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/tree.ts
 *
 * Tree CRUD over the append-only store, plus the invariants that keep the
 * tree a TREE.
 *
 * Every mutation is (validate → append one event). There is no in-place
 * mutation of persisted state anywhere: the durable log is the truth and the
 * in-memory snapshot is a cache rebuilt by folding. That is what makes a
 * crash at any point recoverable — a rejected mutation writes nothing, and an
 * accepted one is durable the moment `appendFileSync` returns.
 */

import {
  type AttackVector,
  type Evidence,
  type Hypothesis,
  type HypothesisCategory,
  type HypothesisInput,
  type HypothesisStatus,
  type NodeKind,
  type Severity,
  type TreeSnapshot,
  OPEN_STATUSES,
  VERDICT_STATUSES,
  isOpen,
  isSchedulable,
  isVerdict,
  validateDescription,
  validateEvidence,
  validateHypothesisInput,
} from "./types.js";
import {
  type NodePatch,
  appendEvent,
  compactIfNeeded,
  descriptionKey,
  load,
  newTreeId,
  nowIso,
} from "./store.js";

// -----------------------------------------------------------------
// Result
// -----------------------------------------------------------------

/**
 * Every mutation returns this. There is no throwing path and no
 * "fire-and-forget": a caller that ignores `ok:false` would be writing to a
 * tree that did not change, so the shape forces the check.
 */
export type Result<T> = { ok: true; value: T; warnings: string[] } | { ok: false; errors: string[] };

function ok<T>(value: T, warnings: string[] = []): Result<T> {
  return { ok: true, value, warnings };
}

function fail<T>(...errors: string[]): Result<T> {
  return { ok: false, errors };
}

// -----------------------------------------------------------------
// Ids and depth
// -----------------------------------------------------------------

/** Next free `H-NNNN`. Reads the folded snapshot so an id is never reused,
 * even after a compaction snapshot reset the node list. */
export function nextNodeId(snapshot: TreeSnapshot): string {
  return `H-${String(snapshot.maxNodeSeq + 1).padStart(4, "0")}`;
}

/** Depth of a node, derived from the parent chain. Returns null when the
 * chain is broken (a parent id that is not in the tree) — callers must treat
 * that as corruption, not as depth 0. */
export function deriveDepth(snapshot: TreeSnapshot, parentId: string | null): number | null {
  let depth = 0;
  let current = parentId;
  const seen = new Set<string>();
  while (current) {
    if (seen.has(current)) return null; // cycle
    seen.add(current);
    const parent = snapshot.byId.get(current);
    if (!parent) return null;
    depth++;
    current = parent.parentId;
  }
  return depth;
}

// -----------------------------------------------------------------
// Reads
// -----------------------------------------------------------------

export function getNode(snapshot: TreeSnapshot, id: string): Hypothesis | undefined {
  return snapshot.byId.get(id);
}

/** Direct children, insertion order. */
export function children(snapshot: TreeSnapshot, id: string): Hypothesis[] {
  return snapshot.nodes.filter((n) => n.parentId === id);
}

/** The node plus every descendant, in insertion order. */
export function subtree(snapshot: TreeSnapshot, id: string): Hypothesis[] {
  const out: Hypothesis[] = [];
  const visit = (current: string): void => {
    const node = snapshot.byId.get(current);
    if (!node) return;
    out.push(node);
    for (const child of children(snapshot, current)) visit(child.id);
  };
  visit(id);
  return out;
}

/** Root → node, inclusive. Empty when the chain is broken. */
export function pathToRoot(snapshot: TreeSnapshot, id: string): Hypothesis[] {
  const chain: Hypothesis[] = [];
  let current: string | null = id;
  const seen = new Set<string>();
  while (current) {
    if (seen.has(current)) return []; // cycle
    seen.add(current);
    const node = snapshot.byId.get(current);
    if (!node) return [];
    chain.unshift(node);
    current = node.parentId;
  }
  return chain;
}

/** Nodes still needing work. */
export function openNodes(snapshot: TreeSnapshot): Hypothesis[] {
  // Scope nodes are excluded: they have no truth value, so counting them as
  // "open work" would inflate every progress figure by one.
  return snapshot.nodes.filter(isSchedulable);
}

/** Confirmed findings — the input to vulnerability combination (stage 4). */
export function confirmedNodes(snapshot: TreeSnapshot): Hypothesis[] {
  return snapshot.nodes.filter((n) => n.status === "confirmed");
}

export function rejectedNodes(snapshot: TreeSnapshot): Hypothesis[] {
  return snapshot.nodes.filter((n) => n.status === "rejected");
}

/** Deepest leaf depth in the tree. */
export function maxDepth(snapshot: TreeSnapshot): number {
  return snapshot.nodes.reduce((max, n) => Math.max(max, n.depth), 0);
}

export interface TreeSummary {
  treeId: string;
  objective: string;
  nodes: number;
  /** Boundary nodes, excluded from  and . */
  scopeNodes: number;
  byStatus: Record<HypothesisStatus, number>;
  byCategory: Record<string, number>;
  maxDepth: number;
  rounds: number;
  tornLines: number;
}

export function summarize(snapshot: TreeSnapshot): TreeSummary {
  const byStatus: Record<HypothesisStatus, number> = { pending: 0, testing: 0, confirmed: 0, rejected: 0, blocked: 0 };
  const byCategory: Record<string, number> = {};
  let scopeNodes = 0;
  for (const node of snapshot.nodes) {
    // A scope node is a boundary, not work: counting it as "pending" would
    // make every progress figure read one too high, forever.
    if (node.nodeKind === "scope") {
      scopeNodes++;
      continue;
    }
    byStatus[node.status] = (byStatus[node.status] ?? 0) + 1;
    byCategory[node.category] = (byCategory[node.category] ?? 0) + 1;
  }
  return {
    treeId: snapshot.treeId,
    objective: snapshot.objective,
    nodes: snapshot.nodes.length,
    scopeNodes,
    byStatus,
    byCategory,
    maxDepth: maxDepth(snapshot),
    rounds: snapshot.rounds,
    tornLines: snapshot.tornLines,
  };
}

/** Find an existing node with the same normalized assertion. */
export function findByDescription(snapshot: TreeSnapshot, description: string): Hypothesis | undefined {
  const key = descriptionKey(description);
  return snapshot.nodes.find((n) => descriptionKey(n.description) === key);
}

// -----------------------------------------------------------------
// Mutations
// -----------------------------------------------------------------

/**
 * Create the tree and its root hypothesis.
 *
 * The user's audit objective IS the root assertion. If it does not read as a
 * falsifiable claim the caller must reformulate it — the root of a
 * hypothesis tree cannot be "audit this project", because no evidence can
 * ever confirm or refute it.
 */
/**
 * Create the tree and its root node.
 *
 * `nodeKind` defaults to `hypothesis`, which keeps `/hypothesis new "<assertion>"`
 * meaning exactly what it always meant: the text you supply IS the first
 * falsifiable claim and the scheduler will examine it.
 *
 * `nodeKind: "scope"` is the OTHER entry point — the one an audit of an
 * unfamiliar project needs. The text is then a boundary ("the project rooted at
 * cwd"), exempt from the assertion gate, and the scheduler skips it: a scope
 * has no truth value, so a round spent falsifying it would be a wasted round.
 * The hypotheses come later, from the recon segments.
 */
export function createTree(
  projectRoot: string,
  objective: string,
  opts: { category?: HypothesisCategory; round?: number; at?: string; nodeKind?: NodeKind } = {},
): Result<{ snapshot: TreeSnapshot; root: Hypothesis }> {
  const current = load(projectRoot);
  if (current.readError) {
    return fail(`cannot read the existing tree log: ${current.readError}`);
  }
  if (current.snapshot.rootId) {
    return fail(
      `a tree already exists in ${projectRoot} (root ${current.snapshot.rootId}: "${current.snapshot.objective.slice(0, 60)}"). Use /hypothesis reset to start a new one, or add nodes to the existing tree.`,
    );
  }

  const nodeKind: NodeKind = opts.nodeKind ?? "hypothesis";
  const input: HypothesisInput = { description: objective, category: opts.category ?? "other", nodeKind };
  const validation = validateHypothesisInput(input);
  if (!validation.ok) return fail(...validation.errors);

  const at = opts.at ?? nowIso();
  const treeId = newTreeId();
  const root: Hypothesis = {
    id: "H-0001",
    nodeKind,
    parentId: null,
    description: objective.trim(),
    category: input.category,
    status: "pending",
    evidence: [],
    depth: 0,
    createdAt: at,
    lastTouchedAt: at,
    score: 0,
    spawnedFrom: [],
    roundIntroduced: opts.round ?? 0,
    timesSelected: 0,
    lastSelectedRound: null,
  };

  if (!appendEvent(projectRoot, { type: "tree_created", at, treeId, objective: root.description })) {
    return fail("the tree log could not be written — check that the project directory is writable");
  }
  if (!appendEvent(projectRoot, { type: "node_added", at, node: root })) {
    return fail("the root node could not be written — the tree was created but has no root; run repair before retrying");
  }

  const snapshot = load(projectRoot).snapshot;
  return ok({ snapshot, root });
}

/**
 * Add a child hypothesis.
 *
 * The interesting refusals, and why each exists:
 *
 *   - A TASK-SHAPED description is refused (`validateDescription`). This is
 *     the whole point of the extension.
 *   - A duplicate assertion is refused and the EXISTING id is named, so the
 *     caller links to it instead of growing a second copy of the same branch.
 *   - `depth` is derived, never accepted from the caller, so a node can never
 *     disagree with its parent chain.
 */
export function addNode(
  projectRoot: string,
  input: HypothesisInput & { at?: string },
): Result<{ snapshot: TreeSnapshot; node: Hypothesis }> {
  const { snapshot, readError } = load(projectRoot);
  if (readError) return fail(`cannot read the tree log: ${readError}`);
  if (!snapshot.rootId) return fail("no tree exists — create one first with a root hypothesis");

  const validation = validateHypothesisInput(input);
  if (!validation.ok) return fail(...validation.errors);

  const parentId = input.parentId ?? snapshot.rootId;
  const parent = snapshot.byId.get(parentId);
  if (!parent) {
    return fail(`parent ${parentId} is not in the tree — pass an existing node id or omit parentId to attach to the root`);
  }

  const depth = deriveDepth(snapshot, parentId);
  if (depth === null) {
    return fail(`the parent chain from ${parentId} is broken (missing ancestor or a cycle) — repair the tree before adding nodes`);
  }

  const duplicate = findByDescription(snapshot, input.description);
  if (duplicate) {
    return fail(
      `this assertion is already in the tree as ${duplicate.id} (status ${duplicate.status}) — link to it instead of re-adding it; a duplicated branch is audited twice and reported twice`,
    );
  }

  const at = input.at ?? nowIso();
  const warnings: string[] = [];
  // A verdict on creation is legal (a hypothesis can be recorded already
  // refuted), but it still needs evidence — checked below.
  const status = input.status ?? "pending";
  const evidence = input.evidence ?? [];
  if (isVerdict(status) && evidence.length === 0) {
    return fail(
      `a node created as "${status}" needs at least one evidence entry — a verdict without raw evidence is an opinion, and the tree's value is that every verdict is re-derivable`,
    );
  }
  if (status === "blocked" && !input.statusReason) {
    return fail("statusReason is required when a node is blocked");
  }
  if (depth + 1 > 0 && parent.depth !== depth - 1) {
    // Defensive: deriveDepth and the stored parent depth must agree.
    warnings.push(`parent ${parentId} stores depth ${parent.depth} but the chain computes ${depth - 1}; the stored value is stale`);
  }

  const node: Hypothesis = {
    id: nextNodeId(snapshot),
    nodeKind: input.nodeKind ?? "hypothesis",
    parentId,
    description: input.description.trim(),
    category: input.category,
    status,
    evidence,
    depth,
    createdAt: at,
    lastTouchedAt: at,
    score: 0,
    spawnedFrom: input.spawnedFrom ?? [],
    roundIntroduced: input.roundIntroduced ?? snapshot.rounds,
    timesSelected: 0,
    lastSelectedRound: null,
    ...(input.attackVector ? { attackVector: input.attackVector } : {}),
    ...(input.segmentId ? { segmentId: input.segmentId } : {}),
    ...(input.severity ? { severity: input.severity } : {}),
    ...(input.statusReason ? { statusReason: input.statusReason } : {}),
  };

  if (!appendEvent(projectRoot, { type: "node_added", at, node })) {
    return fail("the node could not be written — the tree is unchanged");
  }

  compactIfNeeded(projectRoot);
  return ok({ snapshot: load(projectRoot).snapshot, node }, warnings);
}

/** Append a patch event. Every public mutation goes through one of the
 * validated wrappers below; the scheduler uses this directly for its own
 * bookkeeping (score, selection counters), which needs no domain validation. */
export function applyNodePatch(projectRoot: string, id: string, patch: NodePatch, at: string): Result<Hypothesis> {
  const { snapshot, readError } = load(projectRoot);
  if (readError) return fail(`cannot read the tree log: ${readError}`);
  const prev = snapshot.byId.get(id);
  if (!prev) return fail(`node ${id} is not in the tree`);

  const fullPatch: NodePatch = { ...patch, lastTouchedAt: at };
  if (!appendEvent(projectRoot, { type: "node_updated", at, id, patch: fullPatch })) {
    return fail("the update could not be written — the tree is unchanged");
  }
  const next = load(projectRoot).snapshot.byId.get(id)!;
  return ok(next);
}

/** Internal alias so the validated wrappers below read naturally. */
const patchNode = applyNodePatch;

/**
 * Attach evidence to a node.
 *
 * Evidence is append-only at the node level too: entries accumulate, and the
 * order they were collected in is preserved, because "we thought X, then
 * found Y" is different from "we found Y, then claimed X".
 */
export function addEvidence(projectRoot: string, id: string, evidence: Evidence, at = nowIso()): Result<Hypothesis> {
  const check = validateEvidence(evidence);
  if (!check.ok) return fail(...check.errors);
  const { snapshot } = load(projectRoot);
  const prev = snapshot.byId.get(id);
  if (!prev) return fail(`node ${id} is not in the tree`);
  const stamped: Evidence = { ...evidence, at: evidence.at || at };
  return patchNode(projectRoot, id, { evidence: [...prev.evidence, stamped] }, at);
}

/**
 * Record a verdict (or a non-verdict status change).
 *
 * The gate that matters: **a verdict requires evidence.** `confirmed` and
 * `rejected` are the two states that feed everything downstream (a confirmed
 * node becomes a finding and an input to combination; a rejected node prunes
 * a branch), so accepting either without a quotable artifact would poison the
 * whole tree. The evidence may already be on the node or supplied here.
 */
export function setStatus(
  projectRoot: string,
  id: string,
  status: HypothesisStatus,
  opts: { evidence?: Evidence[]; reason?: string; severity?: Severity; at?: string } = {},
): Result<Hypothesis> {
  const at = opts.at ?? nowIso();
  const { snapshot, readError } = load(projectRoot);
  if (readError) return fail(`cannot read the tree log: ${readError}`);
  const prev = snapshot.byId.get(id);
  if (!prev) return fail(`node ${id} is not in the tree`);
  if (prev.status === status) return fail(`node ${id} is already "${status}"`);

  const supplied = opts.evidence ?? [];
  for (const [i, e] of supplied.entries()) {
    const check = validateEvidence(e);
    if (!check.ok) return fail(...check.errors.map((m) => `evidence[${i}]: ${m}`));
  }
  const evidence = [...prev.evidence, ...supplied.map((e) => ({ ...e, at: e.at || at }))];

  if (isVerdict(status) && evidence.length === 0) {
    return fail(
      `"${status}" needs at least one evidence entry — supply it in this call or attach it first with addEvidence. A verdict with no quotable artifact is an opinion, and the next round cannot tell it from a guess.`,
    );
  }
  if (status === "blocked" && !opts.reason && !prev.statusReason) {
    return fail("statusReason is required when a node is blocked — say what it is waiting on");
  }
  if (!isVerdict(status) && isVerdict(prev.status) && !opts.reason) {
    return fail(
      `reopening ${id} from "${prev.status}" to "${status}" needs a reason — a verdict that was already reached must not silently return to the queue`,
    );
  }

  const patch: NodePatch = { status, evidence };
  if (opts.reason) patch.statusReason = opts.reason;
  if (opts.severity) patch.severity = opts.severity;
  // Leaving `confirmed` clears the challenge record: a finding that is reopened
  // and re-confirmed is a NEW claim, so it must be attacked again rather than
  // inheriting the earlier attempt's verdict.
  if (status !== "confirmed" && prev.status === "confirmed") patch.challengedRound = null;
  return patchNode(projectRoot, id, patch, at);
}

/** Mark a node as currently being examined. Exactly one node per round is
 * expected, but this is not enforced here — the scheduler owns that policy. */
export function markTesting(projectRoot: string, id: string, at = nowIso()): Result<Hypothesis> {
  const { snapshot } = load(projectRoot);
  const prev = snapshot.byId.get(id);
  if (!prev) return fail(`node ${id} is not in the tree`);
  if (isVerdict(prev.status)) {
    return fail(`node ${id} already has the verdict "${prev.status}" — reopen it with a reason before testing it again`);
  }
  return patchNode(projectRoot, id, { status: "testing" }, at);
}

/** Store the scheduler's priority for a node (stage 2 computes it; the store
 * only persists it so the round summary can show the ranking actually used). */
export function setScore(projectRoot: string, id: string, score: number, at = nowIso()): Result<Hypothesis> {
  if (!Number.isFinite(score)) return fail("score must be a finite number");
  return patchNode(projectRoot, id, { score }, at);
}

/** Record that a loop round ran. Used for `roundIntroduced` and for the
 * "has this hypothesis sat unexamined for many rounds" signal. */
export function recordRound(projectRoot: string, round: number, at = nowIso()): Result<number> {
  if (!Number.isInteger(round) || round < 0) return fail("round must be a non-negative integer");
  if (!appendEvent(projectRoot, { type: "round_recorded", at, round })) {
    return fail("the round could not be recorded — the tree is unchanged");
  }
  return ok(round);
}

/** Every status a node may be moved to from its current one, for UI
 * completion and error messages. */
export function allowedTransitions(status: HypothesisStatus): HypothesisStatus[] {
  return (["pending", "testing", "confirmed", "rejected", "blocked"] as HypothesisStatus[]).filter((s) => s !== status);
}

export { OPEN_STATUSES, VERDICT_STATUSES, validateDescription };
