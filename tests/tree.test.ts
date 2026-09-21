// pi-audit-hypothesis-tree — tests/tree.test.ts
//
// Pins the tree CRUD and its invariants: a node is a falsifiable assertion,
// depth is derived, a duplicate is refused by name, and a VERDICT requires
// evidence.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import {
  addEvidence,
  addNode,
  children,
  confirmedNodes,
  createTree,
  deriveDepth,
  findByDescription,
  getNode,
  markTesting,
  maxDepth,
  nextNodeId,
  openNodes,
  pathToRoot,
  recordRound,
  rejectedNodes,
  setScore,
  setStatus,
  subtree,
  summarize,
} from "../extensions/hypothesis-tree/tree.ts";
import { validateDescription, validateEvidence } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-tree-"));
}

const ROOT = "the login handler accepts a JWT without verifying its signature";

function seeded(): { cwd: string; rootId: string } {
  const cwd = tmpProject();
  const created = createTree(cwd, ROOT, { category: "auth-bypass" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return { cwd, rootId: created.ok ? created.value.root.id : "" };
}

// -----------------------------------------------------------------
// validateDescription — the whole point of the extension
// -----------------------------------------------------------------

test("a task-shaped description is refused with an actionable message", () => {
  for (const task of [
    "check whether the login handler validates the JWT signature",
    "review the authentication middleware",
    "investigate the deserialization path in the queue consumer",
    "TODO: look at the file upload handler",
    "1. audit the admin routes",
  ]) {
    const result = validateDescription(task);
    assert.equal(result.ok, false, `should refuse: ${task}`);
    assert.ok(
      result.errors.some((e) => e.includes("TASK")),
      `the message must name the problem: ${result.errors.join("; ")}`,
    );
  }
});

test("a falsifiable assertion is accepted", () => {
  for (const assertion of [
    ROOT,
    "the /api/v1/export endpoint does not check object ownership before returning the record",
    "the queue consumer deserializes the message body without a type allowlist",
    "session cookies are issued without the Secure flag",
    "the password reset token is compared with a non-constant-time equality check",
  ]) {
    assert.equal(validateDescription(assertion).ok, true, `should accept: ${assertion}`);
  }
});

test("a bare noun phrase is refused (no truth value)", () => {
  const result = validateDescription("the login endpoint and its middleware chain");
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("truth value")));
});

test("a noun phrase with a plural noun is still refused (no loose \\w+s rule)", () => {
  // The regression this guards: a generic `\w+s\b` hint accepted any word
  // ending in "s" — including "its" — so a bare noun phrase looked like an
  // assertion and the check never fired.
  for (const phrase of [
    "the admin routes and their middleware",
    "the login endpoint and its middleware chain",
    "the upload handler and the storage adapter",
  ]) {
    assert.equal(validateDescription(phrase).ok, false, `should refuse: ${phrase}`);
  }
});

test("the verb-form hint is a superset check: a borderline noun phrase may pass", () => {
  // Documented weakness, asserted so it is not mistaken for a bug later.
  // "call" is both a verb and a noun, so a noun phrase built on it slips
  // through the third hint. Tightening that would start rejecting genuine
  // assertions, which is the worse error — the check exists to catch the
  // obvious todo-shaped entry, not to grade English.
  assert.equal(validateDescription("all the deserialization call sites in the queue consumer").ok, true);
});

test("a too-short description is refused", () => {
  assert.equal(validateDescription("it is broken").ok, false);
  assert.equal(validateDescription("").ok, false);
});

// -----------------------------------------------------------------
// createTree
// -----------------------------------------------------------------

test("createTree makes the objective the root assertion", () => {
  const { cwd, rootId } = seeded();
  const snap = load(cwd).snapshot;
  assert.equal(snap.rootId, rootId);
  assert.equal(snap.nodes.length, 1);
  const root = getNode(snap, rootId)!;
  assert.equal(root.parentId, null);
  assert.equal(root.depth, 0);
  assert.equal(root.status, "pending");
  assert.equal(root.description, ROOT);
  assert.equal(root.category, "auth-bypass");
});

test("createTree refuses a second tree and names the existing root", () => {
  const { cwd, rootId } = seeded();
  const again = createTree(cwd, "another root assertion that is long enough");
  assert.equal(again.ok, false);
  if (!again.ok) {
    assert.ok(again.errors[0]!.includes(rootId), "the message names the existing root so the user can add to it");
  }
});

test("createTree refuses a task-shaped objective", () => {
  const cwd = tmpProject();
  const result = createTree(cwd, "audit the project for security problems");
  assert.equal(result.ok, false);
  assert.equal(load(cwd).snapshot.rootId, "", "nothing is written when the root is refused");
});

// -----------------------------------------------------------------
// addNode
// -----------------------------------------------------------------

test("addNode derives depth from the parent chain", () => {
  const { cwd, rootId } = seeded();
  const child = addNode(cwd, { description: "the signature is checked but the algorithm is taken from the token header", category: "auth-bypass", parentId: rootId });
  assert.equal(child.ok, true);
  if (!child.ok) return;
  assert.equal(child.value.node.depth, 1);
  assert.equal(child.value.node.parentId, rootId);

  const grandchild = addNode(cwd, { description: "the alg=none case reaches the verifier and is accepted", category: "auth-bypass", parentId: child.value.node.id });
  assert.equal(grandchild.ok, true);
  if (!grandchild.ok) return;
  assert.equal(grandchild.value.node.depth, 2);
  assert.equal(maxDepth(load(cwd).snapshot), 2);
});

test("addNode attaches to the root when parentId is omitted", () => {
  const { cwd, rootId } = seeded();
  const result = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.node.parentId, rootId);
});

test("addNode refuses an unknown parent and names it", () => {
  const { cwd } = seeded();
  const result = addNode(cwd, { description: "the audience claim is not validated at all", category: "auth-bypass", parentId: "H-9999" });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors[0]!.includes("H-9999"));
});

test("addNode refuses a duplicate assertion and names the existing node", () => {
  const { cwd } = seeded();
  const first = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(first.ok, true);
  if (!first.ok) return;
  const again = addNode(cwd, { description: "The token expiry is never compared against the current time.", category: "auth-bypass" });
  assert.equal(again.ok, false);
  if (!again.ok) {
    assert.ok(again.errors[0]!.includes(first.value.node.id), "the existing id is named so the caller links instead of duplicating");
  }
  assert.equal(load(cwd).snapshot.nodes.length, 2, "the duplicate was not written");
});

test("addNode refuses an unknown category so the share cap cannot be evaded", () => {
  const { cwd } = seeded();
  const result = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "authBypass" });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors[0]!.includes("unknown category"));
});

test("addNode refuses a node created with a verdict but no evidence", () => {
  const { cwd } = seeded();
  const result = addNode(cwd, {
    description: "the token expiry is never compared against the current time",
    category: "auth-bypass",
    status: "confirmed",
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors.some((e) => e.includes("evidence")));
});

test("addNode refuses a blocked node with no reason", () => {
  const { cwd } = seeded();
  const result = addNode(cwd, {
    description: "the token expiry is never compared against the current time",
    category: "auth-bypass",
    status: "blocked",
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors.some((e) => e.includes("statusReason")));
});

test("addNode refuses a task-shaped child", () => {
  const { cwd } = seeded();
  const result = addNode(cwd, { description: "check the expiry comparison", category: "auth-bypass" });
  assert.equal(result.ok, false);
});

test("addNode carries spawnedFrom and roundIntroduced", () => {
  const { cwd } = seeded();
  const result = addNode(cwd, {
    description: "the missing signature check is shared with the refresh handler",
    category: "auth-bypass",
    spawnedFrom: ["H-0002", "H-0003"],
    roundIntroduced: 4,
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.deepEqual(result.value.node.spawnedFrom, ["H-0002", "H-0003"]);
  assert.equal(result.value.node.roundIntroduced, 4);
});

// -----------------------------------------------------------------
// ids
// -----------------------------------------------------------------

test("nextNodeId never reuses an id", () => {
  const { cwd } = seeded();
  const snap = load(cwd).snapshot;
  assert.equal(nextNodeId(snap), "H-0002");
  addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(nextNodeId(load(cwd).snapshot), "H-0003");
});

test("ids stay unique after a compaction snapshot", () => {
  const { cwd } = seeded();
  addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  // Compaction replaces the folded node list; maxNodeSeq must survive it.
  const { compact } = require("../extensions/hypothesis-tree/store.ts") as typeof import("../extensions/hypothesis-tree/store.ts");
  compact(cwd);
  assert.equal(nextNodeId(load(cwd).snapshot), "H-0003");
});

// -----------------------------------------------------------------
// reads
// -----------------------------------------------------------------

test("children, subtree and pathToRoot agree on the shape", () => {
  const { cwd, rootId } = seeded();
  const a = addNode(cwd, { description: "the signature is checked but the algorithm is taken from the token header", category: "auth-bypass" });
  assert.equal(a.ok, true);
  if (!a.ok) return;
  const b = addNode(cwd, { description: "the alg=none case reaches the verifier and is accepted", category: "auth-bypass", parentId: a.value.node.id });
  assert.equal(b.ok, true);
  if (!b.ok) return;
  const c = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(c.ok, true);
  if (!c.ok) return;

  const snap = load(cwd).snapshot;
  assert.deepEqual(children(snap, rootId).map((n) => n.id), [a.value.node.id, c.value.node.id]);
  assert.deepEqual(subtree(snap, rootId).map((n) => n.id), [rootId, a.value.node.id, b.value.node.id, c.value.node.id]);
  assert.deepEqual(subtree(snap, a.value.node.id).map((n) => n.id), [a.value.node.id, b.value.node.id]);
  assert.deepEqual(pathToRoot(snap, b.value.node.id).map((n) => n.id), [rootId, a.value.node.id, b.value.node.id]);
});

test("pathToRoot on an unknown id is empty, not a throw", () => {
  const { cwd } = seeded();
  assert.deepEqual(pathToRoot(load(cwd).snapshot, "H-9999"), []);
});

test("deriveDepth returns null for a broken chain instead of guessing", () => {
  const { cwd } = seeded();
  assert.equal(deriveDepth(load(cwd).snapshot, "H-9999"), null);
});

test("openNodes and confirmedNodes partition by verdict", () => {
  const { cwd, rootId } = seeded();
  const a = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(a.ok, true);
  if (!a.ok) return;
  setStatus(cwd, a.value.node.id, "rejected", { evidence: [{ kind: "code-slice", at: "", detail: "jwt.ts:88 compares exp" }] });

  const snap = load(cwd).snapshot;
  assert.deepEqual(openNodes(snap).map((n) => n.id), [rootId]);
  assert.deepEqual(confirmedNodes(snap), []);
  assert.deepEqual(rejectedNodes(snap).map((n) => n.id), [a.value.node.id]);
});

test("findByDescription finds a node by normalized assertion", () => {
  const { cwd } = seeded();
  assert.equal(findByDescription(load(cwd).snapshot, ROOT.toUpperCase())?.id, "H-0001");
  assert.equal(findByDescription(load(cwd).snapshot, "nothing like this is in the tree at all"), undefined);
});

// -----------------------------------------------------------------
// evidence
// -----------------------------------------------------------------

test("addEvidence appends and preserves collection order", () => {
  const { cwd, rootId } = seeded();
  addEvidence(cwd, rootId, { kind: "file", at: "", location: { file: "src/auth/jwt.ts", line: 41 }, detail: "const payload = decode(token)" });
  const result = addEvidence(cwd, rootId, { kind: "code-slice", at: "", detail: "// no verify() call on this path" });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.evidence.length, 2);
  assert.equal(result.value.evidence[0]!.kind, "file");
  assert.equal(result.value.evidence[1]!.kind, "code-slice");
  assert.ok(result.value.evidence[0]!.at, "an evidence entry is timestamped");
});

test("addEvidence refuses an empty detail — a location alone proves nothing", () => {
  const { cwd, rootId } = seeded();
  const result = addEvidence(cwd, rootId, { kind: "code-slice", at: "", detail: "" });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors.some((e) => e.includes("detail")));
});

test("addEvidence refuses command-output without the command", () => {
  const { cwd, rootId } = seeded();
  const result = addEvidence(cwd, rootId, { kind: "command-output", at: "", detail: "200 OK" });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors.some((e) => e.includes("command")));
});

test("validateEvidence requires a location for file evidence", () => {
  assert.equal(validateEvidence({ kind: "file", detail: "x" }).ok, false);
  assert.equal(validateEvidence({ kind: "file", detail: "x", location: { file: "a.ts", line: 1 } }).ok, true);
});

test("addEvidence on an unknown node is refused", () => {
  const { cwd } = seeded();
  assert.equal(addEvidence(cwd, "H-9999", { kind: "reasoning", at: "", detail: "x" }).ok, false);
});

// -----------------------------------------------------------------
// setStatus — the verdict gate
// -----------------------------------------------------------------

test("a verdict with no evidence anywhere is refused, with the reason stated", () => {
  const { cwd, rootId } = seeded();
  const result = setStatus(cwd, rootId, "confirmed");
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.ok(result.errors.some((e) => e.includes("evidence")), "the message must say evidence is missing");
    assert.ok(result.errors.some((e) => e.includes("opinion")), "and why that matters");
  }
  assert.equal(getNode(load(cwd).snapshot, rootId)!.status, "pending", "nothing changed");
});

test("a verdict is accepted when evidence already sits on the node", () => {
  const { cwd, rootId } = seeded();
  addEvidence(cwd, rootId, { kind: "code-slice", at: "", detail: "no verify() on this path" });
  const result = setStatus(cwd, rootId, "confirmed");
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.status, "confirmed");
});

test("a verdict is accepted when evidence is supplied in the same call", () => {
  const { cwd, rootId } = seeded();
  const result = setStatus(cwd, rootId, "rejected", {
    evidence: [{ kind: "code-slice", at: "", detail: "jwt.ts:88 calls verify(token, secret)" }],
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.status, "rejected");
  assert.equal(result.value.evidence.length, 1);
});

test("blocked requires a reason", () => {
  const { cwd, rootId } = seeded();
  assert.equal(setStatus(cwd, rootId, "blocked").ok, false);
  assert.equal(setStatus(cwd, rootId, "blocked", { reason: "needs a running instance to reproduce" }).ok, true);
});

test("reopening a verdict requires a reason", () => {
  const { cwd, rootId } = seeded();
  setStatus(cwd, rootId, "rejected", { evidence: [{ kind: "reasoning", at: "", detail: "the guard exists" }] });
  const withoutReason = setStatus(cwd, rootId, "pending");
  assert.equal(withoutReason.ok, false);
  if (!withoutReason.ok) assert.ok(withoutReason.errors.some((e) => e.includes("reason")));

  const withReason = setStatus(cwd, rootId, "pending", { reason: "the guard is bypassable via the alg header" });
  assert.equal(withReason.ok, true);
  if (withReason.ok) assert.equal(withReason.value.status, "pending");
});

test("a no-op status change is refused", () => {
  const { cwd, rootId } = seeded();
  const result = setStatus(cwd, rootId, "pending");
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors[0]!.includes("already"));
});

test("setStatus on an unknown node is refused", () => {
  const { cwd } = seeded();
  assert.equal(setStatus(cwd, "H-9999", "pending").ok, false);
});

test("markTesting refuses a node that already has a verdict", () => {
  const { cwd, rootId } = seeded();
  setStatus(cwd, rootId, "rejected", { evidence: [{ kind: "reasoning", at: "", detail: "guard exists" }] });
  const result = markTesting(cwd, rootId);
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors.some((e) => e.includes("reopen")));
});

// -----------------------------------------------------------------
// score / rounds / summary
// -----------------------------------------------------------------

test("setScore persists a finite score and refuses a non-finite one", () => {
  const { cwd, rootId } = seeded();
  assert.equal(setScore(cwd, rootId, 12.5).ok, true);
  assert.equal(getNode(load(cwd).snapshot, rootId)!.score, 12.5);
  assert.equal(setScore(cwd, rootId, Number.NaN).ok, false);
});

test("recordRound is monotonic and drives roundIntroduced", () => {
  const { cwd } = seeded();
  assert.equal(recordRound(cwd, 3).ok, true);
  const added = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(added.ok, true);
  if (added.ok) assert.equal(added.value.node.roundIntroduced, 3);
  assert.equal(recordRound(cwd, -1).ok, false);
  assert.equal(recordRound(cwd, 1.5).ok, false);
});

test("summarize reports counts, categories and depth", () => {
  const { cwd, rootId } = seeded();
  const a = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(a.ok, true);
  if (!a.ok) return;
  addNode(cwd, { description: "the export endpoint returns records the caller does not own", category: "idor" });
  setStatus(cwd, a.value.node.id, "rejected", { evidence: [{ kind: "code-slice", at: "", detail: "exp is compared" }] });

  const s = summarize(load(cwd).snapshot);
  assert.equal(s.nodes, 3);
  assert.equal(s.byStatus.rejected, 1);
  assert.equal(s.byStatus.pending, 2);
  assert.equal(s.byCategory["auth-bypass"], 2);
  assert.equal(s.byCategory["idor"], 1);
  assert.equal(s.maxDepth, 1);
  assert.ok(s.treeId.startsWith("T-"));
  assert.equal(s.objective, ROOT);
});

test("the whole tree survives a reload (durability, not just in-memory state)", () => {
  const { cwd, rootId } = seeded();
  const a = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(a.ok, true);
  if (!a.ok) return;
  addEvidence(cwd, a.value.node.id, { kind: "file", at: "", location: { file: "src/auth/jwt.ts", line: 88 }, detail: "exp is decoded but never compared" });
  setStatus(cwd, a.value.node.id, "confirmed");

  // A fresh load, as a new process would do.
  const snap = load(cwd).snapshot;
  const node = getNode(snap, a.value.node.id)!;
  assert.equal(node.status, "confirmed");
  assert.equal(node.depth, 1);
  assert.equal(node.parentId, rootId);
  assert.equal(node.evidence.length, 1);
  assert.equal(node.evidence[0]!.location!.file, "src/auth/jwt.ts");
  assert.equal(node.evidence[0]!.location!.line, 88);
});
