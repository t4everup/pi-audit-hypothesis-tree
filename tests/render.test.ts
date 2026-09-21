// pi-audit-hypothesis-tree — tests/render.test.ts
//
// Pins the human review surface: the tree view must make depth (rabbit-holing)
// and the rejection count (is anything being falsified?) visible.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addEvidence, addNode, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { clip, renderSummary, renderTree, statusGlyph, toJson } from "../extensions/hypothesis-tree/render.ts";
import { parseArgs } from "../extensions/hypothesis-tree/index.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-render-"));
}

const ROOT = "the login handler accepts a JWT without verifying its signature";

function seeded(): string {
  const cwd = tmpProject();
  const created = createTree(cwd, ROOT, { category: "auth-bypass" });
  assert.equal(created.ok, true);
  return cwd;
}

// -----------------------------------------------------------------
// glyphs and clipping
// -----------------------------------------------------------------

test("every status has a distinct ASCII glyph", () => {
  const glyphs = (["pending", "testing", "confirmed", "rejected", "blocked"] as const).map(statusGlyph);
  assert.equal(new Set(glyphs).size, glyphs.length, "glyphs must be distinguishable at a glance");
  for (const g of glyphs) assert.ok(/^[\x20-\x7e]$/.test(g), "ASCII only: the output lands in terminals and logs");
});

test("clip cuts on a word boundary where it can and marks the cut", () => {
  assert.equal(clip("short", 20), "short");
  const clipped = clip("the login handler accepts a token without verifying the signature", 30);
  assert.ok(clipped.length <= 30);
  assert.ok(clipped.endsWith("…"));
  assert.ok(!clipped.includes("  "), "no double space from the cut");
});

// -----------------------------------------------------------------
// renderTree
// -----------------------------------------------------------------

test("an empty project says so instead of rendering nothing", () => {
  const lines = renderTree(load(tmpProject()).snapshot);
  assert.equal(lines.length, 1);
  assert.match(lines[0]!, /no hypothesis tree/i);
});

test("the tree renders root first, children indented, depth on every line", () => {
  const cwd = seeded();
  const a = addNode(cwd, { description: "the signature is checked but the algorithm is taken from the token header", category: "auth-bypass" });
  assert.equal(a.ok, true);
  if (!a.ok) return;
  const b = addNode(cwd, { description: "the alg=none case reaches the verifier and is accepted", category: "auth-bypass", parentId: a.value.node.id });
  assert.equal(b.ok, true);
  if (!b.ok) return;

  const lines = renderTree(load(cwd).snapshot);
  assert.equal(lines.length, 3);
  assert.match(lines[0]!, /^\. H-0001 \[pending  \] auth-bypass d0 e0/);
  // A child hangs off the root with a branch marker; a grandchild nests under
  // its parent's marker. The markers are what make depth readable at a glance.
  assert.match(lines[1]!, /^`- \. H-0002 \[/, lines[1]);
  assert.match(lines[2]!, /^   `- \. H-0003 \[/, lines[2]);
  // Depth is printed so a deep ladder is visible without counting indents.
  assert.match(lines[2]!, / d2 /);
});

test("a sibling keeps the vertical guide and the last child closes it", () => {
  const cwd = seeded();
  const a = addNode(cwd, { description: "the signature is checked but the algorithm is taken from the token header", category: "auth-bypass" });
  assert.equal(a.ok, true);
  if (!a.ok) return;
  const b = addNode(cwd, { description: "the alg=none case reaches the verifier and is accepted", category: "auth-bypass", parentId: a.value.node.id });
  assert.equal(b.ok, true);
  if (!b.ok) return;
  const c = addNode(cwd, { description: "the token expiry is never compared against the current time", category: "auth-bypass" });
  assert.equal(c.ok, true);
  if (!c.ok) return;

  const lines = renderTree(load(cwd).snapshot);
  assert.equal(lines.length, 4);
  assert.match(lines[1]!, /^\|- \. H-0002/, "a non-last child keeps the guide open");
  assert.match(lines[2]!, /^\|  `- \. H-0003/, "a grandchild hangs off the open guide");
  assert.match(lines[3]!, /^`- \. H-0004/, "the last child closes the guide");
});

test("the evidence count is on every line — a verdict with one reasoning entry looks weak", () => {
  const cwd = seeded();
  addEvidence(cwd, "H-0001", { kind: "reasoning", at: "", detail: "looks wrong" });
  const lines = renderTree(load(cwd).snapshot);
  assert.match(lines[0]!, /e1/);
});

test("--evidence expands evidence lines under the node", () => {
  const cwd = seeded();
  addEvidence(cwd, "H-0001", { kind: "file", at: "", location: { file: "src/auth/jwt.ts", line: 41 }, detail: "decode(token)" });
  const lines = renderTree(load(cwd).snapshot, { showEvidence: true });
  assert.ok(lines.some((l) => l.includes("src/auth/jwt.ts:41")), lines.join("\n"));
  assert.ok(lines.some((l) => l.includes("decode(token)")));
});

test("a blocked node shows its reason on the line", () => {
  const cwd = seeded();
  setStatus(cwd, "H-0001", "blocked", { reason: "needs a running instance to reproduce" });
  const lines = renderTree(load(cwd).snapshot);
  assert.match(lines[0]!, /blocked: needs a running instance/);
});

test("orphaned nodes are reported, never silently dropped or infinite-looped", () => {
  const cwd = seeded();
  // Hand-craft a log with a node whose parent does not exist.
  const log = path.join(cwd, ".pi-hypothesis", "tree.jsonl");
  fs.appendFileSync(
    log,
    JSON.stringify({
      type: "node_added",
      at: "2026-01-01T00:00:00.000Z",
      node: {
        id: "H-0002",
        parentId: "H-9999",
        description: "an orphaned assertion that is long enough to pass validation",
        category: "other",
        status: "pending",
        evidence: [],
        depth: 1,
        createdAt: "2026-01-01T00:00:00.000Z",
        lastTouchedAt: "2026-01-01T00:00:00.000Z",
        score: 0,
        spawnedFrom: [],
        roundIntroduced: 0,
      },
    }) + "\n",
    "utf-8",
  );
  const lines = renderTree(load(cwd).snapshot);
  assert.ok(lines.some((l) => l.includes("not reachable from the root")), lines.join("\n"));
  assert.ok(lines.some((l) => l.includes("H-0002")), "the orphan is still shown");
});

test("maxNodes bounds the render and says how much was withheld", () => {
  const cwd = seeded();
  for (let i = 0; i < 12; i++) {
    addNode(cwd, { description: `assertion number ${i} about the token handling path that is long enough`, category: "auth-bypass" });
  }
  const lines = renderTree(load(cwd).snapshot, { maxNodes: 5 });
  assert.ok(lines.some((l) => l.includes("not shown")), lines.join("\n"));
  assert.ok(lines.length < 20);
});

// -----------------------------------------------------------------
// renderSummary
// -----------------------------------------------------------------

test("the summary reports every status and the categories", () => {
  const cwd = seeded();
  const a = addNode(cwd, { description: "the export endpoint returns records the caller does not own", category: "idor" });
  assert.equal(a.ok, true);
  if (!a.ok) return;
  setStatus(cwd, a.value.node.id, "confirmed", { evidence: [{ kind: "code-slice", at: "", detail: "no owner check" }] });

  const text = renderSummary(load(cwd).snapshot).join("\n");
  assert.match(text, /Hypothesis tree T-/);
  assert.match(text, /2 node\(s\), depth 1/);
  assert.match(text, /confirmed\s+1/);
  assert.match(text, /auth-bypass/);
  assert.match(text, /idor/);
  assert.match(text, /\(findings\)/);
  assert.match(text, /\(pruned branches\)/);
});

test("the summary nags when nothing has been rejected", () => {
  const cwd = seeded();
  for (let i = 0; i < 4; i++) {
    addNode(cwd, { description: `assertion number ${i} about the token handling path that is long enough`, category: "auth-bypass" });
  }
  const text = renderSummary(load(cwd).snapshot).join("\n");
  assert.match(text, /nothing has been rejected yet/);
});

test("the nag disappears once something is rejected", () => {
  const cwd = seeded();
  for (let i = 0; i < 3; i++) {
    addNode(cwd, { description: `assertion number ${i} about the token handling path that is long enough`, category: "auth-bypass" });
  }
  setStatus(cwd, "H-0001", "rejected", { evidence: [{ kind: "code-slice", at: "", detail: "verify() is called" }] });
  const text = renderSummary(load(cwd).snapshot).join("\n");
  assert.doesNotMatch(text, /nothing has been rejected yet/);
});

test("the summary reports torn lines so a crash is visible", () => {
  const cwd = seeded();
  fs.appendFileSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), "garbage-with-no-newline", "utf-8");
  const text = renderSummary(load(cwd).snapshot).join("\n");
  assert.match(text, /torn line/);
  assert.match(text, /repair/);
});

test("an empty project gets an actionable line, not an empty string", () => {
  const lines = renderSummary(load(tmpProject()).snapshot);
  assert.equal(lines.length, 1);
  assert.match(lines[0]!, /\/hypothesis new/);
});

// -----------------------------------------------------------------
// toJson
// -----------------------------------------------------------------

test("toJson is valid JSON containing every node and the tree metadata", () => {
  const cwd = seeded();
  const parsed = JSON.parse(toJson(load(cwd).snapshot));
  assert.equal(parsed.rootId, "H-0001");
  assert.equal(parsed.nodes.length, 1);
  assert.equal(parsed.objective, ROOT);
  assert.ok(parsed.treeId.startsWith("T-"));
  assert.equal(typeof parsed.rounds, "number");
});

// -----------------------------------------------------------------
// parseArgs — the command grammar must survive assertions full of punctuation
// -----------------------------------------------------------------

test("parseArgs reads quoted positional text and key=value flags", () => {
  const { positional, flags } = parseArgs('add "the alg=none case is accepted by the verifier" parent=H-0002 category=auth-bypass');
  assert.deepEqual(positional, ["add", "the alg=none case is accepted by the verifier"]);
  assert.equal(flags.parent, "H-0002");
  assert.equal(flags.category, "auth-bypass");
});

test("parseArgs keeps an assertion's own punctuation intact", () => {
  const assertion = 'the parser trusts `Content-Length: -1` and reads past the buffer (see src/http.ts:88)';
  const { positional } = parseArgs(`add "${assertion}"`);
  assert.equal(positional[1], assertion);
});

test("parseArgs handles a quoted flag value containing spaces and equals signs", () => {
  const { flags } = parseArgs('evidence H-0001 command-output "200 OK" command="curl -sS -X POST http://x/y?a=1"');
  assert.equal(flags.command, "curl -sS -X POST http://x/y?a=1");
});

test("parseArgs handles single quotes and escaped quotes", () => {
  assert.deepEqual(parseArgs("add 'a single-quoted assertion'").positional, ["add", "a single-quoted assertion"]);
  assert.deepEqual(parseArgs('add "say \\"hi\\" now"').positional, ["add", 'say "hi" now']);
});

test("parseArgs on empty input yields nothing rather than throwing", () => {
  assert.deepEqual(parseArgs(""), { positional: [], flags: {} });
});
