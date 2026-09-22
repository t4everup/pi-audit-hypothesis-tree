// pi-audit-hypothesis-tree — tests/contradictions.test.ts
//
// Pins the contradiction checks: two of the fields the report rests on are typed
// in by the model, and BOTH are contract gates. `severity` is what
// `/goal severity=high` counts; `preAuth` is what `requirePreAuth=1` counts.
// Those two words are the goal, AND the values the model fills in.
//
// Every check is a heuristic over free text, so every one can be wrong. The
// wording is therefore always a QUESTION and nothing is ever blocked — a refusal
// that is wrong teaches the model to write around the check instead of examining
// the claim.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { renderReport } from "../extensions/hypothesis-tree/report.ts";
import { contradictionsOf, renderContradictions } from "../extensions/hypothesis-tree/contradictions.ts";
import type { AttackVector, Hypothesis } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-contra-"));
}

function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

const V = (over: Partial<AttackVector> = {}): AttackVector => ({
  entrypoint: "POST /api/import",
  technique: "XXE to SSRF",
  path: [{ detail: "the parser resolves the entity" }],
  ...over,
});

const node = (over: Partial<Hypothesis>): Pick<Hypothesis, "severity" | "category" | "attackVector"> => ({
  severity: "high",
  category: "ssrf",
  attackVector: V(),
  ...over,
});

// -----------------------------------------------------------------
// preAuth vs the surface it names
// -----------------------------------------------------------------

test("preAuth TRUE on a surface that names an admin console is questioned", () => {
  const found = contradictionsOf(node({ attackVector: V({ preAuth: true, entrypoint: "GET /admin/console/export" }) }));
  assert.equal(found.length, 1);
  assert.equal(found[0]!.field, "preAuth");
  assert.match(found[0]!.message, /preAuth is TRUE/);
  assert.match(found[0]!.message, /"admin"/);
  // A QUESTION: it names the alternative explanation rather than asserting one.
  assert.match(found[0]!.message, /Is an unauthenticated request really reaching it/);
  assert.match(found[0]!.message, /does something in front of it .* reject it first/);
});

test("the authenticated-surface words are matched in the technique too", () => {
  const found = contradictionsOf(node({ attackVector: V({ preAuth: true, technique: "reuse the logged-in session cookie" }) }));
  assert.equal(found.length, 1);
  assert.match(found[0]!.message, /logged-in|session/);
});

test("preAuth TRUE on an ordinary pre-auth path is NOT questioned", () => {
  const found = contradictionsOf(node({ attackVector: V({ preAuth: true, entrypoint: "POST /api/latest/gorgone/command" }) }));
  assert.deepEqual(found, []);
});

test("preAuth FALSE is never questioned — it claims LESS, not more", () => {
  const found = contradictionsOf(node({ attackVector: V({ preAuth: false, entrypoint: "GET /admin/console/export" }) }));
  assert.deepEqual(found, []);
});

test("an unassessed preAuth is never questioned", () => {
  const found = contradictionsOf(node({ attackVector: V({ entrypoint: "GET /admin/console/export" }) }));
  assert.deepEqual(found, []);
});

// -----------------------------------------------------------------
// severity vs class
// -----------------------------------------------------------------

test("a chain component rated CRITICAL is questioned", () => {
  const found = contradictionsOf(node({ category: "open-redirect", severity: "critical", attackVector: V() }));
  assert.equal(found.length, 1);
  assert.equal(found[0]!.field, "severity");
  assert.match(found[0]!.message, /a open-redirect at critical/);
  // It says WHEN it is right, not just that it might be wrong.
  assert.match(found[0]!.message, /right when it IS the whole finding/);
  assert.match(found[0]!.message, /record what it chains into as a gate/);
});

test("the same class at MEDIUM is not questioned", () => {
  assert.deepEqual(contradictionsOf(node({ category: "open-redirect", severity: "medium", attackVector: V() })), []);
});

test("a class that is usually the finding itself is never questioned", () => {
  for (const category of ["deserialization", "command-injection", "sqli", "auth-bypass", "ssrf"] as const) {
    assert.deepEqual(
      contradictionsOf(node({ category, severity: "critical", attackVector: V() })),
      [],
      `${category} at critical must not be second-guessed`,
    );
  }
});

test("both checks can fire at once", () => {
  const found = contradictionsOf(
    node({ category: "csrf", severity: "high", attackVector: V({ preAuth: true, entrypoint: "POST /admin/settings" }) }),
  );
  assert.equal(found.length, 2);
  assert.deepEqual(found.map((c) => c.field).sort(), ["preAuth", "severity"]);
});

// -----------------------------------------------------------------
// Nothing is blocked
// -----------------------------------------------------------------

test("renderContradictions is EMPTY when there is nothing to say", () => {
  assert.equal(renderContradictions(node({})), "");
});

test("the wording is a question and says so", () => {
  const text = renderContradictions(node({ attackVector: V({ preAuth: true, entrypoint: "GET /admin/x" }) }));
  assert.match(text, /a question, not a verdict/);
  assert.match(text, /nothing was blocked/);
  // No imperative: a check that TELLS the model what to conclude is a check that
  // manufactures the conclusion.
  assert.doesNotMatch(text, /\b(must|should|you need to|change this to)\b/i);
});

// -----------------------------------------------------------------
// In the report
// -----------------------------------------------------------------

test("the report shows the contradiction under the finding", () => {
  const cwd = seeded();
  const result = addNode(cwd, {
    description: "the admin console export is reachable without authentication and streams any file",
    category: "open-redirect",
    attackVector: V({ preAuth: true, entrypoint: "GET /admin/console/export" }),
  });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  setStatus(cwd, result.ok ? result.value.node.id : "?", "confirmed", {
    severity: "critical",
    evidence: [{ kind: "code-slice", at: "", location: { file: "src/x.ts", line: 1 }, detail: "x" }],
  });

  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.match(text, /\*\*可能的矛盾（是问题，不是判定）：\*\*/);
  assert.match(text, /preAuth is TRUE/);
  assert.match(text, /record what it chains into as a gate/);
});

test("a finding with no contradiction carries no such block", () => {
  const cwd = seeded();
  const result = addNode(cwd, {
    description: "the gorgone command endpoint forwards without a role check and runs as root",
    category: "auth-bypass",
    attackVector: V({ preAuth: true, entrypoint: "POST /api/latest/gorgone/command" }),
  });
  setStatus(cwd, result.ok ? result.value.node.id : "?", "confirmed", {
    severity: "high",
    evidence: [{ kind: "code-slice", at: "", location: { file: "src/x.ts", line: 1 }, detail: "x" }],
  });
  const text = renderReport(load(cwd).snapshot, null, { language: "zh" });
  assert.doesNotMatch(text, /可能的矛盾/);
});
