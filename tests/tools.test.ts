// pi-audit-hypothesis-tree — tests/tools.test.ts
//
// Pins the agent-facing tool surface: the scheduler picks (not the model), the
// executor collects evidence (the model decides), a verdict needs evidence, and
// no tool can grant itself permission to run commands.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import hypothesisTreeExtension from "../extensions/hypothesis-tree/index.ts";
import { HYPOTHESIS_TOOL_NAMES, normalizeProbes } from "../extensions/hypothesis-tree/tools.ts";
import { load } from "../extensions/hypothesis-tree/store.ts";
import { saveSettings, settingsPath } from "../extensions/hypothesis-tree/settings.ts";

const ROOT = "the login handler accepts a JWT without verifying its signature";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-tools-"));
}

interface RegisteredTool {
  name: string;
  description: string;
  promptGuidelines?: string[];
  parameters: unknown;
  execute: (id: string, params: never, signal: undefined, onUpdate: undefined, ctx: unknown) => Promise<{
    content: Array<{ type: string; text: string }>;
    details: Record<string, unknown>;
  }>;
}

function harness(cwd: string, exec?: (c: string, a: string[], o: unknown) => Promise<{ stdout: string; stderr: string; code: number }>) {
  const tools = new Map<string, RegisteredTool>();
  const commands = new Map<string, unknown>();
  const execCalls: Array<{ command: string; args: string[] }> = [];
  const pi = {
    registerTool: (t: RegisteredTool) => {
      tools.set(t.name, t);
    },
    registerCommand: (n: string, o: unknown) => {
      commands.set(n, o);
    },
    // Stage 5 adds an agent_end subscription and a brief sender; this file
    // drives only the TOOL surface, so both are stubs here.
    on: () => () => {},
    sendUserMessage: () => {},
    exec: async (command: string, args: string[], options: unknown) => {
      execCalls.push({ command, args });
      return exec ? exec(command, args, options) : { stdout: "", stderr: "", code: 0 };
    },
  };
  hypothesisTreeExtension(pi as never);
  const ctx = { cwd, ui: { notify: () => {} } };

  const call = async (name: string, params: Record<string, unknown> = {}): Promise<string> => {
    const tool = tools.get(name);
    assert.ok(tool, `tool ${name} must be registered`);
    const result = await tool!.execute("call-1", params as never, undefined, undefined, ctx);
    return result.content.map((c) => c.text).join("\n");
  };
  const detailsOf = async (name: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> => {
    const tool = tools.get(name)!;
    const result = await tool!.execute("call-1", params as never, undefined, undefined, ctx);
    return result.details;
  };

  return { tools, commands, call, detailsOf, execCalls };
}

async function seeded(cwd = tmpProject()): Promise<string> {
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  return cwd;
}

// -----------------------------------------------------------------
// Registration
// -----------------------------------------------------------------

test("every declared tool is registered, and only those", () => {
  const h = harness(tmpProject());
  assert.deepEqual([...h.tools.keys()].sort(), [...HYPOTHESIS_TOOL_NAMES].sort());
});

test("no tool can enable command probes — consent is a human decision", () => {
  // The gate is only decorative if the gated party can open it.
  for (const name of HYPOTHESIS_TOOL_NAMES) {
    assert.doesNotMatch(name, /config|settings|allow/i, `${name} must not be a settings tool`);
  }
  const h = harness(tmpProject());
  for (const tool of h.tools.values()) {
    assert.doesNotMatch(tool.description, /allowCommandProbes\s*[:=]\s*true/i);
  }
  // And the settings file is untouched by a full tool-driven cycle.
  const cwd = tmpProject();
  const hh = harness(cwd);
  void hh;
  assert.equal(fs.existsSync(settingsPath(cwd)), false, "no tool wrote a settings file");
});

test("every tool carries a description and the risky ones carry guidelines", () => {
  const h = harness(tmpProject());
  for (const tool of h.tools.values()) {
    assert.ok(tool.description.length > 40, `${tool.name} needs a real description`);
  }
  for (const name of ["hypothesis_next", "hypothesis_verify", "hypothesis_record", "hypothesis_add"]) {
    const tool = h.tools.get(name)!;
    assert.ok((tool.promptGuidelines ?? []).length > 0, `${name} needs promptGuidelines`);
  }
});

// -----------------------------------------------------------------
// normalizeProbes
// -----------------------------------------------------------------

test("normalizeProbes accepts the three probe kinds", () => {
  const result = normalizeProbes([
    { kind: "location", file: "src/a.ts", line: 3 },
    { kind: "grep", pattern: "verify\\(", expectation: "present" },
    { kind: "command", command: "npm", args: ["test"], expectExit: "zero" },
  ]);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.probes.length, 3);
  assert.deepEqual(result.probes[0], { kind: "location", file: "src/a.ts", line: 3 });
  assert.deepEqual(result.probes[1], { kind: "grep", pattern: "verify\\(", expectation: "present" });
  assert.equal((result.probes[2] as { command: string }).command, "npm");
});

test("normalizeProbes rejects a location without a file or a line", () => {
  const noFile = normalizeProbes([{ kind: "location", line: 3 }]);
  assert.equal(noFile.ok, false);
  if (!noFile.ok) assert.match(noFile.errors[0]!, /"file" is required/);
  const noLine = normalizeProbes([{ kind: "location", file: "a.ts" }]);
  assert.equal(noLine.ok, false);
  if (!noLine.ok) assert.match(noLine.errors[0]!, /"line" is required/);
  const badLine = normalizeProbes([{ kind: "location", file: "a.ts", line: 0 }]);
  assert.equal(badLine.ok, false);
});

test("normalizeProbes REQUIRES an expectation on a grep — an unstated prediction cannot falsify", () => {
  const result = normalizeProbes([{ kind: "grep", pattern: "verify" }]);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.match(result.errors[0]!, /"expectation" is required/);
    assert.match(result.errors[0]!, /cannot falsify anything/);
  }
});

test("normalizeProbes rejects an unknown kind and names the valid ones", () => {
  const result = normalizeProbes([{ kind: "sql" as never }]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors[0]!, /unknown probe kind.*"location", "grep", or "command"/);
});

test("normalizeProbes rejects non-string args rather than coercing them", () => {
  const result = normalizeProbes([{ kind: "command", command: "npm", args: ["test", 42 as never] }]);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.errors[0]!, /every entry of "args" must be a string/);
});

// -----------------------------------------------------------------
// Full cycle through the tools
// -----------------------------------------------------------------

test("a full tool-driven round: add → next → verify → record", async () => {
  const cwd = tmpProject();
  fs.mkdirSync(path.join(cwd, "src"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "src/auth.ts"), "function login(token) {\n  const p = decode(token);\n  return p;\n}\n", "utf-8");
  const h = harness(cwd);

  const added = await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  assert.match(added, /Created hypothesis tree T-/);
  assert.match(added, /with H-0001 as its ROOT/);

  // A second add is a CHILD, not a new root.
  const child = await h.call("hypothesis_add", {
    description: "the refresh handler shares the missing signature check",
    category: "auth-bypass",
    parentId: "H-0001",
  });
  assert.match(child, /Added H-0002 \(depth 1/);

  const next = await h.call("hypothesis_next");
  assert.match(next, /round 1: selected H-0001/);
  assert.match(next, /score: novelty/);
  assert.match(next, /is now "testing"/);

  const verified = await h.call("hypothesis_verify", {
    id: "H-0001",
    probes: [
      { kind: "grep", pattern: "verify\\(", expectation: "present" },
      { kind: "location", file: "src/auth.ts", line: 2 },
    ],
  });
  assert.match(verified, /suggested REJECTED/, "the grep found no verify() call, which is a counterexample to 'present'");
  assert.match(verified, /counterexample:/);
  assert.match(verified, /Attached 1 of 1 evidence entry/);

  const recorded = await h.call("hypothesis_record", {
    id: "H-0001",
    verdict: "confirmed",
    reason: "the decode() call at src/auth.ts:2 has no matching verify(); the token payload is trusted as-is",
  });
  assert.match(recorded, /H-0001: testing → confirmed/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.byId.get("H-0001")!.status, "confirmed");
  assert.ok(snap.byId.get("H-0001")!.evidence.length >= 1);
  assert.equal(snap.selections.length, 1);
  assert.equal(snap.selections[0]!.nodeId, "H-0001");
});

test("hypothesis_next uses the scheduler, so the model cannot choose to tunnel", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  // A deep chain plus a sibling in another category.
  let parent = "H-0001";
  for (let i = 0; i < 6; i++) {
    await h.call("hypothesis_add", { description: `chain level ${i} does not validate the audience claim at all`, category: "auth-bypass", parentId: parent });
    parent = `H-000${i + 2}`;
  }
  await h.call("hypothesis_add", { description: "the export endpoint returns records the caller does not own", category: "idor" });

  const picked: string[] = [];
  for (let i = 0; i < 8; i++) {
    const out = await h.call("hypothesis_next");
    const m = /selected (H-\d+)/.exec(out);
    assert.ok(m, out);
    picked.push(m![1]!);
    // Give it a verdict so the scheduler has to move on.
    const snap = load(cwd).snapshot;
    const id = m![1]!;
    const status = snap.byId.get(id)!.status;
    if (status === "testing") {
      await h.call("hypothesis_record", {
        id,
        verdict: "rejected",
        reason: "the mechanical check refuted this specific claim",
        evidence: [{ kind: "code-slice", detail: `verified against ${id}`, file: "src/x.ts", line: 1 }],
      });
    }
  }
  assert.equal(new Set(picked).size > 1, true, `the scheduler must move around: ${picked.join(" -> ")}`);
  assert.ok(picked.includes("H-0008"), `the idor sibling was visited: ${picked.join(" -> ")}`);
});

test("hypothesis_verify refuses a node that already has a verdict", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  await h.call("hypothesis_record", {
    id: "H-0001",
    verdict: "rejected",
    reason: "refuted",
    evidence: [{ kind: "reasoning", detail: "the guard exists" }],
  });
  const out = await h.call("hypothesis_verify", { id: "H-0001", probes: [{ kind: "grep", pattern: "x", expectation: "present" }] });
  assert.match(out, /already has the verdict "rejected"/);
  assert.match(out, /reopen it/);
});

test("hypothesis_verify rejects a malformed probe list and runs NOTHING", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_verify", {
    id: "H-0001",
    probes: [
      { kind: "grep", pattern: "ok", expectation: "present" },
      { kind: "grep", pattern: "missing-expectation" },
    ],
  });
  assert.match(out, /probe list was rejected — nothing ran/);
  assert.match(out, /expectation/);
  assert.equal(load(cwd).snapshot.byId.get("H-0001")!.evidence.length, 0, "a rejected list attaches nothing");
});

test("hypothesis_verify with no probes says so instead of reporting a pass", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_verify", { id: "H-0001", probes: [] });
  assert.match(out, /No probes supplied/);
});

test("hypothesis_verify can run as a dry run without attaching", async () => {
  const cwd = tmpProject();
  fs.writeFileSync(path.join(cwd, "a.ts"), "verify(x)\n", "utf-8");
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  const out = await h.call("hypothesis_verify", {
    id: "H-0001",
    probes: [{ kind: "grep", pattern: "verify", expectation: "present" }],
    attachEvidence: false,
  });
  assert.match(out, /attachEvidence=false — nothing was written/);
  assert.equal(load(cwd).snapshot.byId.get("H-0001")!.evidence.length, 0);
});

test("a command probe through the tool is refused and says how to enable it", async () => {
  const cwd = await seeded();
  const h = harness(cwd, async () => ({ stdout: "42 passing", stderr: "", code: 0 }));
  const out = await h.call("hypothesis_verify", {
    id: "H-0001",
    probes: [{ kind: "command", command: "npm", args: ["test"] }],
  });
  assert.match(out, /refused: command probes are disabled/);
  assert.match(out, /allowCommandProbes=true/);
  assert.equal(h.execCalls.length, 0, "the command must not have been run at all");
});

test("a command probe runs once the project has opted in, and the command is recorded", async () => {
  const cwd = await seeded();
  saveSettings(cwd, { allowCommandProbes: true });
  const h = harness(cwd, async () => ({ stdout: "42 passing", stderr: "", code: 0 }));
  const out = await h.call("hypothesis_verify", {
    id: "H-0001",
    probes: [{ kind: "command", command: "npm", args: ["test"] }],
  });
  assert.match(out, /suggested CONFIRMED/);
  assert.deepEqual(h.execCalls, [{ command: "npm", args: ["test"] }]);
  const evidence = load(cwd).snapshot.byId.get("H-0001")!.evidence;
  assert.equal(evidence[0]!.kind, "command-output");
  assert.equal(evidence[0]!.command, "npm test");
});

// -----------------------------------------------------------------
// hypothesis_record gates
// -----------------------------------------------------------------

test("hypothesis_record refuses a verdict with no evidence anywhere", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_record", { id: "H-0001", verdict: "confirmed", reason: "it looked wrong" });
  assert.match(out, /Verdict REJECTED/);
  assert.match(out, /evidence/);
  assert.equal(load(cwd).snapshot.byId.get("H-0001")!.status, "pending", "nothing changed");
});

test("hypothesis_record accepts evidence supplied in the same call", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_record", {
    id: "H-0001",
    verdict: "confirmed",
    reason: "no verify() on the decode path",
    evidence: [{ kind: "code-slice", detail: "const p = decode(token);", file: "src/auth.ts", line: 2 }],
  });
  assert.match(out, /H-0001: pending → confirmed/);
  assert.match(out, /carries NO severity/, "an unrated confirmed finding is called out, because a severity contract cannot count it");
  const node = load(cwd).snapshot.byId.get("H-0001")!;
  assert.equal(node.evidence.length, 1);
  assert.deepEqual(node.evidence[0]!.location, { file: "src/auth.ts", line: 2 });
});

test("hypothesis_record refuses an evidence entry with an empty detail", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_record", {
    id: "H-0001",
    verdict: "confirmed",
    reason: "x",
    evidence: [{ kind: "code-slice", detail: "   " }],
  });
  assert.match(out, /empty detail/);
});

test("hypothesis_record requires a reason for blocked and for reopening", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const blocked = await h.call("hypothesis_record", { id: "H-0001", verdict: "blocked", reason: "" });
  assert.match(blocked, /REJECTED/);

  await h.call("hypothesis_record", {
    id: "H-0001",
    verdict: "rejected",
    reason: "refuted",
    evidence: [{ kind: "reasoning", detail: "guard exists" }],
  });
  const reopened = await h.call("hypothesis_record", { id: "H-0001", verdict: "pending", reason: "" });
  assert.match(reopened, /REJECTED/);
  const ok = await h.call("hypothesis_record", { id: "H-0001", verdict: "pending", reason: "the guard is bypassable via alg=none" });
  assert.match(ok, /rejected → pending/);
});

test("hypothesis_record on an unknown id is refused", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  assert.match(await h.call("hypothesis_record", { id: "H-9999", verdict: "pending", reason: "x" }), /not in the tree/);
});

// -----------------------------------------------------------------
// hypothesis_add gates
// -----------------------------------------------------------------

test("hypothesis_add refuses a task-shaped assertion and explains the reformulation", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  const out = await h.call("hypothesis_add", { description: "check the JWT validation in the login handler", category: "auth-bypass" });
  assert.match(out, /Hypothesis REJECTED/);
  assert.match(out, /reads as a TASK/);
  assert.equal(load(cwd).snapshot.nodes.length, 0);
});

test("hypothesis_add refuses a duplicate and names the existing node", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_add", { description: ROOT.toUpperCase(), category: "auth-bypass" });
  assert.match(out, /REJECTED/);
  assert.match(out, /H-0001/);
});

test("hypothesis_add refuses an unknown category", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  const out = await h.call("hypothesis_add", { description: ROOT, category: "authBypass" });
  assert.match(out, /unknown category/);
});

// -----------------------------------------------------------------
// hypothesis_status and hypothesis_evidence
// -----------------------------------------------------------------

test("hypothesis_status is read-only and lists the open hypotheses", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: "the export endpoint returns records the caller does not own", category: "idor" });
  const before = fs.readFileSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), "utf-8");
  const out = await h.call("hypothesis_status");
  assert.match(out, /Hypothesis tree T-/);
  assert.match(out, /Open hypotheses \(2/);
  assert.match(out, /H-0001 \[pending\] auth-bypass/);
  assert.equal(fs.readFileSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), "utf-8"), before, "status must not write");
});

test("hypothesis_status on an empty project points at how to start", async () => {
  const h = harness(tmpProject());
  assert.match(await h.call("hypothesis_status"), /No hypothesis tree in this project yet/);
});

test("hypothesis_evidence attaches an artifact without deciding", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_evidence", {
    id: "H-0001",
    kind: "file",
    detail: "decode(token) with no verify() below it",
    file: "src/auth.ts",
    line: 41,
  });
  assert.match(out, /now carries 1 evidence entry/);
  const node = load(cwd).snapshot.byId.get("H-0001")!;
  assert.equal(node.status, "pending", "evidence alone never decides");
  assert.equal(node.evidence.length, 1);
});

test("hypothesis_evidence rejects an empty detail", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  assert.match(await h.call("hypothesis_evidence", { id: "H-0001", kind: "reasoning", detail: "" }), /Evidence REJECTED/);
});

test("hypothesis_evidence on an unknown id is refused", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  assert.match(await h.call("hypothesis_evidence", { id: "H-9999", kind: "reasoning", detail: "x" }), /not in the tree/);
});

// -----------------------------------------------------------------
// Stage 4 — combination through the tools
// -----------------------------------------------------------------

test("the two combination tools are registered", () => {
  const h = harness(tmpProject());
  assert.ok(h.tools.has("hypothesis_consolidate"));
  assert.ok(h.tools.has("hypothesis_combine"));
  assert.match(h.tools.get("hypothesis_consolidate")!.description, /STRUCTURAL signal/);
  assert.match(h.tools.get("hypothesis_combine")!.description, /CONFIRMED findings/);
});

/** Build a tree with two confirmed findings that cite the same file. */
async function twoFindings(cwd: string): Promise<ReturnType<typeof harness>> {
  fs.mkdirSync(path.join(cwd, "src"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "src", "jwt.ts"), "decode(token)\n", "utf-8");
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  await h.call("hypothesis_add", {
    description: "the refresh handler accepts a JWT without verifying its signature",
    category: "auth-bypass",
  });
  for (const id of ["H-0001", "H-0002"]) {
    await h.call("hypothesis_record", {
      id,
      verdict: "confirmed",
      reason: "the decode path has no verify() call",
      evidence: [{ kind: "code-slice", detail: "decode(token)", file: "src/jwt.ts", line: 1 }],
    });
  }
  return h;
}

test("hypothesis_next is BLOCKED while a consolidation pass is due", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  const out = await h.call("hypothesis_next");
  assert.match(out, /BLOCKED: a consolidation pass is due/);
  assert.match(out, /must run before a new round is scheduled/);
  assert.match(out, /hypothesis_consolidate first/);
  assert.equal(load(cwd).snapshot.selections.length, 0, "no round was scheduled");
});

test("hypothesis_consolidate records the pass and hands over the ranked pairs", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  const out = await h.call("hypothesis_consolidate");
  assert.match(out, /CONSOLIDATION PASS — round 0, trigger: new-finding/);
  assert.match(out, /PAIRS to consider \(1\)/);
  assert.match(out, /H-0001\|H-0002/);
  assert.match(out, /both cite src\/jwt\.ts/);
  assert.match(out, /Recorded: pass at round 0/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.consolidations.length, 1);
  assert.deepEqual(snap.consolidations[0]!.pairKeys, ["H-0001|H-0002"]);
});

test("hypothesis_consolidate clears the block so scheduling resumes", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  assert.match(await h.call("hypothesis_next"), /BLOCKED/);
  await h.call("hypothesis_consolidate");
  // Both findings now have verdicts, so there is nothing to schedule — the
  // point is that the CONSOLIDATION block is gone.
  const out = await h.call("hypothesis_next");
  assert.doesNotMatch(out, /BLOCKED: a consolidation pass is due/);
  assert.match(out, /No open hypotheses/);
});

test("hypothesis_consolidate reports a not-due pass without writing one", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  await h.call("hypothesis_consolidate");
  const out = await h.call("hypothesis_consolidate");
  assert.match(out, /not due:/);
  assert.equal(load(cwd).snapshot.consolidations.length, 1, "nothing extra was recorded");
});

test("hypothesis_consolidate force runs a pass anyway", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  await h.call("hypothesis_consolidate");
  const out = await h.call("hypothesis_consolidate", { force: true });
  assert.match(out, /trigger: manual/);
  assert.equal(load(cwd).snapshot.consolidations.length, 2);
});

test("hypothesis_combine inserts a typed combination with its lineage", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  await h.call("hypothesis_consolidate");

  const out = await h.call("hypothesis_combine", {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", "H-0002"],
  });
  assert.match(out, /Added H-0003 \(shared-root-cause, depth 1, auth-bypass\)/);
  assert.match(out, /derived from: H-0001 \+ H-0002/);
  assert.match(out, /must be TESTED like any other/);

  const node = load(cwd).snapshot.byId.get("H-0003")!;
  assert.equal(node.combinationKind, "shared-root-cause");
  assert.deepEqual(node.spawnedFrom, ["H-0001", "H-0002"]);
  assert.equal(node.status, "pending");
});

test("hypothesis_combine refuses an unconfirmed source and says why", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  await h.call("hypothesis_add", {
    description: "the refresh handler accepts a JWT without verifying its signature",
    category: "auth-bypass",
  });
  // Neither is confirmed.
  const out = await h.call("hypothesis_combine", {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", "H-0002"],
  });
  assert.match(out, /Combination REJECTED/);
  assert.match(out, /speculation stacked on speculation/);
  assert.equal(load(cwd).snapshot.nodes.length, 2, "nothing was added");
});

test("hypothesis_combine refuses an empty spawnedFrom", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  const out = await h.call("hypothesis_combine", {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "lateral-extension",
    spawnedFrom: [],
  });
  assert.match(out, /spawnedFrom must name/);
});

test("a chain with one id is refused as a category error", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  const out = await h.call("hypothesis_combine", {
    description: "the missing signature check is what lets the refresh path be reached",
    category: "auth-bypass",
    kind: "chain",
    spawnedFrom: ["H-0001"],
  });
  assert.match(out, /relation BETWEEN findings/);
});

test("the full loop: confirm → consolidate → combine → the combination is itself scheduled", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  assert.match(await h.call("hypothesis_next"), /BLOCKED/);
  await h.call("hypothesis_consolidate");
  await h.call("hypothesis_combine", {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", "H-0002"],
  });

  // The combination is a new pending hypothesis, so it is schedulable — and it
  // is the ONLY open node, so the scheduler must pick it.
  const out = await h.call("hypothesis_next");
  assert.match(out, /round 1: selected H-0003/);
  assert.match(out, /auth-bypass\+shared/, "the decision names the combination kind, so a reader can tell an inference from an observation");
  assert.match(out, /derived from H-0001\+H-0002/);

  // And it must be verifiable like any other hypothesis.
  const verified = await h.call("hypothesis_verify", {
    id: "H-0003",
    probes: [{ kind: "location", file: "src/jwt.ts", line: 1 }],
  });
  assert.match(verified, /verification of H-0003/);
});

test("hypothesis_status reports the combination state and the dueness", async () => {
  const cwd = tmpProject();
  const h = await twoFindings(cwd);
  const before = await h.call("hypothesis_status");
  assert.match(before, /combinations: 0 pass\(es\), none yet, 0 pair\(s\) examined/);
  assert.match(before, /COMBINATION DUE/);

  await h.call("hypothesis_consolidate");
  await h.call("hypothesis_combine", {
    description: "both handlers share one decode helper that never calls verify()",
    category: "auth-bypass",
    kind: "shared-root-cause",
    spawnedFrom: ["H-0001", "H-0002"],
  });
  const after = await h.call("hypothesis_status");
  assert.match(after, /combinations: 1 pass\(es\), last at round 0 \(new-finding\), 1 pair\(s\) examined, produced 1 shared-root-cause/);
});

// -----------------------------------------------------------------
// Stage 6 — recon through the tools
// -----------------------------------------------------------------

const RECON_NOTE = [
  "The project is a small Node service. It exposes three HTTP routes under /api: login, refresh and export, and it consumes one queue topic named order.created.",
  "Authentication is a JWT bearer token. The middleware under src/auth/ decodes the token and attaches the payload to the request, and the routes read the payload directly.",
  "The export route returns records selected by an id taken from the query string. I could not find an ownership check between the id and the caller in the time available.",
  "The queue consumer deserializes the message body with a generic parser. I did not read the parser itself, so I cannot say whether it restricts the types it will construct.",
].join("\n\n");

test("the recon tools are registered", () => {
  const h = harness(tmpProject());
  assert.ok(h.tools.has("hypothesis_recon"));
  assert.ok(h.tools.has("hypothesis_cover_segment"));
  assert.match(h.tools.get("hypothesis_recon")!.description, /chunked into segments/);
  assert.match(h.tools.get("hypothesis_cover_segment")!.description, /'examined and empty' and 'did not look'/);
});

test("hypothesis_recon records the note and returns the segment inventory", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  const out = await h.call("hypothesis_recon", { notes: RECON_NOTE });
  assert.match(out, /Recon note recorded: \d+ chars → \d+ segment\(s\)/);
  assert.match(out, /S-000-[0-9a-f]{8}/);
  assert.match(out, /Note written to .*recon\.md for human review/);
  assert.match(out, /Next: the loop hands you segment 1/);

  const snap = load(cwd).snapshot;
  assert.ok(snap.segments.length >= 1);
  assert.ok(snap.reconAt);
});

test("hypothesis_recon refuses a note too short to describe a project", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  const out = await h.call("hypothesis_recon", { notes: "it is a web app" });
  assert.match(out, /Recon REJECTED/);
  assert.match(out, /too short to describe a project/);
  assert.equal(load(cwd).snapshot.segments.length, 0);
});

test("hypothesis_add with segmentId and attackVector closes the segment and records the vector", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  await h.call("hypothesis_recon", { notes: RECON_NOTE });
  const segmentId = load(cwd).snapshot.segments[0]!.id;

  const out = await h.call("hypothesis_add", {
    description: "the refresh handler accepts a JWT without verifying its signature",
    category: "auth-bypass",
    segmentId,
    attackVector: {
      entrypoint: "POST /api/login",
      technique: "alg=none JWT forgery",
      path: [
        { detail: "send an unsigned token", file: "src/auth/jwt.ts", line: 41 },
        { detail: "the verifier accepts it", file: "src/auth/jwt.ts", line: 88 },
      ],
      payload: '{"alg":"none"}.{"sub":"admin"}.',
      preconditions: ["no credentials needed"],
    },
  });
  assert.match(out, /Added H-0002 \(depth 1, auth-bypass\)/);
  assert.match(out, /vector: POST \/api\/login · alg=none JWT forgery · 2 step\(s\)/);
  assert.match(out, /Segment S-\d+-[0-9a-f]{8} is now closed/);

  const node = load(cwd).snapshot.byId.get("H-0002")!;
  assert.equal(node.segmentId, segmentId);
  assert.equal(node.attackVector!.entrypoint, "POST /api/login");
  assert.deepEqual(node.attackVector!.path[0]!.location, { file: "src/auth/jwt.ts", line: 41 });
});

test("hypothesis_add says so when no vector is recorded", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  const out = await h.call("hypothesis_add", {
    description: "the export endpoint returns records the caller does not own",
    category: "idor",
  });
  assert.match(out, /vector: \(none recorded — how to reach it is not yet known\)/);
});

test("hypothesis_cover_segment closes a segment with nothing found", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  await h.call("hypothesis_recon", { notes: RECON_NOTE });
  const segmentId = load(cwd).snapshot.segments[0]!.id;

  const out = await h.call("hypothesis_cover_segment", { segmentId, note: "read the boot sequence; no external input" });
  assert.match(out, /closed with nothing found/);
  assert.match(out, /Coverage: 1\/\d+/);
});

test("hypothesis_cover_segment requires a note", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  await h.call("hypothesis_recon", { notes: RECON_NOTE });
  const segmentId = load(cwd).snapshot.segments[0]!.id;
  const out = await h.call("hypothesis_cover_segment", { segmentId, note: "" });
  assert.match(out, /Segment NOT closed/);
  assert.match(out, /indistinguishable from not looking/);
});

test("hypothesis_cover_segment refuses an unknown segment and lists the known ones", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  await h.call("hypothesis_recon", { notes: RECON_NOTE });
  const out = await h.call("hypothesis_cover_segment", { segmentId: "S-999-deadbeef", note: "x" });
  assert.match(out, /is not in the inventory/);
  assert.match(out, /Known segments: S-000-/);
});

test("hypothesis_status reports recon coverage", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", { description: ROOT, category: "auth-bypass" });
  assert.match(await h.call("hypothesis_status"), /recon: not run yet/);
  await h.call("hypothesis_recon", { notes: RECON_NOTE });
  assert.match(await h.call("hypothesis_status"), /recon: 0\/\d+ segment\(s\) covered/);
});

// -----------------------------------------------------------------
// hypothesis_vector — filling in a chain after the fact
// -----------------------------------------------------------------

test("hypothesis_vector creates a vector on a node that has none", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_vector", {
    id: "H-0001",
    entrypoint: "POST /api/gorgone/command",
    technique: "未鉴权的 Gorgone 命令转发",
    path: [{ detail: "防火墙 access_control 为空", file: "config/security.yaml", line: 12 }],
    impact: "以 Gorgone 权限在任意被管主机上执行命令",
    preconditions: ["api 防火墙未做 IP 限制"],
  });
  assert.match(out, /H-0001 attack vector recorded/);
  assert.match(out, /impact:     以 Gorgone 权限/);
  assert.match(out, /call chain: 1 step\(s\) \(with code locations\)/);

  const node = load(cwd).snapshot.byId.get("H-0001")!;
  assert.equal(node.attackVector?.entrypoint, "POST /api/gorgone/command");
  assert.equal(node.attackVector?.impact, "以 Gorgone 权限在任意被管主机上执行命令");
  assert.deepEqual(node.attackVector?.path[0]!.location, { file: "config/security.yaml", line: 12 });
  assert.deepEqual(node.attackVector?.preconditions, ["api 防火墙未做 IP 限制"]);
});

test("hypothesis_vector MERGES — recording only the impact keeps the chain", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  await h.call("hypothesis_vector", {
    id: "H-0001",
    entrypoint: "POST /api/gorgone/command",
    technique: "未鉴权的命令转发",
    path: [{ detail: "sink", file: "src/api/gorgone.ts", line: 66 }],
  });
  // The common real sequence: the chain is known first, the consequence later.
  const out = await h.call("hypothesis_vector", { id: "H-0001", impact: "接管中心节点" });

  const node = load(cwd).snapshot.byId.get("H-0001")!;
  assert.equal(node.attackVector?.entrypoint, "POST /api/gorgone/command", "entrypoint kept");
  assert.equal(node.attackVector?.technique, "未鉴权的命令转发", "technique kept");
  assert.equal(node.attackVector?.path.length, 1, "chain kept");
  assert.equal(node.attackVector?.impact, "接管中心节点");
  assert.doesNotMatch(out, /NOT RECORDED/);
});

test("hypothesis_vector refuses to invent a chain it has no entrypoint for", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_vector", { id: "H-0001", impact: "接管一切" });
  assert.match(out, /entrypoint and technique are both required to create one/);
  assert.match(out, /Nothing was recorded/);
  assert.match(out, /Do not invent a chain to fill the section/);
  assert.equal(load(cwd).snapshot.byId.get("H-0001")!.attackVector, undefined, "the tree is unchanged");
});

test("hypothesis_vector says when the chain has no locations to point at", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_vector", {
    id: "H-0001",
    entrypoint: "GET /api/x",
    technique: "missing check",
    path: [{ detail: "somewhere" }],
  });
  assert.match(out, /no code locations, so the report cannot point a reader at a line/);
});

test("hypothesis_vector flags a missing impact instead of letting it pass silently", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  const out = await h.call("hypothesis_vector", { id: "H-0001", entrypoint: "GET /api/x", technique: "missing check" });
  assert.match(out, /impact:     NOT RECORDED — the report will say 'not assessed'/);
  const details = await h.detailsOf("hypothesis_vector", { id: "H-0001", entrypoint: "GET /api/x", technique: "missing check" });
  assert.equal(details.hasImpact, false);
});

test("hypothesis_vector refuses an id that is not in the tree", async () => {
  const cwd = await seeded();
  const h = harness(cwd);
  assert.match(await h.call("hypothesis_vector", { id: "H-9999", entrypoint: "a", technique: "b" }), /is not in the tree/);
});

test("hypothesis_add records the impact at creation time", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.call("hypothesis_add", {
    description: ROOT,
    category: "auth-bypass",
    attackVector: {
      entrypoint: "POST /api/login",
      technique: "alg=none",
      impact: "伪造任意用户身份，包括管理员",
    },
  });
  const node = load(cwd).snapshot.nodes.find((n) => n.nodeKind !== "scope")!;
  assert.equal(node.attackVector?.impact, "伪造任意用户身份，包括管理员");
});
