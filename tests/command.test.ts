// pi-audit-hypothesis-tree — tests/command.test.ts
//
// End-to-end check of the REAL registration path: call the default export the
// way pi does, then drive the registered `/hypothesis` handler through a full
// audit cycle (create → derive → evidence → verdict → render).
//
// This is the test that catches a wiring mistake the module tests cannot: a
// wrong handler signature, a subcommand that is registered but unreachable, or
// a `ctx` access that only works in the module layer.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import hypothesisTreeExtension from "../extensions/hypothesis-tree/index.ts";
import { load } from "../extensions/hypothesis-tree/store.ts";

// -----------------------------------------------------------------
// A minimal stand-in for the pieces of ExtensionAPI / ExtensionCommandContext
// this extension touches. Kept deliberately small: if the extension starts
// using something else, this mock stops satisfying it and tsc fails, which is
// the signal that the mock needs to grow.
// -----------------------------------------------------------------

interface RegisteredCommand {
  description?: string;
  getArgumentCompletions?: (prefix: string) => Array<{ value: string; label: string; description?: string }> | null;
  handler: (args: string, ctx: FakeCtx) => Promise<void>;
}

interface FakeCtx {
  cwd: string;
  ui: {
    notify: (message: string, type?: "info" | "warning" | "error") => void;
  };
}

function harness(cwd: string): {
  commands: Map<string, RegisteredCommand>;
  tools: Map<string, unknown>;
  ctx: FakeCtx;
  run: (args: string) => Promise<string>;
  lastNotify: () => string;
} {
  const commands = new Map<string, RegisteredCommand>();
  const notifications: string[] = [];
  const tools = new Map<string, unknown>();
  const pi = {
    registerCommand: (name: string, options: RegisteredCommand) => {
      commands.set(name, options);
    },
    // The extension also registers agent tools; this file drives only the
    // COMMAND surface, so the tool registry is a stub here (tests/tools.test.ts
    // exercises the tools themselves).
    registerTool: (tool: { name: string }) => {
      tools.set(tool.name, tool);
    },
    exec: async () => ({ stdout: "", stderr: "", code: 0 }),
  };
  // The real ExtensionAPI has many more members; the extension must only need
  // registerCommand/registerTool/exec at load time.
  hypothesisTreeExtension(pi as never);

  const ctx: FakeCtx = {
    cwd,
    ui: {
      notify: (message: string) => {
        notifications.push(message);
      },
    },
  };

  return {
    commands,
    tools,
    ctx,
    run: async (args: string) => {
      notifications.length = 0;
      const command = commands.get("hypothesis");
      assert.ok(command, "/hypothesis must be registered");
      await command!.handler(args, ctx);
      return notifications.join("\n");
    },
    lastNotify: () => notifications.join("\n"),
  };
}

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-cmd-"));
}

const ROOT = "the login handler accepts a JWT without verifying its signature";

// -----------------------------------------------------------------
// Registration
// -----------------------------------------------------------------

test("the extension registers /hypothesis and /hypothesis-status on load", () => {
  const h = harness(tmpProject());
  assert.ok(h.commands.has("hypothesis"));
  assert.ok(h.commands.has("hypothesis-status"));
  assert.match(h.commands.get("hypothesis")!.description ?? "", /hypothesis tree/i);
});

test("argument completions offer the verbs and filter by prefix", () => {
  const h = harness(tmpProject());
  const all = h.commands.get("hypothesis")!.getArgumentCompletions!("") ?? [];
  const values = all.map((a) => a.value.trim());
  for (const verb of ["status", "tree", "new", "add", "evidence", "confirm", "reject", "block"]) {
    assert.ok(values.includes(verb), `missing completion: ${verb}`);
  }
  const filtered = h.commands.get("hypothesis")!.getArgumentCompletions!("co") ?? [];
  assert.deepEqual(filtered.map((a) => a.value.trim()), ["consolidate", "combine", "config", "confirm", "compact"]);
  // AutocompleteItem.label is required by pi-tui; assert we supply it.
  for (const item of all) assert.equal(typeof item.label, "string");
});

// -----------------------------------------------------------------
// Full cycle through the command layer
// -----------------------------------------------------------------

test("a full audit cycle works through the command layer and survives a reload", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);

  // 1. no tree yet — the status command must say so, not print nothing
  const empty = await h.run("status");
  assert.match(empty, /No hypothesis tree/);
  assert.match(empty, /\/hypothesis new/);

  // 2. create the tree from the objective
  const created = await h.run(`new "${ROOT}" category=auth-bypass`);
  assert.match(created, /Tree T-/);
  assert.match(created, /H-0001/);
  assert.equal(load(cwd).snapshot.rootId, "H-0001");

  // 3. derive a child hypothesis
  const added = await h.run('add "the signature is checked but the algorithm is taken from the token header" parent=H-0001 category=auth-bypass');
  assert.match(added, /Added H-0002 \(depth 1, auth-bypass\)/);

  // 4. attach raw evidence, then reach a verdict
  const evidence = await h.run('evidence H-0002 code-slice "const { alg } = JSON.parse(b64(token)); verify(token, key, alg)" file=src/auth/jwt.ts line=57');
  assert.match(evidence, /Evidence attached to H-0002/);

  const confirmed = await h.run("confirm H-0002");
  assert.match(confirmed, /H-0002 → confirmed/);

  // 5. the tree view reflects it
  const tree = await h.run("tree --evidence");
  assert.match(tree, /H-0001 \[pending/);
  assert.match(tree, /H-0002 \[confirmed/);
  assert.match(tree, /src\/auth\/jwt\.ts:57/);

  // 6. a fresh load sees exactly the same thing (durability)
  const snap = load(cwd).snapshot;
  assert.equal(snap.nodes.length, 2);
  assert.equal(snap.byId.get("H-0002")!.status, "confirmed");
  assert.equal(snap.byId.get("H-0002")!.depth, 1);
  assert.equal(snap.byId.get("H-0002")!.evidence.length, 1);
  assert.equal(snap.byId.get("H-0002")!.evidence[0]!.location!.line, 57);
});

// -----------------------------------------------------------------
// Refusals reach the user as refusals
// -----------------------------------------------------------------

test("a task-shaped objective is refused at the command layer with an actionable message", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  const out = await h.run('new "audit the login flow for problems"');
  assert.match(out, /REJECTED/);
  assert.match(out, /TASK/);
  assert.equal(load(cwd).snapshot.rootId, "", "nothing was written");
});

test("a verdict without evidence is refused and says why", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}"`);
  const out = await h.run("confirm H-0001");
  assert.match(out, /REJECTED/);
  assert.match(out, /evidence/);
  assert.match(out, /opinion/);
  assert.equal(load(cwd).snapshot.byId.get("H-0001")!.status, "pending");
});

test("a duplicate assertion is refused and names the existing node", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}"`);
  const out = await h.run(`add "${ROOT.toUpperCase()}"`);
  assert.match(out, /REJECTED/);
  assert.match(out, /H-0001/);
});

test("an unknown parent is refused and names it", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}"`);
  const out = await h.run('add "the token expiry is never compared against the current time" parent=H-0042');
  assert.match(out, /REJECTED/);
  assert.match(out, /H-0042/);
});

test("an unknown verb prints the usage instead of failing silently", async () => {
  const h = harness(tmpProject());
  const out = await h.run("frobnicate");
  assert.match(out, /Unknown \/hypothesis action "frobnicate"/);
  assert.match(out, /\/hypothesis {2,}status/);
});

test("missing arguments print the exact usage line", async () => {
  const h = harness(tmpProject());
  assert.match(await h.run("add"), /Usage: \/hypothesis add/);
  assert.match(await h.run("evidence H-0001"), /Usage: \/hypothesis evidence/);
  assert.match(await h.run("reopen H-0001"), /Usage: \/hypothesis reopen/);
  assert.match(await h.run("round"), /Usage: \/hypothesis round/);
});

// -----------------------------------------------------------------
// Crash recovery and compaction through the command layer
// -----------------------------------------------------------------

test("repair drops a torn tail and status reports zero torn lines afterwards", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}"`);
  fs.appendFileSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), '{"type":"node_added","at":"x","node":{"id":"H-00', "utf-8");

  const before = await h.run("status");
  assert.match(before, /torn line/);

  const repaired = await h.run("repair");
  assert.match(repaired, /Repaired: dropped \d+ byte/);

  const after = await h.run("status");
  assert.doesNotMatch(after, /torn line/);
  assert.equal(load(cwd).snapshot.nodes.length, 1, "the complete record survived the repair");
});

test("compact appends a snapshot and keeps the state", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}"`);
  await h.run('add "the token expiry is never compared against the current time" category=auth-bypass');

  const out = await h.run("compact");
  assert.match(out, /Snapshot appended/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.compactions, 1);
  assert.equal(snap.nodes.length, 2);

  const again = await h.run("compact");
  assert.match(again, /Nothing to compact/);
});

test("round is recorded and reported in the summary", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}"`);
  await h.run("round 7");
  const out = await h.run("status");
  assert.match(out, /round 7/);
  assert.equal(load(cwd).snapshot.rounds, 7);
});

// -----------------------------------------------------------------
// The read-only alias
// -----------------------------------------------------------------

test("/hypothesis-status is read-only and prints the same block", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}"`);

  const before = fs.readFileSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), "utf-8");
  const ctx = h.ctx;
  await h.commands.get("hypothesis-status")!.handler("", ctx);
  const out = h.lastNotify();
  assert.match(out, /Hypothesis tree T-/);

  const after = fs.readFileSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), "utf-8");
  assert.equal(after, before, "the status alias must not write");
});

test("the read-only alias reports an unreadable log instead of printing an empty tree", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  fs.mkdirSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), { recursive: true });
  await h.commands.get("hypothesis-status")!.handler("", h.ctx);
  assert.match(h.lastNotify(), /Could not read/);
});

// -----------------------------------------------------------------
// Stage 2 — the scheduler through the command layer
// -----------------------------------------------------------------

test("next schedules a round, records it, and names the pick", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the signature is checked but the algorithm comes from the token header" category=auth-bypass');

  const out = await h.run("next");
  assert.match(out, /round 1: selected H-0001 \(score [\d.-]+\)/);
  assert.match(out, /score: novelty/);
  assert.match(out, /Recorded: round 1 → H-0001/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.rounds, 1);
  assert.equal(snap.selections.length, 1);
  assert.equal(snap.byId.get("H-0001")!.status, "testing");
  assert.equal(snap.byId.get("H-0001")!.timesSelected, 1);
});

test("schedule is a dry run: it prints the same decision and writes nothing", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);

  const before = fs.readFileSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), "utf-8");
  const out = await h.run("schedule");
  assert.match(out, /round 1: selected H-0001/);
  assert.match(out, /dry run — nothing recorded/);
  assert.equal(fs.readFileSync(path.join(cwd, ".pi-hypothesis", "tree.jsonl"), "utf-8"), before, "a dry run must not write");
  assert.equal(load(cwd).snapshot.rounds, 0);
});

test("next on an empty project explains instead of writing a selection", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  const out = await h.run("next");
  assert.match(out, /No hypothesis tree/);
  assert.equal(load(cwd).snapshot.selections.length, 0);
});

test("next honours an explicit round=<n>", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run("next round=5");
  assert.equal(load(cwd).snapshot.rounds, 5);
  assert.equal(load(cwd).snapshot.selections[0]!.round, 5);
});

test("history lists the recorded decisions with their flags", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the signature is checked but the algorithm comes from the token header" category=auth-bypass');
  assert.match(await h.run("history"), /No scheduling decisions recorded yet/);

  await h.run("next");
  await h.run("next");
  const out = await h.run("history 5");
  assert.match(out, /Scheduling history \(last 2/);
  assert.match(out, /r {2}1 {2}H-0001/);
  assert.match(out, /r {2}2 {2}H-0002/);
});

test("history rejects a non-positive count", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}"`);
  assert.match(await h.run("history 0"), /Usage: \/hypothesis history \[n\]/);
  assert.match(await h.run("history abc"), /Usage: \/hypothesis history \[n\]/);
});

test("limits prints the configured numbers and the live run state", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the signature is checked but the algorithm comes from the token header" category=auth-bypass');
  await h.run("next");

  const out = await h.run("limits");
  assert.match(out, /MAX_CONSECUTIVE_DEPTH {2}3/);
  assert.match(out, /MAX_SAME_NODE_ROUNDS {3}2/);
  assert.match(out, /MAX_CATEGORY_RATIO {5}40%/);
  assert.match(out, /novelty {10}10 \/ \(1 \+ timesSelected\)/);
  assert.match(out, /same-node run {4}1\/2/);
  assert.match(out, /round {12}1 recorded, next is 2/);
});

test("a full scheduled round cycle: next → evidence → confirm → consolidate → next moves on", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the signature is checked but the algorithm comes from the token header" category=auth-bypass');

  await h.run("next");
  assert.equal(load(cwd).snapshot.selections[0]!.nodeId, "H-0001");
  await h.run('evidence H-0001 code-slice "verify(token, key, alg)" file=src/auth/jwt.ts line=57');
  await h.run("confirm H-0001");

  // Confirming a finding makes a combination pass due, and the pass is FORCED:
  // scheduling refuses until it has run.
  const blocked = await h.run("next");
  assert.match(blocked, /BLOCKED: a consolidation pass is due/);
  assert.equal(load(cwd).snapshot.selections.length, 1, "no new round was scheduled");

  await h.run("consolidate");
  await h.run("next");
  const snap = load(cwd).snapshot;
  assert.equal(snap.selections.length, 2);
  assert.notEqual(snap.selections[1]!.nodeId, "H-0001", "a node with a verdict is no longer a candidate");
  assert.equal(snap.byId.get("H-0001")!.status, "confirmed");
});

test("status reports the scheduler run state and the relaxation count", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  for (let i = 0; i < 9; i++) {
    await h.run(`add "auth-bypass hypothesis number ${i} about the token handling path" category=auth-bypass`);
  }
  for (let i = 0; i < 6; i++) await h.run("next");

  const out = await h.run("status");
  assert.match(out, /scheduler: same-node run \d\/2, descent run \d\/3 level\(s\), last selected H-\d+/);
  assert.match(out, /round\(s\) had to relax a limit/);
});

// -----------------------------------------------------------------
// Stage 3 — the executor through the command layer
// -----------------------------------------------------------------

test("verify runs a location probe, captures the slice, and attaches the evidence", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  fs.mkdirSync(path.join(cwd, "src"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "src", "auth.ts"), "line1\nconst p = decode(token)\nline3\n", "utf-8");
  await h.run(`new "${ROOT}" category=auth-bypass`);

  const out = await h.run("verify H-0001 file=src/auth.ts line=2");
  assert.match(out, /verification of H-0001: suggested CONFIRMED/);
  assert.match(out, /Attached 1 of 1 evidence entry/);
  const node = load(cwd).snapshot.byId.get("H-0001")!;
  assert.equal(node.evidence.length, 1);
  assert.deepEqual(node.evidence[0]!.location, { file: "src/auth.ts", line: 2 });
  assert.equal(node.status, "pending", "the executor never decides");
});

test("verify with a grep that misses reports a counterexample and suggests rejection", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  fs.writeFileSync(path.join(cwd, "a.ts"), "const x = 1;\n", "utf-8");
  await h.run(`new "${ROOT}" category=auth-bypass`);

  const out = await h.run('verify H-0001 grep="verify\\\\(" expect=present');
  assert.match(out, /suggested REJECTED/);
  assert.match(out, /counterexample:/);
  assert.match(out, /The executor does not decide/);
});

test("verify demands expect= on a grep instead of guessing a prediction", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const out = await h.run('verify H-0001 grep="verify"');
  assert.match(out, /needs expect=present\|absent/);
  assert.equal(load(cwd).snapshot.byId.get("H-0001")!.evidence.length, 0);
});

test("verify refuses a node that already has a verdict", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run("evidence H-0001 reasoning \"the guard exists\"");
  await h.run("reject H-0001 reason=\"the guard is present\"");
  const out = await h.run("verify H-0001 file=README.md line=1");
  assert.match(out, /already has the verdict "rejected"/);
});

test("verify on an unknown id is refused", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  assert.match(await h.run("verify H-9999 file=a.ts line=1"), /is not in the tree/);
});

test("verify with no probe flags prints the usage", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  assert.match(await h.run("verify H-0001"), /No probe given/);
  assert.match(await h.run("verify"), /Usage:/);
});

test("a command probe through the command layer is refused until the project opts in", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const out = await h.run('verify H-0001 command="npm" args="test"');
  assert.match(out, /refused: command probes are disabled/);
  assert.match(out, /allowCommandProbes=true/);
});

// -----------------------------------------------------------------
// config — the human consent surface
// -----------------------------------------------------------------

test("config with no assignment shows every setting and marks the defaults", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  const out = await h.run("config");
  assert.match(out, /Project settings .*settings\.json\) — source: defaults/);
  assert.match(out, /allowCommandProbes\s+false\s+\(default\)/);
  assert.match(out, /commandTimeoutMs\s+120000/);
  assert.match(out, /it is OFF by default and no agent tool can turn it on/);
});

test("config sets a value, coerces its type, and persists it", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  const out = await h.run("config allowCommandProbes=true maxGrepMatches=25");
  assert.match(out, /allowCommandProbes = true/);
  assert.match(out, /maxGrepMatches = 25/);

  const saved = JSON.parse(fs.readFileSync(path.join(cwd, ".pi-hypothesis", "settings.json"), "utf-8"));
  assert.equal(saved.allowCommandProbes, true);
  assert.equal(saved.maxGrepMatches, 25);
  assert.match((await h.run("config")).toString(), /source: file/);
});

test("config refuses an unknown key", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  assert.match(await h.run("config nonsense=1"), /REJECTED.*unknown setting/s);
});

test("config surfaces a corrupt settings file instead of silently using defaults", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  fs.mkdirSync(path.join(cwd, ".pi-hypothesis"), { recursive: true });
  fs.writeFileSync(path.join(cwd, ".pi-hypothesis", "settings.json"), "{ broken", "utf-8");
  const out = await h.run("config");
  assert.match(out, /WARNING: settings\.json is not valid JSON/);
});

// -----------------------------------------------------------------
// Stage 4 — combination through the command layer
// -----------------------------------------------------------------

/** Two confirmed findings citing the same file. */
async function twoConfirmed(h: ReturnType<typeof harness>): Promise<void> {
  fs.mkdirSync(path.join(h.ctx.cwd, "src"), { recursive: true });
  fs.writeFileSync(path.join(h.ctx.cwd, "src", "jwt.ts"), "decode(token)\n", "utf-8");
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  for (const id of ["H-0001", "H-0002"]) {
    await h.run(`evidence ${id} code-slice "decode(token)" file=src/jwt.ts line=1`);
    await h.run(`confirm ${id} reason="no verify() on the decode path"`);
  }
}

test("next is blocked while a combination pass is due, and consolidate clears it", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await twoConfirmed(h);

  const blocked = await h.run("next");
  assert.match(blocked, /BLOCKED: a consolidation pass is due/);
  assert.equal(load(cwd).snapshot.selections.length, 0);

  const pass = await h.run("consolidate");
  assert.match(pass, /CONSOLIDATION PASS — round 0, trigger: new-finding/);
  assert.match(pass, /both cite src\/jwt\.ts/);
  assert.match(pass, /Recorded: pass at round 0/);
  assert.equal(load(cwd).snapshot.consolidations.length, 1);

  // Both findings have verdicts, so there is nothing to schedule — the point
  // is that the consolidation block is gone.
  const after = await h.run("next");
  assert.doesNotMatch(after, /BLOCKED: a consolidation pass is due/);
});

test("consolidate --force runs a pass even when not due", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await twoConfirmed(h);
  await h.run("consolidate");
  assert.match(await h.run("consolidate"), /not due:/);
  assert.match(await h.run("consolidate --force"), /trigger: manual/);
  assert.equal(load(cwd).snapshot.consolidations.length, 2);
});

test("combine inserts a typed combination and reports its lineage", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await twoConfirmed(h);
  await h.run("consolidate");

  const out = await h.run(
    'combine kind=shared-root-cause spawnedFrom=H-0001,H-0002 category=auth-bypass "both handlers share one decode helper that never calls verify()"',
  );
  assert.match(out, /Added H-0003 \(shared-root-cause, auth-bypass\)/);
  assert.match(out, /derived from: H-0001 \+ H-0002/);
  assert.match(out, /\/hypothesis verify H-0003/);

  const node = load(cwd).snapshot.byId.get("H-0003")!;
  assert.equal(node.combinationKind, "shared-root-cause");
  assert.deepEqual(node.spawnedFrom, ["H-0001", "H-0002"]);
});

test("combine without kind or description prints the usage", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await twoConfirmed(h);
  assert.match(await h.run("combine"), /Usage: \/hypothesis combine/);
  assert.match(await h.run('combine "an assertion that is long enough to pass"'), /Usage: \/hypothesis combine/);
});

test("combine refuses an unconfirmed source", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  const out = await h.run(
    'combine kind=shared-root-cause spawnedFrom=H-0001,H-0002 category=auth-bypass "both handlers share one decode helper that never calls verify()"',
  );
  assert.match(out, /REJECTED/);
  assert.match(out, /speculation stacked on speculation/);
});

test("status reports the combination state and the dueness", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await twoConfirmed(h);
  const before = await h.run("status");
  assert.match(before, /combinations: 0 pass\(es\), none yet, 0 pair\(s\) examined, nothing produced/);
  assert.match(before, /COMBINATION DUE/);

  await h.run("consolidate");
  await h.run(
    'combine kind=shared-root-cause spawnedFrom=H-0001,H-0002 category=auth-bypass "both handlers share one decode helper that never calls verify()"',
  );
  const after = await h.run("status");
  assert.match(after, /combinations: 1 pass\(es\), last at round 0 \(new-finding\), 1 pair\(s\) examined, produced 1 shared-root-cause/);
});

test("the tree view marks a combination node as an inference", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await twoConfirmed(h);
  await h.run("consolidate");
  await h.run(
    'combine kind=shared-root-cause spawnedFrom=H-0001,H-0002 category=auth-bypass "both handlers share one decode helper that never calls verify()"',
  );
  const out = await h.run("tree");
  assert.match(out, /auth-bypass\+shared/);
  assert.match(out, /both handlers share one decode helper/);
});
