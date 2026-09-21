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
  hasUI: boolean;
  ui: {
    notify: (message: string, type?: "info" | "warning" | "error") => void;
    setWidget: (key: string, content: string[] | undefined, options?: unknown) => void;
  };
}

function harness(cwd: string, opts: { failSend?: string } = {}): {
  commands: Map<string, RegisteredCommand>;
  tools: Map<string, unknown>;
  hooks: Map<string, unknown>;
  sent: string[];
  ctx: FakeCtx;
  run: (args: string) => Promise<string>;
  runCommand: (name: string, args: string) => Promise<string>;
  lastNotify: () => string;
} {
  const commands = new Map<string, RegisteredCommand>();
  const notifications: string[] = [];
  const tools = new Map<string, unknown>();
  const hooks = new Map<string, unknown>();
  const sent: string[] = [];
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
    // Stage 5: the extension subscribes to agent_settled and can send a round
    // brief. This file drives the COMMAND surface, so the event bus is a stub
    // (tests/loop.test.ts exercises the round engine itself).
    on: (event: string, handler: unknown) => {
      hooks.set(event, handler);
      return () => hooks.delete(event);
    },
    sendUserMessage: (content: string) => {
      // Stage 5 regression: pi rejects a send while the agent is still
      // processing ("Agent is already processing"). The driver must survive
      // that, so the failure is injectable here.
      if (opts.failSend) throw new Error(opts.failSend);
      sent.push(content);
    },
    exec: async () => ({ stdout: "", stderr: "", code: 0 }),
  };
  // The real ExtensionAPI has many more members; the extension must only need
  // registerCommand/registerTool/exec at load time.
  hypothesisTreeExtension(pi as never);

  const ctx: FakeCtx = {
    cwd,
    hasUI: false,
    ui: {
      notify: (message: string) => {
        notifications.push(message);
      },
      setWidget: () => {},
    },
  };

  return {
    commands,
    tools,
    hooks,
    sent,
    ctx,
    /** Drive one command by name and return everything it notified. */
    runCommand: async (name: string, args: string) => {
      notifications.length = 0;
      const command = commands.get(name);
      assert.ok(command, `/${name} must be registered`);
      await command!.handler(args, ctx);
      return notifications.join("\n");
    },
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

// -----------------------------------------------------------------
// Stage 5 — /goal and /loop through the command layer
// -----------------------------------------------------------------


test("/goal and /loop are registered with their own verb sets", () => {
  const h = harness(tmpProject());
  assert.ok(h.commands.has("goal"));
  assert.ok(h.commands.has("loop"));
  const verbs = h.commands.get("goal")!.getArgumentCompletions!("")!.map((a) => a.value.trim());
  for (const v of ["status", "pause", "resume", "stop", "next", "tree", "log"]) {
    assert.ok(verbs.includes(v), `missing ${v}`);
  }
  assert.match(h.commands.get("goal")!.description!, /completion contract/);
  assert.match(h.commands.get("loop")!.description!, /until stopped or the well runs dry/);
});

test("an agent_settled hook is registered", () => {
  const h = harness(tmpProject());
  assert.ok(h.hooks.has("agent_settled"), "the round driver must subscribe to agent_settled (agent_end fires while the agent is still processing)");
});

test("/goal with no tree bootstraps a SCOPE root and starts with a recon round", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  const out = await h.runCommand("goal", '"audit the login flow"');
  assert.match(out, /Goal started: audit the login flow/);
  assert.match(out, /no tree existed, so a SCOPE root was created/);
  assert.match(out, /ROUND 1 — read the project \(recon\)/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.rootId, "H-0001");
  assert.equal(snap.byId.get("H-0001")!.nodeKind, "scope", "the root is a boundary, not an unfalsifiable claim");
  assert.equal(snap.loop!.status, "running");
  assert.equal(snap.roundRecords[0]!.kind, "recon");

  assert.equal(h.sent.length, 1);
  assert.match(h.sent[0]!, /\[AUDIT ROUND 1 — RECON\]/);
  assert.match(h.sent[0]!, /call hypothesis_recon/);
});

test("/goal starts, records round 1, and sends the brief to the model", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');

  const out = await h.runCommand("goal", '"audit the login flow" confirmed=1 severity=high requireChallenged=false');
  assert.match(out, /Goal started: audit the login flow/);
  assert.match(out, /contract: at least 1 confirmed finding\(s\) at severity >= high/);
  assert.match(out, /ROUND 1 — verify H-0001/);
  assert.match(out, /findings ledger: /);

  assert.equal(h.sent.length, 1, "the brief is handed to the model as a user message");
  assert.match(h.sent[0]!, /\[AUDIT ROUND 1 — VERIFY\]/);
  assert.match(h.sent[0]!, /YOUR NODE: H-0001/);
  assert.match(h.sent[0]!, /Contract: at least 1 confirmed finding\(s\), at severity >= high/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.kind, "goal");
  assert.equal(snap.loop!.status, "running");
  assert.equal(snap.loop!.round, 1);
  assert.equal(snap.loop!.awaitingRound, 1);
  assert.equal(snap.loop!.contract!.minSeverity, "high");
});

test("/loop with no objective reuses the tree's objective", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const out = await h.runCommand("loop", "");
  assert.match(out, /Loop started: the login handler accepts a JWT/);
  assert.match(out, /unbounded; plateau after 8 unproductive rounds/);
  assert.equal(load(cwd).snapshot.loop!.contract, null, "a /loop has no finish line");
  assert.equal(load(cwd).snapshot.loop!.kind, "loop");
});

test("/loop status reports the loop and the tree", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", "");
  const out = await h.runCommand("loop", "status");
  assert.match(out, /Audit loop: RUNNING/);
  assert.match(out, /round 1 \(unbounded\)/);
  assert.match(out, /Hypothesis tree T-/);
});

test("/loop pause stops the driver from advancing", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", "");
  assert.equal(h.sent.length, 1);

  assert.match(await h.runCommand("loop", "pause"), /Paused at round 1/);
  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 1, "a paused loop must not send another brief");

  assert.match(await h.runCommand("loop", "resume"), /Resumed at round 1/);
  assert.equal(h.sent.length, 2, "resuming runs the next round immediately");
});

test("/loop stop ends it and the driver stands down", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", "");
  assert.match(await h.runCommand("loop", "stop"), /Stopped at round 1/);
  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 1);
  assert.equal(load(cwd).snapshot.loop!.status, "stopped");
});

test("the agent_settled driver advances the loop and sends the next brief", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("loop", "");
  assert.equal(h.sent.length, 1);

  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 2, "the finished turn starts the next round");
  assert.match(h.sent[1]!, /\[AUDIT ROUND 2 — VERIFY\]/);
  assert.match(h.sent[1]!, /Last round \(1\): H-0001 produced no verdict and no new evidence/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.round, 2);
  assert.equal(snap.loop!.stallRounds, 1);
  assert.equal(snap.roundRecords.length, 2);
});

test("the driver does nothing when no round is in flight", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;

  // No loop at all.
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 0);

  // A loop that has not sent a round yet.
  const { startLoop } = await import("../extensions/hypothesis-tree/loop.ts");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: ROOT });
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 0, "awaitingRound is null, so this turn is not ours");
});

test("the plateau stops a driven /loop with a readable reason", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("loop", "plateau=2");
  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;

  await driver({ type: "agent_settled" }, h.ctx);
  await driver({ type: "agent_settled" }, h.ctx);
  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.status, "stopped");
  assert.match(snap.loop!.stopReason!, /plateau/);
  assert.match(snap.loop!.stopReason!, /the well looks dry/);
  assert.equal(h.sent.length, 2, "no further brief after the plateau");
});

test("/goal completes when the contract is met, and says so", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("goal", '"audit the login flow" confirmed=1 severity=high requireChallenged=false');

  // The model does its job during the round: evidence, a severity, a verdict.
  await h.run('evidence H-0001 code-slice "decode(token)" file=src/auth/jwt.ts line=57');
  await h.run('confirm H-0001 severity=high reason="no verify() on the decode path"');
  await h.run("consolidate");

  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);

  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.status, "complete", snap.loop!.stopReason);
  assert.match(snap.loop!.stopReason!, /contract satisfied at round 1/);
});

test("/goal and /loop are registered with their own verb sets", () => {
  const h = harness(tmpProject());
  assert.ok(h.commands.has("goal"));
  assert.ok(h.commands.has("loop"));
  const verbs = h.commands.get("goal")!.getArgumentCompletions!("")!.map((a) => a.value.trim());
  for (const v of ["status", "pause", "resume", "stop", "next", "tree", "log"]) {
    assert.ok(verbs.includes(v), `missing ${v}`);
  }
  assert.match(h.commands.get("goal")!.description!, /completion contract/);
  assert.match(h.commands.get("loop")!.description!, /until stopped or the well runs dry/);
});

test("an agent_settled hook is registered", () => {
  const h = harness(tmpProject());
  assert.ok(h.hooks.has("agent_settled"), "the round driver must subscribe to agent_settled (agent_end fires while the agent is still processing)");
});

test("/goal with no tree bootstraps a SCOPE root and starts with a recon round", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  const out = await h.runCommand("goal", '"audit the login flow"');
  assert.match(out, /Goal started: audit the login flow/);
  assert.match(out, /no tree existed, so a SCOPE root was created/);
  assert.match(out, /ROUND 1 — read the project \(recon\)/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.rootId, "H-0001");
  assert.equal(snap.byId.get("H-0001")!.nodeKind, "scope", "the root is a boundary, not an unfalsifiable claim");
  assert.equal(snap.loop!.status, "running");
  assert.equal(snap.roundRecords[0]!.kind, "recon");

  assert.equal(h.sent.length, 1);
  assert.match(h.sent[0]!, /\[AUDIT ROUND 1 — RECON\]/);
  assert.match(h.sent[0]!, /call hypothesis_recon/);
});

test("/goal starts, records round 1, and sends the brief to the model", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');

  const out = await h.runCommand("goal", '"audit the login flow" confirmed=1 severity=high requireChallenged=false');
  assert.match(out, /Goal started: audit the login flow/);
  assert.match(out, /contract: at least 1 confirmed finding\(s\) at severity >= high/);
  assert.match(out, /ROUND 1 — verify H-0001/);
  assert.match(out, /findings ledger: /);

  assert.equal(h.sent.length, 1, "the brief is handed to the model as a user message");
  assert.match(h.sent[0]!, /\[AUDIT ROUND 1 — VERIFY\]/);
  assert.match(h.sent[0]!, /YOUR NODE: H-0001/);
  assert.match(h.sent[0]!, /Contract: at least 1 confirmed finding\(s\), at severity >= high/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.kind, "goal");
  assert.equal(snap.loop!.status, "running");
  assert.equal(snap.loop!.round, 1);
  assert.equal(snap.loop!.awaitingRound, 1);
  assert.equal(snap.loop!.contract!.minSeverity, "high");
});

test("/loop with no objective reuses the tree's objective", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const out = await h.runCommand("loop", "");
  assert.match(out, /Loop started: the login handler accepts a JWT/);
  assert.match(out, /unbounded; plateau after 8 unproductive rounds/);
  assert.equal(load(cwd).snapshot.loop!.contract, null, "a /loop has no finish line");
  assert.equal(load(cwd).snapshot.loop!.kind, "loop");
});

test("/loop status reports the loop and the tree", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", "");
  const out = await h.runCommand("loop", "status");
  assert.match(out, /Audit loop: RUNNING/);
  assert.match(out, /round 1 \(unbounded\)/);
  assert.match(out, /Hypothesis tree T-/);
});

test("/loop pause stops the driver from advancing", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", "");
  assert.equal(h.sent.length, 1);

  assert.match(await h.runCommand("loop", "pause"), /Paused at round 1/);
  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 1, "a paused loop must not send another brief");

  assert.match(await h.runCommand("loop", "resume"), /Resumed at round 1/);
  assert.equal(h.sent.length, 2, "resuming runs the next round immediately");
});

test("/loop stop ends it and the driver stands down", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", "");
  assert.match(await h.runCommand("loop", "stop"), /Stopped at round 1/);
  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 1);
  assert.equal(load(cwd).snapshot.loop!.status, "stopped");
});

test("the agent_settled driver advances the loop and sends the next brief", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("loop", "");
  assert.equal(h.sent.length, 1);

  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 2, "the finished turn starts the next round");
  assert.match(h.sent[1]!, /\[AUDIT ROUND 2 — VERIFY\]/);
  assert.match(h.sent[1]!, /Last round \(1\): H-0001 produced no verdict and no new evidence/);

  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.round, 2);
  assert.equal(snap.loop!.stallRounds, 1);
  assert.equal(snap.roundRecords.length, 2);
});

test("the driver does nothing when no round is in flight", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;

  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 0);

  const { startLoop } = await import("../extensions/hypothesis-tree/loop.ts");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: ROOT });
  await driver({ type: "agent_settled" }, h.ctx);
  assert.equal(h.sent.length, 0, "awaitingRound is null, so this turn is not ours");
});

test("the plateau stops a driven /loop with a readable reason", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("loop", "plateau=2");
  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;

  await driver({ type: "agent_settled" }, h.ctx);
  await driver({ type: "agent_settled" }, h.ctx);
  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.status, "stopped");
  assert.match(snap.loop!.stopReason!, /plateau/);
  assert.match(snap.loop!.stopReason!, /the well looks dry/);
  assert.equal(h.sent.length, 2, "no further brief after the plateau");
});

test("/goal completes when the contract is met, and says so", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("goal", '"audit the login flow" confirmed=1 severity=high requireChallenged=false');

  await h.run('evidence H-0001 code-slice "decode(token)" file=src/auth/jwt.ts line=57');
  await h.run('confirm H-0001 severity=high reason="no verify() on the decode path"');
  await h.run("consolidate");

  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);

  const snap = load(cwd).snapshot;
  assert.equal(snap.loop!.status, "complete", snap.loop!.stopReason);
  assert.match(snap.loop!.stopReason!, /contract satisfied at round 1/);
});

test("/loop next runs exactly one round on demand", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("loop", "");
  assert.equal(load(cwd).snapshot.loop!.round, 1);
  await h.runCommand("loop", "next");
  assert.equal(load(cwd).snapshot.loop!.round, 2);
  assert.equal(h.sent.length, 2);
});

test("/loop next without a loop is refused", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  assert.match(await h.runCommand("loop", "next"), /No audit loop is running/);
});

test("/loop log reads the findings ledger, and says so when there is none", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  assert.match(await h.runCommand("loop", "log"), /No findings ledger yet/);
  await h.runCommand("loop", "");
  const out = await h.runCommand("loop", "log");
  assert.match(out, /Findings ledger \(tail of/);
  assert.match(out, /## Round 1 — /);
});

test("/loop tree renders the tree with evidence", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.run('evidence H-0001 code-slice "decode(token)" file=src/auth/jwt.ts line=57');
  const out = await h.runCommand("loop", "tree");
  assert.match(out, /src\/auth\/jwt\.ts:57/);
  assert.match(out, /Hypothesis tree T-/);
});

test("a second /goal is refused while one is RUNNING", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("goal", '"first objective"');
  const out = await h.runCommand("goal", '"second objective"');
  assert.match(out, /REJECTED/);
  assert.match(out, /already RUNNING/);
  assert.match(out, /\/goal resume|\/goal status/);
});

test("/goal start RESUMES a paused goal rather than rejecting it", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("goal", '"an objective"');
  await h.runCommand("goal", "pause");
  const out = await h.runCommand("goal", "start");
  assert.doesNotMatch(out, /REJECTED/);
  assert.match(out, /Resumed the paused goal/);
  assert.match(out, /nothing was reset/);
  assert.match(out, /\/goal stop first/);
});

test("/loop pause twice says what to do instead of restating the state", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", '"an objective"');
  await h.runCommand("loop", "pause");
  const out = await h.runCommand("loop", "pause");
  assert.match(out, /ALREADY PAUSED/);
  assert.match(out, /\/loop resume/);
});

test("/loop start RESUMES a paused loop — the exact flow that used to be rejected", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", '"audit the project"');
  await h.runCommand("loop", "pause");

  const out = await h.runCommand("loop", "start");
  assert.doesNotMatch(out, /REJECTED/);
  assert.match(out, /Resumed the paused loop at round 1/);
  assert.match(out, /nothing was reset/);
  assert.match(out, /\/loop stop first/);
  // And it actually continues: the next round is prepared in the same turn.
  assert.match(out, /ROUND 2/);

  // The second warning in the old flow was `/loop pause` run when already
  // paused, so that message is fixed too.
  await h.runCommand("loop", "pause");
  const twice = await h.runCommand("loop", "pause");
  assert.match(twice, /ALREADY PAUSED at round \d+/);
  assert.match(twice, /\/loop resume/);
});

test("/loop start on a STOPPED loop starts a fresh one, keeping the tree", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", '"first"');
  await h.runCommand("loop", "stop");
  const out = await h.runCommand("loop", '"second"');
  assert.match(out, /Loop started: second/);
  assert.doesNotMatch(out, /Resumed/);
  assert.match(out, /ROUND 1/);
});

test("/loop start with no objective reuses the LOOP's, not the tree's", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  // The tree objective and the loop objective are deliberately different: the
  // tree one comes from whatever created the root, the loop one is what the
  // user actually asked for.
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", '"audit the project"');
  await h.runCommand("loop", "pause");
  const out = await h.runCommand("loop", "start");
  assert.match(out, /Resumed the paused loop at round 1: audit the project/);
});

test("/goal help prints the surface", async () => {
  const h = harness(tmpProject());
  const out = await h.runCommand("goal", "help");
  assert.match(out, /the audit round engine/);
  assert.match(out, /\/goal "<objective>" \[confirmed=1\] \[severity=high\]/);
  assert.match(out, /A round: the scheduler picks a hypothesis/);
});

test("/hypothesis status now includes the loop block", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", "");
  const out = await h.run("status");
  assert.match(out, /Audit loop: RUNNING/);
});

// -----------------------------------------------------------------
// Stage 6 — recon through the command layer
// -----------------------------------------------------------------

const NOTE_PARAGRAPHS = [
  "The project is a small Node service. It exposes three HTTP routes under /api: login, refresh and export, and it consumes one queue topic named order.created.",
  "Authentication is a JWT bearer token. The middleware under src/auth/ decodes the token and attaches the payload to the request, and the routes read the payload directly.",
  "The export route returns records selected by an id taken from the query string. I could not find an ownership check between the id and the caller in the time available.",
  "The queue consumer deserializes the message body with a generic parser. I did not read the parser itself, so I cannot say whether it restricts the types it will construct.",
].join("\n\n");

test("/hypothesis recon with no note explains how to supply one", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const out = await h.run("recon");
  assert.match(out, /recon: not run yet/);
  assert.match(out, /No recon note yet/);
  assert.match(out, /\/hypothesis recon file=/);
});

test("/hypothesis recon submits an inline note and lists the segments", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const out = await h.run(`recon "${NOTE_PARAGRAPHS}"`);
  assert.match(out, /Recon note recorded: \d+ chars → \d+ segment\(s\)/);
  assert.match(out, /S-000-[0-9a-f]{8}/);
  assert.equal(load(cwd).snapshot.segments.length >= 1, true);
});

test("/hypothesis recon reads a note from a file", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const notePath = path.join(cwd, "notes.md");
  fs.writeFileSync(notePath, NOTE_PARAGRAPHS, "utf-8");
  const out = await h.run(`recon file=${notePath}`);
  assert.match(out, /Recon note recorded/);
  assert.ok(fs.existsSync(path.join(cwd, ".pi-hypothesis", "recon.md")), "the note is copied for human review");
});

test("/hypothesis recon reports an unreadable file instead of submitting nothing", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  const out = await h.run(`recon file=${path.join(cwd, "missing.md")}`);
  assert.match(out, /Could not read/);
  assert.equal(load(cwd).snapshot.segments.length, 0);
});

test("/hypothesis recon refuses a note that is too short", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  assert.match(await h.run('recon "it is a web app"'), /REJECTED.*too short/s);
});

test("/hypothesis recon with no note shows the coverage once segments exist", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run(`recon "${NOTE_PARAGRAPHS}"`);
  const out = await h.run("recon");
  assert.match(out, /recon: 0\/\d+ segment\(s\) covered/);
  assert.match(out, /open\s+S-000-/);
  assert.match(out, /note: .*recon\.md/);
});

test("/hypothesis segments lists each segment, its state and what it produced", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  assert.match(await h.run("segments"), /No recon segments yet/);

  await h.run(`recon "${NOTE_PARAGRAPHS}"`);
  const before = await h.run("segments");
  assert.match(before, /open\s+S-000-/);

  const segmentId = load(cwd).snapshot.segments[0]!.id;
  await h.run(
    `add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass segmentId=${segmentId} ` +
      `entrypoint="POST /api/refresh" technique="alg=none"`,
  );
  const after = await h.run("segments");
  assert.match(after, /covered\s+S-000-/);
  assert.match(after, /H-0002 \[pending\].*POST \/api\/refresh/);
});

test("/hypothesis status includes the recon coverage line", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  assert.match(await h.run("status"), /recon: not run yet/);
  await h.run(`recon "${NOTE_PARAGRAPHS}"`);
  assert.match(await h.run("status"), /recon: 0\/\d+ segment\(s\) covered/);
});

test("the tree view marks a scope node and shows an attack vector", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.runCommand("goal", '"audit the login flow"');
  const out = await h.run("tree");
  assert.match(out, /H-0001 \[pending {2}\] other SCOPE d0 e0/, "the scope root is marked");
});

test("the tree view shows the vector inline and expands it with --evidence", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run(
    `add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass ` +
      `entrypoint="POST /api/refresh" technique="alg=none JWT forgery"`,
  );
  const inline = await h.run("tree");
  assert.match(inline, /→POST \/api\/refresh/);

  const expanded = await h.run("tree --evidence");
  assert.match(expanded, /→ entrypoint: POST \/api\/refresh/);
  assert.match(expanded, /technique: alg=none JWT forgery/);
});

// -----------------------------------------------------------------
// The send-failure regression
// -----------------------------------------------------------------
//
// Field bug (2026-09-21, Centreon Web): round 1 completed, round 2 was prepared
// and its fence written, and then the send was REJECTED because the driver was
// subscribed to `agent_end` — which pi fires while the agent is still
// processing. The brief never reached the model, no turn was in flight, so no
// further lifecycle event could ever fire: the loop sat at "running, round 2"
// forever and `/goal start` refused to replace it.
//
// Two things are pinned here: the driver uses `agent_settled`, and a send that
// still fails PARKS the loop with the fence cleared instead of stranding it.

test("the driver subscribes to agent_settled, not agent_end", () => {
  const h = harness(tmpProject());
  assert.equal(h.hooks.has("agent_settled"), true);
  assert.equal(h.hooks.has("agent_end"), false, "agent_end fires while the agent is still processing");
});

test("a rejected brief send PARKS the loop with the fence cleared", async () => {
  const cwd = tmpProject();
  const h = harness(cwd, { failSend: "Agent is already processing. Specify streamingBehavior ('steer' or 'followUp') to queue the message." });
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');

  const out = await h.runCommand("goal", '"audit the login flow"');
  assert.match(out, /could NOT be sent/);
  assert.match(out, /Agent is already processing/);
  assert.match(out, /The loop is PAUSED/);
  assert.match(out, /resume to re-offer the same work/);

  const loop = load(cwd).snapshot.loop!;
  assert.equal(loop.status, "paused", "a failed send must not leave the loop claiming to run");
  assert.equal(loop.awaitingRound, null, "the fence must be cleared — no turn is in flight for that round");
  assert.match(loop.pausedReason!, /could not be delivered/);
});

test("the driver parks the loop when a send is rejected mid-run", async () => {
  const cwd = tmpProject();
  // The FIRST send (from the command) succeeds; the driver's send fails.
  let allow = true;
  const h = harness(cwd);
  const originalSend = (h as unknown as { sent: string[] }).sent;
  void originalSend;
  const piSend = h.sent;
  void piSend;
  // Rebuild the harness with a send that fails only after the first call.
  const cwd2 = tmpProject();
  const commands = new Map<string, RegisteredCommand>();
  const tools = new Map<string, unknown>();
  const hooks = new Map<string, unknown>();
  const sent: string[] = [];
  let calls = 0;
  const pi = {
    registerCommand: (n: string, o: RegisteredCommand) => commands.set(n, o),
    registerTool: (t: { name: string }) => tools.set(t.name, t),
    on: (e: string, fn: unknown) => {
      hooks.set(e, fn);
      return () => hooks.delete(e);
    },
    sendUserMessage: (c: string) => {
      calls++;
      if (calls > 1) throw new Error("Agent is already processing.");
      sent.push(c);
    },
    exec: async () => ({ stdout: "", stderr: "", code: 0 }),
  };
  hypothesisTreeExtension(pi as never);
  const ctx: FakeCtx = { cwd: cwd2, hasUI: false, ui: { notify: () => {}, setWidget: () => {} } };
  await commands.get("hypothesis")!.handler(`new "${ROOT}" category=auth-bypass`, ctx);
  await commands.get("goal")!.handler('"audit the login flow"', ctx);
  assert.equal(sent.length, 1, "round 1 was delivered");
  assert.equal(load(cwd2).snapshot.loop!.awaitingRound, 1);

  // The turn settles; the driver tries to send round 2 and is rejected.
  const driver = hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, ctx);

  const loop = load(cwd2).snapshot.loop!;
  assert.equal(loop.status, "paused");
  assert.equal(loop.awaitingRound, null);
  assert.match(loop.pausedReason!, /round 2 was recorded but its brief could not be delivered/);
  void allow;
  void h;
});

test("/goal resume recovers a loop parked by a failed send", async () => {
  const cwd = tmpProject();
  const h = harness(cwd, { failSend: "Agent is already processing." });
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("goal", '"audit the login flow"');
  assert.equal(load(cwd).snapshot.loop!.status, "paused");

  // A fresh harness whose sends work: the user has fixed the condition.
  const h2 = harness(cwd);
  const out = await h2.runCommand("goal", "resume");
  assert.match(out, /Resumed at round 1/);
  const loop = load(cwd).snapshot.loop!;
  assert.equal(loop.status, "running");
  assert.equal(loop.awaitingRound, 2, "the next round is now in flight");
  assert.equal(h2.sent.length, 1, "and its brief was delivered");
});

// -----------------------------------------------------------------
// A terminal tick must not be silent
// -----------------------------------------------------------------
//
// Field report (2026-09-21, Centreon Web): the goal completed and the ONLY
// signal was the widget glyph changing to ✓. The tick's terminal paths return
// neither a summary nor a brief, so the driver's notify branches were both
// skipped and nothing was said.

test("a completing tick notifies with the reason and the unexamined count", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("goal", '"audit the login flow" confirmed=1 requireConsolidated=false requireChallenged=false');

  // The model does the round's work: confirm the first hypothesis.
  await h.run('evidence H-0001 code-slice "decode(token)" file=src/auth.ts line=1');
  await h.run("confirm H-0001 severity=high reason=\"no verify() on the decode path\"");

  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);

  const out = h.lastNotify();
  assert.match(out, /Audit COMPLETE: contract satisfied at round 1/, out);
  assert.match(out, /1 confirmed, 1 hypothesis\(es\) still UNEXAMINED/, "the leftovers are named, not hidden");
  assert.match(out, /the contract was the finish line, not "examine everything"/);
  assert.match(out, /\/goal start "<objective>" confirmed=<more>/);
  assert.match(out, /\/loop for an unbounded run/);
  assert.equal(load(cwd).snapshot.loop!.status, "complete");
});

test("a completing tick with nothing left over does not nag", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("goal", '"audit the login flow" confirmed=1 requireConsolidated=false requireChallenged=false');
  await h.run('evidence H-0001 code-slice "decode(token)" file=src/auth.ts line=1');
  await h.run("confirm H-0001 severity=high reason=\"x\"");

  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx);
  const out = h.lastNotify();
  assert.match(out, /Audit COMPLETE/);
  assert.doesNotMatch(out, /UNEXAMINED/, "no leftover nag when the tree is fully worked");
});

test("a plateau stop notifies as a warning with its reason", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.run('add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass');
  await h.runCommand("loop", "plateau=1 maxRounds=99");

  const driver = h.hooks.get("agent_settled") as (e: unknown, c: unknown) => Promise<void>;
  await driver({ type: "agent_settled" }, h.ctx); // round 1 unproductive -> plateau
  const out = h.lastNotify();
  assert.match(out, /Audit STOPPED: plateau/, out);
  assert.match(out, /the well looks dry/);
  assert.equal(load(cwd).snapshot.loop!.status, "stopped");
});

// -----------------------------------------------------------------
// Closing the widget panel
// -----------------------------------------------------------------

test("/loop dismiss closes the widget and keeps the audit", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", '"audit the project"');
  const out = await h.runCommand("loop", "dismiss");
  assert.match(out, /Widget hidden/);
  assert.match(out, /still running/);
  assert.match(out, /\/loop show brings the widget back/);
  // The loop itself is untouched: dismissing a panel is not discarding an audit.
  assert.equal(load(cwd).snapshot.loop!.status, "running");
});

test("/loop hide and /loop close are the same verb", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", '"audit the project"');
  assert.match(await h.runCommand("loop", "hide"), /Widget hidden/);
  assert.match(await h.runCommand("loop", "show"), /Widget shown again/);
  assert.match(await h.runCommand("loop", "close"), /Widget hidden/);
});

test("/loop dismiss with nothing to dismiss says so instead of pretending", async () => {
  const h = harness(tmpProject());
  assert.match(await h.runCommand("loop", "dismiss"), /no widget to close/);
});

test("/loop show is refused when the widget is already up", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(`new "${ROOT}" category=auth-bypass`);
  await h.runCommand("loop", '"audit the project"');
  assert.match(await h.runCommand("loop", "show"), /already showing/);
});

test("/loop help lists dismiss and show", async () => {
  const h = harness(tmpProject());
  const out = await h.runCommand("loop", "help");
  assert.match(out, /\/loop dismiss\s+close the widget panel/);
  assert.match(out, /\/loop show\s+bring a closed widget back/);
});
