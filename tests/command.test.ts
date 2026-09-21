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
  ctx: FakeCtx;
  run: (args: string) => Promise<string>;
  lastNotify: () => string;
} {
  const commands = new Map<string, RegisteredCommand>();
  const notifications: string[] = [];
  const pi = {
    registerCommand: (name: string, options: RegisteredCommand) => {
      commands.set(name, options);
    },
  };
  // The real ExtensionAPI has many more members; the extension must only need
  // registerCommand at load time.
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
  assert.deepEqual(filtered.map((a) => a.value.trim()), ["confirm", "compact"]);
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
