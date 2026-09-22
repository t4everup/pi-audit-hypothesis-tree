const fs = require("fs");
const p = "D:/Ai/pi-audit-hypothesis-tree/tests/command.test.ts";
let s = fs.readFileSync(p, "utf-8");
s += `
// -----------------------------------------------------------------
// A contract flag on a /loop is REFUSED, not ignored
// -----------------------------------------------------------------
//
// `/loop` has no finish line, so every contract clause is meaningless to it. They
// used to be built and then dropped by an \`isGoal ? ... : {}\` spread, so someone
// who typed \`severity=high preAuth=1\` saw a loop start and reasonably concluded
// the run was scoped. It was not, and nothing said so.

test("/loop REFUSES a contract flag instead of silently dropping it", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(\`new "\${ROOT}" category=auth-bypass\`);

  const out = await h.runCommand("loop", '"audit" severity=high preAuth=1');
  assert.match(out, /REJECTED: \\/loop does not take contract flags/);
  assert.match(out, /severity, requirePreAuth/, "and it names exactly which ones");
  assert.match(out, /A \\/loop has no finish line/);
  assert.match(out, /NOTHING WAS STARTED/);
  // The two ways forward, both named with the flags it just rejected.
  assert.match(out, /\\/goal "<objective>" severity=<value> requirePreAuth=<value>/);
  assert.match(out, /\\/loop "<objective>" focus=<class>,<class>/);
  // And nothing was actually started.
  assert.equal(load(cwd).snapshot.loop, null);
});

test("/loop explains the category= → focus= difference when that is what you typed", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(\`new "\${ROOT}" category=auth-bypass\`);
  const out = await h.runCommand("loop", '"audit" category=ssrf,sqli');
  assert.match(out, /category= is a contract FILTER/);
  assert.match(out, /focus= is a PREFERENCE/);
  assert.match(out, /still recorded, because a pre-auth RCE is often reached by chaining/);
  assert.equal(load(cwd).snapshot.loop, null);
});

test("/loop still accepts focus, maxRounds and plateau", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(\`new "\${ROOT}" category=auth-bypass\`);
  const out = await h.runCommand("loop", '"audit" focus=ssrf maxRounds=5 plateau=3');
  assert.doesNotMatch(out, /REJECTED/);
  const loop = load(cwd).snapshot.loop!;
  assert.deepEqual(loop.focus, ["ssrf"]);
  assert.equal(loop.maxRounds, 5);
  assert.equal(loop.plateauWindow, 3);
  assert.equal(loop.contract, null, "a /loop still has no contract");
});

test("/goal still accepts the same flags", async () => {
  const cwd = tmpProject();
  const h = harness(cwd);
  await h.run(\`new "\${ROOT}" category=auth-bypass\`);
  const out = await h.runCommand("goal", '"audit" severity=high preAuth=1');
  assert.doesNotMatch(out, /does not take contract flags/);
  const contract = load(cwd).snapshot.loop!.contract!;
  assert.equal(contract.minSeverity, "high");
  assert.equal(contract.requirePreAuth, true);
});

test("/loop help does not advertise the contract flags", async () => {
  const h = harness(tmpProject());
  const out = await h.runCommand("loop", "help");
  assert.match(out, /\\/loop \\["<objective>"\\] \\[maxRounds=0\\] \\[plateau=8\\] \\[focus=a,b\\]/);
  assert.doesNotMatch(out, /\\/loop \\["<objective>"\\][^\\n]*reproduced=1/);
});
`;
fs.writeFileSync(p, s);
console.log("ok");
