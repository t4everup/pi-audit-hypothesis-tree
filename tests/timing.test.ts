// pi-audit-hypothesis-tree — tests/timing.test.ts
//
// Pins the clock: how long a loop has been running, how much of that it was
// actually able to work, and the two ways a duration can lie.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import {
  inFlightAge,
  pauseLoop,
  renderLoopStatus,
  renderWidget,
  resumeLoop,
  shortTiming,
  startLoop,
  stopLoop,
  tickLoop,
} from "../extensions/hypothesis-tree/loop.ts";
import { renderReport } from "../extensions/hypothesis-tree/report.ts";
import { describeTiming, formatDuration, loopTiming } from "../extensions/hypothesis-tree/types.ts";
import type { AuditLoopState } from "../extensions/hypothesis-tree/types.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-timing-"));
}

/** A fixed epoch so every assertion is arithmetic, not a race with the clock. */
const T0 = Date.parse("2026-03-01T10:00:00.000Z");
const at = (minutes: number): string => new Date(T0 + minutes * 60_000).toISOString();
const ms = (minutes: number): number => T0 + minutes * 60_000;

function seeded(cwd = tmpProject()): string {
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  addNode(cwd, { description: "the api dispatcher reaches the orchestration sink without a role check", category: "auth-bypass" });
  return cwd;
}

function started(cwd: string, kind: "goal" | "loop" = "loop"): void {
  const result = startLoop(cwd, load(cwd).snapshot, { kind, objective: "audit", plateauWindow: 99, at: at(0) });
  assert.equal(result.ok, true, result.errors.join("; "));
}

function loopOf(cwd: string): AuditLoopState {
  const loop = load(cwd).snapshot.loop;
  assert.ok(loop, "the loop should exist");
  return loop;
}

// -----------------------------------------------------------------
// formatDuration
// -----------------------------------------------------------------

test("a duration is rendered at the precision a person wants", () => {
  assert.equal(formatDuration(0), "0s");
  assert.equal(formatDuration(42_000), "42s");
  // Seconds appear only under a minute: above that they are noise that changes
  // every time the line is reprinted.
  assert.equal(formatDuration(60_000), "1m 00s");
  assert.equal(formatDuration(17 * 60_000 + 3_000), "17m 03s");
  assert.equal(formatDuration(3_600_000), "1h 00m");
  assert.equal(formatDuration(2 * 3_600_000 + 14 * 60_000), "2h 14m");
  assert.equal(formatDuration(86_400_000), "1d 0h");
  assert.equal(formatDuration(28 * 3_600_000 + 5 * 60_000), "1d 4h");
});

test("a nonsense duration is clamped, never negative", () => {
  assert.equal(formatDuration(-5_000), "0s");
  assert.equal(formatDuration(Number.NaN), "unknown");
  assert.equal(formatDuration(Number.POSITIVE_INFINITY), "unknown");
});

// -----------------------------------------------------------------
// loopTiming
// -----------------------------------------------------------------

test("active time excludes paused time — a night paused is not a night of work", () => {
  const cwd = seeded();
  started(cwd);
  pauseLoop(cwd, load(cwd).snapshot, "lunch", at(60));
  resumeLoop(cwd, load(cwd).snapshot, {}, at(180));

  const timing = loopTiming(loopOf(cwd), ms(200))!;
  assert.equal(timing.wallMs, 200 * 60_000, "wall clock: 3h 20m since the start");
  assert.equal(timing.pausedMs, 120 * 60_000, "paused: the 2h between pause and resume");
  assert.equal(timing.activeMs, 80 * 60_000, "active: 1h 20m");
});

test("a pause that is still open is counted up to the reference instant", () => {
  const cwd = seeded();
  started(cwd);
  pauseLoop(cwd, load(cwd).snapshot, "waiting on the user", at(30));

  const timing = loopTiming(loopOf(cwd), ms(90))!;
  assert.equal(timing.wallMs, 90 * 60_000);
  assert.equal(timing.pausedMs, 60 * 60_000, "the open pause is measured to `now`, not to zero");
  assert.equal(timing.activeMs, 30 * 60_000);
});

test("a loop STOPPED while paused still counts the pause it never resumed from", () => {
  const cwd = seeded();
  started(cwd);
  pauseLoop(cwd, load(cwd).snapshot, "user stopped it", at(30));
  // No resume, so there is no interval to fold into pausedMs — `endedAt` is what
  // closes the interval instead.
  stopLoop(cwd, load(cwd).snapshot, "done", at(150));

  const timing = loopTiming(loopOf(cwd), ms(9999))!;
  assert.equal(timing.activeMs, 30 * 60_000, "30m of work, then 2h paused, then stopped");
  assert.equal(timing.ended, true);
});

test("a finished loop's clock is FROZEN — it does not keep growing", () => {
  const cwd = seeded();
  started(cwd);
  stopLoop(cwd, load(cwd).snapshot, "done", at(45));

  const soon = loopTiming(loopOf(cwd), ms(45))!;
  const muchLater = loopTiming(loopOf(cwd), ms(45 + 10 * 60))!;
  assert.equal(soon.activeMs, muchLater.activeMs, "reading the status a day later must not change the answer");
  assert.equal(muchLater.activeMs, 45 * 60_000);
  assert.equal(muchLater.ended, true);
});

test("a backwards clock jump clamps at zero instead of reporting negative time", () => {
  const cwd = seeded();
  started(cwd);
  const timing = loopTiming(loopOf(cwd), ms(-500))!;
  assert.equal(timing.wallMs, 0);
  assert.equal(timing.activeMs, 0);
});

test("an unreadable start timestamp is reported as unknown, not as zero", () => {
  const cwd = seeded();
  started(cwd);
  const broken = { ...loopOf(cwd), startedAt: "not a date" };
  assert.equal(loopTiming(broken, ms(60)), null, "unknown and zero are different answers");
  assert.match(describeTiming(null, 3), /unknown/);
});

test("a rate is only claimed once there is enough active time to divide by", () => {
  const cwd = seeded();
  started(cwd);
  // 2 seconds in, 1 round: the arithmetic gives 1800 rounds/h, which is noise.
  assert.equal(loopTiming(loopOf(cwd), T0 + 2_000)!.roundsPerHour, null);
  // After an hour of active time it is a real measurement.
  const loop = { ...loopOf(cwd), round: 6 };
  const rate = loopTiming(loop, T0 + 3_600_000)!.roundsPerHour!;
  assert.equal(Math.round(rate), 6);
});

test("the paused clause is omitted when there is no paused time", () => {
  const cwd = seeded();
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 99, at: at(0) });
  const line = describeTiming(loopTiming(loopOf(cwd), ms(60))!, 0);
  assert.equal(line, "elapsed 1h 00m", "no '0m paused' clause to learn to skip");
});

// -----------------------------------------------------------------
// Transitions stamp the clock
// -----------------------------------------------------------------

test("pause, resume and stop each stamp the clock, and it survives a reload", () => {
  const cwd = seeded();
  started(cwd);
  assert.equal(loopOf(cwd).pausedAt, null, "a fresh loop is not paused");
  assert.equal(loopOf(cwd).endedAt, null, "and has not ended");

  pauseLoop(cwd, load(cwd).snapshot, "hold", at(10));
  assert.equal(loopOf(cwd).pausedAt, at(10));

  resumeLoop(cwd, load(cwd).snapshot, {}, at(25));
  assert.equal(loopOf(cwd).pausedAt, null);
  assert.equal(loopOf(cwd).pausedMs, 15 * 60_000, "banked on resume, and durable through the ledger");

  stopLoop(cwd, load(cwd).snapshot, "done", at(40));
  assert.equal(loopOf(cwd).endedAt, at(40));
});

test("a loop that stops on its own stamps endedAt too", () => {
  const cwd = seeded();
  started(cwd);
  const result = stopLoop(cwd, load(cwd).snapshot, "cap", at(5));
  assert.equal(result.ok, true);
  assert.equal(loopOf(cwd).endedAt, at(5));
});

test("a terminal tick freezes the clock at the moment it stopped", () => {
  const cwd = seeded();
  started(cwd, "goal");
  const first = tickLoop(cwd, load(cwd).snapshot, { at: at(1) });
  assert.equal(first.action, "sent");
  // Confirm the only hypothesis so the contract is satisfied on the next tick.
  const node = load(cwd).snapshot.nodes.find((n) => n.status === "testing")!;
  setStatus(cwd, node.id, "confirmed", {
    severity: "high",
    evidence: [{ kind: "code-slice", at: "", location: { file: "a.ts", line: 1 }, detail: "x" }],
  });
  const done = tickLoop(cwd, load(cwd).snapshot, { at: at(90) });
  assert.equal(done.action, "sent", "the challenge round runs before completion");

  // Drive to completion, then check the clock is frozen at the terminal tick.
  const terminal = tickLoop(cwd, load(cwd).snapshot, { at: at(120) });
  assert.ok(["complete", "sent"].includes(terminal.action));
  const loop = loopOf(cwd);
  if (loop.endedAt) {
    const frozen = loopTiming(loop, ms(1000))!.activeMs;
    assert.equal(loopTiming(loop, ms(1000))!.activeMs, frozen, "frozen means frozen");
    assert.equal(loopTiming(loop, ms(1000))!.ended, true);
  }
});

// -----------------------------------------------------------------
// The widget — the line the operator watches
// -----------------------------------------------------------------

test("the widget carries the elapsed time on the state line", () => {
  const cwd = seeded();
  started(cwd);
  tickLoop(cwd, load(cwd).snapshot, { at: at(0) });

  const lines = renderWidget(load(cwd).snapshot, ms(134))!;
  assert.equal(lines[0], "hypothesis ▶ loop round 1 · 0 confirmed · 0 rejected · 1 open", "the scope root is not counted as open work");
  assert.match(lines[1]!, /in flight: round 1/);
  assert.match(lines[1]!, /stall 0\/99/);
  assert.match(lines[1]!, /elapsed 2h 14m$/, "the clock is the last thing on the state line");
});

test("the widget shows how long the in-flight round has been waiting", () => {
  const cwd = seeded();
  started(cwd);
  tickLoop(cwd, load(cwd).snapshot, { at: at(0) });
  // The round was prepared at T0 and the turn has been running 7 minutes.
  assert.match(renderWidget(load(cwd).snapshot, ms(7))![1]!, /in flight: round 1 · 7m 00s ·/);
  assert.equal(inFlightAge(load(cwd).snapshot, loopOf(cwd), ms(7)), "7m 00s");
});

test("the in-flight age is suppressed while paused — a frozen round is not a hang", () => {
  const cwd = seeded();
  started(cwd);
  tickLoop(cwd, load(cwd).snapshot, { at: at(0) });
  pauseLoop(cwd, load(cwd).snapshot, "hold", at(5));

  const line = renderWidget(load(cwd).snapshot, ms(600))![1]!;
  assert.match(line, /in flight: round 1 · stall/, "the round is named with no age between it and the stall counter");
  assert.doesNotMatch(line, /9h 55m/, "an age that keeps climbing on a paused loop reads as a hang");
  assert.match(line, /paused · 5m 00s active/, "the status word says paused, and the clock shows only the 5m it actually worked");
});

test("a finished loop says 'ran', not 'elapsed'", () => {
  const cwd = seeded();
  started(cwd);
  stopLoop(cwd, load(cwd).snapshot, "done", at(30));
  const line = renderWidget(load(cwd).snapshot, ms(9999))![1]!;
  assert.match(line, /ran 30m 00s/);
  assert.doesNotMatch(line, /elapsed/);
  assert.match(renderWidget(load(cwd).snapshot, ms(9999))![0]!, /■/, "the stopped glyph");
});

test("shortTiming separates active from paused instead of adding them up", () => {
  const cwd = seeded();
  started(cwd);
  pauseLoop(cwd, load(cwd).snapshot, "hold", at(30));
  resumeLoop(cwd, load(cwd).snapshot, {}, at(90));
  const loop = loopOf(cwd);

  assert.equal(shortTiming(loop, loopTiming(loop, ms(120))!), "elapsed 1h 00m (1h 00m paused)");
  assert.equal(shortTiming(loop, null), "elapsed unknown");
  assert.equal(shortTiming({ ...loop, status: "paused" }, loopTiming(loop, ms(120))!), "paused · 1h 00m active");
});

// -----------------------------------------------------------------
// The status block
// -----------------------------------------------------------------

test("the status block carries the clock and warns about a stuck turn", () => {
  const cwd = seeded();
  started(cwd);
  tickLoop(cwd, load(cwd).snapshot, { at: at(0) });
  const text = renderLoopStatus(load(cwd).snapshot, ms(200)).join("\n");
  assert.match(text, /elapsed 3h 20m/);
  assert.match(text, /the round in flight has been waiting 3h 20m — a turn that is not moving is a stuck turn/);
  // The raw timestamps stay: they are what you paste into a bug report.
  assert.match(text, /started 2026-03-01T10:00:00\.000Z/);
});

test("the status block has no stuck-turn line when nothing is in flight", () => {
  const cwd = seeded();
  started(cwd);
  stopLoop(cwd, load(cwd).snapshot, "done", at(30));
  const text = renderLoopStatus(load(cwd).snapshot, ms(9999)).join("\n");
  assert.doesNotMatch(text, /stuck turn/);
  assert.match(text, /elapsed 30m 00s · finished/);
});

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

test("the report header states the duration, the split, and the rate", () => {
  const cwd = seeded();
  started(cwd);
  for (let i = 1; i <= 6; i++) tickLoop(cwd, load(cwd).snapshot, { at: at(i * 10) });
  pauseLoop(cwd, load(cwd).snapshot, "hold", at(60));
  resumeLoop(cwd, load(cwd).snapshot, {}, at(180));
  stopLoop(cwd, load(cwd).snapshot, "done", at(200));

  const header = renderReport(load(cwd).snapshot, loopOf(cwd), { at: at(200) }).split("\n").slice(0, 14).join("\n");
  assert.match(header, /- \*\*Duration\*\*: \*\*1h 20m\*\* of active auditing/);
  assert.match(header, /3h 20m wall, 2h 00m paused/);
  assert.match(header, /- \*\*Started\*\*: 2026-03-01T10:00:00\.000Z · \*\*ended\*\*: 2026-03-01T13:20:00\.000Z/);
});

test("a report for a hand-built tree has no duration line", () => {
  const cwd = seeded();
  assert.doesNotMatch(renderReport(load(cwd).snapshot, null), /Duration/);
});

// -----------------------------------------------------------------
// Backwards compatibility
// -----------------------------------------------------------------

test("a loop record written before the clock existed still reads", () => {
  const cwd = seeded();
  started(cwd);
  const legacy = { ...loopOf(cwd), pausedMs: undefined, pausedAt: undefined, endedAt: undefined } as unknown as AuditLoopState;
  const timing = loopTiming(legacy, ms(60));
  assert.ok(timing, "an old record has a start time and nothing else, which is enough");
  assert.equal(timing.pausedMs, 0);
  assert.equal(timing.activeMs, 60 * 60_000, "no banked pause and no open pause means all of it was active");
});
