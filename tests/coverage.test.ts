// pi-audit-hypothesis-tree — tests/coverage.test.ts
//
// Pins the FILE coverage signal, and the round that acts on it.
//
// The gap this closes, measured on a real Centreon audit: 16 paragraphs of recon
// became 4 segments, 92% of every hypothesis came from those 4 windows, and
// NOTHING came from anywhere else. The report said "侦察覆盖 4/4 个片段", which reads
// as complete coverage and means only "I processed the four windows I wrote".
//
// A directory with no hypothesis is not clean. It is UNREAD.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { load } from "../extensions/hypothesis-tree/store.ts";
import { addNode, createTree, setStatus } from "../extensions/hypothesis-tree/tree.ts";
import { startLoop, tickLoop } from "../extensions/hypothesis-tree/loop.ts";
import { renderReport } from "../extensions/hypothesis-tree/report.ts";
import { submitRecon } from "../extensions/hypothesis-tree/recon.ts";
import { COVERAGE, citedFiles, coverageGaps, coverageHeadline, hasCoverageGap, renderCoverageBrief } from "../extensions/hypothesis-tree/coverage.ts";
import type { Evidence } from "../extensions/hypothesis-tree/types.ts";

/** A project with four areas of known size, plus a tiny one that is noise. */
function project(areas: Record<string, number> = { "src/api": 5, "src/admin": 8, "lib/legacy": 12, "modules/plugins": 7 }): string {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "hypo-cov-"));
  for (const [dir, n] of Object.entries(areas)) {
    fs.mkdirSync(path.join(cwd, dir), { recursive: true });
    for (let i = 0; i < n; i++) fs.writeFileSync(path.join(cwd, dir, `f${i}.php`), "<?php\n", "utf-8");
  }
  const created = createTree(cwd, `the project rooted at ${cwd}`, { nodeKind: "scope" });
  assert.equal(created.ok, true, created.ok ? "" : created.errors.join("; "));
  return cwd;
}

/** A recon note long enough to pass the minimum, with `paragraphsPerSegment` control. */
function note(paragraphs: number): string {
  const out: string[] = [];
  for (let i = 0; i < paragraphs; i++) {
    out.push(`Paragraph ${i}: this part of the project has an entrypoint, a trust boundary, and a data flow that I read carefully enough to describe in a sentence of reasonable length.`);
  }
  return out.join("\n\n");
}

function cite(cwd: string, file: string, category = "auth-bypass"): void {
  const r = addNode(cwd, {
    description: `the handler in ${file} reaches a sink without the check the surrounding code relies on`,
    category,
    attackVector: {
      entrypoint: "POST /x",
      technique: "missing check",
      path: [{ detail: "the sink", location: { file, line: 3 } }],
    },
  });
  assert.equal(r.ok, true, r.ok ? "" : r.errors.join("; "));
}

const gapsOf = (cwd: string) => coverageGaps(load(cwd).snapshot, cwd);

// -----------------------------------------------------------------
// citedFiles
// -----------------------------------------------------------------

test("citedFiles reads BOTH the attack vector and the evidence", () => {
  const cwd = project();
  const r = addNode(cwd, {
    description: "the api serializer parses caller XML without disabling external entities",
    category: "xxe",
    attackVector: { entrypoint: "POST /x", technique: "XXE", path: [{ detail: "a", location: { file: "src/api/a.php", line: 1 } }] },
  });
  assert.equal(r.ok, true);
  const evidence: Evidence = { kind: "code-slice", at: "", location: { file: "lib/legacy/b.php", line: 2 }, detail: "x" };
  setStatus(cwd, r.ok ? r.value.node.id : "?", "confirmed", { severity: "high", evidence: [evidence] });

  const cited = citedFiles(load(cwd).snapshot);
  assert.ok(cited.has("src/api/a.php"), "the chain's location counts");
  assert.ok(cited.has("lib/legacy/b.php"), "and so does the evidence's — a file only in evidence was still read");
});

test("citedFiles normalises backslashes and leading ./", () => {
  const cwd = project();
  const r = addNode(cwd, {
    description: "the handler reaches a sink without the check the surrounding code relies on",
    category: "auth-bypass",
    attackVector: { entrypoint: "POST /x", technique: "t", path: [{ detail: "a", location: { file: ".\\src\\api\\a.php", line: 1 } }] },
  });
  assert.equal(r.ok, true);
  assert.ok(citedFiles(load(cwd).snapshot).has("src/api/a.php"), "one file, one entry");
});

// -----------------------------------------------------------------
// coverageGaps — and the grouping bug this caught
// -----------------------------------------------------------------

test("a gap is the SHALLOWEST directory whose whole subtree is untouched", () => {
  const cwd = project();
  cite(cwd, "src/api/f0.php");
  const report = gapsOf(cwd);
  const dirs = report.gaps.map((g) => g.dir);

  // src/api is cited, so it is not a gap — and neither is `src`, because ONE
  // cited file next door must not mark the eight-file src/admin covered. That
  // was the fixed-depth bug.
  assert.ok(!dirs.includes("src/api"), "src/api has a cited file");
  assert.ok(dirs.includes("src/admin"), "src/admin does not, and its neighbour must not cover it");
  assert.ok(!dirs.includes("src"), "src is not wholly untouched: src/api was read");

  // lib and modules have nothing cited at all, so the SHALLOWEST untouched
  // directory is reported — its children are inside the same hole, and listing
  // them would turn one hole into a list nobody reads.
  assert.ok(dirs.includes("lib"), `got ${dirs.join(",")}`);
  assert.ok(!dirs.includes("lib/legacy"), "the child of a reported hole is not listed again");
  assert.ok(dirs.includes("modules"));
});

test("a gap names how many files it holds, biggest first", () => {
  const cwd = project();
  cite(cwd, "src/api/f0.php");
  const report = gapsOf(cwd);
  assert.deepEqual(report.gaps.map((g) => [g.dir, g.files]), [["lib", 12], ["src/admin", 8], ["modules", 7]]);
  // And the headline the fixed depth was hiding.
  assert.equal(report.untouchedFiles, 27, "27 of 32 files sit in untouched subtrees");
  assert.match(coverageHeadline(report), /27 in untouched subtrees/);
});

test("a directory too small to matter is not a gap", () => {
  const cwd = project({ "src/api": 5, tiny: 1 });
  cite(cwd, "src/api/f0.php");
  const report = gapsOf(cwd);
  assert.equal(report.gaps.length, 0, `a ${COVERAGE.MIN_FILES_FOR_GAP - 1}-file directory is noise, not a hole`);
});

test("the walk's file count is reported as a LOWER BOUND when it was truncated", () => {
  const cwd = project();
  const report = gapsOf(cwd);
  // Whatever the budget was, the shape must be honest about it.
  assert.ok(report.projectFiles !== null);
  assert.equal(typeof report.truncated, "boolean");
  assert.match(coverageHeadline(report), /cited/);
  if (report.truncated) assert.match(coverageHeadline(report), /lower bound/);
});

test("a project that cannot be walked says NOT MEASURED, never 'covered'", () => {
  const cwd = project();
  const report = coverageGaps(load(cwd).snapshot, path.join(cwd, "does-not-exist"));
  assert.equal(report.projectFiles, null);
  assert.equal(hasCoverageGap(report), false, "no gap list, because there is nothing to compare against");
  assert.match(coverageHeadline(report), /not measured/);
});

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

test("the report shows the file gap and says a gap is UNREAD, not clean", () => {
  const cwd = project();
  cite(cwd, "src/api/f0.php");
  const text = renderReport(load(cwd).snapshot, null, { language: "zh", coverageReport: gapsOf(cwd) });

  assert.match(text, /## 覆盖/);
  assert.match(text, /\*\*被假设引用过的文件\*\*/);
  // The headline is INSIDE the report, so it follows the report's language. It used
  // to be English unconditionally, which put "1 of 32 file(s) cited (3%)" in the
  // middle of a Chinese document.
  assert.match(text, /1 \/ 32 个文件被引用过（3%）/);
  assert.match(text, /其中 27 个位于完全未被触碰的子树中/);
  assert.match(text, /\*\*ZERO 假设的目录\*\* \| 3 \|/);
  assert.match(text, /一个没有假设的目录不是「干净」，是「没读过」/);
  assert.match(text, /- `lib` — 12 个文件，零假设/);
  assert.match(text, /- `src\/admin` — 8 个文件，零假设/);

  // And the English report gets the English headline back.
  const en = renderReport(load(cwd).snapshot, null, { language: "en", coverageReport: gapsOf(cwd) });
  assert.match(en, /1 of 32 file\(s\) cited \(3%\)/);
});

test("a report with no gap says so without claiming the project was cleared", () => {
  const cwd = project({ "src/api": 5 });
  cite(cwd, "src/api/f0.php");
  const text = renderReport(load(cwd).snapshot, null, { language: "zh", coverageReport: gapsOf(cwd) });
  assert.match(text, /每个够大的目录都至少有一条假设引用过它/);
  assert.match(text, /这不等于查干净了/);
});

test("an unmeasurable coverage is rendered as not measured", () => {
  const cwd = project();
  const text = renderReport(load(cwd).snapshot, null, { language: "zh", coverageReport: coverageGaps(load(cwd).snapshot, "/nope") });
  assert.match(text, /_无法度量/);
  assert.match(text, /\*\*没度量不等于全覆盖。\*\*/);
});

// -----------------------------------------------------------------
// The coverage round
// -----------------------------------------------------------------

test("the coverage round fires once the first note's segments are CLOSED", () => {
  const cwd = project();
  const sub = submitRecon(cwd, note(3), { paragraphsPerSegment: 3 });
  assert.equal(sub.ok, true, sub.ok ? "" : sub.errors.join("; "));
  cite(cwd, "src/api/f0.php");
  // Close every segment.
  for (const segment of load(cwd).snapshot.segments) {
    addNode(cwd, { description: `segment ${segment.id.slice(-4)} reaches a sink without the check the code relies on`, category: "auth-bypass", segmentId: segment.id });
  }

  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds: string[] = [];
  let brief: string | null = null;
  for (let i = 0; i < 6; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const rec = load(cwd).snapshot.roundRecords.at(-1)!;
    kinds.push(rec.kind);
    if (rec.kind === "coverage") { brief = r.brief!; break; }
  }
  assert.ok(kinds.includes("coverage"), `the gap must be acted on: ${kinds.join(",")}`);
  assert.match(brief!, /\[AUDIT ROUND \d+ — COVERAGE\]/);
  assert.match(brief!, /Directories no hypothesis has ever touched/);
  assert.match(brief!, /lib\/  — 12 file\(s\)/);
  assert.match(brief!, /THIS IS A SECOND RECON PASS, AND IT IS THE LAST ONE/);
  // And it must not let the model re-cover old ground: recon_submitted REPLACES
  // the segment inventory.
  assert.match(brief!, /Do NOT re-describe areas the first note already covered/);
  assert.match(brief!, /REPLACES the/);
  assert.match(brief!, /hypothesis_recon/);
});

test("everything under ONE wrapper does not hide the gap", () => {
  // The Checkmk appliance: the source is one tree at `source/rootfs/...`, so a
  // fixed depth of 2 produced three groups and reported "1 gap: source/.idea"
  // while 40 of 898 files had been cited.
  const cwd = project({ "source/rootfs/app": 6, "source/rootfs/lib": 9, "source/rootfs/deep/nested/thing": 5 });
  cite(cwd, "source/rootfs/app/f0.php");
  const report = gapsOf(cwd);
  const dirs = report.gaps.map((g) => g.dir);
  assert.ok(dirs.includes("source/rootfs/lib"), `got ${dirs.join(",")}`);
  assert.ok(dirs.includes("source/rootfs/deep"), "and it descends as far as the untouched subtree goes");
  assert.ok(!dirs.includes("source"), "source is not wholly untouched: source/rootfs/app was read");
  assert.equal(report.untouchedFiles, 14);
});

test("the coverage round does NOT fire while a segment is still open", () => {
  const cwd = project();
  submitRecon(cwd, note(6), { paragraphsPerSegment: 3 });
  cite(cwd, "src/api/f0.php");
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });

  const kinds: string[] = [];
  for (let i = 0; i < 5; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const rec = load(cwd).snapshot.roundRecords.at(-1)!;
    kinds.push(rec.kind);
  }
  // Generating the material comes first: expanding breadth before the queue is
  // produced just moves the queue around.
  assert.ok(!kinds.includes("coverage"), kinds.join(","));
  assert.ok(kinds.every((k) => k === "generate"), kinds.join(","));
});

test("the coverage round does NOT fire when there is no gap", () => {
  const cwd = project({ "src/api": 5 });
  const sub = submitRecon(cwd, note(3), { paragraphsPerSegment: 3 });
  assert.equal(sub.ok, true, sub.ok ? "" : sub.errors.join("; "));
  cite(cwd, "src/api/f0.php");
  for (const segment of load(cwd).snapshot.segments) {
    addNode(cwd, { description: `segment ${segment.id.slice(-4)} reaches a sink without the check the code relies on`, category: "auth-bypass", segmentId: segment.id });
  }

  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  const kinds: string[] = [];
  for (let i = 0; i < 6; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    kinds.push(load(cwd).snapshot.roundRecords.at(-1)!.kind);
  }
  assert.ok(!kinds.includes("coverage"), `a brief with an empty list is a wasted round: ${kinds.join(",")}`);
});

test("the coverage round is BOUNDED — it cannot justify itself forever", () => {
  const cwd = project();
  const sub = submitRecon(cwd, note(3), { paragraphsPerSegment: 3 });
  assert.equal(sub.ok, true, sub.ok ? "" : sub.errors.join("; "));
  cite(cwd, "src/api/f0.php");
  for (const segment of load(cwd).snapshot.segments) {
    addNode(cwd, { description: `segment ${segment.id.slice(-4)} reaches a sink without the check the code relies on`, category: "auth-bypass", segmentId: segment.id });
  }
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });

  let coverageRounds = 0;
  for (let i = 0; i < 30; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    const rec = load(cwd).snapshot.roundRecords.at(-1)!;
    if (rec.kind === "coverage") {
      coverageRounds++;
      // Play the model: it answers with a new note that does NOT reduce the gap,
      // which is the case that would loop forever without a bound.
      submitRecon(cwd, note(3), { paragraphsPerSegment: 3 });
      for (const segment of load(cwd).snapshot.segments) {
        addNode(cwd, { description: `segment ${segment.id.slice(-4)} reaches a sink without the check the code relies on`, category: "auth-bypass", segmentId: segment.id });
      }
    }
  }
  assert.ok(
    coverageRounds <= COVERAGE.MAX_ROUNDS,
    `it ran ${coverageRounds} times; the cap is ${COVERAGE.MAX_ROUNDS}`,
  );
});

test("a coverage round that submits nothing is unproductive", () => {
  const cwd = project();
  const sub = submitRecon(cwd, note(3), { paragraphsPerSegment: 3 });
  assert.equal(sub.ok, true, sub.ok ? "" : sub.errors.join("; "));
  cite(cwd, "src/api/f0.php");
  for (const segment of load(cwd).snapshot.segments) {
    addNode(cwd, { description: `segment ${segment.id.slice(-4)} reaches a sink without the check the code relies on`, category: "auth-bypass", segmentId: segment.id });
  }
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });

  // Walk to the coverage round, then do NOTHING as the model.
  for (let i = 0; i < 6; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    if (load(cwd).snapshot.roundRecords.at(-1)!.kind === "coverage") break;
  }
  const after = tickLoop(cwd, load(cwd).snapshot);
  assert.equal(after.previous!.kind, "coverage");
  assert.match(after.previous!.detail, /no coverage recon note was submitted/);
  assert.equal(after.previous!.produced, false);
});

test("a coverage round that submits a note IS productive", () => {
  const cwd = project();
  const sub = submitRecon(cwd, note(3), { paragraphsPerSegment: 3 });
  assert.equal(sub.ok, true, sub.ok ? "" : sub.errors.join("; "));
  cite(cwd, "src/api/f0.php");
  for (const segment of load(cwd).snapshot.segments) {
    addNode(cwd, { description: `segment ${segment.id.slice(-4)} reaches a sink without the check the code relies on`, category: "auth-bypass", segmentId: segment.id });
  }
  startLoop(cwd, load(cwd).snapshot, { kind: "loop", objective: "audit", plateauWindow: 999 });
  for (let i = 0; i < 6; i++) {
    const r = tickLoop(cwd, load(cwd).snapshot);
    if (r.action !== "sent") break;
    if (load(cwd).snapshot.roundRecords.at(-1)!.kind === "coverage") break;
  }
  // The model reads lib/legacy and writes a new note about it.
  submitRecon(cwd, note(3), { paragraphsPerSegment: 3 });
  const after = tickLoop(cwd, load(cwd).snapshot);
  assert.match(after.previous!.detail, /coverage recon submitted/);
  assert.equal(after.previous!.produced, true);
  assert.equal(load(cwd).snapshot.loop!.coverageRounds, 1, "the budget is spent");
});

test("the coverage brief renders in one place, from the report it was given", () => {
  const cwd = project();
  cite(cwd, "src/api/f0.php");
  const brief = renderCoverageBrief(gapsOf(cwd), "find a pre-auth RCE", 9);
  assert.match(brief, /\[AUDIT ROUND 9 — COVERAGE\]/);
  assert.match(brief, /Audit objective: find a pre-auth RCE/);
  assert.match(brief, /genuinely irrelevant is a finding too/);
});
