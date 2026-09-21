/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/report.ts
 *
 * The audit REPORT: the deliverable a human reads.
 *
 * -----------------------------------------------------------------------
 * Why a report is not the ledger
 * -----------------------------------------------------------------------
 *
 * `findings.md` is a round-by-round log — it answers "what did the loop do".
 * Nobody can act on it, because the answer to "what did you find" is spread
 * across N round sections and mixed with scheduling bookkeeping.
 *
 * The report answers the three questions a reader actually has:
 *
 *   1. What was found, worst first, and how well is each one supported?
 *   2. What was RULED OUT? (A rejection is a result: it prunes the search.)
 *   3. What was NOT examined? (So the reader knows the report's boundary.)
 *
 * -----------------------------------------------------------------------
 * The tier is printed next to every finding
 * -----------------------------------------------------------------------
 *
 * A finding anchored in code a reader can open, and a finding that is an
 * argument with no artifact, must not look alike in a report — that is how an
 * audit hands over a "confirmed high-severity vulnerability" that nobody can
 * check. `verificationTier` derives the distinction from the evidence, and this
 * report states it per finding, plus a section at the end saying plainly what
 * the report does not claim.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import {
  type AuditLoopState,
  type Hypothesis,
  type TreeSnapshot,
  clip,
  hasBeenChallenged,
  severityRank,
  tierLabel,
  verificationTier,
} from "./types.js";
import { STATE_DIR_NAME } from "./store.js";
import { segmentCoverage } from "./recon.js";
import { consolidationStatus } from "./combination.js";
import { planNextRound } from "./scheduler.js";

export const REPORT_NAME = "REPORT.md";

export function reportPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, REPORT_NAME);
}

/** Evidence excerpt cap per finding, so one chatty node cannot swamp the file. */
const EVIDENCE_EXCERPT_CHARS = 800;
const EVIDENCE_ITEMS_PER_FINDING = 6;
const UNEXAMINED_LISTED = 30;

/** Worst first: severity, then category, then id — a stable, readable order. */
function compareBySeverity(a: Hypothesis, b: Hypothesis): number {
  const ra = a.severity ? severityRank(a.severity) : 99;
  const rb = b.severity ? severityRank(b.severity) : 99;
  if (ra !== rb) return ra - rb;
  if (a.category !== b.category) return a.category.localeCompare(b.category);
  return a.id.localeCompare(b.id);
}

/**
 * Where the finding points.
 *
 * The SINK is what matters — the line where the tainted data is consumed — so
 * the last located step of the attack vector wins. Falling back to "the first
 * evidence entry with a location" was wrong in practice: a finding's evidence
 * includes background greps, and the first one is routinely a dependency file
 * rather than the code under audit.
 */
function locationOf(node: Hypothesis): string {
  const path = node.attackVector?.path ?? [];
  for (let i = path.length - 1; i >= 0; i--) {
    const loc = path[i]?.location;
    if (loc) return `${loc.file}:${loc.line}`;
  }
  const evidence = node.evidence;
  for (let i = evidence.length - 1; i >= 0; i--) {
    const loc = evidence[i]?.location;
    if (loc) return `${loc.file}:${loc.line}`;
  }
  return "(no location recorded)";
}

/**
 * The unexamined hypotheses in the order the SCHEDULER would take them.
 *
 * Reusing the scheduler's own ranking rather than re-deriving one keeps the
 * report honest about what the loop would do next — a hand-rolled sort would
 * quietly disagree with it.
 */
function schedulerOrder(snapshot: TreeSnapshot): Hypothesis[] {
  const out: Hypothesis[] = [];
  for (const entry of planNextRound(snapshot).ranked) {
    const node = snapshot.byId.get(entry.nodeId);
    if (node) out.push(node);
  }
  return out;
}

/** One confirmed finding, in full. */
function renderFinding(node: Hypothesis, index: number): string[] {
  const tier = verificationTier(node);
  const lines: string[] = [];
  lines.push(`### ${index}. ${node.id} — ${(node.severity ?? "UNRATED").toUpperCase()} — ${node.category}`);
  lines.push("");
  lines.push(`**Assertion.** ${node.description}`);
  lines.push("");
  lines.push(`**Verification: ${tierLabel(tier)}**`);
  lines.push("");
  lines.push(
    hasBeenChallenged(node)
      ? `**Challenge: SURVIVED** — round ${node.challengedRound} tried to refute this and failed.`
      : `**Challenge: NEVER ATTACKED** — nobody has tried to refute this yet, so it is the auditor agreeing with itself.`,
  );
  lines.push("");
  if (node.combinationKind) {
    lines.push(`**Derived by combination.** ${node.combinationKind} of ${node.spawnedFrom.join(" + ")}`);
    lines.push("");
  }
  lines.push(`**Location.** ${locationOf(node)}`);
  lines.push("");

  if (node.attackVector) {
    const v = node.attackVector;
    lines.push("**Attack vector**");
    lines.push("");
    lines.push(`- Entrypoint: \`${v.entrypoint}\``);
    lines.push(`- Technique: ${v.technique}`);
    if (v.path.length > 0) {
      lines.push("- Path:");
      v.path.forEach((step, i) => {
        const loc = step.location ? ` \`${step.location.file}:${step.location.line}\` —` : "";
        lines.push(`  ${i + 1}.${loc} ${step.detail}`);
      });
    }
    if (v.payload) lines.push(`- Payload: \`${v.payload}\``);
    if (v.preconditions && v.preconditions.length > 0) lines.push(`- Preconditions: ${v.preconditions.join("; ")}`);
    lines.push("");
  } else {
    lines.push("**Attack vector.** none recorded — how to reach this is not yet known (which is different from unreachable)");
    lines.push("");
  }

  if (node.statusReason) {
    lines.push("**The auditor's own statement of scope**");
    lines.push("");
    lines.push(`> ${node.statusReason.replace(/\n/g, "\n> ")}`);
    lines.push("");
  }

  lines.push(`**Evidence (${node.evidence.length} entries)**`);
  lines.push("");
  const shown = node.evidence.slice(0, EVIDENCE_ITEMS_PER_FINDING);
  for (const [i, ev] of shown.entries()) {
    const loc = ev.location ? ` \`${ev.location.file}:${ev.location.line}\`` : "";
    const cmd = ev.command ? ` — \`${ev.command}\`` : "";
    lines.push(`${i + 1}. **${ev.kind}**${loc}${cmd}`);
    lines.push("");
    lines.push("   ```");
    for (const l of clip(ev.detail, EVIDENCE_EXCERPT_CHARS).split("\n")) lines.push(`   ${l}`);
    lines.push("   ```");
    lines.push("");
  }
  if (node.evidence.length > shown.length) {
    lines.push(`_… and ${node.evidence.length - shown.length} more evidence entr(ies) in \`.pi-hypothesis/tree.jsonl\`._`);
    lines.push("");
  }
  return lines;
}

/**
 * The report.
 *
 * Ordered so the reader can stop early: summary, then the findings worst-first,
 * then what was ruled out, then the boundary (what was NOT examined), then the
 * method, then the explicit non-claims.
 */
export function renderReport(snapshot: TreeSnapshot, loop: AuditLoopState | null, opts: { at?: string } = {}): string {
  const at = opts.at ?? new Date().toISOString();
  const hypotheses = snapshot.nodes.filter((n) => n.nodeKind !== "scope");
  const confirmed = snapshot.nodes.filter((n) => n.status === "confirmed").sort(compareBySeverity);
  const rejected = snapshot.nodes.filter((n) => n.status === "rejected");
  const blocked = snapshot.nodes.filter((n) => n.status === "blocked");
  const unexamined = schedulerOrder(snapshot);
  const coverage = segmentCoverage(snapshot);
  const combo = consolidationStatus(snapshot);

  const lines: string[] = [];
  lines.push(`# Code audit report`);
  lines.push("");
  lines.push(`- **Project**: \`${snapshot.objective}\``);
  lines.push(`- **Generated**: ${at}`);
  if (loop) {
    lines.push(`- **Run**: ${loop.kind} · ${loop.status} · round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : ""}`);
    lines.push(`- **Stopped because**: ${loop.stopReason ?? loop.pausedReason ?? "(still running)"}`);
  } else {
    lines.push(`- **Run**: no audit loop was started — this is a tree built by hand`);
  }
  lines.push("");

  // ---- summary ---------------------------------------------------
  lines.push(`## Summary`);
  lines.push("");
  lines.push(`| | |`);
  lines.push(`|---|---|`);
  lines.push(`| Hypotheses recorded | ${hypotheses.length} |`);
  lines.push(`| **Confirmed** | **${confirmed.length}** |`);
  lines.push(`| Rejected (ruled out) | ${rejected.length} |`);
  lines.push(`| Unexamined | ${unexamined.length} |`);
  lines.push(`| Blocked (waiting on something) | ${blocked.length} |`);
  lines.push(`| Recon coverage | ${coverage.total === 0 ? "not run" : `${coverage.covered}/${coverage.total} segments`} |`);
  lines.push(`| Combination passes | ${combo.passes} (${combo.examinedPairs} pair(s) examined) |`);
  lines.push(`| With an attack vector | ${hypotheses.filter((n) => n.attackVector).length}/${hypotheses.length} |`);
  lines.push("");

  if (confirmed.length === 0) {
    lines.push(`**No finding was confirmed.** The audit did not establish a vulnerability. `);
    lines.push(`That is a result, not a failure — see "Ruled out" and "Not examined" below for the boundary of that statement.`);
    lines.push("");
  } else {
    const tiers = { reproduced: 0, static: 0, "reasoning-only": 0 };
    for (const n of confirmed) tiers[verificationTier(n)]++;
    lines.push(`**Verification tiers of the confirmed findings:**`);
    lines.push("");
    lines.push(`- ${tiers.reproduced} reproduced (a command was run and re-runnable)`);
    lines.push(`- ${tiers.static} static (anchored in code, not reproduced)`);
    lines.push(`- ${tiers["reasoning-only"]} reasoning only — **these are opinions, not findings**`);
    lines.push("");
    const challenged = confirmed.filter((n) => hasBeenChallenged(n)).length;
    lines.push(
      `**${challenged}/${confirmed.length} of them have been ATTACKED** — an unchallenged confirmation is the auditor agreeing with itself.`,
    );
    lines.push("");
    if (tiers["reasoning-only"] > 0) {
      lines.push(`> A reasoning-only entry rests on an argument with no artifact. Treat it as a lead to check, never as a confirmed vulnerability.`);
      lines.push("");
    }
  }

  // ---- confirmed -------------------------------------------------
  lines.push(`## Confirmed findings (${confirmed.length})`);
  lines.push("");
  if (confirmed.length === 0) {
    lines.push("_None._");
    lines.push("");
  } else {
    confirmed.forEach((node, i) => lines.push(...renderFinding(node, i + 1)));
  }

  // ---- rejected --------------------------------------------------
  lines.push(`## Ruled out (${rejected.length})`);
  lines.push("");
  if (rejected.length === 0) {
    lines.push("_Nothing was refuted. A tree that only confirms has not been testing anything — treat this as a gap in the audit, not as a clean result._");
    lines.push("");
  } else {
    for (const node of rejected) {
      lines.push(`- **${node.id}** ${node.description}`);
      if (node.statusReason) lines.push(`  - refuted by: ${clip(node.statusReason, 300)}`);
    }
    lines.push("");
  }

  // ---- blocked ---------------------------------------------------
  if (blocked.length > 0) {
    lines.push(`## Blocked (${blocked.length})`);
    lines.push("");
    lines.push("Recorded but not testable yet. The reason is the auditor's own, and it is what the loop is waiting on.");
    lines.push("");
    for (const node of blocked) {
      lines.push(`- **${node.id}** ${node.description}`);
      if (node.statusReason) lines.push(`  - blocked because: ${clip(node.statusReason, 300)}`);
    }
    lines.push("");
  }

  // ---- boundary --------------------------------------------------
  lines.push(`## Not examined (${unexamined.length})`);
  lines.push("");
  if (unexamined.length === 0) {
    lines.push("_Every recorded hypothesis was examined._");
    lines.push("");
  } else {
    lines.push("These are recorded and unexamined, in the order the scheduler would take them. **Nothing here is a claim either way.**");
    lines.push("");
    for (const node of unexamined.slice(0, UNEXAMINED_LISTED)) {
      const v = node.attackVector ? ` → ${node.attackVector.entrypoint}` : "";
      lines.push(`- **${node.id}** [${node.category}]${v} — ${clip(node.description, 160)}`);
    }
    if (unexamined.length > UNEXAMINED_LISTED) {
      lines.push(`- _… and ${unexamined.length - UNEXAMINED_LISTED} more (see \`.pi-hypothesis/tree.jsonl\`)_`);
    }
    lines.push("");
  }
  if (coverage.open.length > 0) {
    lines.push(`**Recon segments never turned into hypotheses**: ${coverage.open.join(", ")}`);
    lines.push("");
  }

  // ---- method ----------------------------------------------------
  lines.push(`## Method`);
  lines.push("");
  lines.push(`- Every hypothesis is a **falsifiable assertion**, not a task. The store refuses task-shaped text.`);
  lines.push(`- Verification is a **falsification attempt**: each probe states what the hypothesis predicts about one mechanical fact, and one counterexample refutes it. A surviving probe means "not refuted here", never "proven".`);
  lines.push(`- A **verdict requires evidence**; a finding's tier above says how strong that evidence is.`);
  lines.push(`- The scheduler enforces anti-tunnelling limits: no more than 3 consecutive levels of descent, 2 consecutive rounds on one node, or 40% of recent picks in one category.`);
  lines.push(`- Confirmed findings are periodically **combined** into new hypotheses (chains, shared root causes, lateral extensions).`);
  lines.push("");

  // ---- non-claims ------------------------------------------------
  lines.push(`## What this report does NOT claim`);
  lines.push("");
  lines.push(`- **It is not a penetration test.** No request was sent to a running system unless a finding's tier says REPRODUCED.`);
  lines.push(`- **A static finding is a strong case, not a proof.** Reachability through a parent class, a global middleware, or a framework default is not settled by reading the controller.`);
  lines.push(`- **Absence of a finding is not absence of a vulnerability.** See "Not examined" — ${unexamined.length} recorded hypotheses were never tested, and the recon itself covers ${coverage.total} segment(s).`);
  lines.push(`- **Severity is the auditor's judgement**, not a CVSS score, and an unrated finding is "not yet judged" rather than "low".`);
  lines.push("");
  lines.push(`---`);
  lines.push("");
  lines.push(`_Generated by pi-audit-hypothesis-tree from \`.pi-glla\`-style durable state: \`.pi-hypothesis/tree.jsonl\` (append-only), \`.pi-hypothesis/findings.md\` (per-round log), \`.pi-hypothesis/recon.md\` (the recon note). No summary here is model-generated — every line is derived from the recorded state._`);
  lines.push("");
  return lines.join("\n");
}

/** Write the report in place (no temp+rename, matching the store's exFAT rule). */
export function writeReport(projectRoot: string, snapshot: TreeSnapshot, loop: AuditLoopState | null, opts: { at?: string } = {}): { ok: boolean; path: string; errors: string[] } {
  const file = reportPath(projectRoot);
  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    fs.writeFileSync(file, renderReport(snapshot, loop, opts), "utf-8");
    return { ok: true, path: file, errors: [] };
  } catch (error) {
    return { ok: false, path: file, errors: [error instanceof Error ? error.message : String(error)] };
  }
}


