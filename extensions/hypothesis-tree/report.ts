/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/report.ts
 *
 * The deliverable: one Markdown file that says what was found, how it was
 * verified, and — just as importantly — what was NOT established.
 *
 * -----------------------------------------------------------------------
 * The shape of a finding
 * -----------------------------------------------------------------------
 *
 * Every confirmed finding is rendered with the same three sections, and each one
 * is rendered EVEN WHEN IT IS EMPTY, saying so explicitly:
 *
 *   调用链 / Call chain        how the attacker gets from the entrypoint to the sink
 *   可利用干什么 / Impact      what they get if it works
 *    PoC 验证 / PoC            what was actually executed, or that nothing was
 *
 * The empty cases are the point. "No impact recorded" and "no impact" are
 * different claims, and a report that silently omits the section lets the reader
 * assume the second. The same goes for an unrecorded call chain: "we do not yet
 * know how to reach it" is not "unreachable".
 *
 * -----------------------------------------------------------------------
 * What is NOT in here
 * -----------------------------------------------------------------------
 *
 * No severity is computed, no impact is inferred, no reachability is assumed.
 * Every one of those is the auditor's judgement and is recorded as a claim the
 * reader can trace back to `.pi-hypothesis/tree.jsonl`. A tool that graded its
 * own findings would be the thing this project exists to replace.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import {
  type Hypothesis,
  type TreeSnapshot,
  type AuditLoopState,
  chainState,
  isUsable,
  formatDuration,
  hasBeenChallenged,
  loopTiming,
  meetsTier,
  severityRank,
  tierLabel,
  verificationTier,
} from "./types.js";import { STATE_DIR_NAME } from "./store.js";
import { segmentCoverage } from "./recon.js";
import { consolidationStatus } from "./combination.js";
import { planNextRound } from "./scheduler.js";
import { type ReportLanguage, type ReportStrings, reportStrings, severityLabel } from "./reportText.js";
export const REPORT_NAME = "REPORT.md";

export function reportPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, REPORT_NAME);
}

/** Evidence excerpt cap for the ONE artifact a finding rests on. */
const EVIDENCE_EXCERPT_CHARS = 900;
/** How many entries the "other evidence" index lists before it just counts. */
const EVIDENCE_INDEX_LIMIT = 8;
const UNEXAMINED_LISTED = 30;

/**
 * Worst first, then rated before unrated.
 *
 * An unrated finding sorts last on purpose: `severityRank` treats a missing
 * severity as the worst rank, which would put "we have not decided" above
 * "critical" — the opposite of what a reader wants.
 */
function compareBySeverity(a: Hypothesis, b: Hypothesis): number {
  const ra = a.severity ? severityRank(a.severity) : Number.POSITIVE_INFINITY;
  const rb = b.severity ? severityRank(b.severity) : Number.POSITIVE_INFINITY;
  if (ra !== rb) return ra - rb;
  return a.id.localeCompare(b.id);
}

/**
 * Where to point the reader.
 *
 * The attack vector's SINK wins, not the first evidence entry. Evidence order is
 * whatever the model happened to record first, and that is frequently a file in
 * `vendor/` — a location that is real, and useless, because the point of the
 * line is to say where the auditor should look.
 */
function locationOf(node: Hypothesis): string {
  const sink = node.attackVector?.path.filter((s) => s.location).at(-1)?.location;
  if (sink) return `\`${sink.file}:${sink.line}\``;
  const anchored = node.evidence.find((e) => e.location)?.location;
  if (anchored) return `\`${anchored.file}:${anchored.line}\``;
  return "—";
}

/** The scheduler's own order, so "not examined" is a priority list, not a dump. */
function schedulerOrder(snapshot: TreeSnapshot): Hypothesis[] {
  const decision = planNextRound(snapshot, { round: snapshot.rounds + 1 });
  const ranked = decision.ranked.map((entry) => snapshot.byId.get(entry.nodeId)).filter((n): n is Hypothesis => !!n);
  const seen = new Set(ranked.map((n) => n.id));
  for (const node of snapshot.nodes) {
    if (node.nodeKind === "scope") continue;
    if (node.status !== "pending" && node.status !== "testing") continue;
    if (!seen.has(node.id)) ranked.push(node);
  }
  return ranked;
}

/**
 * Is the dossier complete — does this finding have all three parts?
 *
 * "Complete" means PRESENT, not "good". The tool cannot judge whether an impact
 * is the right impact; it can only say whether the auditor wrote one down, and
 * that is the honest thing to count.
 */
export interface Dossier {
  chain: boolean;
  impact: boolean;
  poc: boolean;
  complete: boolean;
}

export function dossierOf(node: Hypothesis): Dossier {
  const chain = !!node.attackVector && node.attackVector.path.length > 0;
  const impact = !!node.attackVector?.impact?.trim();
  const poc = node.evidence.some((e) => e.kind === "code-slice" || e.kind === "command-output" || !!e.location);
  return { chain, impact, poc, complete: chain && impact && poc };
}

/** The three sections. Rendered always; the empty case says why it is empty. */
function renderFinding(
  node: Hypothesis,
  index: number,
  t: ReportStrings,
  lang: ReportLanguage,
  snapshotNodes: readonly Hypothesis[],
): string[] {
  const tier = verificationTier(node);
  const lines: string[] = [];
  lines.push(`### ${index}. ${node.id} — ${severityLabel(node.severity, lang)} — ${node.category}`);
  lines.push("");
  lines.push(`${t.assertion} ${node.description}`);
  lines.push("");
  // t.verification already carries its own bold markers, so no trailing ** here —
  // adding one produced a stray unmatched `**` at the end of the line.
  lines.push(`${t.verification} ${t.tierName(tier)}`);
  lines.push("");
  lines.push(
    hasBeenChallenged(node)
      ? t.challengeSurvived(node.challengedRound ?? 0)
      : t.challengeNever,
  );
  lines.push("");
  if (node.combinationKind) {
    lines.push(t.derivedByCombination(node.combinationKind, node.spawnedFrom.join(" + ")));
    lines.push("");
  }
  lines.push(`${t.location} ${locationOf(node)}`);
  lines.push("");

  // ---- the exploitation chain ------------------------------------
  //
  // Placed ABOVE the call chain, because it changes how everything below should
  // be read. A gated sink and a working RCE look identical in a list of
  // "confirmed findings", and only one of them can be used.
  const chain = chainState(node, (id) => snapshotNodes.find((n) => n.id === id));
  // Shown for EVERY state except a deliberate `standalone`. "Nobody asked" and
  // "the answer is nothing" must not look the same in the report.
  if (chain.state !== "standalone") {
    lines.push(`**${t.chainStateLabel}:**`);
    lines.push("");
    if (chain.state === "unassessed") {
      lines.push(`${t.chainUnassessed}`);
      lines.push("");
      lines.push(t.chainUnassessedAsk);
    } else if (chain.state === "untracked") {
      lines.push(t.chainUntracked(node.attackVector?.preconditions?.length ?? 0));
      lines.push("");
      for (const pre of node.attackVector?.preconditions ?? []) lines.push(`- ${pre}`);
    } else {
      const all = [...chain.confirmed, ...chain.pending, ...chain.refuted, ...chain.missing];
      lines.push(
        chain.state === "chain-ready"
          ? t.chainReady(chain.confirmed.join(" + "))
          : chain.state === "broken"
            ? t.chainBroken(chain.refuted.join(", "))
            : t.chainGated([...chain.pending, ...chain.missing].join(", ")),
      );
      lines.push("");
      for (const gateId of all) {
        const gate = snapshotNodes.find((n) => n.id === gateId);
        const mark =
          chain.confirmed.includes(gateId) ? "✓" : chain.refuted.includes(gateId) ? "✗" : chain.missing.includes(gateId) ? "?" : "…";
        lines.push(`- ${mark} **${gateId}** — ${gate ? clip(gate.description, 160) : "(not in the tree)"}`);
      }
    }
    lines.push("");
  }

  // ---- 1. the call chain ----------------------------------------
  //
  // In a FENCE, not a bullet list. Three reasons, and the third is a bug fix:
  // it is materially shorter (no blank lines, no list indentation), the
  // `file:line` of every step lines up in one column so the chain can be
  // scanned, and the DETAIL of a step is frequently multi-line code — inline in
  // a bullet that code leaked out of the list and broke the markdown around it.
  const v = node.attackVector;
  lines.push(t.callChain);
  lines.push("");
  if (!v) {
    lines.push(t.noCallChain);
  } else {
    lines.push("```");
    lines.push(`${t.entrypoint}  ${v.entrypoint}`);
    lines.push(`${t.technique}  ${v.technique}`);
    if (v.path.length > 0) {
      lines.push("");
      v.path.forEach((step, i) => {
        const n = `${i + 1}.`;
        if (step.location) {
          lines.push(`${n} ${step.location.file}:${step.location.line}`);
          lines.push(`   ${step.detail}`);
        } else {
          lines.push(`${n} ${step.detail}`);
        }
      });
    }
    if (v.payload) {
      lines.push("");
      lines.push(`${t.payload}  ${v.payload}`);
    }
    if (v.preconditions && v.preconditions.length > 0) {
      lines.push(`${t.preconditions}  ${v.preconditions.join("; ")}`);
    }
    lines.push("```");
  }
  lines.push("");

  // ---- 2. what it is exploitable for ----------------------------
  lines.push(t.impact);
  lines.push("");
  lines.push(v?.impact?.trim() ? v.impact : t.noImpact);
  lines.push("");

  // ---- 3. the PoC -----------------------------------------------
  //
  // ONE artifact in full, the rest as an index.
  //
  // Printing every anchored entry in full was the single biggest cost in the
  // whole report — measured on a real 13-finding audit, 156 lines PER FINDING,
  // because a grep probe carries its whole context window and a finding can have
  // half a dozen of them. A reader does not need six excerpts of the same file
  // to be convinced; they need the one artifact the finding rests on, and a
  // pointer to the rest. The full text is in `.pi-hypothesis/tree.jsonl` and the
  // report says so.
  //
  // The primary is the SINK — the same anchor the Location line points at —
  // because that is the line a reader opens first.
  lines.push(t.poc);
  lines.push("");
  const reproduced = node.evidence.filter((e) => e.kind === "command-output" && e.command);
  const anchored = node.evidence.filter((e) => e.kind === "code-slice" || (e.location && e.kind !== "command-output"));
  const sink = v?.path.filter((s) => s.location).at(-1)?.location;
  const sinkMatch = sink ? anchored.find((e) => e.location?.file === sink.file && e.location?.line === sink.line) : undefined;
  lines.push("```");
  if (reproduced.length > 0) {
    const primary = reproduced[0]!;
    lines.push(`${t.pocStatus}  ${t.pocReproduced}`);
    lines.push(`${t.pocCommand}  ${primary.command}`);
    lines.push(t.pocOutput);
    for (const l of clip(primary.detail, EVIDENCE_EXCERPT_CHARS).split("\n")) lines.push(`        ${l}`);
    const rest = [...reproduced.slice(1), ...anchored];
    if (rest.length > 0) {
      lines.push("");
      lines.push(t.pocAlso(rest.length));
      for (const ev of rest.slice(0, EVIDENCE_INDEX_LIMIT)) {
        lines.push(`  ${ev.kind}  ${ev.location ? `${ev.location.file}:${ev.location.line}` : "—"}`);
      }
      if (rest.length > EVIDENCE_INDEX_LIMIT) lines.push(`  … +${rest.length - EVIDENCE_INDEX_LIMIT}`);
    }
  } else if (anchored.length > 0) {
    const primary = sinkMatch ?? anchored[0]!;
    lines.push(`${t.pocStatus}  ${t.pocStatic}`);
    lines.push(`${t.pocAnchor}  ${primary.location ? `${primary.location.file}:${primary.location.line}` : "(no location)"}`);
    for (const l of clip(primary.detail, EVIDENCE_EXCERPT_CHARS).split("\n")) lines.push(`        ${l}`);
    const rest = anchored.filter((e) => e !== primary);
    if (rest.length > 0) {
      lines.push("");
      lines.push(t.pocAlso(rest.length));
      for (const ev of rest.slice(0, EVIDENCE_INDEX_LIMIT)) {
        lines.push(`  ${ev.kind}  ${ev.location ? `${ev.location.file}:${ev.location.line}` : "—"}`);
      }
      if (rest.length > EVIDENCE_INDEX_LIMIT) lines.push(`  … +${rest.length - EVIDENCE_INDEX_LIMIT}`);
    }
  } else {
    lines.push(`${t.pocStatus}  ${t.pocNone}`);
  }
  lines.push("```");
  lines.push("");

  // ---- 4. does it need verification? ----------------------------
  //
  // The tier above says how STRONG the evidence is; this says what to DO about
  // it. Those are different questions, and a reader triaging a report needs the
  // second one: which of these can I act on, and which are still claims?
  //
  // Everything here is DERIVED from what was recorded. The tool never decides
  // whether a finding is good enough — it only says what is still missing.
  lines.push(t.needsVerification);
  lines.push("");
  lines.push("```");
  if (node.status === "blocked") {
    lines.push(`${t.verifyBlocked}  ${clip(node.statusReason ?? "(no reason recorded)", 200)}`);
  } else if (tier === "reproduced") {
    lines.push(`${t.verifyNo}  ${t.verifyNoWhy}`);
  } else if (tier === "static") {
    lines.push(`${t.verifyYes}  ${t.verifyYesWhy}`);
  } else {
    lines.push(`${t.verifyMust}  ${t.verifyMustWhy}`);
  }
  // The actionable part: a concrete next step, built from what the auditor
  // already recorded rather than invented here.
  if (tier !== "reproduced") {
    lines.push("");
    lines.push(`${t.verifyHow}`);
    if (v?.entrypoint) {
      lines.push(`  ${t.verifyHowSend} ${v.entrypoint}`);
      if (v.payload) lines.push(`  ${t.verifyHowPayload}  ${v.payload}`);
    } else if (tier === "reasoning-only") {
      lines.push(`  ${t.verifyHowRead}`);
    } else {
      lines.push(`  ${t.verifyHowChain}`);
    }
  }
  if (!hasBeenChallenged(node)) {
    lines.push("");
    lines.push(t.verifyNotChallenged);
  }
  lines.push("```");
  lines.push("");

  // ---- what the depth work produced -------------------------------
  //
  // The children of a confirmed finding ARE the payoff of the pursue round, and
  // without this section they are buried in the tree render. Listing them here
  // is what lets a reader see whether "one bug" was followed into "the whole
  // class" or left standing on its own.
  const children = snapshotNodes.filter((n) => n.parentId === node.id);
  if (children.length === 0) {
    // One line, not a heading and a paragraph: the empty case is the common one
    // for a young tree, and four lines of it per finding is pure bulk.
    lines.push(`${t.derived(0)} ${t.noDerived}`);
    lines.push("");
  } else {
    lines.push(t.derived(children.length));
    lines.push("");
    for (const child of children) {
      const childTier = verificationTier(child);
      const sev = child.severity ? ` ${severityLabel(child.severity, lang)}` : "";
      lines.push(`- **${child.id}** [${child.category}${sev}] [${t.tierName(childTier)}] — ${clip(child.description, 200)}`);
      const where = child.attackVector?.path.filter((s) => s.location).at(-1)?.location;
      if (where) lines.push(`  - \`${where.file}:${where.line}\``);
    }
    lines.push("");
    lines.push(t.derivedNote);
    lines.push("");
  }

  // ---- the auditor's own words ----------------------------------
  if (node.statusReason) {
    lines.push(t.auditorScope);
    lines.push("");
    lines.push(`> ${node.statusReason.replace(/\n/g, "\n> ")}`);
    lines.push("");
  }

  // ---- the evidence the PoC could not show ----------------------
  //
  // ONLY entries with NO location. A located entry is bulky and substitutable —
  // the reader can open the file — so it is indexed in the PoC section above. An
  // unlocated one (a reasoning entry, a request) has no other home and IS the
  // substance of why the auditor believes the finding, so it is printed in full.
  const inPoc = [...reproduced, ...anchored];
  const rest = node.evidence.filter((e) => !inPoc.includes(e));
  if (rest.length > 0) {
    lines.push(t.evidence(node.evidence.length));
    lines.push("");
    for (const ev of rest) {
      const detail = clip(ev.detail, EVIDENCE_EXCERPT_CHARS);
      // One line when it fits, a fence when it does not: a reasoning entry is a
      // sentence, and fencing a sentence is four lines of punctuation.
      if (!detail.includes("\n") && detail.length <= 200) {
        lines.push(`- **${ev.kind}** — ${detail}`);
      } else {
        lines.push(`- **${ev.kind}**`);
        lines.push("");
        lines.push("  ```");
        for (const l of detail.split("\n")) lines.push(`  ${l}`);
        lines.push("  ```");
        lines.push("");
      }
    }
    lines.push("");
  }
  return lines;
}

function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max - 1);
  const space = cut.lastIndexOf(" ");
  return `${space > max * 0.6 ? cut.slice(0, space) : cut}…`;
}

export interface RenderReportOptions {
  at?: string;
  language?: ReportLanguage;
}

/**
 * The report.
 *
 * Ordered so the reader can stop early: summary, then the findings worst-first,
 * then what was ruled out, then the boundary (what was NOT examined), then the
 * method, then the explicit non-claims.
 */
export function renderReport(snapshot: TreeSnapshot, loop: AuditLoopState | null, opts: RenderReportOptions = {}): string {
  const at = opts.at ?? new Date().toISOString();
  const lang = opts.language ?? "zh";
  const t = reportStrings(lang);
  const hypotheses = snapshot.nodes.filter((n) => n.nodeKind !== "scope");
  const confirmed = snapshot.nodes.filter((n) => n.status === "confirmed").sort(compareBySeverity);
  const rejected = snapshot.nodes.filter((n) => n.status === "rejected");
  const blocked = snapshot.nodes.filter((n) => n.status === "blocked");
  const unexamined = schedulerOrder(snapshot);
  const coverage = segmentCoverage(snapshot);
  const combo = consolidationStatus(snapshot);
  const dossiers = confirmed.map((n) => dossierOf(n));
  const complete = dossiers.filter((d) => d.complete).length;
  const chains = new Map(confirmed.map((n) => [n.id, chainState(n, (id) => snapshot.byId.get(id))]));
  const chainReady = [...chains.values()].filter((c) => isUsable(c.state)).length;
  const unassessed = [...chains.values()].filter((c) => c.state === "unassessed" || c.state === "untracked").length;

  const lines: string[] = [];
  lines.push(t.title);
  lines.push("");
  lines.push(t.liveLine1);
  lines.push(t.liveLine2);
  lines.push("");
  lines.push(`- **${t.project}**: \`${snapshot.objective}\``);
  lines.push(`- **${t.generated}**: ${at}`);
  if (loop) {
    lines.push(`- **${t.run}**: ${loop.kind} · ${loop.status} · round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : ""}`);
    // The clock. Active time is the headline because that is the honest answer to
    // "how long did this take"; wall time and paused time sit alongside it so the
    // two can never be confused for each other.
    const timing = loopTiming(loop, Date.parse(at) || Date.now());
    if (timing) {
      const bits = [t.durationActive(formatDuration(timing.activeMs))];
      if (timing.pausedMs > 0) {
        bits.push(t.durationWall(formatDuration(timing.wallMs)));
        bits.push(t.durationPaused(formatDuration(timing.pausedMs)));
      }
      if (timing.roundsPerHour !== null) bits.push(t.durationRate(timing.roundsPerHour.toFixed(1)));
      lines.push(`- **${t.duration}**: ${bits.join(" · ")}`);
    }
    lines.push(`- **${t.started}**: ${loop.startedAt}${loop.endedAt ? ` · **${t.ended}**: ${loop.endedAt}` : ""}`);
    lines.push(`- **${t.stoppedBecause}**: ${loop.stopReason ?? loop.pausedReason ?? t.stillRunning}`);
  } else {
    lines.push(`- **${t.run}**: ${t.noLoop}`);
  }
  lines.push("");

  // ---- summary ---------------------------------------------------
  lines.push(t.summary);
  lines.push("");
  lines.push(`| | |`);
  lines.push(`|---|---|`);
  lines.push(`| ${t.rowHypotheses} | ${hypotheses.length} |`);
  lines.push(`| ${t.rowConfirmed} | **${confirmed.length}** |`);
  lines.push(`| ${t.rowRejected} | ${rejected.length} |`);
  lines.push(`| ${t.rowUnexamined} | ${unexamined.length} |`);
  lines.push(`| ${t.rowBlocked} | ${blocked.length} |`);
  lines.push(
    `| ${t.rowCoverage} | ${coverage.total === 0 ? t.coverageNotRun : t.coverageSegments(coverage.covered, coverage.total)} |`,
  );
  lines.push(`| ${t.rowCombinations} | ${t.combinationLine(combo.passes, combo.examinedPairs)} |`);
  lines.push(`| ${t.rowVectors} | ${hypotheses.filter((n) => n.attackVector).length}/${hypotheses.length} |`);
  if (confirmed.length > 0) {
    lines.push(`| ${t.rowDossier} | **${complete}/${confirmed.length}** |`);
    lines.push(`| ${t.rowExploitable} | **${chainReady}/${confirmed.length}** |`);
    if (unassessed > 0) lines.push(`| ${t.rowUnassessed} | ${unassessed}/${confirmed.length} |`);
  }
  lines.push("");

  // ---- operator input --------------------------------------------
  // What the operator told the audit, and whether it landed. A reader has to be
  // able to tell how much of this was human-directed: an audit that was steered
  // by a hint must not read as one that found its way alone.
  if (snapshot.notes.length > 0) {
    lines.push(t.operatorInput(snapshot.notes.length));
    lines.push("");
    lines.push(`| ${t.colId} | ${t.colKind} | ${t.colDelivered} | ${t.colText} |`);
    lines.push("|---|---|---|---|");
    for (const note of snapshot.notes) {
      const kind = note.pinned ? t.kindStanding : t.kindOneShot;
      const delivered = note.pinned
        ? t.deliveredEveryRound
        : note.deliveredRound === null
          ? t.deliveredNotYet
          : t.deliveredRound(note.deliveredRound);
      lines.push(`| ${note.id} | ${kind} | ${delivered} | ${note.text.replace(/\|/g, "\\|").replace(/\n/g, " ")} |`);
    }
    lines.push("");
  }

  if (confirmed.length === 0) {
    lines.push(t.noFinding);
    lines.push("");
    lines.push(t.noFindingNote);
    lines.push("");
  } else {
    const tiers = { reproduced: 0, static: 0, "reasoning-only": 0 };
    for (const n of confirmed) tiers[verificationTier(n)]++;
    lines.push(t.tierBreakdown);
    lines.push("");
    lines.push(`- ${t.tierReproduced(tiers.reproduced)}`);
    lines.push(`- ${t.tierStatic(tiers.static)}`);
    lines.push(`- ${t.tierReasoning(tiers["reasoning-only"])}`);
    lines.push("");
    const challenged = confirmed.filter((n) => hasBeenChallenged(n)).length;
    lines.push(t.challengedCount(challenged, confirmed.length));
    lines.push("");
    lines.push(t.dossierIncomplete(complete, confirmed.length));
    lines.push("");
    if (complete < confirmed.length) {
      lines.push(t.dossierWarning);
      lines.push("");
    }
    // A gated finding is the most misreadable thing in the file, so the gap is
    // called out in the summary rather than left for the reader to notice.
    if (unassessed > 0) {
      lines.push(t.unassessedWarning(unassessed, confirmed.length));
      lines.push("");
    }
    if (chainReady < confirmed.length - unassessed) {
      lines.push(t.exploitableWarning(confirmed.length - unassessed - chainReady, confirmed.length));
      lines.push("");
    } else if (unassessed === 0) {
      lines.push(t.exploitableNote);
      lines.push("");
    }
    if (tiers["reasoning-only"] > 0) {
      lines.push(t.reasoningWarning);
      lines.push("");
    }
  }

  // ---- confirmed -------------------------------------------------
  lines.push(`## ${t.rowConfirmed.replace(/\*\*/g, "")} (${confirmed.length})`);
  lines.push("");
  if (confirmed.length === 0) {
    lines.push(t.noneRecorded);
    lines.push("");
  } else {
    confirmed.forEach((node, i) => lines.push(...renderFinding(node, i + 1, t, lang, snapshot.nodes)));
  }

  // ---- rejected --------------------------------------------------
  lines.push(t.ruledOut(rejected.length));
  lines.push("");
  if (rejected.length === 0) {
    lines.push(t.ruledOutNone);
    lines.push("");
  } else {
    for (const node of rejected) {
      lines.push(`- **${node.id}** ${node.description}`);
      if (node.statusReason) lines.push(`  - ${t.refutedBy}: ${clip(node.statusReason, 300)}`);
    }
    lines.push("");
  }

  // ---- blocked ---------------------------------------------------
  if (blocked.length > 0) {
    lines.push(t.blocked(blocked.length));
    lines.push("");
    lines.push(t.blockedNote);
    lines.push("");
    for (const node of blocked) {
      lines.push(`- **${node.id}** ${node.description}`);
      if (node.statusReason) lines.push(`  - ${t.blockedBecause}: ${clip(node.statusReason, 300)}`);
    }
    lines.push("");
  }

  // ---- boundary --------------------------------------------------
  lines.push(t.notExamined(unexamined.length));
  lines.push("");
  if (unexamined.length === 0) {
    lines.push(t.notExaminedNone);
    lines.push("");
  } else {
    lines.push(t.notExaminedNote);
    lines.push("");
    for (const node of unexamined.slice(0, UNEXAMINED_LISTED)) {
      const v = node.attackVector ? ` → ${node.attackVector.entrypoint}` : "";
      lines.push(`- **${node.id}** [${node.category}]${v} — ${clip(node.description, 160)}`);
    }
    if (unexamined.length > UNEXAMINED_LISTED) lines.push(t.notExaminedMore(unexamined.length - UNEXAMINED_LISTED));
    lines.push("");
  }
  if (coverage.open.length > 0) {
    lines.push(`${t.segmentsUncovered}: ${coverage.open.join(", ")}`);
    lines.push("");
  }

  // ---- method ----------------------------------------------------
  lines.push(t.method);
  lines.push("");
  lines.push(...t.methodLines);
  lines.push("");

  // ---- non-claims ------------------------------------------------
  lines.push(t.nonClaims);
  lines.push("");
  // Two of the non-claims carry live counts. Substituted rather than left as
  // placeholders: a report that says "{unexamined} hypotheses were never tested"
  // is a report with a bug in it, and the numbers are the whole point of the
  // sentence.
  const subst = (line: string): string =>
    line.replace("{unexamined}", String(unexamined.length)).replace("{segments}", String(coverage.total));
  lines.push(...t.nonClaimLines.map(subst));
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push(t.footer);
  lines.push("");
  return lines.join("\n");
}

export function writeReport(
  projectRoot: string,
  snapshot: TreeSnapshot,
  loop: AuditLoopState | null,
  opts: RenderReportOptions = {},
): { ok: boolean; path: string; errors: string[] } {
  const file = reportPath(projectRoot);
  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    fs.writeFileSync(file, renderReport(snapshot, loop, opts), "utf-8");
    return { ok: true, path: file, errors: [] };
  } catch (error) {
    return { ok: false, path: file, errors: [error instanceof Error ? error.message : String(error)] };
  }
}

export { meetsTier };
