/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/sec.ts
 *
 * `/loopSEC` — give an objective, dig, get a report.
 *
 * -----------------------------------------------------------------------
 * What this mode is, and what it deliberately is not
 * -----------------------------------------------------------------------
 *
 * The hypothesis tree exists to make an audit's output TRUSTWORTHY. Every node is
 * an assertion that can be proven wrong, a verdict requires a quotable artifact, a
 * derived tier says how strong that artifact is, a challenge round attacks the
 * finding afterwards, and a refuted finding leaves the report. All of that is load
 * on every round, and it is load the operator may not want for a first pass over a
 * large codebase.
 *
 * So this mode drops it. There is no assertion gate, no verdict, no tier, no
 * falsification attempt and no challenge round — none of those can exist without
 * an assertion to attack, and a report that claimed them here would be claiming
 * discipline it does not have.
 *
 * ONE REQUIREMENT SURVIVES: a finding must carry an artifact — a `location`, an
 * `evidence` excerpt, or both. The bar is cheap (the model is reading the code, so
 * it has a `file:line`), and it is the entire difference between a triage report
 * and a list of things a model said. `validateFinding` refuses a finding with
 * neither, and `store.ts` drops one on read as well, so a hand-edited log cannot
 * put a bare claim back.
 *
 * The report therefore LEADS with what it is not. A reader who skims a list of
 * findings grouped by severity will assume the severities were checked; the report
 * says, before the first finding, that they were not.
 *
 * -----------------------------------------------------------------------
 * Where the breadth comes from, without hypotheses
 * -----------------------------------------------------------------------
 *
 * The hypothesis mode gets its breadth from recon segments: the note is chunked and
 * every chunk becomes a generation round. A dig round does not generate from a
 * segment, so this mode needs another mechanism — and it uses the one that was
 * already there and measured: **what has not been read yet**.
 *
 * `coverage.ts` computes the untouched subtrees from the files a run has cited.
 * Here the citations come from the findings instead of from hypothesis nodes, and
 * the dig brief hands the model the gap. That is the same adaptive gap the coverage
 * round uses, and it is why a `/loopSEC` run gets wider as it goes rather than
 * re-reading whatever it found first.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { STATE_DIR_NAME, appendEvent, load, nowIso } from "./store.js";
import { type Result } from "./tree.js";
import { coverageGaps, coverageHeadline, type CoverageReport } from "./coverage.js";
import {
  type AuditLoopState,
  type SecFinding,
  type SecFindingPatch,
  type Severity,
  type TreeSnapshot,
  formatDuration,
  loopTiming,
  severityRank,
} from "./types.js";

/** The sec report's file name. Distinct from REPORT.md so the two modes coexist. */
export const SEC_REPORT_FILE = "SEC-REPORT.md";
/** The running journal, one section per round. */
export const SEC_LEDGER_FILE = "SEC-FINDINGS.md";

export function secReportPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, SEC_REPORT_FILE);
}

export function secLedgerPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, SEC_LEDGER_FILE);
}

// -----------------------------------------------------------------
// Recording
// -----------------------------------------------------------------

export interface FindingInput {
  title: string;
  category: string;
  severity?: Severity;
  preAuth?: boolean;
  file?: string;
  line?: number;
  evidence?: string;
  reasoning?: string;
  poc?: string;
  round?: number;
}

/**
 * The one gate this mode keeps, and why it is not negotiable.
 *
 * Everything else about `/loopSEC` is free-form, but a finding with no artifact is
 * not a finding — it is a sentence. The cost of the requirement is a `file:line`
 * the model already has in hand, and the benefit is that every line of the report
 * can be opened and checked by the reader. A mode that dropped this too would
 * produce a document that looks like a security assessment and cannot be verified
 * at all.
 */
export function validateFinding(input: FindingInput): Result<FindingInput> {
  const errors: string[] = [];
  if (typeof input.title !== "string" || input.title.trim() === "") {
    errors.push("title is required — say what the finding is");
  }
  const hasLocation = typeof input.file === "string" && input.file.trim() !== "";
  const hasEvidence = typeof input.evidence === "string" && input.evidence.trim() !== "";
  if (!hasLocation && !hasEvidence) {
    errors.push(
      "a finding needs an artifact: a `file` (with `line`) or an `evidence` excerpt. " +
        "This mode has no assertion gate and no verification tier, so the artifact is the ONLY thing " +
        "a reader can check — without it the report is a list of sentences.",
    );
  }
  if (hasLocation && (typeof input.line !== "number" || !Number.isFinite(input.line) || input.line < 1)) {
    errors.push("`line` must be a 1-based line number when `file` is given");
  }
  if (typeof input.category !== "string" || input.category.trim() === "") {
    errors.push("category is required (free-form here, but it is how the report groups findings)");
  }
  return errors.length === 0 ? { ok: true, value: input, warnings: [] } : { ok: false, errors };
}

/** Next free `F-####` id. */
function nextFindingId(snapshot: TreeSnapshot): string {
  let max = 0;
  for (const f of snapshot.findings) {
    const m = /^F-(\d+)$/.exec(f.id);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `F-${String(max + 1).padStart(4, "0")}`;
}

export function recordFinding(projectRoot: string, input: FindingInput, at = nowIso()): Result<SecFinding> {
  const check = validateFinding(input);
  if (!check.ok) return { ok: false, errors: check.errors };
  const snapshot = load(projectRoot).snapshot;
  const finding: SecFinding = {
    id: nextFindingId(snapshot),
    at,
    round: typeof input.round === "number" && input.round > 0 ? input.round : snapshot.rounds,
    title: input.title.trim(),
    category: input.category.trim(),
    ...(input.severity ? { severity: input.severity } : {}),
    ...(typeof input.preAuth === "boolean" ? { preAuth: input.preAuth } : {}),
    ...(typeof input.file === "string" && input.file
      ? { location: { file: input.file, line: typeof input.line === "number" ? Math.max(1, Math.floor(input.line)) : 1 } }
      : {}),
    ...(typeof input.evidence === "string" && input.evidence ? { evidence: input.evidence } : {}),
    ...(typeof input.reasoning === "string" && input.reasoning ? { reasoning: input.reasoning } : {}),
    ...(typeof input.poc === "string" && input.poc ? { poc: input.poc } : {}),
  };
  if (!appendEvent(projectRoot, { type: "finding_recorded", at, finding })) {
    return { ok: false, errors: ["the finding could not be written to the log"] };
  }
  return { ok: true, value: finding, warnings: [] };
}

export function updateFinding(projectRoot: string, id: string, patch: SecFindingPatch, at = nowIso()): Result<SecFinding> {
  const snapshot = load(projectRoot).snapshot;
  const existing = snapshot.findings.find((f) => f.id === id);
  if (!existing) return { ok: false, errors: [`${id} is not a finding in this run`] };
  // The artifact requirement holds on UPDATE too, or a patch could erase the only
  // thing a reader can check.
  const location = patch.location ?? existing.location;
  const evidence = patch.evidence ?? existing.evidence;
  if (!location && !evidence) {
    return { ok: false, errors: [`${id} would be left with no artifact — a finding needs a location or an evidence excerpt`] };
  }
  if (!appendEvent(projectRoot, { type: "finding_updated", at, id, patch })) {
    return { ok: false, errors: ["the update could not be written to the log"] };
  }
  const after = load(projectRoot).snapshot.findings.find((f) => f.id === id)!;
  return { ok: true, value: after, warnings: [] };
}

export function submitSecRecon(projectRoot: string, note: string, at = nowIso()): Result<string> {
  const text = (note ?? "").trim();
  if (text.length < 200) {
    return {
      ok: false,
      errors: [
        `the recon note must be at least 200 characters (got ${text.length}). It is the ONLY pass over the ` +
          "project, and every later dig round works from it plus what has not been read yet.",
      ],
    };
  }
  if (!appendEvent(projectRoot, { type: "sec_recon_submitted", at, note: text })) {
    return { ok: false, errors: ["the recon note could not be written to the log"] };
  }
  return { ok: true, value: text, warnings: [] };
}

// -----------------------------------------------------------------
// Coverage, from findings instead of from nodes
// -----------------------------------------------------------------

/**
 * Every project-relative file a FINDING cites.
 *
 * The hypothesis version walks `attackVector.path` and `evidence`. This walks the
 * finding's location and — because a finding may carry an evidence excerpt with no
 * location — any `file:line` looking token inside that excerpt, so a paste of a
 * code slice still counts as having read the file it came from.
 */
export function secCitedFiles(snapshot: Pick<TreeSnapshot, "findings">): Set<string> {
  const cited = new Set<string>();
  const add = (file: string | undefined): void => {
    if (!file) return;
    cited.add(path.posix.normalize(file.split("\\").join("/")).replace(/^\.\//, ""));
  };
  for (const finding of snapshot.findings) {
    add(finding.location?.file);
    const text = finding.evidence ?? "";
    // `src/a.py:41` and `src/a.py:41-49` — the two shapes a pasted artifact uses.
    for (const m of text.matchAll(/([A-Za-z0-9_./-]+\.[A-Za-z0-9]+):\d+/g)) add(m[1]);
  }
  return cited;
}

export function secCoverage(snapshot: TreeSnapshot, projectRoot: string): CoverageReport {
  return coverageGaps(snapshot, projectRoot, secCitedFiles(snapshot));
}

// -----------------------------------------------------------------
// The briefs
// -----------------------------------------------------------------

/**
 * Round 1: read the project, write the note.
 *
 * Same stakes as the hypothesis recon, stated the same way, because the note is the
 * ceiling in BOTH modes — the difference is only what later rounds do with it.
 */
export function renderSecReconBrief(snapshot: TreeSnapshot, objective: string, round: number): string {
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — RECON]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  lines.push("Nothing can be dug for before the project has been read. This round produces the RECON NOTE.");
  lines.push("");
  lines.push("THIS IS THE ONLY RECON PASS, AND IT SETS THE CEILING.");
  lines.push("");
  lines.push("Every later round works from this note plus what has not been read yet. **A part of the");
  lines.push("project absent from this note is a part nothing will look at.**");
  lines.push("");
  lines.push("READ THE PROJECT. Use `ls`, `find`, `grep`, `read` — whatever the shape of the repository demands.");
  lines.push("Cover, in prose:");
  lines.push("  - what the project IS (language, framework, what it does, how it is deployed)");
  lines.push("  - its ENTRYPOINTS: HTTP routes, RPC/GraphQL, websockets, CLI verbs, scheduled jobs,");
  lines.push("    queue consumers, file uploads, deserializers, template/plugin loaders");
  lines.push("  - the TRUST BOUNDARIES: where input crosses from unauthenticated to authenticated,");
  lines.push("    and what the authentication actually checks");
  lines.push("  - where the class of bug the objective names would LIVE in this codebase");
  lines.push("  - anything you could NOT work out");
  lines.push("");
  lines.push("Write PARAGRAPHS, not one giant block. Name the files and directories you looked at.");
  lines.push("");
  lines.push("Then stop. Record it with `sec_recon`, and the next round starts digging.");
  return lines.join("\n");
}

/** What has been found so far, one line each. */
function renderFoundSoFar(snapshot: TreeSnapshot): string {
  const findings = snapshot.findings;
  if (findings.length === 0) {
    return "FOUND SO FAR: nothing yet. This round is expected to produce the first finding(s).";
  }
  const lines: string[] = [`FOUND SO FAR (${findings.length}) — do NOT re-report these:`];
  for (const f of [...findings].sort(compareFinding)) {
    const where = f.location ? ` ${f.location.file}:${f.location.line}` : "";
    lines.push(`  ${f.id} [${f.severity ?? "unrated"}] ${f.category} — ${clip(f.title, 110)}${where}`);
  }
  return lines.join("\n");
}

/**
 * A dig round.
 *
 * Four things, in this order, and each one earns its place: the objective (what the
 * run is for), the note (what the project is), what has been found (so the round
 * does not re-report it), and what has NOT been read (which is where the breadth
 * comes from now that there are no segments to generate from).
 */
export function renderSecDigBrief(
  snapshot: TreeSnapshot,
  objective: string,
  round: number,
  coverageReport: CoverageReport,
): string {
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — DIG]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  lines.push("--- YOUR NOTE FROM THE RECON PASS ---");
  lines.push(snapshot.secNote ?? "(no recon note was recorded)");
  lines.push("--- END OF NOTE ---");
  lines.push("");
  lines.push(renderFoundSoFar(snapshot));
  lines.push("");
  lines.push("--- NOT READ YET ---");
  if (coverageReport.projectFiles === null) {
    lines.push(`The project walk could not run (${coverageReport.reason}), so the unread set is unknown.`);
  } else if (coverageReport.gaps.length === 0) {
    lines.push(
      `Every directory of any size has been cited by a finding (${coverageHeadline(coverageReport)}). ` +
        "That is not the same as having been cleared — it means there is no whole block left blank.",
    );
  } else {
    lines.push(`${coverageHeadline(coverageReport)}`);
    lines.push("");
    lines.push("The biggest untouched subtrees:");
    for (const gap of coverageReport.gaps) lines.push(`  ${gap.dir}  (${gap.files} file(s), nothing recorded from it)`);
    lines.push("");
    lines.push("**A directory with no finding is not clean, it is UNREAD.** These are the parts the note did");
    lines.push("not reach. Spend some of this round there.");
  }
  lines.push("");
  lines.push("--- WHAT TO DO ---");
  lines.push("Go and look. Read code, follow the data from an entrypoint to a sink, and when you have");
  lines.push("something worth recording, record it with `sec_finding`.");
  lines.push("");
  lines.push("**This mode has no assertion gate.** You do not have to phrase a finding as a falsifiable");
  lines.push("claim, and there is no verdict, no tier and no challenge round. What a finding MUST carry is");
  lines.push("an artifact: a `file` + `line`, or an `evidence` excerpt, or both. That is the only thing a");
  lines.push("reader of the report can check, so a finding without one is refused.");
  lines.push("");
  lines.push("Record what you actually found, at the severity you actually believe. Recording nothing is a");
  lines.push("legitimate outcome for a round — a run that invents findings to look productive is worse than");
  lines.push("one that comes back empty.");
  return lines.join("\n");
}

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

function clip(text: string, max: number): string {
  const t = (text ?? "").replace(/\s+/g, " ").trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

function compareFinding(a: SecFinding, b: SecFinding): number {
  const ra = a.severity ? severityRank(a.severity) : 99;
  const rb = b.severity ? severityRank(b.severity) : 99;
  if (ra !== rb) return ra - rb;
  return a.id.localeCompare(b.id);
}

export interface SecReportOptions {
  /** ISO timestamp to stamp the report with. */
  at?: string;
  coverageReport?: CoverageReport;
}

/** Findings grouped by severity, worst first, with the unrated last. */
export function secFindingsBySeverity(snapshot: TreeSnapshot): { rated: SecFinding[]; unrated: SecFinding[] } {
  const sorted = [...snapshot.findings].sort(compareFinding);
  return { rated: sorted.filter((f) => f.severity), unrated: sorted.filter((f) => !f.severity) };
}

export function renderSecReport(
  snapshot: TreeSnapshot,
  loop: AuditLoopState | null,
  opts: SecReportOptions = {},
): string {
  const at = opts.at ?? nowIso();
  const coverage = opts.coverageReport ?? null;
  const lines: string[] = [];
  const findings = snapshot.findings;
  const { rated, unrated } = secFindingsBySeverity(snapshot);
  const preAuth = findings.filter((f) => f.preAuth === true).length;

  lines.push("# /loopSEC — findings");
  lines.push("");
  lines.push("_Generated from the recorded state of a `/loopSEC` run. Nothing here is summarised by a model._");
  lines.push("");
  lines.push(`- **Objective**: \`${snapshot.objective || loop?.objective || "(none)"}\``);
  lines.push(`- **Generated**: ${at}`);
  if (loop) {
    lines.push(`- **Run**: sec · ${loop.status} · round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : ""}`);
    const timing = loopTiming(loop, Date.parse(at) || Date.now());
    if (timing) lines.push(`- **Duration**: ${formatDuration(timing.activeMs)} active`);
    lines.push(`- **Stopped because**: ${loop.stopReason ?? loop.pausedReason ?? "(still running)"}`);
  }
  lines.push("");

  // ---- THE CAVEAT, BEFORE THE FINDINGS ------------------------------------
  //
  // Placed here rather than at the foot, and that is deliberate. Everywhere else in
  // this extension the non-claims go last; here the reader is about to scroll a list
  // of findings GROUPED BY SEVERITY, and severity is exactly the field this mode
  // does not check. A reader who meets the caveat afterwards has already formed the
  // wrong impression.
  lines.push("## READ THIS FIRST — what this report is not");
  lines.push("");
  lines.push("**This is a triage list, not a verified audit.** `/loopSEC` runs without the hypothesis tree,");
  lines.push("and that removes every mechanism that made the other report's findings checkable:");
  lines.push("");
  lines.push("| Not present | What that means here |");
  lines.push("|---|---|");
  lines.push("| **No verification tier** | Nothing distinguishes a finding confirmed by running a command from one read out of the source. |");
  lines.push("| **No falsification attempt** | Nobody tried to prove any of these wrong. The false-positive rate is UNKNOWN, not low. |");
  lines.push("| **No challenge round** | Each finding is the auditor agreeing with itself. |");
  lines.push("| **No severity check** | Severity is the auditor's own judgement, made once, unreviewed. |");
  lines.push("| **No assertion gate** | A finding may be a vague statement of an area rather than a claim about behaviour. |");
  lines.push("");
  lines.push("**What IS enforced: every finding carries an artifact.** A `file:line` or an evidence excerpt is");
  lines.push("required, so every line below can be opened and checked by hand. That is the only guarantee this");
  lines.push("mode makes, and it is why the requirement exists.");
  lines.push("");
  lines.push("For findings you intend to act on, re-run the same objective under `/loop` — there the finding");
  lines.push("gets a tier, an attempt to refute it, and a challenge round.");
  lines.push("");

  // ---- summary ------------------------------------------------------------
  lines.push("## Summary");
  lines.push("");
  lines.push("| | |");
  lines.push("|---|---|");
  lines.push(`| Findings recorded | ${findings.length} |`);
  for (const sev of ["critical", "high", "medium", "low", "info"] as const) {
    const n = rated.filter((f) => f.severity === sev).length;
    if (n > 0) lines.push(`| ${sev} | ${n} |`);
  }
  if (unrated.length > 0) lines.push(`| **no severity recorded** | **${unrated.length}** |`);
  lines.push(`| Reachable WITHOUT authentication | ${preAuth} |`);
  lines.push(`| Marked post-auth | ${findings.filter((f) => f.preAuth === false).length} |`);
  lines.push(`| Authentication NOT assessed | ${findings.filter((f) => typeof f.preAuth !== "boolean").length} |`);
  lines.push(`| Recon note recorded | ${snapshot.secNote ? "yes" : "**no**"} |`);
  lines.push("");
  if (findings.length === 0) {
    lines.push("**No findings were recorded.** That is a legitimate outcome — a run that invents findings to");
    lines.push("look productive is worse than one that comes back empty — but it is not evidence that the");
    lines.push("project is clean. See the unread list below.");
    lines.push("");
  }

  // ---- coverage -----------------------------------------------------------
  if (coverage) {
    lines.push("## Coverage");
    lines.push("");
    lines.push(`| | |`);
    lines.push(`|---|---|`);
    lines.push(`| Files cited by a finding | ${coverageHeadline(coverage)} |`);
    lines.push(`| Directories with ZERO findings | ${coverage.gaps.length} |`);
    lines.push("");
    if (coverage.projectFiles === null) {
      lines.push(`_Not measured — ${coverage.reason}. **Not measured is not fully covered.**_`);
    } else if (coverage.gaps.length === 0) {
      lines.push("Every directory of any size is cited by at least one finding. That is not the same as having");
      lines.push("been cleared — it only means there is no whole block left blank.");
    } else {
      lines.push("> **A directory with no finding is not \"clean\", it is UNREAD.** These are the parts the recon");
      lines.push("> note did not reach, and they bound how much of the project this run actually saw.");
      lines.push("");
      for (const gap of coverage.gaps) lines.push(`- \`${gap.dir}\` — ${gap.files} file(s), nothing recorded from it`);
    }
    lines.push("");
  }

  // ---- the findings -------------------------------------------------------
  lines.push(`## Findings (${findings.length})`);
  lines.push("");
  if (findings.length === 0) {
    lines.push("_None recorded._");
    lines.push("");
  } else {
    const ordered = [...rated, ...unrated];
    ordered.forEach((f, i) => {
      lines.push(...renderSecFinding(f, i + 1));
    });
  }

  // ---- what was not read --------------------------------------------------
  if (coverage && coverage.gaps.length > 0) {
    lines.push("## Not read");
    lines.push("");
    lines.push("These subtrees were never cited by a finding. They are not clean; nobody looked.");
    lines.push("");
    for (const gap of coverage.gaps) lines.push(`- \`${gap.dir}\` — ${gap.files} file(s)`);
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push("_Written by pi-audit-hypothesis-tree from `.pi-hypothesis/` — the append-only log, the findings");
  lines.push("journal and the recon note. Re-run `/loopSEC report` to regenerate it from state._");
  lines.push("");
  return lines.join("\n");
}

function renderSecFinding(f: SecFinding, index: number): string[] {
  const lines: string[] = [];
  const sev = f.severity ? severityZh(f.severity) : "未评级";
  lines.push(`### ${index}. ${f.id} — ${sev} — ${f.category}`);
  lines.push("");
  lines.push(f.title);
  lines.push("");
  if (f.location) lines.push(`**位置：** \`${f.location.file}:${f.location.line}\``);
  lines.push(
    `**是否需要身份认证：** ${
      f.preAuth === true ? "认证前可达" : f.preAuth === false ? "认证后" : "未评估（这不等于认证前）"
    }`,
  );
  lines.push(`**记录于：** 第 ${f.round} 轮 · ${f.at}`);
  lines.push("");
  if (f.reasoning) {
    lines.push("**为什么：**");
    lines.push("");
    lines.push(f.reasoning);
    lines.push("");
  }
  if (f.evidence) {
    lines.push("**物证：**");
    lines.push("");
    const fence = fenceFor(f.evidence);
    lines.push(fence);
    for (const line of f.evidence.split("\n")) lines.push(line);
    lines.push(fence);
    lines.push("");
  }
  if (f.poc) {
    lines.push("**PoC：**");
    lines.push("");
    const fence = fenceFor(f.poc);
    lines.push(fence);
    for (const line of f.poc.split("\n")) lines.push(line);
    lines.push(fence);
    lines.push("");
  }
  lines.push(
    "> **未经验证。** 这条没有验证等级、没有被尝试证伪、没有对抗复核。它是审计员的判断加一份可查的物证。",
  );
  lines.push("");
  return lines;
}

/** A fence longer than anything inside it. See reportText.ts on why this matters. */
function fenceFor(text: string): string {
  let longest = 0;
  for (const m of text.match(/`+/g) ?? []) longest = Math.max(longest, m.length);
  return "`".repeat(Math.max(3, longest + 1));
}

function severityZh(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "严重";
    case "high":
      return "高危";
    case "medium":
      return "中危";
    case "low":
      return "低危";
    case "info":
      return "信息";
  }
}

/** A compact view of the findings, for `/sec tree`. */
export function renderSecFindings(snapshot: TreeSnapshot): string[] {
  if (snapshot.findings.length === 0) {
    return [
      snapshot.secNote
        ? "No findings recorded yet."
        : "No recon note and no findings yet — round 1 reads the project.",
    ];
  }
  const lines: string[] = [`${snapshot.findings.length} finding(s):`, ""];
  for (const f of [...snapshot.findings].sort(compareFinding)) {
    const where = f.location ? `  ${f.location.file}:${f.location.line}` : "  (evidence only)";
    const auth = f.preAuth === true ? " [pre-auth]" : f.preAuth === false ? " [auth]" : " [auth NOT assessed]";
    lines.push(`  ${f.id} [${f.severity ?? "unrated"}] ${f.category}${auth}${where}`);
    lines.push(`     ${clip(f.title, 100)}`);
  }
  return lines;
}

// -----------------------------------------------------------------
// Writing
// -----------------------------------------------------------------

export function writeSecReport(
  projectRoot: string,
  snapshot: TreeSnapshot,
  loop: AuditLoopState | null,
  opts: SecReportOptions = {},
): Result<string> {
  const reportPath = secReportPath(projectRoot);
  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    const text = renderSecReport(snapshot, loop, {
      ...opts,
      coverageReport: opts.coverageReport ?? secCoverage(snapshot, projectRoot),
    });
    // Only the append-and-truncate pair this project uses everywhere: no rename,
    // no held fd, so a non-NTFS volume cannot fail the write.
    fs.writeFileSync(reportPath, text, "utf-8");
  } catch (error) {
    return { ok: false, errors: [`could not write the report: ${(error as Error).message}`] };
  }
  return { ok: true, value: reportPath, warnings: [] };
}

/**
 * Append one round to the journal.
 *
 * CUMULATIVE, like the hypothesis ledger and for the same reason: this is written
 * when the round is PREPARED, so it cannot contain the round's own output. Listing
 * only `finding.round === round` therefore printed "no finding recorded this round"
 * for every round and showed the findings in NONE of them — measured, 2 findings and
 * five entries all claiming zero.
 *
 * The full list also makes the journal readable on its own: a reader can see what
 * the run knew at each point without diffing consecutive entries.
 */
export function appendSecLedger(
  projectRoot: string,
  snapshot: TreeSnapshot,
  round: number,
  summary: readonly string[],
  at = nowIso(),
): boolean {
  const findings = [...snapshot.findings].sort(compareFinding);
  const body: string[] = [];
  body.push("");
  body.push(`## Round ${round} — ${at}`);
  body.push("");
  const fence = fenceFor(summary.join("\n"));
  body.push(fence);
  body.push(...summary);
  body.push(fence);
  body.push("");
  body.push(`### Findings so far (${findings.length})`);
  body.push("");
  if (findings.length === 0) {
    body.push("_none yet_");
  } else {
    for (const f of findings) {
      const where = f.location ? ` — ${f.location.file}:${f.location.line}` : "";
      const when = f.round > 0 ? ` (r${f.round})` : "";
      body.push(`- [${f.severity ?? "unrated"}] **${f.id}** ${f.title} — ${f.category}${where}${when}`);
    }
  }
  body.push("");
  try {
    fs.mkdirSync(path.join(projectRoot, STATE_DIR_NAME), { recursive: true });
    fs.appendFileSync(secLedgerPath(projectRoot), body.join("\n"), "utf-8");
    return true;
  } catch {
    return false;
  }
}

/**
 * The skill guidance is NOT appended here.
 *
 * `loop.ts` owns brief assembly — it appends the operator's notes, the run's scope,
 * the output requirements and the skill guidance to every brief in every mode, in
 * one place. Doing it here as well would apply it twice in sec mode and would put
 * the same decision in two files.
 */
export function secRoundBrief(
  snapshot: TreeSnapshot,
  objective: string,
  round: number,
  coverageReport: CoverageReport,
): string {
  return snapshot.secNote === null
    ? renderSecReconBrief(snapshot, objective, round)
    : renderSecDigBrief(snapshot, objective, round, coverageReport);
}
