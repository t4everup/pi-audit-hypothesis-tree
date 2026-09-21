/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/executor.ts
 *
 * The verification executor: it runs bounded probes and turns their RAW output
 * into `Evidence`.
 *
 * -----------------------------------------------------------------------
 * What this module is, and what it deliberately is not
 * -----------------------------------------------------------------------
 *
 * It is NOT a hypothesis understander. Turning "the login handler does not
 * validate the JWT signature" into a grep pattern would be guessing, and a
 * guess dressed as analysis is exactly what this extension exists to avoid.
 *
 * It IS a bounded evidence collector with one formal rule: **a probe is a
 * falsification attempt.** The caller states what the hypothesis PREDICTS about
 * one mechanical fact (`expectation: "present" | "absent"`), and the probe
 * reports whether the prediction held:
 *
 *   survived    — the prediction held; the hypothesis was not falsified here
 *   falsified   — the prediction failed; this is a COUNTEREXAMPLE
 *   inconclusive— the probe could not establish anything (missing target,
 *                 refused, timed out)
 *
 * That is Popperian falsification in mechanical form, and it is why the
 * aggregation rule is asymmetric:
 *
 *   ONE counterexample refutes the hypothesis, so any `falsified` suggests
 *   `rejected`. Many survivals only mean "not yet refuted", so they suggest
 *   `confirmed` — support, never proof.
 *
 * -----------------------------------------------------------------------
 * The executor NEVER changes a node's status
 * -----------------------------------------------------------------------
 *
 * `runVerification` returns a SUGGESTION and a set of ready-to-attach evidence.
 * Deciding is a separate, deliberate act (`setStatus`), because the whole point
 * of separating evidence from verdict is that a machine can collect the first
 * and must not silently produce the second.
 *
 * -----------------------------------------------------------------------
 * Bounds
 * -----------------------------------------------------------------------
 *
 * Every probe is bounded, and the bounds are enforced rather than documented:
 * a file walk has a file/size/line budget, a grep has a match cap, a command
 * has a hard timeout and an output cap, and a runaway regex is refused before
 * it runs. A probe that cannot be bounded is refused, not attempted.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type { Evidence, Hypothesis } from "./types.js";
import { isVerdict } from "./types.js";
import { PROBE_SKIP_DIRS, PROBE_SKIP_DIRS_NOTE, type HypothesisSettings } from "./settings.js";

// -----------------------------------------------------------------
// Probe definitions
// -----------------------------------------------------------------

/** What the hypothesis predicts about the mechanical fact the probe checks. */
export type ProbeExpectation = "present" | "absent";

export interface LocationProbe {
  kind: "location";
  /** Project-relative path. */
  file: string;
  /** 1-based line. */
  line: number;
  /** `present` (default) means "this code is here and says what I claim". */
  expectation?: ProbeExpectation;
  note?: string;
}

export interface GrepProbe {
  kind: "grep";
  /** JavaScript regular expression source. */
  pattern: string;
  /** REQUIRED: a grep with no stated prediction cannot falsify anything. */
  expectation: ProbeExpectation;
  /** Optional project-relative subdirectory to restrict the walk to. */
  subPath?: string;
  /** Case-insensitive by default; set false for a case-sensitive search. */
  ignoreCase?: boolean;
  note?: string;
}

export interface CommandProbe {
  kind: "command";
  /** Executable name or path, passed to the host exec (no shell). */
  command: string;
  args?: string[];
  /** Expected exit code. `"zero"` (default) or `"nonzero"`. */
  expectation?: "zero" | "nonzero";
  /** Per-probe timeout; clamped to the settings ceiling. */
  timeoutMs?: number;
  note?: string;
}

export type Probe = LocationProbe | GrepProbe | CommandProbe;

export type ProbeOutcome = "survived" | "falsified" | "inconclusive";

export interface ProbeResult {
  probe: Probe;
  outcome: ProbeOutcome;
  /** One line: what happened. */
  summary: string;
  /**
   * What this probe establishes, and — more importantly — what it does NOT.
   * Every result carries this because a probe's output is always weaker than
   * it looks, and the weakness has to travel with the evidence.
   */
  establishes: string;
  /** Quotable artifacts, ready for `addEvidence`. */
  evidence: Evidence[];
  errors: string[];
}

export interface VerificationOutcome {
  nodeId: string;
  nodeDescription: string;
  results: ProbeResult[];
  /** A SUGGESTION. The executor never applies it. */
  suggestedVerdict: "confirmed" | "rejected" | "inconclusive";
  rationale: string[];
  /** The counterexample that refuted the hypothesis, when there is one. */
  counterexample: string | null;
  /** Every probe's evidence, flattened. */
  evidence: Evidence[];
  /** True when at least one probe produced a quotable artifact. */
  hasQuotableEvidence: boolean;
  /** True when the probes could not settle it and more work is needed. */
  needsMoreProbes: boolean;
}

/** The host's exec surface, injected so this module stays testable. */
export type ExecFn = (
  command: string,
  args: string[],
  options: { cwd: string; timeout: number; signal?: AbortSignal },
) => Promise<{ stdout: string; stderr: string; code: number }>;

export interface RunVerificationOptions {
  projectRoot: string;
  node: Hypothesis;
  probes: Probe[];
  settings: HypothesisSettings;
  /** Absent ⇒ `command` probes are refused (not silently skipped). */
  exec?: ExecFn;
  signal?: AbortSignal;
  at?: string;
}

// -----------------------------------------------------------------
// Bounds helpers
// -----------------------------------------------------------------

/**
 * Truncate captured output, keeping the head AND the tail.
 *
 * The tail is weighted heavier because that is where a test runner or a
 * compiler puts the failure. Dropping the tail (the obvious `slice(0, max)`)
 * would keep the banner and throw away the error.
 */
export function truncateOutput(text: string, max: number): string {
  if (text.length <= max) return text;
  const headRoom = Math.floor(max / 3);
  const tailRoom = max - headRoom;
  const omitted = text.length - max;
  return (
    text.slice(0, headRoom) +
    `\n[… ${omitted} character(s) omitted — the head and the tail are kept, the middle is dropped …]\n` +
    text.slice(text.length - tailRoom)
  );
}

/**
 * Refuse a regex that is a plausible catastrophic-backtracking hazard.
 *
 * This is a MITIGATION, not a guarantee — JavaScript has no regex timeout, and
 * a general ReDoS decider is not something a probe can carry. What it catches
 * is the classic shape: a quantified group whose own body is quantified
 * (`(a+)+`, `(\w*)*`, `(a{1,})*`). A pattern that slips past this is still
 * bounded by the line budget, so the worst case is a slow probe rather than a
 * wedged extension.
 */
export function looksCatastrophic(pattern: string): string | null {
  if (pattern.length > 500) return "pattern is longer than 500 characters";
  // A group containing a quantifier, itself quantified.
  if (/\([^()]*[+*][^()]*\)\s*[+*]/.test(pattern)) return "a quantified group contains another quantifier (nested quantifier — catastrophic backtracking hazard)";
  if (/\([^()]*\{\d+,\}[^()]*\)\s*[+*{]/.test(pattern)) return "a quantified group contains an unbounded repetition (nested quantifier)";
  // Alternation of overlapping prefixes inside a quantified group, the other
  // classic shape: (a|a)* / (a|ab)+
  if (/\((\w+)\|\1[^)]*\)\s*[+*]/.test(pattern)) return "a quantified group alternates overlapping alternatives";
  return null;
}

/** True when the regex compiles. Returns the error message otherwise. */
export function regexError(pattern: string, ignoreCase: boolean): string | null {
  try {
    new RegExp(pattern, ignoreCase ? "i" : "");
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

// -----------------------------------------------------------------
// Filesystem walk (bounded)
// -----------------------------------------------------------------

interface WalkResult {
  files: string[];
  truncated: boolean;
  reason: string;
}

/**
 * Split text into lines the way a text editor counts them: a trailing newline
 * terminates the last line rather than starting an empty one.
 *
 * `"a\nb\n".split(/\r?\n/)` yields three elements, so a 2-line file would be
 * reported as 3 lines and a `file:3` citation would look valid when it points
 * past the end — exactly the fabrication the location probe exists to catch.
 */
export function splitLines(text: string): string[] {
  const lines = text.split(/\r?\n/);
  if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/** Walk the project for text files, within the configured budget. */
export function walkProject(
  projectRoot: string,
  subPath: string | undefined,
  settings: HypothesisSettings,
): WalkResult {
  const root = path.resolve(projectRoot);
  const start = subPath ? path.resolve(root, subPath) : root;
  // Never walk outside the project: a probe must not read the host.
  const rel = path.relative(root, start);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    return { files: [], truncated: true, reason: `"${subPath}" resolves outside the project root` };
  }

  const files: string[] = [];
  let truncated = false;
  let reason = "";
  const stack: string[] = [start];

  while (stack.length > 0) {
    if (files.length >= settings.maxFilesScanned) {
      truncated = true;
      reason = `stopped at the ${settings.maxFilesScanned}-file budget`;
      break;
    }
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    // Sorted so two runs of the same probe walk the same files in the same
    // order. A budget-truncated scan is only interpretable if it is
    // reproducible — an arbitrary directory order makes "we stopped at 4000
    // files" mean a different 4000 files every time.
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (PROBE_SKIP_DIRS.includes(entry.name)) continue;
        stack.push(path.join(dir, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;
      const abs = path.join(dir, entry.name);
      try {
        if (fs.statSync(abs).size > settings.maxFileBytes) continue;
      } catch {
        continue;
      }
      files.push(abs);
      if (files.length >= settings.maxFilesScanned) {
        // Record the truncation HERE, not only at the top of the loop: when the
        // budget is hit on the last directory the stack is already empty, the
        // while condition fails, and the top-of-loop check never runs — so the
        // walk would silently look complete.
        truncated = true;
        reason = `stopped at the ${settings.maxFilesScanned}-file budget`;
        break;
      }
    }
  }
  return { files, truncated, reason };
}

/** Cheap binary sniff: a NUL byte in the first 4 KiB means "do not grep this". */
function looksBinary(buffer: Buffer): boolean {
  const limit = Math.min(buffer.length, 4096);
  for (let i = 0; i < limit; i++) if (buffer[i] === 0) return true;
  return false;
}

// -----------------------------------------------------------------
// Probes
// -----------------------------------------------------------------

function evidenceAt(kind: Evidence["kind"], at: string, detail: string, location?: Evidence["location"], command?: string): Evidence {
  return {
    kind,
    at,
    ...(location ? { location } : {}),
    ...(command ? { command } : {}),
    detail,
  };
}

/** Read `file:line` with context. The anti-fabrication gate: a citation that
 * does not exist is a falsified prediction, not a warning. */
export function runLocationProbe(
  projectRoot: string,
  probe: LocationProbe,
  settings: HypothesisSettings,
  at: string,
): ProbeResult {
  const expectation: ProbeExpectation = probe.expectation ?? "present";
  const abs = path.resolve(projectRoot, probe.file);
  const rel = path.relative(path.resolve(projectRoot), abs);
  const establishes = `establishes only what ${probe.file}:${probe.line} currently contains (${settings.locationContext} lines of context). It does not establish that this is the only such site, nor that the code is reachable.`;

  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    return {
      probe, outcome: "inconclusive",
      summary: `${probe.file} resolves outside the project root — refused`,
      establishes,
      evidence: [],
      errors: [`${probe.file} resolves outside the project root`],
    };
  }

  let content: string;
  try {
    if (!fs.existsSync(abs)) {
      return {
        probe,
        outcome: expectation === "absent" ? "survived" : "falsified",
        summary: `${probe.file} does not exist`,
        establishes,
        evidence: [],
        errors: [],
      };
    }
    const stat = fs.statSync(abs);
    if (!stat.isFile()) {
      return { probe, outcome: "inconclusive", summary: `${probe.file} is not a file`, establishes, evidence: [], errors: [] };
    }
    content = fs.readFileSync(abs, "utf-8");
  } catch (error) {
    return {
      probe, outcome: "inconclusive",
      summary: `${probe.file} could not be read`,
      establishes,
      evidence: [],
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }

  const lines = splitLines(content);
  if (probe.line > lines.length) {
    return {
      probe,
      outcome: expectation === "absent" ? "survived" : "falsified",
      summary: `${probe.file}:${probe.line} is past the end of the file (${lines.length} lines)`,
      establishes,
      evidence: [],
      errors: [],
    };
  }

  const from = Math.max(1, probe.line - settings.locationContext);
  const to = Math.min(lines.length, probe.line + settings.locationContext);
  const slice: string[] = [];
  for (let n = from; n <= to; n++) {
    const marker = n === probe.line ? ">" : " ";
    slice.push(`${marker} ${String(n).padStart(6)} | ${lines[n - 1] ?? ""}`);
  }
  const detail = truncateOutput(slice.join("\n"), settings.maxOutputChars);

  return {
    probe,
    outcome: "survived",
    summary: `${probe.file}:${probe.line} exists (${lines.length} lines); captured ${to - from + 1} line(s) of context`,
    establishes,
    evidence: [evidenceAt("code-slice", at, detail, { file: probe.file, line: probe.line })],
    errors: [],
  };
}

/** Bounded in-process regex search. No shell, no injection surface. */
export function runGrepProbe(
  projectRoot: string,
  probe: GrepProbe,
  settings: HypothesisSettings,
  at: string,
): ProbeResult {
  const establishes = `establishes only that the pattern /${probe.pattern}/ is ${probe.expectation === "present" ? "present" : "absent"} in the scanned files. A pattern match is not a data flow: it does not establish that the matched code is reachable, or that the match means what the hypothesis claims. ${PROBE_SKIP_DIRS_NOTE}.`;
  const ignoreCase = probe.ignoreCase ?? true;

  const bad = looksCatastrophic(probe.pattern);
  if (bad) {
    return { probe, outcome: "inconclusive", summary: `pattern refused: ${bad}`, establishes, evidence: [], errors: [bad] };
  }
  const invalid = regexError(probe.pattern, ignoreCase);
  if (invalid) {
    return { probe, outcome: "inconclusive", summary: `pattern does not compile: ${invalid}`, establishes, evidence: [], errors: [invalid] };
  }
  const re = new RegExp(probe.pattern, ignoreCase ? "i" : "");

  const walk = walkProject(projectRoot, probe.subPath, settings);
  if (walk.files.length === 0 && walk.truncated) {
    return { probe, outcome: "inconclusive", summary: `nothing scanned: ${walk.reason}`, establishes, evidence: [], errors: [walk.reason] };
  }

  const matches: Array<{ file: string; line: number; text: string }> = [];
  let linesScanned = 0;
  let filesScanned = 0;
  let budgetHit = false;

  for (const abs of walk.files) {
    if (matches.length >= settings.maxGrepMatches || linesScanned >= settings.maxLinesScanned) {
      budgetHit = true;
      break;
    }
    let buffer: Buffer;
    try {
      buffer = fs.readFileSync(abs);
    } catch {
      continue;
    }
    if (looksBinary(buffer)) continue;
    filesScanned++;
    const relFile = path.relative(path.resolve(projectRoot), abs).replace(/\\/g, "/");
    const lines = splitLines(buffer.toString("utf-8"));
    for (let i = 0; i < lines.length; i++) {
      linesScanned++;
      if (linesScanned >= settings.maxLinesScanned) {
        budgetHit = true;
        break;
      }
      const text = lines[i]!;
      if (re.test(text)) {
        matches.push({ file: relFile, line: i + 1, text: text.trim().slice(0, 300) });
        if (matches.length >= settings.maxGrepMatches) {
          budgetHit = true;
          break;
        }
      }
    }
  }

  const found = matches.length > 0;

  // A scan that did not cover the project cannot establish ABSENCE.
  //
  // Finding a match is proof regardless of coverage. NOT finding one is not:
  // the walk may have stopped before the file that contains it, and "the grep
  // matched nothing" then reads as "the check is missing" — which confirms a
  // hypothesis the code actually contradicts. So an incomplete scan downgrades
  // a negative result to inconclusive instead of letting it count as evidence.
  //
  // Field report (2026-09-21, Centreon Web): 7062 files under `vendor/` against
  // a 4000-file budget meant every unscoped grep stopped inside dependencies and
  // reported "absent" for anything in `src/`.
  const scanIncomplete = walk.truncated || linesScanned >= settings.maxLinesScanned;
  const outcome: ProbeOutcome = found
    ? probe.expectation === "present"
      ? "survived"
      : "falsified"
    : scanIncomplete
      ? "inconclusive"
      : probe.expectation === "present"
        ? "falsified"
        : "survived";

  const budgetNote = [
    matches.length >= settings.maxGrepMatches ? `${settings.maxGrepMatches} matches` : "",
    linesScanned >= settings.maxLinesScanned ? `${settings.maxLinesScanned} lines` : "",
    walk.truncated ? `${settings.maxFilesScanned} files (${walk.reason})` : "",
  ].filter(Boolean).join(" / ");
  const budgetSuffix = budgetNote ? ` [scan stopped at the budget: ${budgetNote}]` : "";
  const summary = found
    ? `/${probe.pattern}/ matched ${matches.length} line(s) in ${new Set(matches.map((m) => m.file)).size} file(s)${budgetSuffix}`
    : scanIncomplete
      ? `/${probe.pattern}/ matched nothing, but the scan was INCOMPLETE (${budgetNote || walk.reason}) — absence is not established`
      : `/${probe.pattern}/ matched nothing in ${filesScanned} file(s)${budgetSuffix}`;

  const evidence: Evidence[] = [];
  if (found) {
    const body = matches
      .map((m) => `${m.file}:${m.line}: ${m.text}`)
      .join("\n");
    evidence.push(
      evidenceAt("code-slice", at, `pattern /${probe.pattern}/ (expectation: ${probe.expectation})\n${truncateOutput(body, settings.maxOutputChars)}`, {
        file: matches[0]!.file,
        line: matches[0]!.line,
      }),
    );
  }

  return { probe, outcome, summary, establishes, evidence, errors: [] };
}

/**
 * Run a bounded command.
 *
 * Refused unless the project has opted in (`allowCommandProbes`). A refusal is
 * `inconclusive` rather than a silent skip, so the outcome never reads as
 * "nothing to see here".
 *
 * The command runs through the host's exec surface with no shell, in the
 * project root, with a hard timeout. This is NOT a sandbox — the command has
 * whatever authority the host gives it. The consent gate is the control; the
 * timeout and the output cap are the bounds.
 */
export async function runCommandProbe(
  projectRoot: string,
  probe: CommandProbe,
  settings: HypothesisSettings,
  exec: ExecFn | undefined,
  at: string,
  signal?: AbortSignal,
): Promise<ProbeResult> {
  const establishes = `establishes the exit code and output of \`${probe.command} ${(probe.args ?? []).join(" ")}\` at the time it ran. It does not establish that the command is the right test, that it covers the hypothesis, or that its result is stable.`;
  const expectation = probe.expectation ?? "zero";

  if (!settings.allowCommandProbes) {
    const why = "command probes are disabled for this project (set allowCommandProbes with `/hypothesis config` if you want them)";
    return { probe, outcome: "inconclusive", summary: `refused: ${why}`, establishes, evidence: [], errors: [why] };
  }
  if (!exec) {
    const why = "no exec surface is available in this context (command probes need the extension API)";
    return { probe, outcome: "inconclusive", summary: `refused: ${why}`, establishes, evidence: [], errors: [why] };
  }
  if (!probe.command || typeof probe.command !== "string" || probe.command.trim() === "") {
    const why = "command probe has an empty command";
    return { probe, outcome: "inconclusive", summary: `refused: ${why}`, establishes, evidence: [], errors: [why] };
  }

  const timeout = Math.min(settings.commandTimeoutMs, Math.max(1_000, probe.timeoutMs ?? settings.commandTimeoutMs));
  let stdout = "";
  let stderr = "";
  let code = -1;
  let timedOut = false;
  try {
    const result = await exec(probe.command, probe.args ?? [], { cwd: projectRoot, timeout, ...(signal ? { signal } : {}) });
    stdout = String(result.stdout ?? "");
    stderr = String(result.stderr ?? "");
    code = typeof result.code === "number" ? result.code : -1;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    timedOut = /timed?\s*out|timeout/i.test(message);
    return {
      probe,
      outcome: "inconclusive",
      summary: timedOut ? `timed out after ${timeout}ms` : `failed to run: ${message}`,
      establishes,
      evidence: [
        evidenceAt(
          "command-output",
          at,
          truncateOutput(`[exit: unknown]\n${message}`, settings.maxOutputChars),
          undefined,
          `${probe.command} ${(probe.args ?? []).join(" ")}`.trim(),
        ),
      ],
      errors: [message],
    };
  }

  const zero = code === 0;
  const satisfied = expectation === "zero" ? zero : !zero;
  const outcome: ProbeOutcome = satisfied ? "survived" : "falsified";
  const body = `[exit: ${code}]\n--- stdout ---\n${stdout || "(empty)"}\n--- stderr ---\n${stderr || "(empty)"}`;

  return {
    probe,
    outcome,
    summary: `exit ${code} (expected ${expectation})`,
    establishes,
    evidence: [
      evidenceAt("command-output", at, truncateOutput(body, settings.maxOutputChars), undefined, `${probe.command} ${(probe.args ?? []).join(" ")}`.trim()),
    ],
    errors: [],
  };
}

// -----------------------------------------------------------------
// Aggregation
// -----------------------------------------------------------------

/**
 * Run every probe and aggregate by the falsification rule.
 *
 * Asymmetric on purpose: one counterexample refutes, many survivals only fail
 * to refute. A hypothesis with three surviving probes is *supported*, not
 * proven, and the rationale says so.
 */
export async function runVerification(opts: RunVerificationOptions): Promise<VerificationOutcome> {
  const at = opts.at ?? new Date().toISOString();
  const node = opts.node;
  const results: ProbeResult[] = [];

  for (const probe of opts.probes) {
    if (probe.kind === "location") results.push(runLocationProbe(opts.projectRoot, probe, opts.settings, at));
    else if (probe.kind === "grep") results.push(runGrepProbe(opts.projectRoot, probe, opts.settings, at));
    else results.push(await runCommandProbe(opts.projectRoot, probe, opts.settings, opts.exec, at, opts.signal));
  }

  const falsified = results.filter((r) => r.outcome === "falsified");
  const survived = results.filter((r) => r.outcome === "survived");
  const inconclusive = results.filter((r) => r.outcome === "inconclusive");
  const evidence = results.flatMap((r) => r.evidence);

  const rationale: string[] = [];
  let suggestedVerdict: VerificationOutcome["suggestedVerdict"];
  let counterexample: string | null = null;

  if (results.length === 0) {
    suggestedVerdict = "inconclusive";
    rationale.push("No probes were supplied. A hypothesis cannot be settled without at least one falsification attempt.");
  } else if (falsified.length > 0) {
    suggestedVerdict = "rejected";
    counterexample = falsified[0]!.summary;
    rationale.push(
      `REFUTED by ${falsified.length} of ${results.length} probe(s). One counterexample refutes the hypothesis, so the suggestion is "rejected".`,
    );
    for (const r of falsified) rationale.push(`  counterexample: ${r.summary}`);
    rationale.push("  This is a suggestion only — record the verdict with the evidence attached.");
  } else if (survived.length > 0) {
    suggestedVerdict = "confirmed";
    rationale.push(
      `SUPPORTED: all ${survived.length} probe(s) held. Support is not proof — the probes confirm the mechanical facts they checked, not the hypothesis as a whole.`,
    );
    if (inconclusive.length > 0) {
      rationale.push(`  ${inconclusive.length} probe(s) were inconclusive and contributed nothing either way.`);
    }
  } else {
    suggestedVerdict = "inconclusive";
    rationale.push(
      `INCONCLUSIVE: all ${inconclusive.length} probe(s) failed to establish anything (missing target, refused, or timed out). More probes are needed before a verdict.`,
    );
  }

  for (const r of results) {
    rationale.push(`  [${r.outcome}] ${r.summary}`);
  }
  if (results.some((r) => r.evidence.length === 0)) {
    rationale.push("  NOTE: at least one probe produced no quotable artifact, so it cannot support a verdict on its own.");
  }

  return {
    nodeId: node.id,
    nodeDescription: node.description,
    results,
    suggestedVerdict,
    rationale,
    counterexample,
    evidence,
    hasQuotableEvidence: evidence.length > 0,
    needsMoreProbes: suggestedVerdict === "inconclusive",
  };
}

// -----------------------------------------------------------------
// Guard
// -----------------------------------------------------------------

/** A node with a verdict is not re-verified; it must be reopened first, so a
 * verdict is never silently replaced by a later probe run. */
export function verificationRefusal(node: Hypothesis): string | null {
  if (isVerdict(node.status)) {
    return `node ${node.id} already has the verdict "${node.status}" — reopen it with a reason before re-verifying, so the old verdict is not silently overwritten`;
  }
  return null;
}

/** Render an outcome as text for the command surface and the round summary. */
export function renderOutcome(outcome: VerificationOutcome): string[] {
  const lines: string[] = [
    `verification of ${outcome.nodeId}: suggested ${outcome.suggestedVerdict.toUpperCase()}`,
    `  "${outcome.nodeDescription}"`,
    "",
    ...outcome.rationale.map((r) => `  ${r}`),
  ];
  if (outcome.evidence.length > 0) {
    lines.push("");
    lines.push(`  ${outcome.evidence.length} evidence entry/entries produced:`);
    for (const e of outcome.evidence) {
      const loc = e.location ? ` ${e.location.file}:${e.location.line}` : "";
      lines.push(`    - ${e.kind}${loc}: ${e.detail.split("\n")[0]!.slice(0, 100)}`);
    }
  }
  lines.push("");
  lines.push("  The executor does not decide. Attach the evidence and record the verdict deliberately.");
  return lines;
}
