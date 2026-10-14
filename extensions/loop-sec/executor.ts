/**
 * pi-audit-loopsec — extensions/loop-sec/executor.ts
 *
 * The bounded project walk — the only piece of the old executor that has a
 * /loopSEC use. The verify probes it once served went with the hypothesis tools:
 * coverage walking and probing shared a budget and a skip list, and keeping the
 * whole file would have kept three hundred lines that nothing can call.
 */
import * as fs from "node:fs";
import * as path from "node:path";

import { PROBE_SKIP_DIRS, type HypothesisSettings } from "./settings.js";

export interface WalkResult {
  /** Absolute paths, in walk order. */
  files: string[];
  truncated: boolean;
  /** Why the walk stopped early, when it did. */
  reason: string;
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
