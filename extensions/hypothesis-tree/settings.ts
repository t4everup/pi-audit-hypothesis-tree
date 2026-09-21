/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/settings.ts
 *
 * Project-level settings, at `<project>/.pi-hypothesis/settings.json`.
 *
 * -----------------------------------------------------------------------
 * Why there is a consent gate here at all
 * -----------------------------------------------------------------------
 *
 * Stage 3 adds a `command` probe: the executor can run a bounded shell command
 * and capture its output as evidence. That is what makes "run the test suite"
 * and "send the request" possible — and it is also the only probe that can
 * change the world.
 *
 * So it is OFF by default, and the switch lives in a file only the HUMAN can
 * write: the `/hypothesis config` command writes it, and no agent tool exposes
 * it. An agent cannot authorize itself to run commands; the user grants that
 * once, deliberately. The read-only probes (reading a location, grepping) need
 * no gate because they cannot mutate anything.
 *
 * -----------------------------------------------------------------------
 * Write discipline
 * -----------------------------------------------------------------------
 *
 * A settings file is small, single-valued, and user-controlled, so it is
 * written in place with `writeFileSync` — NOT via temp-file + rename, which is
 * the exFAT hazard the store avoids (see store.ts). A crash mid-write leaves a
 * truncated JSON document, which the reader treats as "unreadable → defaults",
 * so the failure mode is a lost preference rather than a broken project.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { STATE_DIR_NAME } from "./store.js";

export const SETTINGS_NAME = "settings.json";

export interface HypothesisSettings {
  /**
   * Consent gate for `command` probes. FALSE by default.
   *
   * Read-only probes are unaffected: they run whether or not this is set.
   */
  allowCommandProbes: boolean;
  /** Hard ceiling for one command probe, in milliseconds. */
  commandTimeoutMs: number;
  /** Hard cap on captured output per probe (characters, after truncation). */
  maxOutputChars: number;
  /** Hard cap on grep matches returned. */
  maxGrepMatches: number;
  /** Lines of context captured around a location probe. */
  locationContext: number;
  /** Hard cap on how many files a grep probe will open. */
  maxFilesScanned: number;
  /** Hard cap on the size of one file a probe will read (bytes). */
  maxFileBytes: number;
  /** Hard cap on the total lines a grep probe will examine. */
  maxLinesScanned: number;
}

export const DEFAULT_SETTINGS: HypothesisSettings = {
  allowCommandProbes: false,
  commandTimeoutMs: 120_000,
  maxOutputChars: 8_000,
  maxGrepMatches: 50,
  locationContext: 6,
  maxFilesScanned: 4_000,
  maxFileBytes: 2_000_000,
  maxLinesScanned: 400_000,
};

/**
 * Directory names a probe never descends into.
 *
 * `.pi-hypothesis` is excluded because probing the audit's own state would let
 * a hypothesis "find" its own record and self-confirm — the tree would become
 * evidence for itself.
 */
export const PROBE_SKIP_DIRS: readonly string[] = [
  ".git",
  "node_modules",
  ".pi-hypothesis",
  "dist",
  "build",
  "out",
  "target",
  ".next",
  ".venv",
  "__pycache__",
  "coverage",
  ".cache",
];

export function settingsPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, SETTINGS_NAME);
}

export interface LoadedSettings {
  settings: HypothesisSettings;
  /** Where the values came from — so a UI can say "these are defaults". */
  source: "file" | "defaults" | "partial";
  /** Present when the file exists but could not be used. */
  error?: string;
}

/**
 * Load settings, falling back to defaults on anything unusable.
 *
 * Never throws: an unreadable or corrupt settings file must not stop an audit,
 * and silently ignoring a CORRUPT file would hide the user's intent — hence
 * `error` and `source` are reported rather than swallowed.
 */
export function loadSettings(projectRoot: string): LoadedSettings {
  const file = settingsPath(projectRoot);
  let text: string;
  try {
    if (!fs.existsSync(file)) return { settings: { ...DEFAULT_SETTINGS }, source: "defaults" };
    text = fs.readFileSync(file, "utf-8");
  } catch (error) {
    return {
      settings: { ...DEFAULT_SETTINGS },
      source: "defaults",
      error: error instanceof Error ? error.message : String(error),
    };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    return {
      settings: { ...DEFAULT_SETTINGS },
      source: "defaults",
      error: `settings.json is not valid JSON (${error instanceof Error ? error.message : String(error)}) — using defaults`,
    };
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { settings: { ...DEFAULT_SETTINGS }, source: "defaults", error: "settings.json must be a JSON object — using defaults" };
  }

  const o = raw as Record<string, unknown>;
  const settings = { ...DEFAULT_SETTINGS };
  let partial = false;

  const bool = (key: keyof HypothesisSettings): void => {
    if (key in o) {
      if (typeof o[key] === "boolean") settings[key] = o[key] as never;
      else partial = true;
    }
  };
  const num = (key: keyof HypothesisSettings, min: number, max: number): void => {
    if (key in o) {
      const value = o[key];
      if (typeof value === "number" && Number.isFinite(value)) {
        settings[key] = Math.min(max, Math.max(min, Math.floor(value))) as never;
      } else {
        partial = true;
      }
    }
  };

  bool("allowCommandProbes");
  num("commandTimeoutMs", 1_000, 3_600_000);
  num("maxOutputChars", 200, 500_000);
  num("maxGrepMatches", 1, 5_000);
  num("locationContext", 0, 200);
  num("maxFilesScanned", 1, 200_000);
  num("maxFileBytes", 1_024, 200_000_000);
  num("maxLinesScanned", 100, 20_000_000);

  return { settings, source: partial ? "partial" : "file" };
}

/**
 * Merge a patch into the settings file.
 *
 * Only the keys present in `patch` are written; the rest keep whatever the file
 * already had (or the defaults, when the file did not exist). Writing the whole
 * resolved object would silently persist defaults for keys the user never set,
 * which then look like deliberate choices.
 */
export function saveSettings(
  projectRoot: string,
  patch: Partial<HypothesisSettings>,
): { ok: boolean; errors: string[]; settings?: HypothesisSettings } {
  const errors: string[] = [];
  const validated: Partial<HypothesisSettings> = {};

  for (const [key, value] of Object.entries(patch) as [keyof HypothesisSettings, unknown][]) {
    if (!(key in DEFAULT_SETTINGS)) {
      errors.push(`unknown setting "${key}" (known: ${Object.keys(DEFAULT_SETTINGS).join(", ")})`);
      continue;
    }
    if (typeof DEFAULT_SETTINGS[key] === "boolean") {
      if (typeof value !== "boolean") errors.push(`${key} must be true or false`);
      else validated[key] = value as never;
      continue;
    }
    if (typeof value !== "number" || !Number.isFinite(value)) {
      errors.push(`${key} must be a number`);
      continue;
    }
    validated[key] = value as never;
  }
  if (errors.length > 0) return { ok: false, errors };

  // Re-read so unknown/extra keys already in the file are preserved verbatim.
  let existing: Record<string, unknown> = {};
  const file = settingsPath(projectRoot);
  try {
    if (fs.existsSync(file)) {
      const parsed: unknown = JSON.parse(fs.readFileSync(file, "utf-8"));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) existing = parsed as Record<string, unknown>;
    }
  } catch {
    // A corrupt file is replaced by the patch alone; the load path already
    // reported the corruption, and refusing to write would strand the user.
  }

  const next = { ...existing, ...validated };
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    // In place, no rename: the exFAT-safe choice for a small single-valued file.
    fs.writeFileSync(file, JSON.stringify(next, null, 2) + "\n", "utf-8");
  } catch (error) {
    return { ok: false, errors: [`could not write ${file}: ${error instanceof Error ? error.message : String(error)}`] };
  }

  return { ok: true, errors: [], settings: loadSettings(projectRoot).settings };
}
