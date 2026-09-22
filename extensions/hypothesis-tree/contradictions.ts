/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/contradictions.ts
 *
 * Two of the fields the report rests on are typed in by the model, and both are
 * CONTRACT GATES:
 *
 *   `severity`  — `/goal severity=high` counts findings at or above it
 *   `preAuth`   — `requirePreAuth=1` counts findings reachable without auth
 *
 * Those two words are the goal ("find a pre-auth high-severity RCE") AND the
 * values the model fills in. That is a finish line drawn by the party being
 * measured, and it cannot be closed by a tool — severity and reachability are
 * judgements about code that only the auditor can make.
 *
 * What the tool CAN do is notice when the recorded values sit badly next to the
 * recorded evidence, and say so.
 *
 * -----------------------------------------------------------------------
 * A QUESTION, NEVER A VERDICT
 * -----------------------------------------------------------------------
 *
 * Every check here is a heuristic over free text, so every one of them can be
 * wrong: `/admin/login` is a pre-auth path that contains "admin", and an open
 * redirect that carries a session token IS critical. So the wording is always a
 * question — "the entrypoint mentions 'admin'; is an unauthenticated request
 * really reaching it?" — and it NEVER blocks anything.
 *
 * Blocking on a heuristic is worse than missing an inflation: a refusal that is
 * wrong teaches the model to write around the check instead of examining the
 * claim, and a wrong warning only costs a sentence.
 */

import type { Hypothesis, HypothesisCategory, Severity } from "./types.js";

export interface Contradiction {
  /** Which recorded value the evidence sits badly next to. */
  field: "preAuth" | "severity";
  /** A question, phrased so answering it either way is a real answer. */
  message: string;
}

/**
 * Words that suggest a request arrives through an authenticated surface.
 *
 * Deliberately about the SURFACE rather than the actor: an entrypoint that names
 * a console, a dashboard or a session is describing a place people log in to,
 * which is worth checking against a `preAuth: true`.
 */
const AUTHENTICATED_SURFACE =
  /\b(admin(?:istration)?|console|dashboard|back-?office|account settings|after (?:log|sign)[- ]?in|requires? (?:auth|a session|a token)|authenticated|logged[- ]in|session)\b/i;

/**
 * Classes that are usually a COMPONENT of a chain rather than the finding.
 *
 * At `critical` or `high` they are not impossible — an open redirect that carries
 * a session token is account takeover — but reporting the component as the whole
 * finding is the commoner mistake, and the fix is to record what it chains into.
 */
const USUALLY_A_COMPONENT: readonly HypothesisCategory[] = ["open-redirect", "csrf", "session-fixation"];

const SEVERE: readonly Severity[] = ["critical", "high"];

/** Does anything recorded here sit badly next to anything else recorded here? */
export function contradictionsOf(node: Pick<Hypothesis, "severity" | "category" | "attackVector">): Contradiction[] {
  const out: Contradiction[] = [];
  const v = node.attackVector;
  if (!v) return out;

  // 1. Declared reachable without authentication, described as a place you log in.
  if (v.preAuth === true) {
    const surface = `${v.entrypoint} ${v.technique}`;
    const hit = AUTHENTICATED_SURFACE.exec(surface);
    if (hit) {
      out.push({
        field: "preAuth",
        message:
          `preAuth is TRUE, but the entrypoint/technique names "${hit[0]}", which is an authenticated surface. ` +
          `Is an unauthenticated request really reaching it — or does something in front of it (a firewall, ` +
          `a gateway, an entry authenticator) reject it first?`,
      });
    }
  }

  // 2. A chain component rated as the whole finding.
  if (node.severity && SEVERE.includes(node.severity) && USUALLY_A_COMPONENT.includes(node.category)) {
    out.push({
      field: "severity",
      message:
        `a ${node.category} at ${node.severity}. That is right when it IS the whole finding (an open redirect ` +
        `carrying a session token is account takeover), and inflated when it is a step toward one. ` +
        `If it is a step, record what it chains into as a gate and let the chain carry the severity.`,
    });
  }

  return out;
}

/** One line per contradiction, for a tool response. */
export function renderContradictions(node: Pick<Hypothesis, "severity" | "category" | "attackVector">): string {
  const found = contradictionsOf(node);
  if (found.length === 0) return "";
  return [
    "",
    "POSSIBLE CONTRADICTION — a question, not a verdict, and nothing was blocked:",
    ...found.map((c) => `  - ${c.message}`),
  ].join("\n");
}
