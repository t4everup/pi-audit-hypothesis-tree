/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/types.ts
 *
 * The data model. Read this file first: the whole extension is a consequence
 * of one decision — **a node is a falsifiable ASSERTION, not a task.**
 *
 * "Check whether the login handler validates the JWT signature" is a task. It
 * cannot be confirmed or rejected; it can only be "done", and a done task
 * produces no knowledge. "The login handler does not validate the JWT
 * signature" is a hypothesis: reading `src/auth/jwt.ts:41` either supports it
 * or refutes it, and either outcome is a durable fact about the codebase.
 *
 * Everything downstream depends on that distinction:
 *   - a node has a STATUS that is a verdict (confirmed / rejected), not a
 *     progress marker;
 *   - a node has EVIDENCE, because a verdict without raw evidence is an
 *     opinion;
 *   - a node has CHILDREN, because refuting "the handler validates the
 *     signature" immediately raises "then how is the signature trusted?" —
 *     the tree grows by falsification, not by decomposition.
 */

// -----------------------------------------------------------------
// Hypothesis
// -----------------------------------------------------------------

/**
 * Verdict lifecycle.
 *
 *   pending    — recorded, not yet examined.
 *   testing    — currently being examined (exactly one node per round in the
 *                default scheduler, so this is also the "in flight" marker).
 *   confirmed  — evidence supports the assertion. A confirmed node is a
 *                FINDING and becomes an input to vulnerability combination.
 *   rejected   — evidence refutes the assertion. A rejection is a RESULT, not
 *                a failure: it is what prunes the search space.
 *   blocked    — cannot be examined yet (needs a runtime, a credential, a
 *                sibling hypothesis to resolve first). Blocked nodes are
 *                re-queued, never silently dropped.
 */
export type HypothesisStatus = "pending" | "testing" | "confirmed" | "rejected" | "blocked";

/** Statuses that are terminal verdicts — a node here is never re-tested
 * unless it is explicitly reopened with new evidence. */
export const VERDICT_STATUSES: readonly HypothesisStatus[] = ["confirmed", "rejected"];

/** Statuses that still need work from the scheduler. */
export const OPEN_STATUSES: readonly HypothesisStatus[] = ["pending", "testing", "blocked"];

export function isVerdict(status: HypothesisStatus): boolean {
  return status === "confirmed" || status === "rejected";
}

// -----------------------------------------------------------------
// Severity
// -----------------------------------------------------------------

/**
 * How bad it is if the assertion is true.
 *
 * Kept separate from `category` (what kind of bug) because the two answer
 * different questions and a completion contract needs the first: "find one
 * verified high-severity vulnerability" is not expressible in terms of classes
 * alone. It is OPTIONAL — an audit that has not yet judged impact should not be
 * forced to guess — and the `/goal` contract treats "unset" as "not yet rated",
 * never as "low".
 */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Rank for comparison: lower is worse, so `severityRank(a) <= severityRank(b)`
 * means "a is at least as bad as b". */
export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

/** True when `severity` is at least as bad as `floor`. */
export function meetsSeverity(severity: Severity | undefined, floor: Severity): boolean {
  if (!severity) return false;
  return severityRank(severity) <= severityRank(floor);
}

export function isOpen(status: HypothesisStatus): boolean {
  return !isVerdict(status);
}

/**
 * May the scheduler pick this node?
 *
 * A `scope` node is excluded because it has no truth value: it declares a
 * boundary, so a round spent "falsifying" it would produce nothing. Everything
 * that counts "open work" must use this predicate rather than `isOpen` alone,
 * or the scope node would inflate every progress figure by one and the loop
 * would look like it always has something left to do.
 */
export function isSchedulable(node: Pick<Hypothesis, "nodeKind" | "status">): boolean {
  return node.nodeKind !== "scope" && isOpen(node.status);
}

// -----------------------------------------------------------------
// Verification tier — how well a verdict is supported
// -----------------------------------------------------------------

/**
 * How much a verdict actually rests on.
 *
 *   reasoning-only — every evidence entry is an argument with no artifact. The
 *                    verdict is the model's opinion, and a report that presents
 *                    it as a finding is worse than one that omits it.
 *   static         — at least one real `file`/`code-slice` with a location. The
 *                    claim is anchored in code a reader can open.
 *   reproduced     — at least one `command-output` carrying the command that
 *                    produced it. Someone can re-run it.
 *
 * This is DERIVED from the evidence, never declared by the model: "trustworthy"
 * has to be a property of the record, not a self-assessment. It is what lets a
 * completion contract demand a high-severity finding that is actually anchored,
 * and what lets a report say honestly which findings are opinions.
 */
export type VerificationTier = "reasoning-only" | "static" | "reproduced";

export const VERIFICATION_TIERS: readonly VerificationTier[] = ["reasoning-only", "static", "reproduced"];

/** Rank for comparison: higher is better supported. */
export function tierRank(tier: VerificationTier): number {
  return VERIFICATION_TIERS.indexOf(tier);
}

/** True when `tier` is at least as well supported as `floor`. */
export function meetsTier(tier: VerificationTier, floor: VerificationTier): boolean {
  return tierRank(tier) >= tierRank(floor);
}

export function verificationTier(node: Pick<Hypothesis, "evidence">): VerificationTier {
  const reproduced = node.evidence.some(
    (e) => e.kind === "command-output" && typeof e.command === "string" && e.command.trim() !== "",
  );
  if (reproduced) return "reproduced";
  const anchored = node.evidence.some((e) => (e.kind === "code-slice" || e.kind === "file") && e.location);
  if (anchored) return "static";
  return "reasoning-only";
}

/** One-line label for a report or a status line. */
export function tierLabel(tier: VerificationTier): string {
  switch (tier) {
    case "reproduced":
      return "REPRODUCED (a command was run)";
    case "static":
      return "STATIC (anchored in code, not reproduced)";
    case "reasoning-only":
      return "REASONING ONLY (no artifact — an opinion, not a finding)";
  }
}

/**
 * The categories an audit hypothesis can belong to.
 *
 * The set is closed on purpose. The scheduler enforces a per-category share
 * cap (MAX_CATEGORY_RATIO), and a free-form category field would let the
 * agent evade that cap by inventing a new spelling for the same class
 * ("auth-bypass", "authBypass", "authentication-bypass" — three categories,
 * three times the budget). `other` exists for the genuine remainder and is
 * itself capped.
 */
export const HYPOTHESIS_CATEGORIES = [
  // authentication / authorization
  "auth-bypass",
  "idor",
  "privilege-escalation",
  "session-fixation",
  "csrf",
  // injection
  "sqli",
  "nosqli",
  "command-injection",
  "ssti",
  "xxe",
  "ldap-injection",
  "header-injection",
  // data flow / file
  "path-traversal",
  "arbitrary-file-read",
  "arbitrary-file-write",
  "file-upload",
  "ssrf",
  "open-redirect",
  // execution / parsing
  "deserialization",
  "rce",
  "memory-safety",
  "race-condition",
  // disclosure / config
  "info-disclosure",
  "hardcoded-secret",
  "weak-crypto",
  "misconfiguration",
  "dependency-risk",
  // remainder
  "other",
] as const;

export type HypothesisCategory = (typeof HYPOTHESIS_CATEGORIES)[number] | (string & {});

const CATEGORY_SET = new Set<string>(HYPOTHESIS_CATEGORIES);

export function isKnownCategory(category: string): boolean {
  return CATEGORY_SET.has(category);
}

/**
 * Raw evidence. "Raw" is load-bearing: an evidence entry must be quotable
 * verbatim so a human (or a verifier) can re-derive the verdict from the
 * entry alone. A summary is not evidence.
 */
export type EvidenceKind =
  /** A location in the tree: file + line. */
  | "file"
  /** A verbatim code excerpt. */
  | "code-slice"
  /** A request / response pair, or a reproduction command's output. */
  | "request"
  /** Output of a command that was actually run, plus the command. */
  | "command-output"
  /** An explicit reasoning step with no artifact (weakest; recorded so it is
   * visible as weak rather than hidden). */
  | "reasoning";

export const EVIDENCE_KINDS: readonly EvidenceKind[] = ["file", "code-slice", "request", "command-output", "reasoning"];

export interface EvidenceLocation {
  /** Path relative to the audited project root, forward slashes. */
  file: string;
  /** 1-based line number. */
  line: number;
}

export interface Evidence {
  kind: EvidenceKind;
  /** ISO timestamp the evidence was collected. */
  at: string;
  /** Present for `file` / `code-slice`; optional elsewhere when the evidence
   * happens to cite a location. */
  location?: EvidenceLocation;
  /** For `command-output`: the exact command that produced `detail`. */
  command?: string;
  /** The verbatim excerpt, request, or command output. */
  detail: string;
}

/**
 * One node of the hypothesis tree.
 *
 * Field notes that are easy to get wrong:
 *
 * `depth` is derived, never supplied by the caller — `tree.ts` computes it
 * from the parent so the two can never disagree. It is persisted anyway
 * because the scheduler's depth penalty must be computable from a single
 * record without walking the parent chain.
 *
 * `spawnedFrom` records the CONFIRMED findings that produced this hypothesis
 * (vulnerability combination, stage 4). A node derived from a single parent
 * assertion is a plain child and leaves this empty; a node derived from the
 * interaction of several findings lists all of them, which is what makes a
 * vulnerability CHAIN distinguishable from a coincidence.
 *
 * `roundIntroduced` is the loop iteration that created the node, so a
 * hypothesis that has sat unexamined for many rounds is visible as such.
 *
 * `score` is a cache of the scheduler's computation (stage 2). It is stored
 * so the UI and the round summary can show the ranking that was actually
 * used, rather than a recomputation that might differ.
 */
export interface Hypothesis {
  /** Stable id, `H-0001`-style. Assigned by the store, never by the caller. */
  id: string;
  /**
   * What kind of node this is.
   *
   *   hypothesis — a falsifiable assertion. The default, and the only kind that
   *                may be scheduled for verification.
   *   scope      — a BOUNDARY declaration ("the audit covers this project",
   *                "this subsystem"), NOT a claim. Exempt from the assertion
   *                gate, because "audit this project" cannot be confirmed or
   *                refuted and pretending otherwise would put an unfalsifiable
   *                node at the root of a falsification tree.
   *
   * A scope node is never a scheduling candidate: it has no truth value, so
   * asking a model to falsify it is a wasted round. The scheduler filters it
   * out (`planNextRound`).
   */
  nodeKind: NodeKind;
  /** null only for the root. */
  parentId: string | null;
  /**
   * For a `hypothesis`: the falsifiable assertion, stated as a claim about the
   * codebase. MUST read as an assertion ("X does not validate Y"), never as a
   * task ("check X"). Enforced by `validateDescription`.
   *
   * For a `scope`: what the boundary IS. Free prose — no truth value is
   * claimed for it, so the gate does not apply.
   */
  description: string;
  category: HypothesisCategory;
  status: HypothesisStatus;
  evidence: Evidence[];
  /** Derived from the parent chain. Root is 0. */
  depth: number;
  createdAt: string;
  lastTouchedAt: string;
  /** Scheduler priority cache. Defaults to 0 until stage 2 computes it. */
  score: number;
  /** Confirmed findings / hypotheses this node was derived from. */
  spawnedFrom: string[];
  /** Loop round that introduced this node. 0 for the root. */
  roundIntroduced: number;
  /**
   * Scheduler bookkeeping: how many rounds have SELECTED this node.
   *
   * Stored on the node rather than derived from the selection log because the
   * log is kept as a bounded window (see `HISTORY_WINDOW`) and compaction
   * replaces the folded state — a counter that lived only in the window would
   * silently reset and the novelty term would re-award full marks to a node
   * that had already been examined five times.
   */
  timesSelected: number;
  /** The round that last selected this node; null when never selected. */
  lastSelectedRound: number | null;
  /**
   * Which kind of vulnerability combination produced this node (stage 4).
   *
   * `spawnedFrom` records the LINEAGE but not the RELATIONSHIP: "H-0007 came
   * from H-0002 and H-0005" does not say whether H-0007 is a dependency, a
   * shared defect, or a generalization. Recording the kind is what makes the
   * combination report readable, and what lets a later pass ask "have we
   * already looked for a shared root cause between these two?" without
   * re-deriving it from the descriptions.
   */
  combinationKind?: CombinationKind;
  /**
   * How the attacker would actually reach and trigger this assertion (stage 6).
   *
   * A field rather than a child node because a vector is a PROPERTY of the
   * hypothesis — "how would this be exploited" — not another proposition that
   * needs its own falsification. Modelling it as a child would bury a tree of
   * eight hypotheses under twenty-four vector nodes, and the scheduler would
   * spend its anti-tunnelling budget verifying payload sketches.
   */
  attackVector?: AttackVector;
  /** The recon segment that produced this node (stage 6). */
  segmentId?: string;
  /**
   * How bad it is if the assertion is true. Optional: an unrated finding is
   * "not yet judged", which is different from "low" — and a completion
   * contract that demanded severity would otherwise force a guess.
   */
  severity?: Severity;
  /**
   * Why the node is `blocked`, or why a verdict was reached without strong
   * evidence. Required for `blocked`; optional otherwise.
   */
  statusReason?: string;
}

// -----------------------------------------------------------------
// Node kind
// -----------------------------------------------------------------

/**
 * A node is either a falsifiable claim or a boundary declaration.
 *
 * The distinction exists because an audit starts from something you do NOT yet
 * understand: "the project rooted at cwd" is a scope, not a hypothesis, and
 * forcing the user to phrase it as a claim produces a root like "this project
 * contains a vulnerability", which no evidence can refute.
 */
export type NodeKind = "scope" | "hypothesis";

export const NODE_KINDS: readonly NodeKind[] = ["scope", "hypothesis"];

/**
 * Truncate on a word boundary where possible, so a cut assertion is still
 * readable.
 *
 * Lives here rather than in render.ts so recon.ts can use it: recon.ts is
 * imported BY the renderer, so importing the renderer back would close a module
 * cycle (render → recon → render).
 */
export function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max - 1);
  const space = cut.lastIndexOf(" ");
  return (space > max * 0.6 ? cut.slice(0, space) : cut) + "…";
}

// -----------------------------------------------------------------
// Attack vector (stage 6)
// -----------------------------------------------------------------

/** One step of the path from the entrypoint to the sink. */
export interface AttackStep {
  /** Where this step is, when it is a code location. */
  location?: EvidenceLocation;
  /** What happens here. */
  detail: string;
}

/**
 * How an attacker reaches and triggers the hypothesis.
 *
 * Deliberately structured rather than prose: an entrypoint and a path are what
 * let the combination pass (stage 4) notice that two findings share a reachable
 * route, and what let a reviewer check the claim without re-reading the code.
 *
 * An EMPTY vector is legal and means "how to reach this is not yet known" —
 * which is a different statement from "it is unreachable", and the renderer
 * says so.
 */
export interface AttackVector {
  /** How the attacker gets in: a route, a queue, a CLI verb, a file drop. */
  entrypoint: string;
  /** The chain from the entrypoint to the sink, in order. */
  path: AttackStep[];
  /** The technique: "alg=none JWT forgery", "path traversal via ../", … */
  technique: string;
  /** A concrete payload or reproduction sketch, when one is known. */
  payload?: string;
  /** What must hold for the vector to work. */
  preconditions?: string[];
}

/** The fields a caller supplies to create a node. `id`, `depth`, timestamps
 * and `score` are derived by the store. */
export interface HypothesisInput {
  description: string;
  category: HypothesisCategory;
  /** Omit to attach to the root. */
  parentId?: string | null;
  /** Defaults to `hypothesis`. `scope` skips the assertion gate. */
  nodeKind?: NodeKind;
  status?: HypothesisStatus;
  evidence?: Evidence[];
  spawnedFrom?: string[];
  roundIntroduced?: number;
  attackVector?: AttackVector;
  /** The recon segment this node came from (stage 6). */
  segmentId?: string;
  severity?: Severity;
  statusReason?: string;
}

// -----------------------------------------------------------------
// Recon segments (stage 6)
// -----------------------------------------------------------------

/**
 * One chunk of the agent's recon notes.
 *
 * The audit starts from a project nobody has read yet, so the first thing the
 * model produces is prose: what the project is, where its entrypoints are, what
 * the trust boundaries look like. That prose is then chunked MECHANICALLY into
 * segments, and each segment becomes the input for one hypothesis-generation
 * round.
 *
 * Chunking the model's own notes rather than the raw source is deliberate. A
 * file or a line range can split a function in half, so a hypothesis derived
 * from it is guessing; a paragraph boundary is where the MODEL stopped a
 * thought, so each segment is semantically whole. It also bounds the phase: a
 * 500-file repository is 500 rounds if you chunk by file, and three to eight if
 * you chunk the notes.
 */
export interface ReconSegment {
  /** `S-<index>-<hash8>` — position AND content, so an edited note re-opens
   * only the segments that actually changed. */
  id: string;
  /** 0-based position in the note. */
  index: number;
  /** How many blank-line-separated paragraphs this segment covers. */
  paragraphs: number;
  /** The segment's text, verbatim. */
  text: string;
  /** Content hash of `text` (first 8 hex chars). */
  hash: string;
}

/**
 * Coverage of the recon note.
 *
 * This is the mechanical answer to "when is hypothesis generation finished".
 * Without a denominator the generation phase could not terminate — the model
 * can always invent another hypothesis — and "the well is dry" would be
 * indistinguishable from "the model stopped trying".
 */
export interface SegmentCoverage {
  /** Total segments in the current note. */
  total: number;
  /** Segments that produced at least one hypothesis or were explicitly closed. */
  covered: number;
  /** Segment ids still waiting for a generation round. */
  open: string[];
}

/** Why a segment is considered done. */
export type SegmentOutcome =
  /** At least one hypothesis was added from it. */
  | "produced"
  /** Examined and deliberately closed with nothing (a recorded result). */
  | "nothing-found";

export interface SegmentRecord {
  segmentId: string;
  at: string;
  outcome: SegmentOutcome;
  /** Hypothesis ids produced from this segment. */
  hypothesisIds: string[];
  /** Required for `nothing-found`, so "empty" is a stated result. */
  note?: string;
}

// -----------------------------------------------------------------
// Consolidation (stage 4)
// -----------------------------------------------------------------

/**
 * The three ways confirmed findings combine into a new hypothesis.
 *
 *   chain              — A depends on B (you need B to reach A)
 *   shared-root-cause  — A and B are both consequences of one missing check
 *   lateral-extension  — A bypasses X; the same technique may bypass Y
 *
 * `chain` and `shared-root-cause` are relations BETWEEN findings (they need a
 * pair); `lateral-extension` generalizes ONE finding, which is why a
 * consolidation pass also considers singletons.
 */
export type CombinationKind = "chain" | "shared-root-cause" | "lateral-extension";

export const COMBINATION_KINDS: readonly CombinationKind[] = ["chain", "shared-root-cause", "lateral-extension"];

/**
 * Short tag for a combination kind, kept tiny so it can ride on a node line or
 * a decision line. Lives here rather than in render.ts so the scheduler can use
 * it without importing the renderer (which imports the scheduler).
 */
export function combinationTag(kind: CombinationKind): string {
  switch (kind) {
    case "chain":
      return "chain";
    case "shared-root-cause":
      return "shared";
    case "lateral-extension":
      return "ext";
  }
}

/** Why a consolidation pass ran. */
export type ConsolidationTrigger =
  /** `CONSOLIDATION.INTERVAL` rounds have passed since the last pass. */
  | "interval"
  /** A new finding was confirmed since the last pass. */
  | "new-finding"
  /** The user or the agent asked for one explicitly. */
  | "manual";

/**
 * One pair of confirmed findings, with the MECHANICAL signals that made it
 * worth considering.
 *
 * The extension does not decide whether two findings are related — that is a
 * semantic judgement, and deriving it mechanically would be guessing. What it
 * does is compute the structural facts (shared files, line proximity, tree
 * relationship, categories) so the judgement is grounded rather than made from
 * two prose summaries, and so the N² pair space is bounded and ordered.
 */
export interface ConsolidationPair {
  aId: string;
  bId: string;
  /** Stable key for "this pair has been examined". */
  key: string;
  score: number;
  /** Human-readable reasons, strongest first. */
  signals: string[];
  sharedFiles: string[];
  /** Closest distance in lines between the two findings' evidence in a shared
   * file, or null when they share no file. */
  minLineDistance: number | null;
  treeRelation: "ancestor" | "sibling" | "unrelated";
}

/** A confirmed finding that has not yet been generalized. */
export interface ConsolidationSingle {
  id: string;
  score: number;
  signals: string[];
}

/**
 * The audit trail of one consolidation pass.
 *
 * Written even when the pass produced nothing (`skipped` says why), because
 * "we looked and found no combination" is a result, and a pass that left no
 * record is indistinguishable from a pass that never ran.
 */
export interface ConsolidationRecord {
  round: number;
  at: string;
  trigger: ConsolidationTrigger;
  /** The confirmed set at the time, so the pass is reproducible. */
  confirmedIds: string[];
  /** Pair keys handed to the model; these are marked examined. */
  pairKeys: string[];
  /** Singleton ids handed to the model. */
  singleIds: string[];
  /** Non-null when the pass had nothing to hand over. */
  skipped: string | null;
}

/** The plan for one consolidation pass, before it is recorded. */
export interface ConsolidationPlan {
  round: number;
  trigger: ConsolidationTrigger;
  /** False when the trigger has not fired; `reason` says which condition is unmet. */
  due: boolean;
  reason: string;
  confirmed: Hypothesis[];
  pairs: ConsolidationPair[];
  singles: ConsolidationSingle[];
  /** Non-null when a due pass has nothing to examine. */
  skipped: string | null;
}

// -----------------------------------------------------------------
// The audit loop (stage 5)
// -----------------------------------------------------------------

/** `/goal` runs until a contract is met; `/loop` runs until stopped. */
export type AuditLoopKind = "goal" | "loop";

export type AuditLoopStatus =
  | "running"
  | "paused"
  /** Stopped by the user, the plateau, or the round cap. */
  | "stopped"
  /** `/goal` only: the completion contract is satisfied. */
  | "complete";

/**
 * What `/goal` is waiting for.
 *
 * Every clause is MECHANICAL and evaluated against the folded tree, because a
 * completion condition the extension cannot check is a completion condition the
 * model grades itself on — which is the failure this whole project exists to
 * avoid.
 */
export interface CompletionContract {
  /** At least this many confirmed findings. */
  minConfirmed: number;
  /** At least one confirmed finding at this severity or worse. */
  minSeverity?: Severity;
  /** Restrict the count to these classes (empty/absent = any). */
  categories?: string[];
  /** Also require that no combination pass is pending. */
  requireConsolidated: boolean;
  /**
   * Only findings whose evidence includes a real artifact count.
   *
   * Default TRUE, because a verdict resting entirely on `reasoning` entries is
   * the model's opinion: letting it satisfy a completion contract is how an
   * audit reports a "confirmed high-severity vulnerability" that nobody can
   * open a file and check.
   */
  requireArtifact: boolean;
  /**
   * Only findings REPRODUCED by a command probe count.
   *
   * Default FALSE, because it needs `allowCommandProbes` — a project that has
   * not granted that consent would have an uncompletable goal. Turn it on when
   * you want proof rather than a strong static case.
   */
  requireReproduced: boolean;
}

export interface AuditLoopState {
  kind: AuditLoopKind;
  objective: string;
  /** null for `/loop` — it has no finish line. */
  contract: CompletionContract | null;
  status: AuditLoopStatus;
  startedAt: string;
  updatedAt: string;
  /** Highest round whose brief has been sent. */
  round: number;
  /**
   * The round whose turn is in flight, or null.
   *
   * This is the anti-stacking fence: the loop only sends a brief when nothing
   * is awaiting completion, so a slow or failed turn cannot pile up rounds.
   */
  awaitingRound: number | null;
  /** 0 = unbounded. */
  maxRounds: number;
  /** Consecutive rounds that produced no new verdict before the loop stops. */
  plateauWindow: number;
  stallRounds: number;
  stopReason?: string;
  pausedReason?: string;
}

/**
 * One round of the loop.
 *
 * The `*AtStart` fields are the baseline that lets the NEXT tick judge the round
 * without a second event: comparing the node's status and the confirmed count
 * now against what they were when the round began is enough to say whether the
 * round produced anything. Derived beats recorded here — there is no window in
 * which the two can disagree.
 */
/**
 * What a round does.
 *
 *   recon       — read the unknown project and submit recon notes
 *   generate    — turn ONE recon segment into falsifiable hypotheses + vectors
 *   verify      — falsify one hypothesis
 *   consolidate — look for combinations among the confirmed findings
 *
 * `recon` and `generate` exist because an audit of an unfamiliar project cannot
 * start with a hypothesis: there is nothing to hypothesise ABOUT until the
 * project has been read. Stages 1–5 assumed a tree already existed; these two
 * rounds are how it comes to exist.
 */
export type RoundKind = "recon" | "generate" | "verify" | "consolidate";

export const ROUND_KINDS: readonly RoundKind[] = ["recon", "generate", "verify", "consolidate"];

export interface RoundRecord {
  round: number;
  at: string;
  /** A verify round examines one node; a consolidate round runs a pass. */
  kind: RoundKind;
  /** For a `generate` round: which segment was handed over. */
  segmentId?: string | null;
  nodeId: string | null;
  nodeStatusAtStart: HypothesisStatus | null;
  nodeEvidenceAtStart: number;
  confirmedAtStart: number;
  /** The human-readable round summary, persisted so the ledger can be rebuilt. */
  summary: string[];
}

// -----------------------------------------------------------------
// Scheduling (stage 2)
// -----------------------------------------------------------------

/**
 * The score breakdown for one candidate. Every term is stored, not just the
 * total, because the scheduler's whole job is to be AUDITABLE: "why was this
 * node picked" must be answerable from the record alone, without replaying
 * the formula against a snapshot that has since changed.
 */
export interface ScoreBreakdown {
  /** Bonus for never-examined nodes; decays with `timesSelected`. */
  novelty: number;
  /** Bonus for evidence already collected — a node close to a verdict is
   * cheap value to finish. */
  evidence: number;
  /** Bonus for a category that is under-represented in the recent window. */
  categoryDiversity: number;
  /** Penalty proportional to depth: a deep node is narrower and costs more
   * context to examine. */
  depthPenalty: number;
  /** Penalty for having been selected recently. */
  recencyPenalty: number;
  /** Penalty for a node that is currently `blocked` (it was blocked for a
   * reason, so re-picking it immediately is usually waste). */
  blockedPenalty: number;
  /** Bonus for a node left mid-examination (`testing` with no verdict) —
   * finish what was started before opening a new front. */
  testingBoost: number;
  total: number;
}

/** A hard constraint that disqualified one candidate this round. */
export type ScheduleConstraint =
  | "max-same-node-rounds"
  | "max-consecutive-depth"
  | "max-category-ratio";

export interface ScheduleVeto {
  nodeId: string;
  constraint: ScheduleConstraint;
  detail: string;
}

/**
 * One recorded scheduling decision — the round's audit trail.
 *
 * Persisted so the round summary can show the ranking that was ACTUALLY used
 * rather than a recomputation, and so a human reviewing the loop can see
 * whether the anti-rabbit-hole rules fired.
 */
export interface SelectionRecord {
  round: number;
  nodeId: string;
  at: string;
  score: number;
  breakdown: ScoreBreakdown;
  /** Human-readable rationale, in the order the scheduler derived it. */
  reasons: string[];
  /** Candidates disqualified by a hard constraint. */
  vetoes: ScheduleVeto[];
  /**
   * Constraints that had to be relaxed because NO candidate satisfied them.
   *
   * This field exists because the alternative — refusing to schedule — would
   * deadlock the loop. Relaxing is sometimes correct (if every open hypothesis
   * is one category, the category cap is unsatisfiable), but it must never be
   * silent: an empty array means the rules held.
   */
  relaxations: string[];
  /** How many open hypotheses were considered. */
  candidates: number;
  /**
   * Categories whose share of the OPEN population already exceeds the cap.
   * A diagnostic about the TREE, not about this pick: the scheduler cannot
   * spread attention when one category is nearly all the remaining work.
   */
  populationSkew: string[];
}

/** A scheduling decision before it is persisted. */
export interface ScheduleDecision {
  round: number;
  /** null when there was nothing schedulable (no tree, or no open nodes). */
  selected: Hypothesis | null;
  breakdown: ScoreBreakdown | null;
  reasons: string[];
  vetoes: ScheduleVeto[];
  relaxations: string[];
  candidates: number;
  populationSkew: string[];
  /** The full ranking that was considered, highest first (bounded). */
  ranked: Array<{ nodeId: string; score: number; vetoedBy: ScheduleConstraint | null }>;
}

// -----------------------------------------------------------------
// Tree snapshot
// -----------------------------------------------------------------

/**
 * The folded state. Produced by `store.load()`, never persisted directly
 * (except inside an append-only compaction snapshot).
 */
export interface TreeSnapshot {
  /** Stable tree id, assigned at creation. */
  treeId: string;
  /** The user's audit objective — the root node's `description`. */
  objective: string;
  /** Root node id. */
  rootId: string;
  /** All nodes, insertion order (root first). */
  nodes: Hypothesis[];
  byId: Map<string, Hypothesis>;
  /** Ordered ids of every node, oldest first. */
  order: string[];
  /**
   * Bounded history of scheduling decisions, oldest first. Bounded by
   * `HISTORY_WINDOW` so the snapshot stays small; the per-node counters that
   * need to be unbounded live on the nodes themselves.
   */
  selections: SelectionRecord[];
  /**
   * Bounded history of consolidation passes (stage 4), oldest first.
   *
   * The examined-pair set is DERIVED from these records rather than stored
   * separately, so there is one source of truth for "has this pair been looked
   * at". Bounded by `CONSOLIDATION_HISTORY_WINDOW`; a very long audit may
   * re-offer an ancient pair, which costs one extra consideration and is
   * preferable to an unbounded snapshot.
   */
  consolidations: ConsolidationRecord[];
  /** The audit loop, or null when none has been started. */
  loop: AuditLoopState | null;
  /** Bounded round history, oldest first. */
  roundRecords: RoundRecord[];
  /**
   * The recon note, chunked. Empty until a recon round has submitted notes.
   * Recomputed whenever the note changes, so an edited note re-opens only the
   * segments whose text actually differs.
   */
  segments: ReconSegment[];
  /** Per-segment outcomes, oldest first. Bounded. */
  segmentRecords: SegmentRecord[];
  /** ISO timestamp of the newest recon submission, or null. */
  reconAt: string | null;
  /** Highest `SEC`-style sequence number already used, so ids are never
   * reused even after a compaction. */
  maxNodeSeq: number;
  /** Rounds started so far (stage 2+; 0 until the loop runs). */
  rounds: number;
  /** Lines that failed to parse while folding (crash telemetry). A non-zero
   * value is reported, never silently swallowed. */
  tornLines: number;
  /** Number of `snapshot` records folded past — how many times the log was
   * compacted. */
  compactions: number;
  /** ISO timestamp of the newest event folded. */
  updatedAt: string;
}

// -----------------------------------------------------------------
// Validation
// -----------------------------------------------------------------

export interface ValidationResult {
  ok: boolean;
  errors: string[];
}

const NON_EMPTY = (v: unknown): boolean => typeof v === "string" && v.trim().length > 0;

/** Minimum length of a usable assertion. */
export const MIN_DESCRIPTION_CHARS = 20;

/**
 * Task-shaped openings that make a description a TASK rather than a
 * hypothesis. Rejecting these is the single cheapest way to keep the tree
 * from degenerating into a todo list.
 *
 * The list is deliberately about the SHAPE of the sentence, not about
 * vocabulary policing: "check", "review", "look at", "audit", "scan",
 * "investigate", "find", "examine", "test whether" all ask for an action and
 * produce no knowledge when they end.
 */
const TASK_SHAPED_PREFIXES = [
  /^\s*(?:please\s+)?(?:check|verify|review|inspect|examine|look\s+(?:at|into)|audit|scan|investigate|explore|find|search|test|probe|analyze|analyse|assess|evaluate|determine|identify|locate|enumerate|list)\b/i,
  /^\s*(?:please\s+)?(?:test|check)\s+whether\b/i,
  /^\s*(?:todo|task|step)\s*[:#-]/i,
  /^\s*\d+[.)]\s+/,
];

/**
 * A description that is only a noun phrase has no truth value. "The login
 * endpoint and its middleware chain" cannot be confirmed or refuted — it is
 * a subject with no predicate.
 *
 * The third hint is a VERB-FORM check, and it is deliberately a curated list
 * rather than a generic `\w+s\b`. The generic form matched any word ending in
 * `s` — including "its" — so it accepted exactly the noun phrases this check
 * exists to refuse. The list is a superset check (any one verb is enough), so
 * a genuine assertion phrased with an unlisted verb still passes as long as it
 * has a copula or a negation; the cost of a miss is a clearer rejection
 * message, not a lost hypothesis.
 */
const ASSERTION_HINTS = [
  // copula / auxiliary
  /\b(?:is|are|was|were|does|do|did|has|have|had|can|could|will|would|must|should|may|might|isn't|aren't|doesn't|don't|didn't|can't|won't)\b/i,
  // negation / absence / weakness
  /\b(?:not|never|no|without|missing|lacks?|lacking|absent|unchecked|unsafe|unvalidated|unescaped|unbounded|unauthenticated|unauthori[sz]ed|unprotected|unsanitized|insufficient|incorrect|wrong|stale|leaks?|exposes?|bypass(?:es|ed)?|allows?|permits?|accepts?|trusts?|ignores?)\b/i,
  // a predicate verb that distinguishes "X does Y" from "X and Y"
  /\b(?:validates?|verifies?|checks?|compares?|decodes?|encodes?|parses?|escapes?|sanitizes?|sanitises?|enforces?|rejects?|returns?|writes?|reads?|executes?|deserializes?|deserialises?|handles?|uses?|calls?|passes?|stores?|loads?|resolves?|follows?|honors?|honours?|respects?|applies?|guards?|protects?|restricts?|filters?|injects?|reflects?|redirects?|fetches?|sends?|receives?|binds?|concatenates?|interpolates?|truncates?|casts?|assigns?|initializes?|initialises?|frees?|allocates?|copies?|opens?|creates?|deletes?|updates?|mutates?)\b/i,
];

/**
 * Validate that a description is a FALSIFIABLE ASSERTION.
 *
 * Three mechanical rules, in order of value:
 *   1. It must not open like a task (TASK_SHAPED_PREFIXES).
 *   2. It must be long enough to be specific.
 *   3. It must contain something with a truth value (ASSERTION_HINTS).
 *
 * This cannot judge whether an assertion is *interesting* — that is the
 * auditor's job. It only refuses the shapes that are provably not
 * hypotheses, so the failure mode is a clear rejection message rather than a
 * tree full of todos.
 */
export function validateDescription(description: string): ValidationResult {
  const errors: string[] = [];
  if (!NON_EMPTY(description)) {
    errors.push("description is required");
    return { ok: false, errors };
  }
  const text = description.trim();
  if (text.length < MIN_DESCRIPTION_CHARS) {
    errors.push(
      `description must be a specific assertion (at least ${MIN_DESCRIPTION_CHARS} characters); got ${text.length}`,
    );
  }
  for (const re of TASK_SHAPED_PREFIXES) {
    if (re.test(text)) {
      errors.push(
        `description reads as a TASK, not a hypothesis ("${text.slice(0, 40)}…"). State what you believe about the codebase and can be proven wrong — e.g. instead of "check the JWT validation" write "the login handler accepts a JWT without verifying its signature".`,
      );
      break;
    }
  }
  if (!ASSERTION_HINTS.some((re) => re.test(text))) {
    errors.push(
      `description has no truth value — it must be an assertion that can be confirmed or refuted (got "${text.slice(0, 60)}")`,
    );
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Validate an attack vector.
 *
 * `entrypoint` and `technique` are required when a vector is supplied at all:
 * a vector that names neither says nothing about how the hypothesis would be
 * reached, and an empty vector is expressed by OMITTING the field rather than
 * by supplying a hollow one.
 */
export function validateAttackVector(vector: Partial<AttackVector> | undefined): ValidationResult {
  const errors: string[] = [];
  if (vector === undefined) return { ok: true, errors };
  if (!vector || typeof vector !== "object") return { ok: false, errors: ["attackVector must be an object"] };
  if (!NON_EMPTY(vector.entrypoint)) {
    errors.push("attackVector.entrypoint is required — how does the attacker get in? (a route, a queue, a CLI verb, a file drop)");
  }
  if (!NON_EMPTY(vector.technique)) {
    errors.push("attackVector.technique is required — what is the attack? (e.g. \"alg=none JWT forgery\")");
  }
  if (vector.path !== undefined) {
    if (!Array.isArray(vector.path)) errors.push("attackVector.path must be an array of steps");
    else {
      vector.path.forEach((step, i) => {
        if (!step || typeof step !== "object" || !NON_EMPTY(step.detail)) {
          errors.push(`attackVector.path[${i}] needs a detail`);
        }
      });
    }
  }
  if (vector.preconditions !== undefined && !Array.isArray(vector.preconditions)) {
    errors.push("attackVector.preconditions must be an array of strings");
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Validate a caller-supplied node input, minus the derived fields.
 *
 * A `scope` node is EXEMPT from the assertion gate. That is the whole point of
 * the kind: an audit of an unfamiliar project begins with a boundary ("the
 * project rooted at cwd"), and forcing that boundary to be phrased as a claim
 * produces a root like "this project contains a vulnerability" — which no
 * evidence can refute, so the root of a falsification tree would be the one
 * node that can never be falsified.
 */
export function validateHypothesisInput(input: Partial<HypothesisInput>): ValidationResult {
  const kind: NodeKind = input.nodeKind ?? "hypothesis";
  const errors: string[] = [];

  if (!NODE_KINDS.includes(kind)) {
    errors.push(`nodeKind must be one of ${NODE_KINDS.join("|")}`);
  } else if (kind === "scope") {
    if (!NON_EMPTY(input.description)) errors.push("a scope node needs a description of the boundary it declares");
  } else {
    errors.push(...validateDescription(input.description ?? "").errors);
  }

  if (!NON_EMPTY(input.category)) {
    errors.push("category is required");
  } else if (!isKnownCategory(input.category as string)) {
    errors.push(
      `unknown category "${input.category}" — use one of the known classes so the per-category share cap cannot be evaded by inventing a spelling (see HYPOTHESIS_CATEGORIES)`,
    );
  }
  if (input.status !== undefined && !OPEN_STATUSES.includes(input.status) && !VERDICT_STATUSES.includes(input.status)) {
    errors.push(`unknown status "${input.status}"`);
  }
  if (input.status === "blocked" && !NON_EMPTY(input.statusReason)) {
    errors.push("statusReason is required when a node is blocked — an unexplained block is indistinguishable from abandonment");
  }
  if (input.evidence !== undefined) {
    if (!Array.isArray(input.evidence)) errors.push("evidence must be an array");
    else input.evidence.forEach((e, i) => errors.push(...validateEvidence(e).errors.map((m) => `evidence[${i}]: ${m}`)));
  }
  if (input.spawnedFrom !== undefined && !Array.isArray(input.spawnedFrom)) {
    errors.push("spawnedFrom must be an array of node ids");
  }
  errors.push(...validateAttackVector(input.attackVector).errors);
  if (input.segmentId !== undefined && !NON_EMPTY(input.segmentId)) {
    errors.push("segmentId must be a non-empty segment id when supplied");
  }
  return { ok: errors.length === 0, errors };
}

/** Validate one evidence entry. */
export function validateEvidence(evidence: Partial<Evidence> | undefined): ValidationResult {
  const errors: string[] = [];
  if (!evidence || typeof evidence !== "object") return { ok: false, errors: ["evidence must be an object"] };
  if (!NON_EMPTY(evidence.kind) || !EVIDENCE_KINDS.includes(evidence.kind as EvidenceKind)) {
    errors.push(`kind must be one of ${EVIDENCE_KINDS.join("|")}`);
  }
  if (!NON_EMPTY(evidence.detail)) {
    errors.push("detail is required — an evidence entry without the verbatim excerpt, request, or output proves nothing");
  }
  if (evidence.kind === "command-output" && !NON_EMPTY(evidence.command)) {
    errors.push("command is required for command-output evidence (the output is not reproducible without it)");
  }
  if (evidence.kind === "file") {
    if (!evidence.location) errors.push("location { file, line } is required for file evidence");
    else if (!NON_EMPTY(evidence.location.file) || !Number.isFinite(evidence.location.line)) {
      errors.push("location must be { file: string, line: number }");
    }
  }
  return { ok: errors.length === 0, errors };
}
