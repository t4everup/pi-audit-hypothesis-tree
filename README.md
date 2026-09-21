# pi-audit-hypothesis-tree

A [pi](https://github.com/earendil-works/pi) extension that runs a **code audit
as a hypothesis tree** instead of a task list.

Every node is a **falsifiable assertion** about the codebase. The scheduler
(stage 2) forbids rabbit-holing. Confirmed findings get combined into new
hypotheses (stage 4).

---

## Why a hypothesis tree

A task list cannot be wrong. "Check the login handler" has no truth value: you
either did it or you did not, and when you are done you know nothing you did
not know before.

An assertion can be wrong. `the login handler accepts a JWT without verifying
its signature` is either supported by `src/auth/jwt.ts:41` or refuted by it,
and **both outcomes are durable knowledge**:

- confirmed → a finding, and an input to vulnerability combination;
- rejected → a pruned branch, and a reason to look somewhere else.

That distinction is the whole extension:

| Task list | Hypothesis tree |
|---|---|
| `check the JWT validation` | `the login handler accepts a JWT without verifying its signature` |
| status = progress (`todo` → `done`) | status = **verdict** (`confirmed` / `rejected`) |
| "done" needs no artifact | a verdict needs **raw evidence** |
| grows by decomposition | grows by **falsification** |
| "how much is left?" | "what have we ruled out?" |

## Install

```bash
cd D:/Ai/pi-audit-hypothesis-tree
npm install
```

Then point pi at the package (or install it), and the extension loads
`extensions/hypothesis-tree/index.ts`.

## Stage 1 — data model, persistence, CRUD

**Append-only JSONL store, hypothesis CRUD, and a `/hypothesis` command.**

```
/hypothesis                          status: counts, categories, depth, scheduler runs
/hypothesis tree [--evidence]        render the tree
/hypothesis json                     full tree as JSON
/hypothesis new "<root assertion>" [category=<c>]
/hypothesis add "<assertion>" [parent=<id>] [category=<c>]
/hypothesis evidence <id> <kind> "<detail>" [file=<f>] [line=<n>] [command="<c>"]
/hypothesis confirm <id> [reason="…"]
/hypothesis reject  <id> [reason="…"]
/hypothesis block   <id> reason="…"
/hypothesis reopen  <id> reason="…"
/hypothesis testing <id>
/hypothesis round <n>
/hypothesis repair                   drop a torn tail (crash recovery)
/hypothesis compact                  append a state snapshot (bounded reads)
```

## Stage 3 — the verification executor

**Bounded probes that turn raw output into durable evidence, plus the agent
tool surface that drives the whole tree.**

### The one formal rule: a probe is a falsification attempt

```
expectation: "present"  →  if this pattern is NOT here, my hypothesis is wrong
expectation: "absent"   →  if this pattern IS here, my hypothesis is wrong
```

Each probe reports one of three outcomes:

| Outcome | Meaning |
|---|---|
| `survived` | the prediction held — the hypothesis was **not refuted here** |
| `falsified` | the prediction failed — this is a **counterexample** |
| `inconclusive` | the probe established nothing (missing target, refused, timed out) |

Aggregation is **asymmetric on purpose**: one counterexample refutes, so any
`falsified` suggests `rejected`; many survivals only fail to refute, so they
suggest `confirmed` — *support, never proof*. The rationale says so explicitly.

### Three probe kinds

| Kind | What it does | Bounds |
|---|---|---|
| `location` | reads `file:line` and captures the slice with its coordinate | context lines, output cap, refused outside the project root |
| `grep` | bounded regex search, no shell | match cap, file/size/line budget, skips `.git`/`node_modules`/`.pi-hypothesis`/`dist`, skips binary files, refuses nested-quantifier ReDoS shapes |
| `command` | runs a bounded command and captures its output | **OFF by default** (see below), hard timeout, output cap, no shell |

Every result carries an `establishes` field stating what the probe does **not**
prove. A grep result always says *"a pattern match is not a data flow"*,
because that is the mistake this whole extension exists to prevent.

### The consent gate

`command` probes are the only probe that can change the world, so they are
disabled until the project opts in:

```
/hypothesis config allowCommandProbes=true
```

**No agent tool can set it.** The switch lives in
`.pi-hypothesis/settings.json`, and only the human-facing `/hypothesis config`
command writes it — a model that could grant itself permission would make the
gate decorative. A refused command probe is reported as `inconclusive`, never
as a silent pass.

### The executor never decides

`hypothesis_verify` returns a **suggestion** and attaches the evidence. It does
not touch the node's status, and it refuses to re-verify a node that already
has a verdict (reopen it first, so an old verdict is never silently replaced).

### Agent tools

| Tool | Who is in charge |
|---|---|
| `hypothesis_status` | read-only: the tree, the open hypotheses in scheduler order, the run lengths, the combination state |
| `hypothesis_next` | **the scheduler picks, not the model** — the model cannot choose to tunnel because it does not choose. Blocked while a consolidation pass is due |
| `hypothesis_verify` | the model supplies the falsification attempt; the executor collects the evidence |
| `hypothesis_record` | the only way to change a status, and it refuses a verdict with no evidence |
| `hypothesis_add` | growth, with the same assertion-shape gate (and it creates the root when no tree exists) |
| `hypothesis_consolidate` | ranks the confirmed pairs; the model judges which are real |
| `hypothesis_combine` | inserts a chain / shared-root-cause / lateral-extension |
| `hypothesis_evidence` | attach an artifact without deciding |

### Verify from the command line too

```
/hypothesis verify <id> file=<f> line=<n>
/hypothesis verify <id> grep="<re>" expect=present|absent [path=<sub>]
/hypothesis verify <id> command="<exe>" [args="a b"] [expectExit=zero|nonzero]
/hypothesis config [key=value]
```

## Stage 4 — vulnerability combination

**Every 3 rounds, or whenever a finding is confirmed, a pass looks for chains
and shared root causes among the confirmed findings.**

```
/hypothesis consolidate [--force]
/hypothesis combine kind=<k> spawnedFrom=<a,b> category=<c> "<assertion>"
```

### The forced trigger

A due pass **blocks scheduling**. `hypothesis_next` refuses until it has run.

Left optional the pass would never happen: the model is always busy with the
round in front of it, and an audit that only ever adds single findings never
finds the chains — which are the reason to keep a tree at all.

It cannot deadlock, because a pass that finds nothing is still **recorded**
(with `skipped` saying why), so the trigger clears either way. A pass that left
no record would be indistinguishable from a pass that never ran.

### What is mechanical, and what is not

*"Do these two findings share a root cause?"* is a semantic judgement. A module
that answered it by comparing words would be guessing. So the split is:

| Mechanical (the extension) | Semantic (the model) |
|---|---|
| which pairs are worth a look, and in what order | whether the pair is actually related |
| the structural facts about a pair | the hypothesis that expresses it |
| that a pair has already been examined | whether the earlier answer was good |
| validating and inserting the result | phrasing the assertion |

With N confirmed findings there are N² pairs. The model cannot be handed all of
them, cannot rank them, and cannot be trusted to remember which ones it already
considered. The extension does exactly those three things and nothing more.

### The signals

| Signal | Weight | Why |
|---|---|---|
| shared evidence file | +6 each, capped 12 | the strongest structural signal |
| evidence lines ≤ 50 apart | +5 | plausibly the same region |
| evidence lines ≤ 200 apart | +2 | same area, probably not the same site |
| same class | +3 | a shared root cause is plausible |
| **different** classes | +2 | a cross-class chain is possible *and valuable if real* |
| ancestor / descendant | +4 | a dependency (chain) is plausible |
| siblings | +2 | they share a parent hypothesis |
| evidence depth | +1.5 each, capped 3 | better-grounded findings pair better |

Both same-class and cross-class score, so neither crowds the other out of the
top-N cut. Every pair carries its signals as text, so the judgement is grounded
in structure rather than in reading two prose summaries.

### The three kinds

| Kind | Shape | Needs |
|---|---|---|
| `chain` | A depends on B — you need B to reach A | 2+ confirmed ids |
| `shared-root-cause` | A and B are both consequences of one missing check | 2+ confirmed ids |
| `lateral-extension` | A bypasses X; the same technique may bypass Y | 1 confirmed id |

**Every `spawnedFrom` id must be a CONFIRMED finding.** A combination derived
from an unconfirmed hypothesis is speculation stacked on speculation, and it
would let the tree grow without any of the evidence that makes a node worth
having. The store refuses it and says so.

A combination is a **new hypothesis**, not a conclusion: it enters as `pending`
and must be verified like anything else. The tree view marks it `+chain` /
`+shared` / `+ext` so a reader can tell an inference from an observation, and
the scheduler's decision line does too.

### Reporting nothing is the correct answer

The brief says so explicitly:

> A pair with a strong structural signal may still have NO real relationship.
> Reporting none is the correct answer then — a fabricated chain is worse than
> no chain, because it sends the next rounds after something that does not exist.

## Stage 6 — auditing a project you have never read

**`/goal` with no tree now bootstraps itself: it declares a SCOPE, reads the
project, chunks its own recon notes into segments, and generates hypotheses +
attack vectors from each segment.**

```
/hypothesis recon [file=<p>|<note>]   show coverage, or submit a recon note
/hypothesis segments                  each segment, its state, and what it produced
```

### The problem this solves

Stages 1–5 all assumed a tree already existed. But the normal case is the
opposite: you are handed a repository you have never read, and you cannot write
*"the login handler accepts a JWT without verifying its signature"* until you
have found the login handler.

```
/goal "find a pre-auth auth bypass"     ← no tree, no hypotheses, no idea
   ↓  round 1  RECON       read the project, submit prose notes
   ↓           (chunked into segments of 3–5 paragraphs)
   ↓  round 2  GENERATE    segment 1 → hypotheses + attack vectors
   ↓  round 3  GENERATE    segment 2 → …
   ↓  round N  VERIFY      the tree now exists; stages 2–5 take over
```

### A scope node is a boundary, not a claim

The root is created with `nodeKind: "scope"` and is **exempt from the assertion
gate**. Forcing a boundary to be phrased as a claim produces a root like *"this
project contains a vulnerability"* — which no evidence can refute, so the root
of a falsification tree would be the one node that can never be falsified.

A scope node is also **never scheduled**: it has no truth value, so a round
spent falsifying it would be wasted. It is excluded from the open-work count too,
or it would inflate every progress figure by one, forever.

`/hypothesis new "<assertion>"` still creates a *hypothesis* root and is
unchanged — when you already know what to claim, that claim is the first thing
the scheduler examines.

### Why the model's NOTES are chunked, not the source

| Chunking the source | Chunking the recon notes |
|---|---|
| a file or line range splits functions in half → the hypothesis is a guess about code never seen whole | a paragraph boundary is where the **model** stopped a thought, so every segment is semantically complete |
| "340 of 500 files read" says nothing about whether the interesting ones were understood | coverage means "every part of the recon has been turned into hypotheses" |
| a 500-file repo is 500 rounds | a note is 3–8 segments, so generation is 3–8 rounds |

The chunking itself is mechanical: blank-line-separated paragraphs, grouped N at
a time (default 4, clamped to 3–5), with **fenced code blocks kept intact** so a
block containing blank lines is not cut in half.

### Coverage is the denominator

*"When is generation finished"* needs a mechanical answer, or the phase never
ends: a model can always invent another hypothesis, and "the well is dry" would
be indistinguishable from "the model stopped trying".

Segment ids are **content + position** derived (`S-003-1a2b3c4d`), so editing
the recon note re-opens **only** the segments whose text actually changed —
unchanged segments keep their id and stay covered.

A segment closes when a hypothesis names it, or when `hypothesis_cover_segment`
closes it explicitly. That second form **requires a note**: *"we looked and
there was nothing"* and *"we did not look"* must not be the same record.

### Attack vectors are a field, not a node

```jsonc
"attackVector": {
  "entrypoint": "POST /api/login",
  "technique": "alg=none JWT forgery",
  "path": [
    { "detail": "send an unsigned token", "location": { "file": "src/auth/jwt.ts", "line": 41 } },
    { "detail": "the verifier accepts it",  "location": { "file": "src/auth/jwt.ts", "line": 88 } }
  ],
  "payload": "{\"alg\":\"none\"}.{\"sub\":\"admin\"}.",
  "preconditions": ["the login route is reachable without credentials"]
}
```

A vector is a **property** of the hypothesis — "how would this be exploited" —
not another proposition needing its own falsification. Modelling it as a child
would bury eight hypotheses under twenty-four vector nodes, and the scheduler
would spend its anti-tunnelling budget verifying payload sketches.

An **absent** vector means *"how to reach this is not yet known"*, which is a
different statement from *"it is unreachable"* — and the tree view says so.

```
! H-0002 [confirmed] auth-bypass d1 e3 →POST /api/login  the login handler accepts a JWT…
```

### The two new tools

| Tool | What it does |
|---|---|
| `hypothesis_recon` | submit the recon note; returns the segment inventory |
| `hypothesis_cover_segment` | close a segment with nothing found (note required) |

And `hypothesis_add` gained `segmentId` (which closes the segment) and
`attackVector`.

## What is NOT here yet

Nothing from the six-stage plan. Deliberately out of scope:

- binary / decompilation auditing (the auditor's tool surface is
  `read,grep,find,ls,bash` only);
- dynamic exploitation against a running target (the executor runs bounded
  commands only when the project opts in, and never mutates);
- multi-model adversarial cross-check.

Those are separable later stages, not omissions.

## Stage 2 — the anti-rabbit-hole scheduler

**Three hard limits, a scoring function that pays for going elsewhere, and a
recorded rationale for every pick.**

```
/hypothesis next [round=<n>]         schedule the next round and RECORD it
/hypothesis schedule [round=<n>]     the same decision, dry run (writes nothing)
/hypothesis history [n]              the last n decisions with their flags
/hypothesis limits                   the configured limits, weights, and live run state
```

### The three limits

| Limit | Value | What it stops |
|---|---|---|
| `MAX_CONSECUTIVE_DEPTH` | **3 levels** | walking down one branch. Measured in **levels**, not steps: one round that jumps three levels counts as three, or the limit could be walked past three levels at a time |
| `MAX_SAME_NODE_ROUNDS` | **2** | grinding one hypothesis while producing no verdict and no new lead |
| `MAX_CATEGORY_RATIO` | **40%** of the last 10 picks | a whole audit becoming about authentication |

The descent run resets on a **lateral move**, so the rule forces a sideways
step inside the branch rather than an exit from it. A sibling is not a descent.

### Scoring

```
score = novelty + evidence + category-diversity + testing-boost
        − depth − recency − blocked

  novelty       10 / (1 + timesSelected)
  evidence      2 per entry, capped at 6      (a node near a verdict is cheap value)
  diversity     8 × (1 − the category's share of the recent window)
  depth         −1.5 per level
  recency       −8 at 0 rounds since, −2 per round, floor 0
  blocked       −4
  testing       +3                            (finish what you started)
```

Every term is stored in the decision record, so "why was this node picked" is
answerable from the log alone rather than by replaying the formula against a
snapshot that has since changed. Ties break by shallower depth, then id — the
ranking is a total order, so the same snapshot always produces the same pick.

### Relaxation is never silent

If every open hypothesis is `auth-bypass`, the 40% cap is unsatisfiable, and a
scheduler that treated it as an absolute veto would refuse to schedule anything
— a deadlock, which is worse than a skewed round. So when no candidate
survives, limits are relaxed in a fixed order and every relaxation is recorded:

```
RELAXED max-category-ratio: no candidate satisfied it, so it was dropped for
this round. This means the TREE is skewed, not just the last pick — add
hypotheses in other categories or close the open ones.
```

Relaxation order is **category → descent → same-node**: category is the weakest
rule and the most likely to be honestly unsatisfiable; a third consecutive
round on one node is the most pathological state and the last to permit. An
empty `relaxations` array means the limits held.

The scheduler also reports **population skew** — categories whose share of the
*open* hypotheses already exceeds the cap. That is a finding about the tree,
not about the pick: it says the scheduler cannot spread attention because one
class of bug is nearly all the remaining work.

### Why this is structural, not advisory

The tunneling failure is not a discipline problem, it is an incentive problem:
the deepest node is always the most concrete and therefore always feels most
tractable. The limits make continued descent **impossible** rather than
discouraged, and the diversity term actively pays for going somewhere else.

The suite pins the emergent property directly: against a deliberately
tunnel-shaped tree (a 9-node chain plus one sibling in another category),
10 simulated rounds never descend more than 3 levels consecutively, never take
one node three rounds in a row, and do visit the other category.

## Try it

```
/hypothesis new "the login handler accepts a JWT without verifying its signature" category=auth-bypass
/hypothesis add "the signature is checked but the algorithm is taken from the token header" category=auth-bypass
/hypothesis add "the export endpoint returns records the caller does not own" category=idor

/hypothesis next          # round 1: schedules H-0001 and explains why
/hypothesis verify H-0001 file=src/auth/jwt.ts line=57
/hypothesis verify H-0001 grep="verify\\s*\\(" expect=present
/hypothesis confirm H-0001

# Confirming a finding makes a combination pass due, which blocks scheduling:
/hypothesis consolidate
/hypothesis combine kind=shared-root-cause spawnedFrom=H-0001,H-0002 category=auth-bypass \
    "both handlers share one decode helper that never calls verify()"
/hypothesis next          # the combination is a new hypothesis and gets scheduled
/hypothesis limits        # the limits, the weights, and the live run state
/hypothesis tree --evidence
```

## The invariants the store enforces

These are not conventions — the store refuses the write.

**A node must be a falsifiable assertion.** `check whether the login handler
validates the JWT` is refused, because no evidence can ever confirm or refute
it. The refusal message shows the reformulation.

**A verdict requires raw evidence.** `confirmed` and `rejected` feed
everything downstream, so a verdict with no quotable artifact is refused —
"a verdict without evidence is an opinion". Evidence is one of `file`,
`code-slice`, `request`, `command-output`, `reasoning`, and
`command-output` must carry the command that produced it.

**A duplicate assertion is refused by name.** The error names the existing
node id, so the caller links to it instead of growing a second copy of the
same branch. Comparison is on a normalized form of the assertion, so
punctuation and case do not create a duplicate.

**`depth` is derived, never supplied.** It is computed from the parent chain,
so a node cannot disagree with its own ancestry.

**The category set is closed.** A free-form category would let a per-category
share cap (stage 2) be evaded by inventing a spelling — `auth-bypass`,
`authBypass`, `authentication-bypass` would be three categories with three
times the budget.

## Persistence

Append-only JSONL at `<project>/.pi-hypothesis/tree.jsonl`.

```
{"type":"tree_created","at":"…","treeId":"T-…","objective":"…"}
{"type":"node_added","at":"…","node":{…}}
{"type":"node_updated","at":"…","id":"H-0002","patch":{"status":"confirmed"}}
{"type":"snapshot","at":"…","snapshot":{…}}
```

Latest record wins per node id, merged on **key presence** — a status-only
patch must not reset the node's category or its evidence.

### exFAT safety

This was a hard requirement, so it is a hard constraint in the code and in a
test. The store **never** calls `renameSync`, `linkSync`, `copyFileSync`, or
holds an open descriptor. It only calls `mkdirSync` and `appendFileSync` with
the default `"a"` flag — one `O_APPEND` write per record on a descriptor that
the call opens and closes. There is no link and no rename for a
non-journaling volume to fail on.

The cost is that a crash can tear the **last** line. That is handled rather
than hoped away: every record ends in exactly one `\n`, so a file whose last
byte is not `\n` has a torn tail — detected precisely, skipped on read,
reported as `tornLines`, and removable with `/hypothesis repair` (an in-place
`truncateSync`, no second file). Recovery is correct after a crash at any byte
offset.

### Compaction without rewriting

`/hypothesis compact` **appends** a `snapshot` record holding the folded
state. The reader starts from the newest snapshot and folds only what came
after, so read cost is bounded while the file stays append-only. The file
grows monotonically — the accepted trade for correctness on a filesystem with
no journal.

## What is NOT here yet

- **stage 4** — vulnerability combination every 3 rounds / per new finding;
- **stage 5** — `/goal` and `/loop` integration, the round summary, the
  pause/resume/stop surface, and the tree widget.

The `/hypothesis` command exists so stages 1–3 are **verifiable by hand** — you
can create a tree, derive children, attach evidence, run falsification probes,
reach verdicts, and watch the scheduler choose, without any of the above.

## Stage 5 — `/goal` and `/loop`

**The round engine.** `/goal` runs one audited objective until a mechanical
completion contract is satisfied; `/loop` keeps auditing until stopped or the
well runs dry.

```
/goal "<objective>" [confirmed=1] [severity=high] [category=a,b] [maxRounds=20] [plateau=5]
/loop ["<objective>"] [maxRounds=0] [plateau=8]

/goal status | pause | resume | stop | cancel | next | tree | log
/loop status | pause | resume | stop | next | tree | log
```

### The six-step round, and who owns each step

| Step | Owner |
|---|---|
| 1. the scheduler picks a node | **the extension** (mechanical) |
| 2. the node is examined | the model's turn |
| 3. status + evidence are updated | the model, through tools |
| 4. whether to combine is decided | **the extension** (the forced trigger) |
| 5. the findings ledger is written | **the extension** |
| 6. a round summary is emitted | **the extension** |

The extension cannot examine a hypothesis — that is the model's job — so a round
is driven by handing the model a **brief** and letting its turn do steps 2–3.
Everything the extension *can* do mechanically, it does; nothing it cannot do is
faked.

A brief looks like this:

```
[AUDIT ROUND 4 — VERIFY]

Audit goal: find a pre-auth auth bypass in the login flow
Contract: at least 1 confirmed finding(s), at severity >= high
  0/1 confirmed finding(s); 0 at severity >= high

Last round (3): H-0002 gained evidence but no verdict yet (0 → 2)

YOUR NODE: H-0004 — "the export endpoint returns records the caller does not own"
  class idor · depth 1 · 0 evidence entry/entries · status testing

The scheduler picked it because:
  ...score: novelty 10.0 + evidence 0.0 + diversity 8.0 ...

DO THIS, in order:
  1. Decide which MECHANICAL fact would refute this assertion.
  2. Call hypothesis_verify on H-0004 with those probes.
     - a grep probe REQUIRES expectation: "present" or "absent".
     - a probe that cannot fail proves nothing.
  3. Call hypothesis_record with the verdict and the counterexample or the support.
     - one counterexample refutes: record "rejected" when a probe fails.
     - never record "confirmed" from a surviving grep alone.
  4. If the verdict raises a NEW question, call hypothesis_add for it.

Then stop. The next round is scheduled automatically after this turn ends.
```

### The anti-stacking fence

The loop records the round whose turn is **in flight** (`awaitingRound`), and
only sends a brief when nothing is awaiting completion. A slow, failed, or
aborted turn therefore cannot pile rounds on top of each other.

The finished round is judged by **comparing the tree against the round's
baseline** (the node's status and evidence count at the start, the confirmed
count at the start) rather than by a second "outcome" event. Derived beats
recorded: there is no window in which the two can disagree, and a lost outcome
event would make the stall counter wrong forever.

### Three bounds, so a night is not burned

| Bound | `/goal` | `/loop` |
|---|---|---|
| the completion contract is satisfied | yes | n/a |
| `plateau` — consecutive rounds that produced neither a verdict nor new evidence | 5 | 8 |
| `maxRounds` | 20 | 0 (unbounded) |

Each stop records a reason, and every reason distinguishes *finished* from
*gave up*:

```
contract satisfied at round 3: 1/1 confirmed finding(s); 1 at severity >= high
plateau — 5 consecutive round(s) produced no verdict and no new evidence (window 5); the well looks dry
no open hypotheses remain (No open hypotheses — every node has a verdict.)
```

### The completion contract is mechanical

A completion condition the extension cannot check is a condition the model
grades itself on. So every clause is evaluated against the folded tree:

- `confirmed=2` — at least two confirmed findings;
- `severity=high` — at least one of them rated `high` or worse;
- `category=idor,ssrf` — restricted to those classes;
- and (by default) no combination pass pending.

**An unrated finding is "not yet judged", never "low".** A `severity` contract
that cannot count an unrated finding says so explicitly:

```
0 at severity >= high (2 confirmed finding(s) carry no severity yet — they are NOT counted as low)
```

### The findings ledger

`.pi-hypothesis/findings.md`, appended every round, append-only:

```markdown
## Round 4 — 2026-09-21T02:14:00.000Z

```
ROUND 4 — verify H-0004
  last round: H-0002 → confirmed (2 evidence entry/entries)
  node: "the export endpoint returns records the caller does not own"
  idor · depth 1 · 2 evidence · status testing
  tree: 9 nodes · 2 confirmed · 1 rejected · 6 open · depth 3
  combinations: 1 pass(es), last at round 3, 1 pair(s) examined
  contract: at least 1 confirmed finding(s), at severity >= high
    1/1 confirmed finding(s) ✓
  stall: 0/5 · round cap 20
```

### Confirmed findings (2)

- [high] **H-0002** the login handler accepts a JWT without verifying its signature — auth-bypass — src/auth/jwt.ts:57
- [high] **H-0005** both handlers share one decode helper that never calls verify() — auth-bypass (shared-root-cause of H-0002+H-0003)

### Tree snapshot (9 nodes)

```
! H-0001 [confirmed] auth-bypass d0 e2  the login handler accepts a JWT...
`- ! H-0002 [confirmed] auth-bypass+shared d1 e3  both handlers share...
```
```

### The widget

Three lines below the editor, so the loop's state is visible without a command:

```
hypothesis ▶ goal round 4/20 · 2 confirmed · 1 rejected · 6 open
  in flight: round 4 · stall 0/5
  contract open: 1/1 confirmed finding(s)
```

### A note on the command names

`/goal` and `/loop` are the spec's names, and they are free because the
previously installed `pi-goal-list-loop-audit` was removed. **Do not install
both at once**: pi suffixes every duplicate command registration, and the bare
names stop routing at all.

## Try it end to end

```
/hypothesis new "the login handler accepts a JWT without verifying its signature" category=auth-bypass
/hypothesis add "the refresh handler accepts a JWT without verifying its signature" category=auth-bypass
/hypothesis add "the export endpoint returns records the caller does not own" category=idor

/goal "find a pre-auth auth bypass" confirmed=1 severity=high
```

From there the loop drives itself: each turn it hands the model the next
hypothesis with the reasons it was chosen, the model falsifies it, the verdict
is recorded, a due combination pass pre-empts the next round, and the round is
written to the ledger. `/goal status` shows the contract gap; `/goal log` shows
the ledger; `/goal pause` stops the driver mid-flight.

## Development

```bash
npm run check        # tsc --noEmit
npm test             # 438 tests, ~5s, spawns nothing
npm run test:stage1  # the store/tree/render files only
```

The suite is pure: no subprocesses, no network, no browsers. Command probes are
exercised through an injected fake exec, so no test runs a real command; the
round driver is driven by invoking the registered `agent_end` hook directly.

extensions/hypothesis-tree/
  types.ts      Hypothesis / Evidence / status / category / score model
  store.ts      append-only JSONL, exFAT-safe, torn-tail repair, compaction
  tree.ts       CRUD, derived depth, duplicate refusal, verdict-needs-evidence
  scheduler.ts  the three limits, scoring, relaxation, decision record
  settings.ts   project settings + the command-probe consent gate
  executor.ts   bounded probes, falsification aggregation, evidence framing
  combination.ts pair ranking, the forced trigger, combination validation
  recon.ts      recon chunking, segment coverage, attack-vector framing
  loop.ts       the round engine: contract, tick, brief, summary, ledger
  tools.ts      the ten agent tools
  render.ts     text tree / summary / JSON
  index.ts      /hypothesis + /goal + /loop, the agent_end driver, the widget
```

## Acceptance criteria — where each one is pinned

| Criterion | Test |
|---|---|
| a tree can be created with the user's objective as its root | `tree.test.ts` — createTree; `tools.test.ts` — hypothesis_add creates the root |
| a `/goal` on an UNREAD project bootstraps itself | `command.test.ts` — a SCOPE root is created and round 1 is RECON |
| the recon note is chunked and each segment yields hypotheses + vectors | `recon.test.ts` — chunking, coverage, the full flow bootstrap → recon → generate → verify |
| sub-hypotheses are derived and the scheduler switches branches | `scheduler.test.ts` — the emergent-property test; `loop.test.ts` — the driven-loop limits test |
| confirmed / rejected verdicts carry evidence | `tree.test.ts` — the verdict gate; `tools.test.ts` — hypothesis_record |
| a combination pass fires and produces a new hypothesis | `combination.test.ts`; `loop.test.ts` — a consolidate round pre-empts verify |
| no file-lock error on a non-NTFS volume | `store.test.ts` — the exFAT source pin (no rename/link/held descriptor) |
| `/loop` runs N rounds with readable summaries | `loop.test.ts` — "/loop runs N rounds and every round summary is readable" |

## Provenance

Pi extension API verified against
`@earendil-works/pi-coding-agent/dist/core/extensions/types.d.ts`
(`ExtensionAPI.registerCommand`, `RegisteredCommand.handler`,
`AutocompleteItem`) and the installed
`pi-goal-list-loop-audit@0.38.68` extension's real usage — not assumed.

MIT.
