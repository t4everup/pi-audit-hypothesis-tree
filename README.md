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
| `hypothesis_status` | read-only: the tree, the open hypotheses in scheduler order, the run lengths |
| `hypothesis_next` | **the scheduler picks, not the model** — the model cannot choose to tunnel because it does not choose |
| `hypothesis_verify` | the model supplies the falsification attempt; the executor collects the evidence |
| `hypothesis_record` | the only way to change a status, and it refuses a verdict with no evidence |
| `hypothesis_add` | growth, with the same assertion-shape gate (and it creates the root when no tree exists) |
| `hypothesis_evidence` | attach an artifact without deciding |

### Verify from the command line too

```
/hypothesis verify <id> file=<f> line=<n>
/hypothesis verify <id> grep="<re>" expect=present|absent [path=<sub>]
/hypothesis verify <id> command="<exe>" [args="a b"] [expectExit=zero|nonzero]
/hypothesis config [key=value]
```

## What is NOT here yet

- **stage 4** — vulnerability combination every 3 rounds / per new finding;
- **stage 5** — `/goal` and `/loop` integration, the round summary, the
  pause/resume/stop surface, and the tree widget.

The `/hypothesis` command and the tools make stages 1–3 **usable end to end by
hand**: create a tree, grow it, let the scheduler pick, run falsification
probes, record verdicts.

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
/hypothesis next          # round 2: H-0001 has a verdict, so it moves on
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

## Development

```bash
npm run check        # tsc --noEmit
npm test             # 241 tests, ~2.5s, spawns nothing
npm run test:stage1  # the store/tree/render files only
```

The suite is pure: no subprocesses, no network, no browsers. Command probes are
exercised through an injected fake exec, so no test runs a real command.

extensions/hypothesis-tree/
  types.ts      Hypothesis / Evidence / status / category / score model
  store.ts      append-only JSONL, exFAT-safe, torn-tail repair, compaction
  tree.ts       CRUD, derived depth, duplicate refusal, verdict-needs-evidence
  scheduler.ts  the three limits, scoring, relaxation, decision record
  settings.ts   project settings + the command-probe consent gate
  executor.ts   bounded probes, falsification aggregation, evidence framing
  tools.ts      the six agent tools
  render.ts     text tree / summary / JSON
  index.ts      /hypothesis command + read-only /hypothesis-status alias
```

## Provenance

Pi extension API verified against
`@earendil-works/pi-coding-agent/dist/core/extensions/types.d.ts`
(`ExtensionAPI.registerCommand`, `RegisteredCommand.handler`,
`AutocompleteItem`) and the installed
`pi-goal-list-loop-audit@0.38.68` extension's real usage — not assumed.

MIT.
