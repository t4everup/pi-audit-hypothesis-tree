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

## Stage 1 — what exists now

**Data model, append-only persistence, tree CRUD, and a `/hypothesis` command.**

```
/hypothesis                          status: counts, categories, depth
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

### Try it

```
/hypothesis new "the login handler accepts a JWT without verifying its signature" category=auth-bypass
/hypothesis add "the signature is checked but the algorithm is taken from the token header" parent=H-0001 category=auth-bypass
/hypothesis evidence H-0002 code-slice "verify(token, key, alg)" file=src/auth/jwt.ts line=57
/hypothesis confirm H-0002
/hypothesis tree --evidence
```

```
. H-0001 [pending  ] auth-bypass d0 e0  the login handler accepts a JWT without verifying its signature
`- ! H-0002 [confirmed] auth-bypass d1 e1  the signature is checked but the algorithm is taken from the token header
       - code-slice src/auth/jwt.ts:57: verify(token, key, alg)
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

Stage 1 is deliberately a foundation. Not implemented:

- **stage 2** — the scheduler: `MAX_CONSECUTIVE_DEPTH`, `MAX_SAME_NODE_ROUNDS`,
  `MAX_CATEGORY_RATIO`, scoring, and the per-round decision rationale;
- **stage 3** — the verification executor (static analysis, taint tracing,
  running tests) and the agent tools that drive it;
- **stage 4** — vulnerability combination every 3 rounds / per new finding;
- **stage 5** — `/goal` and `/loop` integration, the round summary, the
  pause/resume/stop surface, and the tree widget.

The `/hypothesis` command exists so stage 1 is **verifiable by hand** — you can
create a tree, derive a child, attach evidence, reach a verdict, and see the
tree, without any of the above.

## Development

```bash
npm run check        # tsc --noEmit
npm test             # 110 tests, ~0.5s, spawns nothing
npm run test:stage1  # the stage-1 files only
```

The suite is pure: no subprocesses, no network, no browsers.

## Provenance

Pi extension API verified against
`@earendil-works/pi-coding-agent/dist/core/extensions/types.d.ts`
(`ExtensionAPI.registerCommand`, `RegisteredCommand.handler`,
`AutocompleteItem`) and the installed
`pi-goal-list-loop-audit@0.38.68` extension's real usage — not assumed.

MIT.
