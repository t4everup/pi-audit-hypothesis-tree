# pi-audit-loopsec

A source-code audit engine for [pi](https://github.com/earendil-works/pi-coding-agent).
Point it at a project, give it an objective, and it runs rounds against a persistent
hypothesis tree until it can produce a report you can check.

**The tree is the point.** Every node is a falsifiable assertion about the codebase, every
verdict needs a quotable artifact, and the report says how strong each finding's evidence
is. A model left to summarise its own work produces confident prose; a model forced to
record what it checked, what it found, and what would have made it wrong produces something
a reader can verify.

Two modes:

| | hypothesis mode | triage mode |
|---|---|---|
| commands | `/goal`, `/loop` | `/loopsec` |
| the record | assertions with verdicts and tiers | findings with artifacts |
| trust comes from | falsification, a tier, a challenge round | the artifact, and a report that says what is missing |
| use it for | findings you intend to act on | a first pass over a large codebase |

## Install

```bash
git clone https://github.com/t4everup/pi-audit-loopsec
# symlink or copy it where pi loads extensions, then /reload
```

Then, in the project you want audited:

```
/goal "find a pre-auth RCE"
/loop "audit the auth flow"          # no finish line
/loopsec "挖掘认证前rce漏洞"           # no hypothesis tree
```

## The three commands

All three share one engine and one command surface — `status | pause | resume | stop |
cancel | next | tree | log | report | note | context | notes | dismiss | show | help`.

```
/goal "<objective>" [confirmed=1] [severity=high] [category=a,b] [maxRounds=20] [plateau=5]
                    [reproduced=1] [impact=1] [preAuth=1] [exploitable=1]
/loop ["<objective>"] [maxRounds=0] [plateau=8] [focus=a,b]
/loopsec "<objective>" [maxRounds=0] [plateau=8]
```

| | `/goal` | `/loop` | `/loopsec` |
|---|---|---|---|
| stops when | a contract is met, the plateau fires, or the cap | the plateau fires or you stop it | the plateau fires or you stop it |
| default cap | 20 rounds | unbounded | unbounded |
| default plateau | 5 | 8 | 8 |
| contract flags | yes | **refused**, not ignored | refused |
| the record | hypothesis tree | hypothesis tree | findings + a surface work list |

`/loop` refuses contract flags rather than dropping them, and names both ways forward —
three flags in the docs never worked because the parser read a different spelling, and a
flag that is silently ignored is worse than one that is refused.

`resume` cannot move a reached round cap, so it refuses and names the fix rather than
reporting a success that does nothing:

```
REJECTED: the round cap (3) is already reached at round 3, so resuming would stop again
immediately and send no round.
Raise the cap in place:  /goal resume maxRounds=13
Or start a new one:      /goal start "<objective>" maxRounds=13
```

## How a round works

### The six steps

1. **Evaluate the last round** — did it produce anything? Derived by comparing the tree
   against the round's baseline, never declared.
2. **Check the contract** (`/goal` only).
3. **Check the operator's round budget** (`pause <n>`), *before* the plateau, so a pause is
   the operator's instruction taking effect rather than an accident of the well running dry.
4. **Check the plateau and the cap.**
5. **Pick a round kind** — generate, challenge, consolidate, pursue, recon, coverage, verify.
6. **Write the round record, the ledger and the report, then send the brief.**

### The anti-stacking fence

`awaitingRound` is set when a brief goes out and cleared when the next round is evaluated.
The loop only advances when a round it started is actually in flight, so a slow or failed
turn cannot pile rounds on top of each other.

The driver subscribes to **`agent_settled`, not `agent_end`**: `agent_end` fires while the
agent is still processing, so sending a brief there fails with "Agent is already
processing" and the loop stops dead after round 1 with its fence set and no turn in flight.

### The scheduler's three limits

| limit | default | what it stops |
|---|---|---|
| consecutive depth | 3 levels | tunnelling down one branch |
| consecutive rounds on one node | 2 | re-litigating the same assertion |
| share of one category in the last 10 picks | 40% | a tree that is all `auth-bypass` |

Ranking weights novelty (10), category diversity (8), the run's `focus` (6), a testing node
(3), a chain gate (14), with penalties for blocked (4) and for a node already examined this
deep (8).

**Relaxation is never silent.** When the limits cannot all be satisfied the scheduler
records which one it relaxed and why, because a limit that quietly stops applying is a
limit you cannot trust.

### Side quests rotate, and that matters

`consolidate`, `challenge`, `pursue` and `coverage` share one rule — **never two in a row** —
which bounds the whole tier to half the rounds. A fixed precedence decides which of them
gets that half, and it does not work, because every one of these kinds can be *always
available*: challenge while any confirmation is un-attacked, pursue while any high finding
still has budget, consolidate on almost every new finding. Whichever sits at the top takes
every slot.

Both directions were measured on the real Checkmk run:

```
consolidate above challenge   consolidate 13, challenge  3   → 29 of 32 confirmations never attacked
challenge above consolidate   consolidate  8, challenge  8, pursue 0
```

The second is the instructive one: swapping the order did not fix the starvation, it
**relocated** it, and the depth round went from rare to unreachable. So the due side quests
are picked **least-recently-run** instead. Measured over 80 rounds of the same tree:
`challenge 18, consolidate 12, pursue 18, verify 32`.

### The completion contract

```json
{
  "minConfirmed": 1,
  "minSeverity": "high",
  "requireArtifact": true,
  "requireConsolidated": true,
  "requireChallenged": true
}
```

Checked **before** the round kind is chosen. Without `requireChallenged` a confirmation
satisfies the contract immediately, the goal completes, and the challenge round never runs —
the model's first confident judgement ends the audit, right or wrong. With it:

```
confirm → challenge → consolidate (forced) → complete
```

The challenge comes first because `hypothesis_combine` refuses to build a chain out of
unconfirmed findings ("a combination of unconfirmed hypotheses is speculation stacked on
speculation"), so the thing that makes a confirmation trustworthy has to happen before the
thing that builds on it.

## The report

A finding looks like this — SIX sections, in the order a hunter reads them
（标题行 · 描述 · 权限 · 怎么打 · 调用链 · 链子分析）. Everything below the
quote is **derived from state** — the report never summarises, it renders what
was recorded.

````markdown
### 1. H-0014 · 高危 · privilege-escalation

> login.py 的 origtarget 未经转义就被拼进内联 JS
> 在管理员会话内执行任意脚本。

**位置：** `source/.../webconf/pages/login.py:147` · 认证：认证后 · 验证：已复现 · 对抗复核：第 23 轮攻击后存活

**怎么打**

```c
<the manual request + the one artifact the finding rests on, in full; the rest as an index>
```

**调用链**

```c
入口  POST /webconf/login.py?_origtarget=...
1. source/.../login.py:147
   把 _origtarget 交给 set_reload
2. source/.../htmllib.py:423
   set_reload(%s, '%s') 无任何编码
```

**链子分析**

```c
**攻击链成立** — 所有前提已确认。这一条可以实际利用。
- ✓ **H-0017** — 登录页的 CSP 含 'unsafe-inline'，内联 script 不会被拦
<the auditor's own scope statement, the unlocated evidence, the derived hypotheses>
```
````

### The sections, and what each one answers

| section | what it answers |
|---|---|
| 标题行 | id · severity · category |
| 描述 | what is claimed, and what an attacker gains |
| 权限 | is it even in scope for a pre-auth audit |
| **怎么打** | **how a reader checks it — the PoC, manual step first** |
| 调用链 | how it is reached, one `file:line` per hop |
| 链子分析 | the gate state, the auditor's scope, the reasoning from sink back to source |

`attackVector.impact` is a **field, not prose**, because a report that never states the
payoff leaves the reader to infer it — and "not assessed" has to be visible as a gap rather
than absent. It is quoted as the second line of the 描述 block.

### `权限` — the question a pre-auth audit asks

**Tri-state, and the unassessed case is not folded into either answer.**

| | |
|---|---|
| `认证前可达` | `attackVector.preAuth === true` |
| `认证后` | `false` |
| `未评估` | absent — **"nobody determined it" is not "the answer is no"** |

Collapsing the third into either inflates the finding or silently drops it, so the report
counts the pre-auth total from the recorded tri-state and an unassessed finding does **not**
count as pre-auth.

### The empty cases are the point

A section a finding does not have is **stated**, not left blank:

- no manual PoC → `未记录手工验证步骤` inside the 怎么打 fence (a reader who cannot see that it is missing will
  assume the request above was checked)
- no impact → `未评估影响`, quoted in the 描述 block
- no gates recorded → `未声明前提` — which is **not** the same as "needs none", and the
  report says so

### The manual PoC

```json
{ "poc": "curl -sS -b 'webconf_cma=<uuid>|<hmac>' .../login.py?_origtarget=...",
  "pocExpected": "the response body contains the unescaped <script>set_reload(...)" }
```

**`pocExpected` is the half that is usually missing.** Without it the reader runs the request
and cannot tell whether it worked — which is how a manual PoC becomes a manual shrug.

**Writing a poc does NOT make a finding REPRODUCED.** A request nobody sent is still a
claim. Nor does merely running a command: the tier requires the author to **declare** that
the command's output demonstrates this assertion, via `reproduces: true`. A command that
only located the code — `grep`, `sed -n`, `ls`, `find`, `cat` — belongs to the weaker
`COMMAND RAN` tier.

### Size

Measured, because a report nobody reads is not a deliverable: **71 lines per finding**, down
from 156. The PoC section prints ONE artifact in full — the sink, the line a reader opens
first — and indexes the rest by `file:line`, because a reader does not need six excerpts of
the same file to be convinced. The full text is in `.pi-hypothesis/tree.jsonl`, and the
report says so.

### The fence tag

Every content fence opens with a language tag — **`c` by default** — because a fence with no
tag gets no highlighting at all, and most targets are C.

```
/hypothesis config fenceLanguage=sh      # or cpp, java, xml, python…
/hypothesis config fenceLanguage=        # empty turns the tag off
```

The tag goes on the **opening** fence only: a tagged closer is content, not a closer. It is a
hint to the viewer, never a claim about the file.

## Coverage

**A directory with no hypothesis is not "clean", it is UNREAD.** Those are different claims,
and a report that shows one tiny gap while 40% of the files were never cited is a report that
overstates itself.

```
| **被假设引用过的文件** | 59 of 898 file(s) cited (7%) — 378 in untouched subtrees |
| **ZERO 假设的目录** | 9 |
```

The gap is **adaptive, not a fixed depth.** A fixed depth fails both ways: grouping by one
segment collapses `src/api` and `src/admin` into `src`, so one cited file marks the whole
tree covered; grouping by two fails on a project where everything lives under a single
wrapper. Measured on the Checkmk appliance the source is one tree at `source/rootfs/...`, so
a fixed depth 2 said "1 gap: `source/.idea`" while 399 of 898 files were untouched. The walk
now descends only while a directory is *touched* and reports the shallowest wholly-untouched
subtree.

The coverage round hands the model the gap and nothing else, capped at two rounds: a round
kind that can always justify itself is the failure mode this codebase has hit repeatedly.

## Exploitation chains — a sink is not an exploit

A confirmed finding whose reachability depends on something unverified is **real but not
usable**, and the report must not present it as a working vulnerability.

```
hypothesis_vector H-0007 requires=[H-0003, H-0011]
```

| state | meaning |
|---|---|
| `standalone` | no gates — complete by definition |
| `chain-ready` | every gate confirmed |
| `gated` | at least one gate still open |
| `broken` | a gate was **refuted** — the chain as stated cannot work |
| `unassessed` | no gates recorded, which is not the same as needing none |
| `untracked` | prose preconditions that nothing will ever test |

The state is **derived, never declared** — a node cannot claim to be usable. Gates are
scheduled ahead of everything else, because confirming a gate is the highest-value next step
there is: it can turn a finding from unusable into usable, or from false into refuted, and no
amount of further reading does either.

**A refuted gate breaks the chain** rather than staying open. And nothing is lost if the model
forgets to link: `hypothesis_record` looks for recorded preconditions with no gates attached
and offers to track them at the moment of confirmation.

**`requires` is validated, not trusted.** It is refused when it names an id that is not in
the tree, the scope node, itself, a duplicate, or would create a **cycle** — an untracked
precondition is prose that never gets tested, a cycle means neither finding could ever be
reported as ready, and an unanswerable "is this chain ready?" reads as "probably fine".

### What makes a pair worth combining

Mechanical signals rank the pairs; the model judges which are real. Both **same-class and
cross-class** score, so neither crowds the other out of the top-N cut.

| signal | weight | why |
|---|---|---|
| shared evidence file | +6 each, capped 12 | the strongest structural signal |
| evidence lines ≤ 50 apart | +5 | plausibly the same region |
| ancestor / descendant | +4 | a dependency (chain) is plausible |
| same class | +3 | a shared root cause is plausible |
| **different** classes | +2 | a cross-class chain is possible *and valuable if real* |
| siblings | +2 | they share a parent hypothesis |
| evidence lines ≤ 200 apart | +2 | same area, probably not the same site |
| evidence depth | +1.5 each, capped 3 | better-grounded findings pair better |

Every pair carries its signals **as text**, so the judgement is grounded in structure rather
than in reading two prose summaries. The pass is forced on a schedule, because a trigger that
only the model can fire is a trigger that never fires — and a pass that hands over candidates
and combines nothing earns a longer wait, because that is exactly what should count against
the plateau.

### Ladders

Each vulnerability class has curated depth axes — 19 classes plus a generic fallback — and
the most valuable axis is marked:

```
## rce 的深度轴
每一轴都要 settle 掉 — 读代码得出「是」或「否」，两者同样有用。
**最关键的一轴（只查一条就查它）：**
  THE LAST STEP — what turns this into code execution, and is that step actually reachable?

全部轴：
  - SINK — which exact call executes (eval, system, deserialize, template, native)?
  - INPUT PATH — how does attacker input reach it, and is any part of it constrained?
  - CONSTRAINTS — length, charset, encoding, escaping, or an allowlist to work around?
  - PRE-AUTH — is the entry reachable without authentication?
  - GATES — what else must hold, and has each been verified?
```

They are **questions, never conclusions**, and they feed the two moments where the model can
still act: the pursue round (depth on a high finding) and the challenge round (attack the
finding from an angle you have not used). An axis you cannot settle becomes a `requires`
gate, not prose — prose is recorded, printed, and then tested by nothing.

## `/loopsec` — dig, without the hypothesis tree

Give an objective, let it analyse, get a report. No tree, no assertions, no verdicts.

The hypothesis tree exists to make an audit's output **trustworthy**, and every piece of it
is load on every round. `/loopsec` drops the load — and says so **first**, before the
findings, because the reader is about to scroll a list grouped by severity and severity is
exactly the field this mode does not check:

| Not present | What that means |
|---|---|
| **No verification tier** | Nothing distinguishes a finding confirmed by running a command from one read out of the source. |
| **No falsification attempt** | Nobody tried to prove any of these wrong. The false-positive rate is UNKNOWN, not low. |
| **No challenge round** | Each finding is the auditor agreeing with itself. |
| **No severity check** | Severity is the auditor's own judgement, made once, unreviewed. |
| **No assertion gate** | A finding may be a vague statement of an area rather than a claim about behaviour. |

### The one rule it keeps

**Every finding must carry an artifact** — a `file` + `line`, or an `evidence` excerpt.
Without one it is refused, and the store drops such a finding on **read** as well, so a
hand-edited log cannot put a bare claim back. The bar is cheap and it is the entire
difference between a triage report and a list of sentences.

### The round flow

```
Round 1        RECON    — read the project, write the note (sec_recon)
Round 2        SURFACE  — enumerate the attack surface into a WORK LIST (sec_surface)
Round 3..N     ANALYZE  — work ONE item on that list, all the way down
Round N+1      SURFACE  — exhausted; enumerate again with what the analysis revealed
```

**The loop ASSIGNS the item.** That is what makes this an analysis rather than a look
around: one item per round, and a round cannot drift onto something else because it found
its assignment uninteresting.

**The plan still governs — and it is not frozen.** Everything nobody promoted keeps the order
the enumerator wrote. But the enumerator wrote it in **round 2, with almost nothing read**,
and a model that has spent fifteen rounds tracing data flows knows things it did not know
then. So an item can be sent to the front:

```
sec_surface title="..." priority=1      # a place the analysis just revealed
sec_update  S-0003 priority=1           # one you already listed, now more promising
```

The hypothesis mode already re-ranks every round — novelty, gate boost, category diversity
— so a frozen enumeration order was the inconsistent one. What this is NOT is a licence to
chase whatever you just thought of: promotion is an explicit act on an item, the item still
gets one round, ties keep plan order (`sort` is stable and the comparator returns 0), and the
next brief reports how many items are queued ahead:

```
QUEUED AHEAD OF THE PLAN (2):
  S-0003 [p1] the config parser
  S-0004 [p1] check_auth() 本身只比字符串
These are analysed before the plan order. If that list is growing faster than you clear it,
you are not re-prioritising — you are thrashing.
```

**No cap, deliberately.** A model can send every item to the front, and a limit it cannot see
the reason for is one it works around. The honest defence is a number it CAN see: two items
ahead of a plan of thirty is a fact it can act on, where a silent reorder is not.

**The items are COORDINATES, not claims** — `POST /diag/ping` is a place. Enumerating places
must not require asserting anything about them first, or the mode is back to the gate it
exists to avoid.

The analyze brief carries the method — entry → controlled input → **the check, read the check
itself rather than its name** → sink, and "trace it ALL before concluding, because a guess
written into the report is one a reader cannot tell apart from a checked conclusion" — and
the class depth axes.

### The list has a soft ceiling

A list of 200 items is 200 rounds, and **every one of them is "productive"** because it
examines something — so the plateau never fires and the run goes quiet for hours with no
warning. Measured: the share of rounds spent enumerating is `1/(k+1)` for a sweep of `k`
items, so the cost is not the cap itself, it is the **commitment the cap bounds**.

```
SURFACE AT 60 ITEMS (soft ceiling 60). It was recorded — refusing it would lose it — but the
run is now committed to at least 41 more round(s).
Analyse before enumerating further: `sec_surface` again only for a place that matters MORE
than what is already waiting.
```

**SOFT, and that is the design.** Refusing the item the model just found loses information —
and an item it cannot record is an item the run will never come back to. Once the list is at
the ceiling the surface brief stops asking for a sweep entirely and says why:

```
**THE LIST IS ALREADY AT 60 ITEMS** (soft ceiling 60), and every one of them costs a round.
Do NOT sweep again for its own sake. `sec_surface` only for a place that matters more than
what is already waiting — the analysis is what produces findings, and a list nobody finishes
produces none.
```

The analyze brief carries the same fact at the point where the model would grow the list, which
is where it can act on it.

### A clearance can be WITHDRAWN, and the report stops claiming it looked at less than it did

Two bugs found by **running the tools against each other**, not by reading them.

**1. A cleared item could not be reopened, and the refusal named a command that does not exist.**

```
sec_dig S-0001   →  "If the guard turned out not to hold, reopen it first:
                     sec_update S-0001 status=open"
sec_update S-0001 status=open   →  "S-0001 is not a finding in this run"
                                        status stays `cleared`, forever
```

`sec_update` takes a **finding** id and has no `status` field, so the advice sent the model to a
dead end — and a guard turning out not to hold is a case the mode's own refusal says happens. A
refusal that names a command which does not exist is worse than one that names nothing: it looks
like a tool bug from the inside.

```
sec_reopen S-0003 "check_auth() returns early for /diag/* before the public table"
```

The reason is required, for the same reason `sec_clear` requires one: a clearance asserts that
something protects the code, and withdrawing that is a claim too. `digSurface` now points at
`sec_reopen`, and a test follows the advice end to end — refuse, reopen, then the dig succeeds.

**2. The report called items it had examined "没看过".**

Every `open` item was printed under `尚未分析` with *"它们不是干净的，是没看过"* — including items that
had been **handed a round and left unresolved**, which is the ordinary outcome of a round that
produces nothing. The section that exists to bound the audit's honesty was making the audit look
narrower than it was.

`SecSurface.attempts` is incremented by the loop on prepare, and the list is split:

```
| **看过但未定论** | 3 |

## 尚未分析
这些项从没被分配过轮次。**它们不是干净的，是没看过。**

## 看过但未定论
这些项被分配过轮次，但**既没确认有防护、也没得出结论**。它们不是「没看过」—— 是看过了、没查完。
```

**`attempts` does NOT feed `surfaceProgress.examined`.** The plateau reads that number, and the
loop increments `attempts` on prepare — so widening it would make the day a round is *prepared*
look productive, and the plateau would stop working. A test pins that the two numbers differ and
that an attempt is not a result.

### An item may take more than one round

Before this, **an item got one round.** A round spent genuinely tracing something that needed
a second pass recorded nothing and moved no status, so it counted as unproductive — **the
model paid a plateau slot for being thorough**, and the cheap way out was to close the item
hastily. That is the wrong incentive, and it is the opposite of what an audit wants.

```
sec_dig S-0003        # "I am not finished with it — give me another round"
```

- **It comes back NEXT round**, ahead of the plan — and ahead of a *promoted* item too.
  Finishing a trace you started beats starting a more promising-looking one: an abandoned
  trace is wasted work, an unstarted item is still just an item.
- **A depth round counts as PROGRESS**, so it does not burn the plateau.
- **It is budgeted** — 2 rounds, the same `pursueRounds` setting the hypothesis mode uses for
  depth, and `0` disables it in both. Past the budget, `sec_dig` is refused and the refusal
  names both ways out, because *a depth round that never ends is the same as never deciding*.
- **The budget is spent by the LOOP on prepare**, like `pursueSpent`, so a crash or a stalled
  turn cannot hand out unlimited rounds.

The budget runs out *before* the item stops being interesting, and that is deliberate: past it
the item drops back to plan order rather than holding the queue forever.

A cleared item cannot be dug. A clearance names a guard, and asking for depth does not undo
it — the refusal says how to reopen if the guard moved.

### The brief now says what just happened, and how close the run is to stopping

Two lines that were **absent from every sec brief**:

```
Last round (9): nothing was examined and nothing was recorded
UNPRODUCTIVE ROUNDS: 1/8 — **7 more and this run STOPS.** An examined item is what resets
it; if you are about to try the same angle again, try a different one.
MIT-DIG (1) — these are not finished:
  S-0003  depth round 1/2  check_auth() 本身只比字符串
```

The stall counter is the only **self-correction signal** the mode has. Without it a run ends
for a reason the model never learned — it is at 7/8 with no idea.

And `ALREADY CLEARED` was cut at `slice(-12)`, so past twelve clearances **the oldest reasons
fell out of the brief** and the model could not tell why an area had been ruled out. It is now
cut at 40 and **states the total**, so a reader can see what is missing rather than inferring
it from the list length.

### Clearing an item is a RESULT, and the plateau knows it

`sec_clear` requires a reason that **names the guard**:

```
S-0003 cannot be cleared with "nothing found" — say WHICH guard you found and where.
```

And a round that **examines an item is productive even when it finds nothing**:

| | before | now |
|---|---|---|
| traced the flow, concluded "guarded" | unproductive | **productive** |
| the plateau counted | findings | **items examined** |
| eight careful rounds | **stopped the run** | keeps working |

Measured: five analyze rounds, four of which found nothing, `stall 0/8`. Under the old rule
that run would have stopped after eight rounds of doing exactly what it was asked to do — and
the incentive that creates is to report something, anything, to look busy, which in a mode
with no verification is the worst possible incentive.

### A chain is a finding

**Combination is orthogonal to the assertion gate** — chaining was never about assertions,
and dropping it along with them was a design mistake rather than a trade.

```
写任意文件            → medium
写进一个会被执行的文件 → root RCE
```

Two findings, one bug — and a report that lists them separately and never says the word has
missed it.

```
sec_finding title="..." category="rce" severity="critical" chainOf=["F-0001", "F-0007"]
```

A chain needs **no artifact of its own**: its artifact IS its parts, each of which carries
one. Every id must already exist, and the refusal **names the findings it does have** so the
next call can be right. The question is asked on every analyze round — "does what you are
looking at, together with something already recorded, reach somewhere neither reaches alone?"
— and the report gets a `## 组合链` section before the findings.

### One finding, ordered the way a hunter reads it

Measured on the real X-Road report before this: **27–102 lines per finding**, 8–9 of them
four labelled metadata lines, the PoC **last** under 36–55 lines of evidence, and the call
chain buried in Chinese prose — one finding named six `file:line` locations *inside its
sentences* and none of them could be read off the page.

````
### 1. F-0001 · 严重 · auth-bypass

> 认证前删除任意安全服务器的客户端关联与认证证书

`src/.../ManagementRequestVerifier.java:165` · 认证：**认证前可达** · 第 9 轮 · 攻击面 S-0006

**怎么打**
```c
curl -k -sS -X POST 'https://TARGET:4002/managementservice/manage' ...
```

**调用链**
```c
1. src/common/SecurityConfig.java:51
   permitAll() 让该端点无需认证即可访问
2. src/common/ManagementRequestVerifier.java:165
   按 serviceCode 分派；clientDeletion 被分到不继承 BaseSignedRequestCallback 的 callback
```

**说明**   接口默认 attachment 是空实现。
**物证**   <fenced artifact>

_未经验证：无等级 · 无证伪 · 无对抗复核_
````

The order is the fix: what it is → where and whether it needs auth → **how to run it** → the
chain → the evidence. The chain is `SecFinding.path`, a structured list rendered as a fenced
numbered list so the `file:line` column reads down the page.

### The long-run shape, measured

```
shape                              rounds  surface        findings  re-enumerated  stopped by
diminishing sweeps (3,3,2,2,1,1,0)     28  13, all read          1              0  plateau
never sweeps again                      8  0                     0              0  plateau
constant 2 per sweep                  120  80, all read         10              0  ran to cap
```

It grows and it does not thrash. The share of rounds spent enumerating is `1/(k+1)` for a
sweep of k items — 50% at k=1, 10% at k=10 — which is the **model's** rate, not the loop's
structure. The report shows it (`花在枚举上的轮次 | 10/30 (33%)`), and the analyze brief asks
the model to record a new place the moment the analysis reveals one, which grows the list
without spending a whole round on enumeration.

### Tools

| Tool | Purpose |
|---|---|
| `sec_recon` | the one recon note the run works from. Not chunked. |
| `sec_surface` | add one item to the work list. A **coordinate**, not a claim. |
| `sec_finding` | record a finding. `title`, `category`, an artifact. `severity` and `preAuth` are the auditor's judgement and nothing checks them. |
| `sec_clear` | mark an item examined and guarded. **The reason must name the guard.** |
| `sec_update` | correct a finding instead of recording a duplicate. |

### Files

`SEC-REPORT.md` and `SEC-FINDINGS.md`, not `REPORT.md`/`findings.md`, so a sec run and a
hypothesis run in the same project cannot overwrite each other's output. The report is in
Chinese by default (`reportLanguage`), and the fence tag is `c` (`fenceLanguage`).

## Verification — what a probe is

### A probe is a falsification attempt

You state **what the hypothesis predicts** about one mechanical fact, and the tool reports
whether that prediction held.

| | |
|---|---|
| `present` | if this is **not** here, my hypothesis is wrong |
| `absent` | if this **is** here, my hypothesis is wrong |

Aggregation is **asymmetric**: one counterexample refutes, however many probes survived.
A surviving probe means *not refuted here* — **never** *proven*.

### Three probe kinds

| kind | what it settles | consent |
|---|---|---|
| `grep` | is this pattern present in the project? | no gate |
| `location` | what is at `file:line`? | no gate |
| `command` | run it and read the output | **gated** |

### The consent gate

`allowCommandProbes` is **false** by default and no agent tool can set it — only the operator,
via `/hypothesis config allowCommandProbes=true`. Read-only probes run regardless.

### The executor never decides

It runs the probes, returns the evidence, and **suggests** a verdict. Recording one is a
separate, deliberate act. A tool that wrote its own verdicts would make the model's job
"agree with the grep".

### The tier is derived, not declared

`reasoning-only` → `static` → `command-ran` → `reproduced`. **A command alone is not enough**:
the author must declare `reproduces: true` — that the output IS the demonstration.

The weaker rule counted a `grep` as a reproduction. Measured on a real audit, 2 of 17 HIGH
findings held the REPRODUCED tier on the strength of `ls -l` and `grep -c`, while their own
dossiers said in writing "not executed this round; does not claim reproduction" — so the
report's header said REPRODUCED and its own text twenty lines below denied it. The tool
cannot tell a reproduction from a reconnaissance by reading the command, so it stopped
guessing: under-claiming is the safe direction, and the command itself is still recorded and
still printed.

### A confirmation must survive something

`hypothesis_record` refuses `confirmed` unless a **verification run survived** or a
**written refutation** exists — what would have made this FALSE, and what you found looking
for it. A confirmation with neither is the auditor agreeing with itself, and the report says
`证伪尝试：无` when that is the case.

## Steering a run

### Operator notes

```
/loopsec note <text>      # this round only — an instruction
/loopsec context <text>   # every round — a standing fact
/loopsec notes            # what is recorded and what has landed
```

`note` is consumed when a brief carries it; `context` is pinned and carried by every brief.
Delivery is **recorded, not inferred**, so a crash between preparing a brief and the model
answering cannot silently drop one. `OPERATOR.md` is a human-readable mirror.

### The clock

Active time is the headline, with wall time and paused time alongside so the two can never be
confused. A pause interval is opened on pause and closed by resume — or by the stop, so a
pause that is never resumed is still counted.

### Controlling a run

```
pause                 pause now
pause <n>             run n MORE rounds, then pause
pause <reason>        pause now, recording why
resume [<n>]          resume, optionally for a bounded stretch
stop                  end it; the report is kept
next                  run one round now instead of waiting for the turn to end
dismiss | show        close or restore the widget panel
```

`pause <n>` is a bound `maxRounds` cannot express, because `maxRounds` counts from the start
rather than from now. **`start` on a paused loop resumes it**; it refuses only on a different
objective.

### The widget

A status panel below the editor: kind, round, stall counter, the contract gap, recent rounds.
`dismiss` sets a **flag** rather than clearing a record, because the widget is re-set on every
refresh — and start/resume clears it.

## Settings

`.pi-hypothesis/settings.json`.

| key | default | |
|---|---|---|
| `reportLanguage` | `"zh"` | the report's scaffolding, and the language the brief asks the model to write in |
| `fenceLanguage` | `"c"` | the tag content fences open with; empty turns it off |
| `allowCommandProbes` | `false` | the consent gate for `command` probes. **No agent tool can set it.** |
| `commandTimeoutMs` | `120000` | |
| `reconSegmentParagraphs` | `4` | clamped to 3–5 |
| `pursueRounds` | `2` | 0 disables the pursue round |
| `maxFilesScanned` / `maxFileBytes` / `maxLinesScanned` | | the walk's budget |
| `maxGrepMatches` / `locationContext` / `maxOutputChars` | | probe output bounds |

## Design notes

The non-obvious decisions, and why.

- **The model's NOTES are chunked, not the source.** A recon note's paragraph boundaries are
  semantically whole, so chunking them is cheap and correct; chunking source produces
  arbitrary windows. It also bounds generation to 3–8 rounds.
- **A `scope` node is a boundary, not a claim** — exempt from the assertion gate and never
  scheduled.
- **The store refuses a task-shaped description.** `check whether the login handler validates
  the JWT` can never be confirmed or refuted, so a round spent on it is wasted.
- **`blocked` is progress.** `isResolved()` covers confirmed, rejected and blocked; counting
  blocked as nothing rewards forcing a false negative or positive.
- **A trigger that is always true eats the schedule.** Found three times by hand, now guarded
  by `tests/invariants.test.ts` — and the guard was validated by reverting the fix and
  checking the expected tests fail.
- **`focus=` is a bias, not a filter.** A pre-auth RCE is often reached by chaining a finding
  from another class, and a hard filter would make exactly that chain unfindable.
- **Contradiction checks are questions and never block.** `preAuth: true` on an
  authenticated-surface entrypoint, or a `critical` rating on a usually-component class, is
  raised for the model to answer. A refusal that is wrong teaches writing around the check.
- **Domain knowledge lives in the extension, not a skill file** — but the ladders are
  *questions*, never conclusions.
- **The executor suggests; the model decides.** A verdict is a separate, deliberate act.

## Persistence

`.pi-hypothesis/tree.jsonl` is an **append-only JSONL event log**. State is a fold over it.
`snapshot` records make compaction bounded without a rewrite, and the log is the source of
truth — a torn last line is repaired, never silently swallowed.

**exFAT-safe:** only `appendFileSync` and `writeFileSync`. No `renameSync`, no `linkSync`, no
held descriptor, and no locking.

The store enforces: a verdict requires evidence; a description must be falsifiable; a
duplicate assertion is refused **by name** so the caller links to the existing node.

**Every normalizer rebuilds records from an explicit field allowlist.** That has silently
eaten a new field four times — `Evidence.reproduces`, `AuditLoopKind: "sec"`, the
`SecSurface` fields, and `SecFinding.path` — each written to the log and dropped on the way
back in with no error, because the record that lost it still validated. Every one has a
round-trip test.

## Skills

A `SKILL.md` gives the model *what to look for*; this extension gives it *how to record it*
— ids, the four status words, the scheduler's rounds. The extension cannot enumerate skills,
so every brief says to read a matching one.

**The trap**: a skill that prescribes a *method* turns into a ritual, and the model follows
it after it stops being useful. The briefs therefore hand over the class axes as questions
rather than as a procedure.

## Development

```bash
npm run check     # tsc --noEmit
npm test          # bun test
```

828 tests across 21 files. `tests/invariants.test.ts` is the one that matters most: it asserts
the anti-starvation invariants over a long busy loop, and it has caught every scheduling bug
so far.

## Acceptance criteria — where each one is pinned

| criterion | pinned by |
|---|---|
| a hypothesis must be falsifiable | `tree.test.ts` — the assertion gate |
| a verdict requires evidence | `tree.test.ts`, `tools.test.ts` |
| a probe is a falsification attempt | `executor.test.ts` |
| one counterexample refutes | `executor.test.ts` |
| the tier is derived, never declared | `report.test.ts` |
| no round kind starves another | `invariants.test.ts` |
| a false positive cannot stick | `loop.test.ts` — the challenge round |
| the report states its own gaps | `report.test.ts`, `coverage.test.ts` |
| the store survives exFAT | `store.test.ts` |

## Provenance

Written for a real audit of a Checkmk appliance and an X-Road security server. Every
non-obvious decision in this document is one a measurement forced, and the numbers are in the
commit messages.
