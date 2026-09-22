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

## Which surface for a code audit

| | `/goal` | `/loop` |
|---|---|---|
| Finish line | a mechanical contract | none — it runs until the well is dry or you stop it |
| Stops on the first finding? | **yes, by design** — that is what a contract means | **no** |
| Use when | you want ONE verified high finding | **you are auditing a codebase** |

**A `/goal` is not a code audit.** Its contract is satisfied by the first
qualifying finding, so a false positive ends it. For auditing a project, use
`/loop`:

```
/loop "find pre-auth high-severity vulnerabilities"
```

It has no finish line, so a confirmation never stops it. It ends at the plateau
(8 consecutive rounds that produced no verdict and no new evidence) or when you
stop it.

### The challenge round — why a false positive no longer sticks

A confirmation is a hypothesis too, and the only thing that catches a wrong one
is an attempt to falsify it. So the loop runs a **challenge** round: it hands
the model a finding this audit already confirmed and asks it to **refute** it.

```
[AUDIT ROUND 9 — CHALLENGE]

This finding was CONFIRMED earlier in this audit:
  H-0002 — HIGH — auth-bypass
  "The `api` firewall declares `security: true` but relies only on optional…"

**Your job this round is to REFUTE it.** …
  - Find the check, guard, middleware, framework default, or caller that makes the
    claim FALSE. Grep for it with expectation: "present".
  - Attack the REACHABILITY assumption: is that controller actually routed at that path?
    Does the parent class, a listener, or a framework default apply a global check?
  - Attack the PRECONDITIONS: do they hold in a real deployment, or only in theory?
```

- **Refuted** → the finding is rejected. That is a RESULT: a false positive was
  removed, and the round counts as progress.
- **Survived** → the finding keeps its status and gains
  `Challenge: SURVIVED — round 9 tried to refute this and failed`.
- The attempt is recorded **before** the round runs, so a crash or a stalled
  model cannot re-challenge the same finding forever.
- One challenge per confirmation, then a 5-round cadence. Reopening and
  re-confirming a finding clears the record — it is a NEW claim.

**Challenge outranks recon**: a confirmed finding leaves nothing schedulable, so
with recon first the loop would go read more of the project instead of checking
its own conclusion.

### The `/goal` contract, and why it now demands a challenge

```json
{
  "minConfirmed": 1,
  "minSeverity": "high",
  "requireArtifact": true,
  "requireReproduced": false,
  "requireConsolidated": true,
  "requireChallenged": true
}
```

The contract is checked **before** the round kind is chosen. Without
`requireChallenged`, a confirmation satisfies it immediately, the goal
completes, and the challenge round never runs — the model's first confident
judgement ends the audit, right or wrong. With it, the order is:

```
confirm → consolidate (forced) → challenge → complete
```

`reproduced=1` additionally requires a command probe to have reproduced the
finding. It needs `allowCommandProbes`, so it is off by default:

```
/hypothesis config allowCommandProbes=true
/loop "find pre-auth high-severity vulnerabilities"
```

## Skills — and the trap in them

**The skill LIST is in your context** (pi puts names + descriptions in the system
prompt), and `/loop` sends its brief into the SAME session, so the list is
there in every round. But **nothing made the model read a `SKILL.md`** — pi's own
docs warn "models don't always do this", and a round brief makes it worse: the
brief is a complete procedure ("DO THIS, in order: 1… 2… 3…"), so there is no
reason to go looking for a second set of instructions.

Every brief now says so:

```
## 技能（skills）

你的技能列表里如果有匹配本次审计的（平台 / 框架 / 漏洞类别的专项技能），
**先 read 它的 SKILL.md**，把它的内容当作「**找什么**」：目标类别、绕过手法、
要检查的配置项、该平台的坑。

但「**怎么记**」以本扩展为准：

  - 节点编号用工具返回的 `H-xxxx`，**不要用技能自创的** `H1.2.3` 之类；
  - 状态词只用 `hypothesis_record` 支持的那几个（confirmed / rejected / blocked / pending），
    **不要用技能自造的** Supported / Refuted 之类；
  - 技能若描述了自己的轮次流程，或「生成 5-10 个子节点」这类配额，**忽略它的流程部分**——
    轮次和配额由本扩展的调度器决定，它带反钻牛角尖的硬限制。

技能里没有匹配的就跳过，**不要为了读技能浪费一轮**。
```

### Why the second half matters

A skill written for this job **is** a prompt-only version of the same design, so
it carries its own vocabulary — node labels like `H1.2.3`, status words like
`Supported` / `Refuted`, quotas like "generate 5-10 children". All of that
**conflicts** with this extension's mechanism, and a model holding both produces
a tree the tools cannot read.

So the split is stated explicitly:

| from the skill | from this extension |
|---|---|
| **what to look for** — target classes, bypass techniques, config to check | **how to record it** — `H-xxxx` ids, the four status words, the scheduler's rounds |

The extension is a *mechanism*; a skill is *domain knowledge*. The extension has
no opinion about what a PHP type-juggling bug looks like, and a skill has no
scheduler, no ledger and no report.

## The report — what a finding looks like

`REPORT.md` is regenerated after every round. Its headings and labels follow
`reportLanguage` (**`zh` by default**); the findings themselves are **quoted
verbatim** from the record, never translated — a report that paraphrases its own
evidence is laundering it.

```
/loop "代码审计这个项目，挖掘认证前高危漏洞"
/hypothesis config reportLanguage=zh     # zh (default) | en
```

Every confirmed finding carries the **same three sections**, and each one is
rendered **even when it is empty**, saying so:

```markdown
### 1. H-0002 — 高危 — auth-bypass

**断言：** api 防火墙声明 security: true 但 access_control 为空，GorgoneController::sendCommand
无任何鉴权即可转发命令

**验证等级：** 静态（锚定在代码中，但未复现）
**对抗复核：已被攻击并存活**——第 3 轮尝试推翻它，失败了。
**位置：** `src/Service/GorgoneService.php:95`

#### 调用链
- 入口: `POST /api/latest/gorgone/command`
- 手法: 防火墙未定义访问控制 + 控制器无角色校验，直接转发任意 Gorgone 命令
- 调用链:
  1. `config/packages/security.yaml:12` — api 防火墙只声明 security: true，access_control 列表为空
  2. `src/Api/Controller/GorgoneController.php:66` — sendCommand 没有 denyAccessUnlessGranted
  3. `src/Service/GorgoneService.php:95` — 命令原样交给 GorgoneService::send()
- 载荷: `POST /api/latest/gorgone/command  {"command":"whoami"}`

#### 可利用干什么
以 Gorgone 的权限在任意被管主机上执行命令，进而拿下中心节点

#### PoC 验证
**静态证据，未复现。**下面的代码锚点是发现的基础，但没有运行任何东西。
```

### The sections, and the fourth one

Every confirmed finding carries the **same sections**, and each is rendered **even
when it is empty**, saying so. The call chain and the PoC are **fenced code
blocks** — materially shorter than bullet lists, the `file:line` of every step
lines up in one column so the chain scans, and a step whose detail is multi-line
code can no longer leak out and break the markdown around it.

````markdown
#### 调用链

```
入口  POST /api/latest/gorgone/command
手法  防火墙未定义访问控制 + 控制器无角色校验

1. config/packages/security.yaml:12
   api 防火墙只声明 security: true，access_control 列表为空
2. src/Api/Controller/GorgoneController.php:66
   sendCommand 没有 denyAccessUnlessGranted

载荷  {"command":"whoami"}
前置条件  api 防火墙未做 IP 白名单
```

#### PoC 验证

```
手工验证
  GET /dsview/servlet/AxisServlet HTTP/1.1
  Host: TARGET
预期  返回 200 且页面出现 AxisServlet 的管理界面（而非 302 跳登录）

状态  静态证据，未复现 —— 下面的代码锚点是发现的基础，但没有运行任何东西
锚点  src/Api/Controller/GorgoneController.php:66
        public function sendCommand(Request $request): JsonResponse
        {
            $this->gorgoneService->send($request->request->get('command'));
        }

其余证据（15 条，此处只列位置，正文见 tree.jsonl）
  code-slice  config/packages/security.yaml:42
  … +14
```

#### 是否需要身份认证

```
认证前  未认证的请求即可到达这个 sink —— 这正是本次审计要找的类型
```
````

### `是否需要身份认证` — the question a pre-auth audit asks

The tier says how **strong** the evidence is. This says whether the finding is even
**in scope**. It is the metric the goal is phrased in, and it is **tri-state**:

| `attackVector.preAuth` | the section says |
|---|---|
| `true` | `认证前` — an unauthenticated request reaches this sink |
| `false` | `认证后` — a session is required; making it pre-auth means chaining an auth bypass in front of it |
| omitted | `未评估` — **and it is NOT counted as pre-auth** |

The third row is the point. **"Nobody determined it" and "the answer is no" are
different claims**, and a report that collapses them either inflates the finding
or silently drops it. So the summary counts from the recorded tri-state:

```
| **认证前可达** | **1/3** |
```

`preAuth: false` is preserved through the ledger as a real value, not dropped as
falsy — losing it would turn a recorded "requires a session" into "unassessed",
which is exactly the inflation this is guarding against.

```
/loop "只找认证前 RCE" requirePreAuth=1
```

`requirePreAuth` is a **contract clause** (default off — a post-auth finding is
still a finding). An **unassessed** finding does not satisfy it.

### The empty cases are the point

| section | source | when it is missing |
|---|---|---|
| **调用链** | `attackVector.path`, each step with `file`+`line` | _未记录调用链。**「还不知道怎么到达」和「不可达」是两件不同的事**_ |
| **可利用干什么** | `attackVector.impact` | _未评估影响。这不是「没有影响」，而是「没有评估」_ |
| **PoC 验证** | the evidence | `已复现` / `静态证据，未复现` / `没有物证` |
| **是否需要身份认证** | `attackVector.preAuth` (tri-state) | always present; `未评估` is its own answer |

"No impact recorded" and "no impact" are different claims, and a report that
silently omits the section lets the reader assume the second.

### The manual PoC — something a reader can paste and run

The PoC section used to show only the **evidence** — why the auditor believes it.
A reader cannot act on that. What they need is the **request**:

```
手工验证
  GET /dsview/servlet/AxisServlet HTTP/1.1
  Host: TARGET
预期  返回 200 且页面出现 AxisServlet 的管理界面（而非 302 跳登录）
```

Three things, and the reader cannot check the finding without all of them:

| field | what it is |
|---|---|
| `attackVector.poc` | a **copy-pasteable request** — a curl line or raw HTTP |
| `attackVector.pocExpected` | **what to look for** — `200 with the AxisServlet banner`, `a 5-second delay` |
| the evidence | a **code anchor with file:line**, or a command's output |

`poc` is **not** `payload`. A payload is what to inject (`' OR 1=1--`); a poc is the
whole thing you paste. And `entrypoint` cannot serve as either — it is prose
("any route selected by the api firewall"), which is why it is a separate field.

**`pocExpected` is the half that is usually missing.** Without it the reader runs
the request and cannot tell whether it worked — which is how a manual PoC becomes
a manual shrug.

**Writing a poc does NOT make a finding REPRODUCED.** A request nobody sent is
still a claim; the tier requires a command **output** carrying the command that
produced it. If `allowCommandProbes` is on, the brief says to *run* the poc and
record the output — that is what moves it from STATIC to REPRODUCED.

And when there is no manual step, the report **says so** rather than leaving the
section blank:

```
未记录手工验证步骤 —— 这条发现现在只能靠读代码相信。要能自己验证，
需要一条可复制的请求和「看什么才算成功」。
```

### Size

Measured on the real Centreon audit, 13 confirmed findings:

| | before | after |
|---|---|---|
| lines per finding | 156 | **71.5** |
| the confirmed section | 2031 lines / 95.5 KB | **930 lines / 48.1 KB** |
| the whole report | 2152 lines / 109.5 KB | **1051 lines / 62.2 KB** |

The bigger of the two changes was **not** the fenced blocks. Printing every
anchored entry **in full** was the real cost: a grep probe carries its whole
context window, and a finding can have half a dozen of them. The PoC section now
shows **one** artifact — the sink, the line a reader opens first — and indexes the
rest by location. The full text is in `.pi-hypothesis/tree.jsonl`.

Evidence with **no location** — a reasoning entry, a request — is still printed in
full: it has no other home, and it is the substance of why the auditor believes
the finding.

### Filling in the sections

The impact and the call chain are recorded through the attack vector. A
hypothesis is often confirmed **before** anyone works out how to reach it, so
there is a tool for filling them in afterwards:

```
hypothesis_add     { description, category, attackVector: { entrypoint, technique, path[], impact } }
hypothesis_vector  { id, impact }        # merges: records only what you give it
```

`hypothesis_vector` **merges**, so recording the impact later keeps the chain you
already gave. It refuses to create a vector with no entrypoint rather than
letting you invent one.

The summary counts complete dossiers:

```
| **档案完整（调用链+影响+PoC）** | **1/2** |
```

`impact=1` makes a complete dossier a **contract clause** — the audit may not
stop until every qualifying finding states what an attacker gains:

```
/loop "代码审计这个项目" impact=1
```

## Coverage — a directory with no hypothesis is UNREAD

Measured on the real Centreon audit: 16 paragraphs of recon became **4 segments**,
**92%** of every hypothesis came from those 4 windows, and **nothing** came from
anywhere else. The report said `侦察覆盖 4/4 个片段` — a number that reads as
complete coverage and means only *"I processed the four windows I chose to write"*.

So the report now measures the **files**, not the segments:

```
## 覆盖

| **被假设引用过的文件** | 14 of 3200 file(s) cited (0%) |
| **ZERO 假设的目录** | 3 |

> **一个没有假设的目录不是「干净」，是「没读过」。**这是两件不同的事。
> 本次审计的广度上限，就是侦察笔记提到的范围——下面这些是它没提到的部分。

- `lib/legacy` — 12 个文件，零假设
- `src/admin` — 8 个文件，零假设
```

**Both sides are derived, neither is declared:** the cited set is the `file` of every
attack-vector step and every evidence location over every node (so it is
cumulative), and the project set is the same bounded walk the grep probe uses,
with the same skip list — so the two cannot disagree about what "the project" is.

### The coverage round

Once the first note's segments are **all closed**, if there is a gap the loop runs
a **COVERAGE** round that hands over the untouched directories and asks for a
second — and last — recon note:

```
[AUDIT ROUND 2 — COVERAGE]

  14 of 3200 file(s) cited (0%)

**Directories no hypothesis has ever touched:**

  lib/legacy/  — 12 file(s)
  src/admin/   — 8 file(s)

THIS IS A SECOND RECON PASS, AND IT IS THE LAST ONE.
Write a NEW recon note covering ONLY the areas above. …

  - Do NOT re-describe areas the first note already covered. This note REPLACES the
    segment inventory, so re-covering old ground would spend the round on
    hypotheses the tree already has.
  - If one of them turns out to be generated, vendored or dead, SAY SO — a directory
    that is genuinely irrelevant is a finding too, and it stops the next pass looking.
```

**It goes HIGH — right after generation — because expanding breadth is worth more
early than one more verification.** If the untouched directories hold the pre-auth
RCE, verifying the hypotheses the first note produced will never find it.

**And it is bounded** to `COVERAGE.MAX_ROUNDS = 2`, because a round kind that can
always justify itself is the failure mode this codebase has hit three times.

### Two things it gets right by construction

**Grouping is by TWO path segments, not one.** Grouping by the first segment
collapses `src/api` and `src/admin` into `src`, so one cited file under `src/api`
marks the whole `src` tree covered — including the eight-file `src/admin` nobody
read. On a real application, where almost everything lives under one or two
top-level names, that reported near-total coverage of a project that had been
sampled. There is a regression test for it.

**A directory too small to matter is not a gap** (`MIN_FILES_FOR_GAP = 3`), or the
list is mostly noise and the real holes are not visible in it.

## The pursue round — depth


Every other round kind moves to a **sibling** hypothesis. Measured on the real
Centreon audit, that produces a wide, shallow tree: **29 nodes at depth 1, 8 at
depth 2, 1 at depth 3**. And a finding is rarely one endpoint — a missing check is
usually missing in a shared helper, a base class or a framework default that the
whole surface inherits.

So after a **HIGH-or-worse** finding is confirmed, the loop spends a budget of
rounds going **deeper on that one**, asking the four questions that produce depth:

```
[AUDIT ROUND 7 — PURSUE]

  1. WHAT ELSE does this root cause imply? If the check is missing HERE, where else is it
     missing? Find the siblings that share the same helper / base class / config entry.
     This is usually the highest-yield question: it turns one finding into a class.
  2. WHO CALLS this? Is there a path that reaches the same sink from a MORE privileged
     position, or from an UNAUTHENTICATED one?
  3. HOW FAR does it go? read → write, write → execute, execute → lateral movement?
  4. WHAT does it combine with? Use hypothesis_combine.
```

The output is new child hypotheses, and the report lists them per finding.

### Bounded three ways

| bound | why |
|---|---|
| **never two side quests in a row** | challenge + pursue + combine each had their own cadence and together squeezed verify to **1 round in 9**. They now share ONE rule |
| a **per-finding budget** (`pursueRounds`, default 2) | depth is the expensive round — it does not advance the breadth-first sweep |
| an **unproductive round closes the pursuit** | a lead that yields nothing costs one round, not the budget |

```
/hypothesis config pursueRounds=0     # switch the round off
```

Only findings at **HIGH or worse** are pursued: a depth round spent on an `info`
finding is a round a `high` finding's whole bug class could have used.

## Exploitation chains — a sink is not an exploit

The shape this exists for, from a real audit:

```
H-0039  ScheduledTask.a(byte[]) calls new ObjectInputStream(...).readObject()
        with no ObjectInputFilter, and the bytes come from three BYTEA columns
        of Scheduled_Tasks — CONFIRMED, the code says so
H-0040  can anything write schedule_data BEFORE authentication?
```

**H-0039 is not speculation.** It is a confirmed sink that is exploitable **only
if** H-0040 holds. Before this, the report presented it exactly like a working
pre-auth RCE, and nothing ever prompted anyone to go and test the gate.

### `requires` — the missing edge

`spawnedFrom` records **lineage** ("H-0007 came from H-0002 and H-0005") and
deliberately not the relationship. `hypothesis_combine` requires every source to
be **already confirmed**, because "A and B together give C" *is* speculation if
either is open.

That leaves the commonest real shape inexpressible:

| | meaning | needs |
|---|---|---|
| **combination** | A and B together give C | A **and** B confirmed |
| **conditional finding** | A gives C **if** B holds | A confirmed, **B is the open question** |

`Hypothesis.requires` is the second one: the ids that must be confirmed for this
finding to be **usable**.

```
hypothesis_add    { description, category, requires: ["H-0040"] }
hypothesis_vector { id, requires: ["H-0040"] }     # or after the fact
```

### The state is derived, never declared

```ts
export type ChainState = "standalone" | "gated" | "chain-ready" | "broken";
```

| state | meaning |
|---|---|
| `standalone` | no gates — whatever it is, it works on its own |
| `gated` | confirmed, but a gate is still unverified — a real sink waiting on a way in |
| `chain-ready` | every gate confirmed — the chain works |
| `broken` | a gate was **refuted**, so the route cannot work as stated |

`broken` is checked **first**: one broken link means the chain cannot come good,
and calling it `gated` would imply it might.

A model that could mark its own chain "ready" would mark every chain ready. The
answer comes from the gates' own statuses.

### It is scheduled, not left to be noticed

**A gate of a confirmed finding is the most valuable hypothesis in the tree** —
verifying it is what turns a confirmed sink into a working exploit. So it gets a
`gateBoost` of **14**, above novelty (10):

```
round 5: selected H-0002 (score 30.5) from 7 open hypothesis(es)
  score: novelty 10.0 + evidence 0.0 + diversity 8.0 + testing 0.0 − depth 1.5 …
```

Scoped to gates of **confirmed** findings. A gate of an unconfirmed hypothesis is
just another hypothesis, and boosting it would let a model that writes many gated
findings steer the whole schedule.

### And nothing is lost if the model forgets

`preconditions` is prose: recorded, printed, **never tested by anything**. So when
a finding is confirmed with preconditions and no gates, `hypothesis_record` says
so at the moment the model still has the finding in hand:

```
UNTRACKED PRECONDITIONS. This finding records 1 precondition(s) that NOTHING
will ever test:
  - api 防火墙未做 IP 白名单
As it stands the report presents this as USABLE, and it may not be.
For each precondition that is not already established:
  1. hypothesis_add it as its own falsifiable assertion (a gate), then
  2. hypothesis_vector H-0039 requires=[<the gate id>] to link them.
```

### In the report

```markdown
**攻击链:**

**攻击链未成立** —— 还需要这些前提成立：H-0002。sink 是真的，但路还没打通。

- … **H-0002** — Scheduled_Tasks 表的 schedule_data/task_data/task_results 三个 BYTEA 列可以被认证前写入
```

And the summary counts **usability**, not just confirmation:

```
| **可实际利用（攻击链完整）** | **0/1** |

> **其中 1/1 条的利用前提尚未验证。**确认了 sink，不等于确认了能到达 sink 的路。
> 「攻击链未成立」的条目是**真实但暂时用不了**的发现，不要当作可用漏洞上报。
```

`requireExploitable` makes that a **contract clause** (default off, because you
usually find the sink before the way in):

```
/loop "只找认证前 RCE" requireExploitable=1
```

### Validation

`requires` is refused when it names an id that is not in the tree, the scope
node, itself, a duplicate, or would create a **cycle**. An untracked precondition
is prose that never gets tested; a cycle means neither finding could ever be
reported as ready; and an unanswerable "is this chain ready?" reads as "probably
fine".

## Exploitation ladders — the axes nobody asks about

The extension is a **mechanism**: it has an opinion about how a claim is recorded
and falsified, and none about what a PHP type-juggling bug looks like. But there
is one thing it must know — **the standard axes of depth for a class**. Not how to
exploit anything, just the questions.

The gap this closes, from a real scenario:

```
confirmed:   the server fetches a caller-directed URL, file:// included,
             exfiltrated indirectly through the parsed result
never asked: is the response reflected back?  (the echo channel)
```

**An unasked axis is not a gap in the report — it is a gap the report cannot see.**
And a confirmed sink whose preconditions nobody examined was being reported as a
usable finding.

### It feeds the two moments where the model can still act

```
[AUDIT ROUND 7 — PURSUE]        and      hypothesis_record → confirmed

## The depth axes for ssrf

Settle EACH axis by reading code — "no" is as useful an answer as "yes".
**An axis you cannot settle becomes a GATE hypothesis** (`requires`), not prose.
Prose is recorded, printed, and then tested by nothing.

**The one that matters most — if you check only one, check this:**
  ECHO CHANNEL — is any part of the fetched response reflected to the attacker
  (body, status, headers, timing, error text)? Full echo / semi-blind / fully blind
  decides whether this is a file-read primitive or a port-scan at best.

All of them:
  - ECHO CHANNEL — is any part of the fetched response reflected back?
  - PROTOCOL ALLOWLIST — file:// (local file read), gopher:// and dict:// (protocol
    smuggling to internal services), ftp://, jar://.
  - REDIRECTS — a redirect to an internal address walks past a hostname allowlist.
  - INTERNAL REACH — 127.0.0.1, RFC1918, 169.254.169.254 (cloud metadata), a socket?
  - BLIND EXFIL — with no echo, can the result leave any other way?
  - REQUEST SHAPE — are method, headers or body attacker-controlled?

Write each unsettled axis as its own hypothesis, then link it with
`hypothesis_vector H-0002 requires=[...]`.
```

It is also in the **challenge** brief: the axes are what to *attack* — "there
really is no echo channel" is a claim that can be checked.

### The shape of an axis

Each is a **question answerable by reading code**, phrased so a "no" is as useful
as a "yes". The answer becomes a **gate**, not prose: a gate gets scheduled,
confirmed or refuted, and shows up in the chain state.

| | |
|---|---|
| `ssrf` | **echo channel** / protocol allowlist / redirects / internal reach / blind exfil / request shape |
| `deserialization` | **gadget chain on the classpath** / type restriction / input control / entry precondition / engine |
| `command-injection` | **does it reach a shell at all** / separators / quote escape / allowlist bypass / blind confirmation |
| `path-traversal` | **read or write** / encoding bypass / absolute path / prefix bypass / symlinks / downstream parsing |
| `xxe` | **is entity resolution even enabled** / echo / out-of-band / file read / SSRF |
| `sqli` | **real parameterization** / injection type / echo / DB privilege / second order |
| `auth-bypass` | **global enforcement** / entry point / route aliases / normalization / the same base class / default-deny |
| `ssti` | **is the engine sandboxed** / version / echo / reach / is the template SOURCE controlled |

19 classes are curated; the rest fall back to a generic ladder, because **the
absence of knowledge must not look like the absence of a question**.

### What a ladder is not

It is not a checklist that manufactures findings. Every axis is answerable either
way, and the block says so explicitly:

> Settle EACH axis by reading code — "no" is as useful an answer as "yes".

A ladder that only made sense if the answer were "yes" would produce exactly the
speculation this whole system exists to avoid.

## Closing the widget

A finished audit's widget otherwise sits on screen forever — nothing will ever
update it again, and hiding it once is not enough because the next refresh puts
it back. So the dismissal is a **flag on the loop**, not a one-off UI call:

```
/loop dismiss      # or /loop hide, /loop close
/loop show         # bring it back
```

```
Widget hidden. The loop finished at round 12; its report and the tree are
untouched. /loop show brings it back, /loop start begins a new audit.
```

**Dismissing a panel and discarding an audit are different actions.** The tree,
the round history, the contract, the clock, the findings ledger and `REPORT.md`
all survive; only the widget goes. `/loop status` still reports everything and
says the widget is hidden.

Starting or resuming **clears** the flag — you are working again, so the widget
comes back.

## Controlling a run

```
/loop start ["<objective>"]     start an audit — or RESUME the paused one
/loop pause                     stop the clock, keep everything
/loop resume [maxRounds=N]      continue in place
/loop stop                      end it (the tree is kept)
/loop status                    where it is, how long it has been going
```

### `/start` on a paused loop resumes it

"start" is the word a person types when they want the audit to go again, and
with a paused loop present that is exactly what they mean. So it resumes in
place rather than refusing:

```
Resumed the paused loop at round 12: audit the project
  nothing was reset — the tree, the contract and the round number are unchanged.
  the stall counter was reset, so the plateau starts fresh.
  to start a DIFFERENT audit: /loop stop first.
```

It still **refuses** when resuming would silently keep something the user is no
longer asking for, and the refusal names the command that works:

| existing loop | what `/loop start` does |
|---|---|
| none | starts fresh |
| **running** | refuses: `/loop status` to watch, `/loop pause` to stop the clock |
| **paused**, same kind + objective | **resumes in place** |
| **paused**, different objective | refuses: resuming would keep the old one |
| **paused**, different kind (`/goal` over a `/loop`) | refuses: that is a different audit |
| stopped / complete | starts fresh (the tree is kept) |

With no objective given, `/loop start` reuses **the loop's** objective, not the
tree's: the tree objective is whatever created the root (often a scope line),
while the loop carries the audit you actually asked for.

## Steering a run that is already going

An audit runs for hours and you learn things while it runs. You do not have to
stop it, and you do not have to watch it re-derive what you already know.

```
/loop note the queue consumer is where the last incident was — start there
/loop context the admin API is under /admin/v2, the UI one is legacy
/loop notes
```

| verb | reaches the model | use for |
|---|---|---|
| `/loop note <text>` | **the next round only** | an instruction for this stretch of work |
| `/loop context <text>` | **every round** | a durable fact about the project |

The distinction is the whole design. A one-shot note that stayed forever would
keep pulling the audit back to a stale instruction; a durable fact that was
consumed once would be forgotten by round three.

What the model sees, right after the round banner:

```
[AUDIT ROUND 12 — VERIFY]

## OPERATOR INPUT (from the person running this audit)

This is not project content and not a hypothesis — it is information from the operator.
Treat it as authoritative context and use it, but it does not replace evidence.

- **[standing context]** the admin API is under /admin/v2, the UI one is legacy
- the queue consumer is where the last incident was — start there
```

- Delivery is **recorded, not inferred**: a note that was actually shown is
  marked with the round that showed it, so a crash between preparing a brief and
  the model answering cannot silently drop it.
- Notes are the one thing in the ledger that is **never windowed**. A selection
  can be re-derived by re-reading the project; a note exists nowhere else.
- `/loop notes` (or `/loop note` with no text) shows what is pending, what is
  standing, and what has already been spent.

## The report is live

`REPORT.md` is **regenerated after every round**, not only when the loop stops:

```
/loop report        # print it now
```

It is a pure function of the tree, so it can never disagree with the ledger, and
reloading the file is how you watch a long audit progress. It carries an
`## Operator input` table saying what you told the audit and whether it landed —
an audit that was steered by a hint must not read as one that found its way alone.

Alongside it, `.pi-hypothesis/OPERATOR.md` is the human-readable mirror of your
notes.

## The clock

The widget carries the time on its state line, right after what the loop is
doing:

```
hypothesis ▶ loop round 15 · 4 confirmed · 1 rejected · 26 open
  in flight: round 15 · 3m 40s · stall 0/8 · elapsed 2h 14m
  contract open: 1/1 qualifying confirmed finding(s)
```

`in flight: … · 3m 40s` and `elapsed 2h 14m` answer the two questions a watcher
actually has: **is it stuck**, and **how long has this been going**. A round that
has been "in flight" for an hour is a stuck turn, and that is invisible from the
round number alone.

`/loop status` gives the full version:

```
  elapsed 2h 02m · (2h 14m wall, 12m paused) · 3.4 rounds/h
  the round in flight has been waiting 3m 40s — a turn that is not moving is a stuck turn
  started 2026-03-01T10:00:00.000Z, updated 2026-03-01T12:14:00.000Z
```

### Paused time is separated from wall time

They answer different questions, and reporting only the wall clock makes a loop
that sat paused overnight claim a night of work. **Active** time is the honest
"how long has this been running"; wall and paused time are shown next to it so
the two can never be confused.

| | |
|---|---|
| `elapsed 2h 02m` | active — the headline |
| `2h 14m wall` | since the start, including pauses |
| `12m paused` | time it could not work |
| `3.4 rounds/h` | over **active** time, so a pause does not flatter the rate |

A pause is banked when the loop **resumes**, and if it is stopped while paused,
`endedAt` closes the interval instead — a pause nobody resumed from is still
counted.

A finished loop's clock is **frozen** at `endedAt`: reading the status a day
later must not change the answer. And every span is clamped at zero, so a system
clock that jumps backwards shows `0s` rather than a negative duration.

The report header carries the same numbers:

```
- **Duration**: **2h 02m** of active auditing · 2h 14m wall, 12m paused · 3.4 rounds/h
- **Started**: 2026-03-01T10:00:00.000Z · **ended**: 2026-03-01T12:14:00.000Z
```

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

### `resume` and the round cap
The round cap is **durable**, so `/goal resume` cannot move it — the tick would
immediately re-stop with the same reason and send no round. Rather than report a
success that does nothing, `resume` refuses and names the fix:

```
REJECTED: the round cap (3) is already reached at round 3, so resuming would stop again immediately and send no round.
Raise the cap in place:  /goal resume maxRounds=13
Or start a new one:      /goal start "<objective>" maxRounds=13  (the tree and its hypotheses are kept either way)
```

`resume maxRounds=<n>` continues **in place**: same round counter, same tree,
same hypotheses. A **plateau** stop does not have this problem — resume resets
the stall counter, so it genuinely recovers.

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
npm test             # 728 tests, ~20s, spawns nothing
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
  report.ts     the audit REPORT (the deliverable a human reads)
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
