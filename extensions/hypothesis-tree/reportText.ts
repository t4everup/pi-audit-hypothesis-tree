/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/reportText.ts
 *
 * The report's own words, in two languages.
 *
 * -----------------------------------------------------------------------
 * What is translated, and what is NOT
 * -----------------------------------------------------------------------
 *
 * This file holds the SCAFFOLDING: headings, labels, the method section, the
 * explicit non-claims. Those are the tool's words and the tool must say them in
 * the reader's language.
 *
 * It does NOT hold the findings. An assertion, a status reason, an evidence
 * excerpt and an impact are the MODEL's words, recorded verbatim in whatever
 * language the model wrote them. Translating them here would mean the report
 * paraphrases its own evidence, which is exactly the kind of laundering this
 * project exists to avoid — a reader must see the auditor's actual claim, not a
 * rendering of it.
 *
 * So a Chinese report needs both: these strings, AND a brief that tells the
 * model to write its assertions and evidence in Chinese. `reportLanguage` drives
 * both.
 *
 * -----------------------------------------------------------------------
 * Why a table and not a lookup at each call site
 * -----------------------------------------------------------------------
 *
 * A report with a missing translation is worse than one in the wrong language:
 * a half-translated heading reads as a bug and hides the structure. One object
 * per language means a new string cannot be added without both being updated —
 * the compiler refuses the incomplete one.
 */

export type ReportLanguage = "zh" | "en";

export const REPORT_LANGUAGES: ReportLanguage[] = ["zh", "en"];

export function isReportLanguage(value: unknown): value is ReportLanguage {
  return value === "zh" || value === "en";
}

/** The label for a severity, so a Chinese report does not say "HIGH". */
export function severityLabel(severity: string | undefined, lang: ReportLanguage): string {
  if (!severity) return lang === "zh" ? "未评级" : "UNRATED";
  const zh: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" };
  return lang === "zh" ? (zh[severity] ?? severity.toUpperCase()) : severity.toUpperCase();
}

export interface ReportStrings {
  // ---- header ----
  title: string;
  liveLine1: string;
  liveLine2: string;
  project: string;
  generated: string;
  run: string;
  noLoop: string;
  duration: string;
  durationActive: (d: string) => string;
  durationWall: (d: string) => string;
  durationPaused: (d: string) => string;
  durationRate: (r: string) => string;
  started: string;
  ended: string;
  stoppedBecause: string;
  stillRunning: string;

  // ---- summary ----
  summary: string;
  colMetric: string;
  colValue: string;
  rowHypotheses: string;
  rowConfirmed: string;
  rowRejected: string;
  rowUnexamined: string;
  rowBlocked: string;
  rowCoverage: string;
  rowCombinations: string;
  rowVectors: string;
  rowDossier: string;
  coverageNotRun: string;
  coverageSegments: (covered: number, total: number) => string;
  combinationLine: (passes: number, pairs: number) => string;

  // ---- headline states ----
  noFinding: string;
  noFindingNote: string;
  tierBreakdown: string;
  tierReproduced: (n: number) => string;
  tierStatic: (n: number) => string;
  tierReasoning: (n: number) => string;
  challengedCount: (n: number, total: number) => string;
  reasoningWarning: string;
  dossierIncomplete: (complete: number, total: number) => string;
  dossierWarning: string;

  // ---- operator input ----
  operatorInput: (n: number) => string;
  colId: string;
  colKind: string;
  colDelivered: string;
  colText: string;
  kindStanding: string;
  kindOneShot: string;
  deliveredEveryRound: string;
  deliveredNotYet: string;
  deliveredRound: (n: number) => string;

  // ---- one finding ----
  assertion: string;
  verification: string;
  /** The verification tier, in the reader language — tierLabel() is English-only. */
  tierName: (tier: "reproduced" | "static" | "reasoning-only") => string;
  chainLabel: string;
  challengeSurvived: (round: number) => string;
  challengeNever: string;
  derivedByCombination: (kind: string, from: string) => string;
  location: string;
  callChain: string;
  entrypoint: string;
  technique: string;
  payload: string;
  preconditions: string;
  noCallChain: string;
  impact: string;
  noImpact: string;
  poc: string;
  pocStatus: string;
  pocAnchor: string;
  pocReproduced: string;
  pocStatic: string;
  pocNone: string;
  pocCommand: string;
  pocOutput: string;
  pocAlso: (n: number) => string;
  authRequirement: string;
  authPre: string;
  authPreWhy: string;
  authPost: string;
  authPostWhy: string;
  authUnassessed: string;
  authUnassessedWhy: string;
  rowPreAuth: string;
  preAuthNote: (n: number, t: number) => string;
  chainStateLabel: string;
  chainReady: (gates: string) => string;
  chainGated: (gates: string) => string;
  chainBroken: (gates: string) => string;
  chainStandalone: string;
  chainUntracked: (n: number) => string;
  chainUnassessed: string;
  chainUnassessedAsk: string;
  rowUnassessed: string;
  unassessedWarning: (n: number, t: number) => string;
  rowExploitable: string;
  exploitableWarning: (n: number, t: number) => string;
  exploitableNote: string;
  derived: (n: number) => string;
  derivedNote: string;
  noDerived: string;
  pursuedTimes: (n: number, budget: number) => string;
  auditorScope: string;
  evidence: (n: number) => string;
  evidenceMore: (n: number) => string;

  // ---- other sections ----
  ruledOut: (n: number) => string;
  ruledOutNone: string;
  refutedBy: string;
  blocked: (n: number) => string;
  blockedNote: string;
  blockedBecause: string;
  notExamined: (n: number) => string;
  notExaminedNone: string;
  notExaminedNote: string;
  notExaminedMore: (n: number) => string;
  segmentsUncovered: string;
  method: string;
  methodLines: string[];
  nonClaims: string;
  nonClaimLines: string[];
  noneRecorded: string;
  footer: string;
}

const ZH: ReportStrings = {
  title: "# 代码审计报告",
  liveLine1: "> **本文件在 loop 运行的每一轮后都会重新生成。**它展示的是审计的**当前状态**，",
  liveLine2: "> 不是结束时拍下的快照——重新打开这个文件就能看到进度。",
  project: "项目",
  generated: "生成时间",
  run: "运行",
  noLoop: "没有启动审计循环——这棵树是手工建立的",
  duration: "耗时",
  durationActive: (d) => `**${d}** 的有效审计时间`,
  durationWall: (d) => `墙钟 ${d}`,
  durationPaused: (d) => `暂停 ${d}`,
  durationRate: (r) => `${r} 轮/小时`,
  started: "开始",
  ended: "结束",
  stoppedBecause: "停止原因",
  stillRunning: "（仍在运行）",

  summary: "## 概览",
  colMetric: "项目",
  colValue: "值",
  rowHypotheses: "记录的假设",
  rowConfirmed: "**已确认**",
  rowRejected: "已推翻（排除）",
  rowUnexamined: "未检验",
  rowBlocked: "阻塞（等待条件）",
  rowCoverage: "侦察覆盖",
  rowCombinations: "组合推理轮次",
  rowVectors: "带攻击向量的",
  rowDossier: "**档案完整（调用链+影响+PoC）**",
  coverageNotRun: "未运行",
  coverageSegments: (c, t) => `${c}/${t} 个片段`,
  combinationLine: (p, pairs) => `${p} 轮（检查了 ${pairs} 对）`,

  noFinding: "**没有确认任何漏洞。**本次审计**未能**确立一个漏洞。",
  noFindingNote: "这是一个结果，不是失败——下面的「已推翻」和「未检验」界定了这个结论的边界。",
  tierBreakdown: "**已确认发现的验证等级分布：**",
  tierReproduced: (n) => `${n} 条已复现（真的运行了命令，且可重跑）`,
  tierStatic: (n) => `${n} 条静态（锚定在代码中，但未复现）`,
  tierReasoning: (n) => `${n} 条仅推理——**这些是观点，不是发现**`,
  challengedCount: (n, t) => `**其中 ${n}/${t} 条已被对抗复核攻击过**——没有被攻击过的确认，只是审计员在附和自己。`,
  reasoningWarning: "> 「仅推理」的条目只有论证、没有物证。把它当作**待核查的线索**，绝不要当作已确认的漏洞。",
  dossierIncomplete: (c, t) => `**${c}/${t} 条发现具备完整档案**（调用链 + 影响 + PoC 验证）。`,
  dossierWarning: "> 档案不完整的条目缺哪一段，下面就会明说缺哪一段。**缺失不是「没有影响」，而是「没有评估」**——这两者不能混为一谈。",

  operatorInput: (n) => `## 操作员输入（${n} 条）`,
  colId: "编号",
  colKind: "类型",
  colDelivered: "是否已送达模型",
  colText: "内容",
  kindStanding: "长期",
  kindOneShot: "一次性",
  deliveredEveryRound: "每一轮",
  deliveredNotYet: "**尚未**",
  deliveredRound: (n) => `第 ${n} 轮`,

  assertion: "**断言：**",
  verification: "**验证等级：**",
  tierName: (tier) =>
    tier === "reproduced"
      ? "已复现（运行过命令，且可重跑）"
      : tier === "static"
        ? "静态（锚定在代码中，但未复现）"
        : "仅推理（没有物证——这是观点，不是发现）",
  chainLabel: "调用链",
  challengeSurvived: (r) => `**对抗复核：已被攻击并存活**——第 ${r} 轮尝试推翻它，失败了。`,
  challengeNever: "**对抗复核：从未被攻击**——还没有人尝试推翻它，所以这只是审计员在附和自己。",
  derivedByCombination: (k, from) => `**由组合推理得出。**${k}，来源：${from}`,
  location: "**位置：**",
  callChain: "#### 调用链",
  entrypoint: "入口",
  technique: "手法",
  payload: "载荷",
  preconditions: "前置条件",
  noCallChain: "_未记录调用链。**「还不知道怎么到达」和「不可达」是两件不同的事**——这只是前者。_",
  impact: "#### 可利用干什么",
  noImpact: "_未评估影响。模型记录了这个漏洞**怎么打**，但没有记录**打下来能拿到什么**。这不是「没有影响」，而是「没有评估」。_",
  poc: "#### PoC 验证",
  pocStatus: "状态",
  pocAnchor: "锚点",
  pocReproduced: "已复现 —— 下面的命令真的运行过，可重跑",
  pocStatic: "静态证据，未复现 —— 下面的代码锚点是发现的基础，但没有运行任何东西",
  pocNone: "没有物证 —— 只有论证，没有代码锚点，也没有运行过任何命令",
  pocCommand: "命令",
  pocOutput: "输出",
  pocAlso: (n) => `其余证据（${n} 条，此处只列位置，正文见 tree.jsonl）`,
  authRequirement: "#### 是否需要身份认证",
  authPre: "认证前",
  authPreWhy: "未认证的请求即可到达这个 sink —— 这正是本次审计要找的类型",
  authPost: "认证后",
  authPostWhy:
    "需要已认证会话才能到达。这是一个真实的发现，但不是认证前的——要变成认证前，需要在它前面接一条鉴权绕过（用 requires 把那条挂上）。",
  authUnassessed: "未评估",
  authUnassessedWhy:
    "没有记录到达这个 sink 需要什么身份。**这不等于认证前**——「没评估」和「认证前」是两件不同的事，报告不会把它算进认证前。",
  rowPreAuth: "**认证前可达**",
  preAuthNote: (n, t) => `其中 ${n}/${t} 条认证前可达。`,
  chainStateLabel: "攻击链",
  chainReady: (gates) => `**攻击链成立** —— 所有前提已确认（${gates}）。这一条可以实际利用。`,
  chainGated: (gates) => `**攻击链未成立** —— 还需要这些前提成立：${gates}。sink 是真的，但路还没打通。`,
  chainBroken: (gates) => `**攻击链已断** —— ${gates} 已被推翻，所以按当前描述这条路走不通。sink 仍然真实，但入口不成立。`,
  chainStandalone: "独立成立（已评估前提，无依赖）",
  chainUntracked: (n) =>
    `**前提未跟踪** —— 记录了 ${n} 个前置条件，但**没有任何一条被变成假设**，所以没有任何东西会去检验它们。` +
    `这条发现现在读起来像是可用的，而它可能不是。`,
  chainUnassessed: "**利用前提未评估** —— 这条发现没有声明任何依赖。",
  chainUnassessedAsk:
    "**这不等于它不需要依赖。**没有人问过「要到达这个 sink，还需要什么成立」。先问这些：入口是否可达？是否需要认证？" +
    "协议/重定向/主机名是否被限制？响应是否回显？",
  rowUnassessed: "**利用前提未评估**",
  unassessedWarning: (n, t) =>
    `> **其中 ${n}/${t} 条的利用前提从未被评估。**没有人问过「要到达它还需要什么成立」，` +
    `所以它们被当成自包含的——而「没记录前提」和「不需要前提」是两件事。`,
  rowExploitable: "**可实际利用（攻击链完整）**",
  exploitableWarning: (n, t) =>
    `> **其中 ${n}/${t} 条的利用前提尚未验证。**确认了 sink，不等于确认了能到达 sink 的路。` +
    `「攻击链未成立」的条目是**真实但暂时用不了**的发现，不要当作可用漏洞上报。`,
  exploitableNote: "每条确认发现都标了攻击链状态：独立成立 / 攻击链成立 / 攻击链未成立 / 攻击链已断 / 前提未评估。",
  derived: (n) => `#### 衍生假设（追索产出，${n} 条）`,
  derivedNote: "每一条都是顺着这条发现的根因往下挖出来的。**广度靠枚举，深度靠这个。**",
  noDerived: "_未追索。这一条只有它自己——它的根因在别处是否也成立、谁能到达它、它能走多远，还没有人查过。_",
  pursuedTimes: (n, budget) => `追索 ${n}/${budget} 轮`,
  auditorScope: "**审计员自述的范围**",
  evidence: (n) => `**证据（${n} 条）**`,
  evidenceMore: (n) => `_……另有 ${n} 条证据在 \`.pi-hypothesis/tree.jsonl\` 中。_`,

  ruledOut: (n) => `## 已推翻 / 排除（${n}）`,
  ruledOutNone: "_没有被推翻的条目。**一棵只确认、从不推翻的树，说明它没有在真正检验任何东西**——请把这当作审计的缺口，而不是干净的结果。_",
  refutedBy: "推翻依据",
  blocked: (n) => `## 阻塞（${n}）`,
  blockedNote: "已记录但当前无法检验。理由是审计员自己给的，也正是循环在等待的东西。",
  blockedBecause: "阻塞原因",
  notExamined: (n) => `## 未检验（${n}）`,
  notExaminedNone: "_所有已记录的假设都检验过了。_",
  notExaminedNote: "以下条目已记录但未检验，按调度器会选取的顺序排列。**这里的任何一条都不构成任何方向的结论。**",
  notExaminedMore: (n) => `- _……另有 ${n} 条（见 \`.pi-hypothesis/tree.jsonl\`）_`,
  segmentsUncovered: "**侦察片段未产出假设**",
  method: "## 方法",
  methodLines: [
    "- 每条假设都是一个**可被证伪的断言**，不是一件待办事项。存储层会拒绝任务式文本。",
    "- 验证是一次**证伪尝试**：每个探针声明该假设对某一个机械事实的预测，一个反例即可推翻。探针存活只意味着「此处未被推翻」，**永远不等于「已证明」**。",
    "- **判定必须有证据**；上面每条发现的验证等级说明了证据有多强。",
    "- 调度器强制反钻牛角尖限制：连续下降不超过 3 层、同一节点不超过 2 轮、最近 10 次选取中同一类别不超过 40%。",
    "- 已确认的发现会被周期性地**组合**成新假设（攻击链、共同根因、横向扩展）。",
    "- 每条已确认的发现都会收到一次**对抗复核**：把该发现交给模型并要求它**推翻**。被推翻的发现会被移出报告——**一个误报被移除，是结果，不是失败**。",
  ],
  nonClaims: "## 本报告**不**声称的内容",
  nonClaimLines: [
    "- **这不是一次渗透测试。**除非某条发现的等级标为「已复现」，否则没有任何请求被发送到运行中的系统。",
    "- **静态发现是一个强论证，不是证明。**父类、全局中间件或框架默认值是否已经拦住了它，光读这个控制器是定不了的。",
    "- **没有发现，不等于没有漏洞。**见「未检验」——有 {unexamined} 条已记录的假设从未被检验，而侦察本身也只覆盖了 {segments} 个片段。",
    "- **严重程度是审计员的判断**，不是 CVSS 评分；未评级的发现意味着「尚未判定」，而不是「低危」。",
    "- **误报率不是零。**对抗复核降低了它，但没有消除它——它仍然是同一个模型在自我审查，只是换了一个对抗性的视角。",
  ],
  noneRecorded: "_无。_",
  footer:
    "_由 pi-audit-hypothesis-tree 从持久化状态生成：`.pi-hypothesis/tree.jsonl`（仅追加）、" +
    "`.pi-hypothesis/findings.md`（逐轮日志）、`.pi-hypothesis/recon.md`（侦察笔记）、" +
    "`.pi-hypothesis/OPERATOR.md`（操作员输入）。**本报告中没有任何摘要由模型生成——每一行都来自已记录的状态。**_",
};

const EN: ReportStrings = {
  title: "# Code audit report",
  liveLine1: "> **This file is regenerated every round while a loop is running.** It is a view of the",
  liveLine2: "> audit's current state, not a snapshot taken at the end — reload it to see progress.",
  project: "Project",
  generated: "Generated",
  run: "Run",
  noLoop: "no audit loop was started — this is a tree built by hand",
  duration: "Duration",
  durationActive: (d) => `**${d}** of active auditing`,
  durationWall: (d) => `${d} wall`,
  durationPaused: (d) => `${d} paused`,
  durationRate: (r) => `${r} rounds/h`,
  started: "Started",
  ended: "ended",
  stoppedBecause: "Stopped because",
  stillRunning: "(still running)",

  summary: "## Summary",
  colMetric: "",
  colValue: "",
  rowHypotheses: "Hypotheses recorded",
  rowConfirmed: "**Confirmed**",
  rowRejected: "Rejected (ruled out)",
  rowUnexamined: "Unexamined",
  rowBlocked: "Blocked (waiting on something)",
  rowCoverage: "Recon coverage",
  rowCombinations: "Combination passes",
  rowVectors: "With an attack vector",
  rowDossier: "**Complete dossier (chain + impact + PoC)**",
  coverageNotRun: "not run",
  coverageSegments: (c, t) => `${c}/${t} segments`,
  combinationLine: (p, pairs) => `${p} (${pairs} pair(s) examined)`,

  noFinding: "**No finding was confirmed.** The audit did not establish a vulnerability.",
  noFindingNote: 'That is a result, not a failure — see "Ruled out" and "Not examined" below for the boundary of that statement.',
  tierBreakdown: "**Verification tiers of the confirmed findings:**",
  tierReproduced: (n) => `${n} reproduced (a command was run and re-runnable)`,
  tierStatic: (n) => `${n} static (anchored in code, not reproduced)`,
  tierReasoning: (n) => `${n} reasoning only — **these are opinions, not findings**`,
  challengedCount: (n, t) => `**${n}/${t} of them have been ATTACKED** — an unchallenged confirmation is the auditor agreeing with itself.`,
  reasoningWarning: "> A reasoning-only entry rests on an argument with no artifact. Treat it as a lead to check, never as a confirmed vulnerability.",
  dossierIncomplete: (c, t) => `**${c}/${t} findings have a complete dossier** (call chain + impact + PoC).`,
  dossierWarning: "> An incomplete dossier says which part is missing, below. **A missing part is \"not assessed\", not \"no impact\"** — the two must not be confused.",

  operatorInput: (n) => `## Operator input (${n})`,
  colId: "id",
  colKind: "kind",
  colDelivered: "reached the model",
  colText: "text",
  kindStanding: "standing",
  kindOneShot: "one-shot",
  deliveredEveryRound: "every round",
  deliveredNotYet: "**not yet**",
  deliveredRound: (n) => `round ${n}`,

  assertion: "**Assertion.**",
  verification: "**Verification:**",
  tierName: (tier) =>
    tier === "reproduced"
      ? "REPRODUCED (a command was run and is re-runnable)"
      : tier === "static"
        ? "STATIC (anchored in code, not reproduced)"
        : "REASONING ONLY (no artifact — an opinion, not a finding)",
  chainLabel: "call chain",
  challengeSurvived: (r) => `**Challenge: SURVIVED** — round ${r} tried to refute this and failed.`,
  challengeNever: "**Challenge: NEVER ATTACKED** — nobody has tried to refute this yet, so it is the auditor agreeing with itself.",
  derivedByCombination: (k, from) => `**Derived by combination.** ${k} of ${from}`,
  location: "**Location:**",
  callChain: "#### Call chain",
  entrypoint: "Entrypoint",
  technique: "Technique",
  payload: "Payload",
  preconditions: "Preconditions",
  noCallChain: "_No call chain recorded. **\"How to reach it is not yet known\" and \"unreachable\" are different things** — this is the first one._",
  impact: "#### What it is exploitable for",
  noImpact: "_Impact not assessed. The model recorded **how** to attack this, not **what it gets**. That is \"not assessed\", not \"no impact\"._",
  poc: "#### PoC verification",
  pocStatus: "status",
  pocAnchor: "anchor",
  pocReproduced: "REPRODUCED — the command below was actually run and can be re-run",
  pocStatic: "STATIC, not reproduced — the anchor below is what the finding rests on; nothing was executed",
  pocNone: "No artifact — an argument only: no code anchor, and no command was run",
  pocCommand: "command",
  pocOutput: "output",
  pocAlso: (n) => `other evidence (${n}) — locations only here; full text in tree.jsonl`,
  authRequirement: "#### Does it need authentication?",
  authPre: "PRE-AUTH",
  authPreWhy: "an unauthenticated request reaches this sink — this is the type this audit is looking for",
  authPost: "POST-AUTH",
  authPostWhy:
    "a session is required first. A real finding, but not a pre-auth one — making it pre-auth means chaining an authentication bypass in front of it (link it with requires).",
  authUnassessed: "NOT ASSESSED",
  authUnassessedWhy:
    "nothing records what it takes to reach this sink. **That is not the same as pre-auth** — \"not assessed\" and \"pre-auth\" are different claims, and the report does not count it as pre-auth.",
  rowPreAuth: "**Pre-auth reachable**",
  preAuthNote: (n, t) => `${n}/${t} are reachable without authentication.`,
  chainStateLabel: "Chain",
  chainReady: (gates) => `**CHAIN READY** — every gate is confirmed (${gates}). This one can actually be used.`,
  chainGated: (gates) => `**CHAIN NOT READY** — still waiting on ${gates}. The sink is real; the way in is not established.`,
  chainBroken: (gates) => `**CHAIN BROKEN** — ${gates} was refuted, so this route cannot work as stated. The sink is still real; the entry is not.`,
  chainStandalone: "stands alone (gates assessed, none needed)",
  chainUntracked: (n) =>
    `**PRECONDITIONS UNTRACKED** — ${n} precondition(s) are recorded and NOT ONE became a hypothesis, so nothing will ever test them. ` +
    `This finding currently reads as usable, and it may not be.`,
  chainUnassessed: "**EXPLOITATION PRECONDITIONS NOT ASSESSED** — this finding declares no dependency.",
  chainUnassessedAsk:
    "**That is not the same as needing none.** Nobody asked what must hold to reach this sink. Ask at least: is the entry reachable? does it need auth? " +
    "are protocol / redirect / hostname restricted? is the response reflected back?",
  rowUnassessed: "**Preconditions not assessed**",
  unassessedWarning: (n, t) =>
    `> **${n} of ${t} have NEVER had their exploitation preconditions assessed.** Nobody asked what must hold to reach them, ` +
    `so they are being treated as self-contained — and "no preconditions recorded" is not "no preconditions needed".`,
  rowExploitable: "**Actually usable (complete chain)**",
  exploitableWarning: (n, t) =>
    `> **${n} of ${t} have unverified exploitation preconditions.** Confirming a sink is not confirming a way to reach it. ` +
    `A \"chain not ready\" entry is a real finding you cannot use yet — do not report it as a working vulnerability.`,
  exploitableNote: "Every confirmed finding carries its chain state: standalone / chain-ready / gated / broken / not assessed.",
  derived: (n) => `#### Hypotheses derived from this (${n})`,
  derivedNote: "Each one came from following this finding's root cause deeper. **Breadth comes from enumeration; depth comes from this.**",
  noDerived: "_Never pursued. This finding stands alone — whether its root cause holds elsewhere, who reaches it, and how far it goes have not been checked._",
  pursuedTimes: (n, budget) => `pursued ${n}/${budget} round(s)`,
  auditorScope: "**The auditor's own statement of scope**",
  evidence: (n) => `**Evidence (${n} entries)**`,
  evidenceMore: (n) => `_… and ${n} more evidence entr(ies) in \`.pi-hypothesis/tree.jsonl\`._`,

  ruledOut: (n) => `## Ruled out (${n})`,
  ruledOutNone: "_Nothing was refuted. A tree that only confirms has not been testing anything — treat this as a gap in the audit, not as a clean result._",
  refutedBy: "refuted by",
  blocked: (n) => `## Blocked (${n})`,
  blockedNote: "Recorded but not testable yet. The reason is the auditor's own, and it is what the loop is waiting on.",
  blockedBecause: "blocked because",
  notExamined: (n) => `## Not examined (${n})`,
  notExaminedNone: "_Every recorded hypothesis was examined._",
  notExaminedNote: "These are recorded and unexamined, in the order the scheduler would take them. **Nothing here is a claim either way.**",
  notExaminedMore: (n) => `- _… and ${n} more (see \`.pi-hypothesis/tree.jsonl\`)_`,
  segmentsUncovered: "**Recon segments never turned into hypotheses**",
  method: "## Method",
  methodLines: [
    "- Every hypothesis is a **falsifiable assertion**, not a task. The store refuses task-shaped text.",
    "- Verification is a **falsification attempt**: each probe states what the hypothesis predicts about one mechanical fact, and one counterexample refutes it. A surviving probe means \"not refuted here\", never \"proven\".",
    "- A **verdict requires evidence**; a finding's tier above says how strong that evidence is.",
    "- The scheduler enforces anti-tunnelling limits: no more than 3 consecutive levels of descent, 2 consecutive rounds on one node, or 40% of recent picks in one category.",
    "- Confirmed findings are periodically **combined** into new hypotheses (chains, shared root causes, lateral extensions).",
    "- Every confirmed finding receives a **challenge round**: it is handed back to the model with the instruction to REFUTE it. A refuted finding is removed from this report — **removing a false positive is a result, not a failure**.",
  ],
  nonClaims: "## What this report does NOT claim",
  nonClaimLines: [
    "- **It is not a penetration test.** No request was sent to a running system unless a finding tier says REPRODUCED.",
    "- **A static finding is a strong case, not a proof.** Reachability through a parent class, a global middleware, or a framework default is not settled by reading the controller.",
    "- **Absence of a finding is not absence of a vulnerability.** See \"Not examined\" — {unexamined} recorded hypotheses were never tested, and the recon itself covers {segments} segment(s).",
    "- **Severity is the auditor's judgement**, not a CVSS score, and an unrated finding is \"not yet judged\" rather than \"low\".",
    "- **The false-positive rate is not zero.** The challenge round lowers it; it does not remove it — it is still the same model reviewing itself from an adversarial angle.",
  ],
  noneRecorded: "_None._",
  footer:
    "_Generated by pi-audit-hypothesis-tree from durable state: `.pi-hypothesis/tree.jsonl` (append-only), " +
    "`.pi-hypothesis/findings.md` (per-round log), `.pi-hypothesis/recon.md` (the recon note), " +
    "`.pi-hypothesis/OPERATOR.md` (operator input). **No summary here is model-generated — every line is derived from the recorded state.**_",
};

export const REPORT_STRINGS: Record<ReportLanguage, ReportStrings> = { zh: ZH, en: EN };

export function reportStrings(lang: ReportLanguage): ReportStrings {
  return REPORT_STRINGS[lang];
}
