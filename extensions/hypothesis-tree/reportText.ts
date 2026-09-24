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

import type { VerificationTier } from "./types.js";

export const REPORT_LANGUAGES: ReportLanguage[] = ["zh", "en"];

export function isReportLanguage(value: unknown): value is ReportLanguage {
  return value === "zh" || value === "en";
}

/** The label for a severity, so a Chinese report does not say "HIGH". */
/**
 * A fence long enough to hold `parts` verbatim.
 *
 * Markdown closes a fence only with a run of backticks at least as long as the
 * opening one. The strings this report embeds are transcripts, and a transcript
 * frequently contains its OWN ``` fence — a model that ran a command and pasted
 * the output, or one that quoted a code block. Embedding that inside a ``` fence
 * closes the outer fence early.
 *
 * The damage is invisible to a parity check: the outer CLOSING fence then opens a
 * new fence, so the document keeps an EVEN number of fence lines while every
 * section after the bad one is swallowed into a code block. Measured on a real
 * audit: 9 of 228 evidence entries carried a fence, and the first of them
 * corrupted all 17 findings below it.
 *
 * So the fence is DERIVED from the content instead of assumed to be three.
 */
export function fenceFor(...parts: string[]): string {
  let longest = 0;
  for (const p of parts) for (const m of p.match(/`+/g) ?? []) longest = Math.max(longest, m.length);
  return "`".repeat(Math.max(3, longest + 1));
}
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
  rowConfirmedAtTarget: (floor: string) => string;
  rowConfirmedBelowTarget: (floor: string) => string;
  confirmedAtTargetTitle: (floor: string, n: number) => string;
  confirmedBelowTitle: (floor: string, n: number) => string;
  belowTargetNote: (n: number, floor: string) => string;
  noneAtTarget: (floor: string) => string;
  refutationLabel: string;
  noRefutation: string;
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
  tierCommandRan: (n: number) => string;
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
  tierName: (tier: VerificationTier) => string;
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
  pocManual: string;
  pocExpected: string;
  noPoc: string;
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
  contradiction: string;
  coverageTitle: string;
  rowCitedFiles: string;
  rowGapDirs: string;
  coverageNotMeasured: (why: string) => string;
  coverageGapNote: string;
  coverageNoGap: string;
  coverageGapLine: (dir: string, files: number) => string;
  probesOff: (n: number, t: number) => string;
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
  rowConfirmedAtTarget: (floor) => `**已确认（达标 ≥ ${floor}）**`,
  rowConfirmedBelowTarget: (floor) => `已确认（低于 ${floor} 或未评级）`,
  confirmedAtTargetTitle: (floor, n) => `## 已确认发现（达标：≥ ${floor}，${n} 条）`,
  confirmedBelowTitle: (floor, n) => `## 已确认发现（未达标：低于 ${floor} 或未评级，${n} 条）`,
  belowTargetNote: (n, floor) =>
    `> 这 ${n} 条是**真实但低于目标等级**的发现。它们仍在报告里（它们是真的），但不和达标的混在一起——`
    + `对「找认证前 ${floor} 漏洞」这个目标来说，它们是噪音。`,
  noneAtTarget: (floor) => `**没有一条达到目标等级（≥ ${floor}）。**下面的条目是真实的，但目标还没达成。`,
  refutationLabel: "**证伪尝试（书面）：**",
  noRefutation:
    "**证伪尝试：无** —— 这条确认背后既没有探针运行，也没有书面推翻尝试。它只是审计员在附和自己。",
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
  tierReproduced: (n) => `${n} 条已复现（命令跑过，且作者声明该输出**就是**这条断言的证明）`,
  tierCommandRan: (n) =>
    `${n} 条跑过命令，但**没有人声明它证明了这条断言**——命令是真的、可重跑，缺的是它与本断言的关联。` +
    `\`grep\`/\`ls\`/\`sed\` 这类定位命令落在这里；一条真复现如果忘了标记也落在这里`,
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
      ? "已复现（命令跑过，且作者声明该输出就是本断言的证明）"
      : tier === "command-ran"
        ? "跑过命令（但未声明它证明了本断言）"
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
  pocManual: "手工验证",
  pocExpected: "预期",
  noPoc:
    "未记录手工验证步骤 —— 这条发现现在只能靠读代码相信。要能自己验证，需要一条可复制的请求和「看什么才算成功」。",
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
  contradiction: "**可能的矛盾（是问题，不是判定）：**",
  coverageTitle: "## 覆盖",
  rowCitedFiles: "**被假设引用过的文件**",
  rowGapDirs: "**ZERO 假设的目录**",
  coverageNotMeasured: (why) => `_无法度量 —— ${why}。**没度量不等于全覆盖。**_`,
  coverageGapNote:
    "> **一个没有假设的目录不是「干净」，是「没读过」。**这是两件不同的事。本次审计的广度上限，就是侦察笔记提到的范围——下面这些是它没提到的部分。",
  coverageNoGap: "每个够大的目录都至少有一条假设引用过它。这不等于查干净了，只等于没有整块空白。",
  coverageGapLine: (dir, files) => "- `" + dir + "` — " + files + " 个文件，零假设",
  probesOff: (reproduced, total) =>
    "- **`allowCommandProbes` 是关的**，所以本次的「已复现」档来自**作者自己写的 `reproduces: true` 声明**，" +
    `而不是工具实际跑过的探针。${reproduced}/${total} 条确认发现到达了这一档；` +
    "上面的等级分布把「到达了」和「跑了命令但没人声明它证明了本断言」分开列出。" +
    "打开该设置（`/hypothesis config allowCommandProbes=true`）可以让工具自己去跑探针。",
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
  rowConfirmedAtTarget: (floor) => `**Confirmed (at target: >= ${floor})**`,
  rowConfirmedBelowTarget: (floor) => `Confirmed (below ${floor}, or unrated)`,
  confirmedAtTargetTitle: (floor, n) => `## Confirmed findings (at target: >= ${floor}, ${n})`,
  confirmedBelowTitle: (floor, n) => `## Confirmed findings (below ${floor}, or unrated: ${n})`,
  belowTargetNote: (n, floor) =>
    `> These ${n} are **real findings below the target severity**. They stay in the report — they are`
    + ` real — but not mixed in with the ones that meet it: for a goal of \"find a pre-auth ${floor}\"`
    + ` vulnerability, they are noise.`,
  noneAtTarget: (floor) => `**Nothing reached the target severity (>= ${floor}).** The entries below are real; the target is not met.`,
  refutationLabel: "**Refutation attempt (written):**",
  noRefutation:
    "**Refutation attempt: NONE** — neither a probe run nor a written attempt stands behind this confirmation. It is the auditor agreeing with itself.",
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
  tierReproduced: (n) =>
    `${n} reproduced (a command ran AND the author declared its output IS the proof of this claim)`,
  tierCommandRan: (n) =>
    `${n} ran a command, but **nobody declared it demonstrates this claim** — the command is real and re-runnable, ` +
    `what is missing is its link to the assertion. \`grep\`/\`ls\`/\`sed\` land here; so does a real reproduction ` +
    `whose author forgot to mark it`,
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
      ? "REPRODUCED (a command ran and its output IS the proof of this claim)"
      : tier === "command-ran"
        ? "COMMAND RAN (a command ran, but nobody declared it demonstrates this claim)"
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
  pocManual: "reproduce by hand",
  pocExpected: "expect",
  noPoc:
    "No manual reproduction step recorded — this finding can only be believed by reading code. To check it yourself you need a pasteable request and a description of what success looks like.",
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
  contradiction: "**Possible contradiction — a question, not a verdict:**",
  coverageTitle: "## Coverage",
  rowCitedFiles: "**Files cited by a hypothesis**",
  rowGapDirs: "**Directories with ZERO hypotheses**",
  coverageNotMeasured: (why) => `_Not measured — ${why}. **Not measured is not fully covered.**_`,
  coverageGapNote:
    "> **A directory with no hypothesis is not \"clean\", it is UNREAD.** Those are different claims. The audit's breadth is bounded by what the recon note mentioned, and these are the parts it did not.",
  coverageNoGap: "Every directory of any size is cited by at least one hypothesis. That is not the same as having been cleared — it only means there is no whole block left blank.",
  coverageGapLine: (dir, files) => "- `" + dir + "` — " + files + " file(s), zero hypotheses",
  probesOff: (reproduced, total) =>
    "- **`allowCommandProbes` is OFF**, so this run's REPRODUCED tier comes from the author's own " +
    "`reproduces: true` declaration rather than from a probe the tool executed. " +
    `${reproduced} of ${total} confirmed findings reached it; the tier breakdown above separates those from the ` +
    "findings where a command ran but nobody declared it demonstrates the claim. Turn it on " +
    "(`/hypothesis config allowCommandProbes=true`) to have the tool run the probes itself.",
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

// -----------------------------------------------------------------
// `/loopSEC` — the triage report's own words
// -----------------------------------------------------------------
//
// A second table rather than a second file, because the rule this file exists to
// enforce is "one object per language so a new string cannot be added without both
// being updated". Splitting the sec strings out would leave that rule in two places.
//
// The CAVEAT is the load-bearing part. Everywhere else in this extension the
// non-claims go at the foot of the report; here they go FIRST, because the reader is
// about to scroll findings GROUPED BY SEVERITY and severity is exactly the field
// this mode does not check.

export interface SecStrings {
  title: string;
  generatedFrom: string;
  objective: string;
  generatedAt: string;
  run: string;
  duration: string;
  stoppedBecause: string;
  /** `yes`/`no` for the summary's boolean rows, in the reader's language. */
  yes: string;
  no: string;
  stillRunning: string;

  // The caveat, printed before anything else.
  caveatTitle: string;
  caveatIntro: string;
  caveatColMissing: string;
  caveatColMeans: string;
  caveatNoTier: string;
  caveatNoTierWhy: string;
  caveatNoFalsification: string;
  caveatNoFalsificationWhy: string;
  caveatNoChallenge: string;
  caveatNoChallengeWhy: string;
  caveatNoSeverity: string;
  caveatNoSeverityWhy: string;
  caveatNoGate: string;
  caveatNoGateWhy: string;
  caveatEnforced: string;
  caveatRerun: string;

  summaryTitle: string;
  rowFindings: string;
  rowUnrated: string;
  rowPreAuth: string;
  rowPostAuth: string;
  rowUnassessed: string;
  rowNote: string;
  noFindings: string;

  coverageTitle: string;
  rowCited: string;
  rowGapDirs: string;
  coverageNotMeasured: (why: string) => string;
  coverageNoGap: string;
  coverageGapNote: string;
  coverageGapLine: (dir: string, files: number) => string;

  findingsTitle: (n: number) => string;
  noneRecorded: string;

  notReadTitle: string;
  notReadNote: string;

  // One finding.
  location: string;
  authRequirement: string;
  authPre: string;
  authPost: string;
  authUnassessed: string;
  recordedAt: (round: number, at: string) => string;
  why: string;
  evidenceLabel: string;
  pocLabel: string;
  notVerified: string;

  footer: string;
}

const SEC_ZH: SecStrings = {
  title: "# /loopSEC — 发现",
  generatedFrom: "_由 `/loopSEC` 运行的持久化状态生成。这里没有任何摘要由模型生成。_",
  objective: "目标",
  generatedAt: "生成于",
  run: "运行",
  duration: "时长",
  stoppedBecause: "停止原因",
  yes: "是",
  no: "**没有**",
  stillRunning: "（仍在运行）",

  caveatTitle: "## 先读这一段 —— 这份报告**不是**什么",
  caveatIntro:
    "**这是一份三角测量清单，不是已验证的审计。** `/loopSEC` 不跑假设树，因此移除了所有让另一份报告的发现可被核查的机制：",
  caveatColMissing: "没有的东西",
  caveatColMeans: "在这里意味着什么",
  caveatNoTier: "**没有验证等级**",
  caveatNoTierWhy: "分不出「跑了命令确认的」和「从源码读出来的」。",
  caveatNoFalsification: "**没有证伪尝试**",
  caveatNoFalsificationWhy: "没有任何一条被尝试推翻过。误报率是**未知**，不是低。",
  caveatNoChallenge: "**没有对抗复核**",
  caveatNoChallengeWhy: "每一条都是审计员在附和自己。",
  caveatNoSeverity: "**没有等级核查**",
  caveatNoSeverityWhy: "等级是审计员一次性的判断，未经复核。",
  caveatNoGate: "**没有断言门禁**",
  caveatNoGateWhy: "一条发现可能是对某个区域的模糊描述，而不是关于行为的断言。",
  caveatEnforced:
    "**强制执行的是：每条发现都带物证。** `file:line` 或一段物证摘录是必需的，所以下面每一行都可以被人工打开核查。这是本模式唯一的保证，也是那条规则存在的原因。",
  caveatRerun:
    "打算上报的发现，用 `/loop` 重跑同一个目标 —— 那里它才会拿到验证等级、一次证伪尝试和一次对抗复核。",

  summaryTitle: "## 概览",
  rowFindings: "记录的发现",
  rowUnrated: "**未评级的**",
  rowPreAuth: "无需认证可达",
  rowPostAuth: "标注为认证后",
  rowUnassessed: "**认证要求未评估**",
  rowNote: "已记录侦察笔记",
  noFindings:
    "**没有记录任何发现。** 这是合法结果——一轮为了看起来有产出而编造发现，比空手而归更糟——但它**不是**项目干净的证据。见下面的「未读」。",

  coverageTitle: "## 覆盖",
  rowCited: "**被某条发现引用过的文件**",
  rowGapDirs: "**ZERO 发现的目录**",
  coverageNotMeasured: (why) => `_未测量 —— ${why}。**未测量不等于已覆盖。**_`,
  coverageNoGap:
    "每个够大的目录都至少有一条发现引用过它。这不等于查干净了，只等于没有整块空白。",
  coverageGapNote:
    "> **一个目录里没有发现，不是「干净」，是「未读」。** 这些是侦察笔记没有覆盖到的部分，它们限制了这次运行到底看了项目的多少。",
  coverageGapLine: (dir, files) => `- \`${dir}\` — ${files} 个文件，没有记录到任何东西`,

  findingsTitle: (n) => `## 发现（${n}）`,
  noneRecorded: "_没有记录。_",

  notReadTitle: "## 未读",
  notReadNote: "这些子树从未被任何发现引用过。它们不是干净的，是没人看过。",

  location: "**位置：**",
  authRequirement: "**是否需要身份认证：**",
  authPre: "认证前可达",
  authPost: "认证后",
  authUnassessed: "未评估（这不等于认证前）",
  recordedAt: (round, at) => `**记录于：** 第 ${round} 轮 · ${at}`,
  why: "**为什么：**",
  evidenceLabel: "**物证：**",
  pocLabel: "**PoC：**",
  notVerified:
    "> **未经验证。** 这条没有验证等级、没有被尝试证伪、没有对抗复核。它是审计员的判断加一份可查的物证。",

  footer:
    "_由 pi-audit-hypothesis-tree 从 `.pi-hypothesis/` 生成 —— 仅追加的日志、发现台账和侦察笔记。重跑 `/loopSEC report` 可从状态重新生成。_",
};

const SEC_EN: SecStrings = {
  title: "# /loopSEC — findings",
  generatedFrom: "_Generated from the recorded state of a `/loopSEC` run. Nothing here is summarised by a model._",
  objective: "Objective",
  generatedAt: "Generated",
  run: "Run",
  duration: "Duration",
  stoppedBecause: "Stopped because",
  yes: "yes",
  no: "**no**",
  stillRunning: "(still running)",

  caveatTitle: "## READ THIS FIRST — what this report is not",
  caveatIntro:
    "**This is a triage list, not a verified audit.** `/loopSEC` runs without the hypothesis tree, and that removes every mechanism that made the other report's findings checkable:",
  caveatColMissing: "Not present",
  caveatColMeans: "What that means here",
  caveatNoTier: "**No verification tier**",
  caveatNoTierWhy: "Nothing distinguishes a finding confirmed by running a command from one read out of the source.",
  caveatNoFalsification: "**No falsification attempt**",
  caveatNoFalsificationWhy: "Nobody tried to prove any of these wrong. The false-positive rate is UNKNOWN, not low.",
  caveatNoChallenge: "**No challenge round**",
  caveatNoChallengeWhy: "Each finding is the auditor agreeing with itself.",
  caveatNoSeverity: "**No severity check**",
  caveatNoSeverityWhy: "Severity is the auditor's own judgement, made once, unreviewed.",
  caveatNoGate: "**No assertion gate**",
  caveatNoGateWhy: "A finding may be a vague statement of an area rather than a claim about behaviour.",
  caveatEnforced:
    "**What IS enforced: every finding carries an artifact.** A `file:line` or an evidence excerpt is required, so every line below can be opened and checked by hand. That is the only guarantee this mode makes, and it is why the requirement exists.",
  caveatRerun:
    "For findings you intend to act on, re-run the same objective under `/loop` — there the finding gets a tier, an attempt to refute it, and a challenge round.",

  summaryTitle: "## Summary",
  rowFindings: "Findings recorded",
  rowUnrated: "**no severity recorded**",
  rowPreAuth: "Reachable WITHOUT authentication",
  rowPostAuth: "Marked post-auth",
  rowUnassessed: "**Authentication NOT assessed**",
  rowNote: "Recon note recorded",
  noFindings:
    "**No findings were recorded.** That is a legitimate outcome — a run that invents findings to look productive is worse than one that comes back empty — but it is not evidence that the project is clean. See the unread list below.",

  coverageTitle: "## Coverage",
  rowCited: "**Files cited by a finding**",
  rowGapDirs: "**Directories with ZERO findings**",
  coverageNotMeasured: (why) => `_Not measured — ${why}. **Not measured is not fully covered.**_`,
  coverageNoGap:
    "Every directory of any size is cited by at least one finding. That is not the same as having been cleared — it only means there is no whole block left blank.",
  coverageGapNote:
    "> **A directory with no finding is not \"clean\", it is UNREAD.** These are the parts the recon note did not reach, and they bound how much of the project this run actually saw.",
  coverageGapLine: (dir, files) => `- \`${dir}\` — ${files} file(s), nothing recorded from it`,

  findingsTitle: (n) => `## Findings (${n})`,
  noneRecorded: "_None recorded._",

  notReadTitle: "## Not read",
  notReadNote: "These subtrees were never cited by a finding. They are not clean; nobody looked.",

  location: "**Location:**",
  authRequirement: "**Authentication required:**",
  authPre: "reachable WITHOUT authentication",
  authPost: "needs authentication",
  authUnassessed: "NOT ASSESSED (which is not the same as pre-auth)",
  recordedAt: (round, at) => `**Recorded:** round ${round} · ${at}`,
  why: "**Why:**",
  evidenceLabel: "**Evidence:**",
  pocLabel: "**PoC:**",
  notVerified:
    "> **NOT VERIFIED.** No tier, no attempt to refute it, no challenge round. It is the auditor's judgement plus one artifact you can check.",

  footer:
    "_Written by pi-audit-hypothesis-tree from `.pi-hypothesis/` — the append-only log, the findings journal and the recon note. Re-run `/loopSEC report` to regenerate it from state._",
};

export const SEC_STRINGS: Record<ReportLanguage, SecStrings> = { zh: SEC_ZH, en: SEC_EN };

export function secStrings(lang: ReportLanguage): SecStrings {
  return SEC_STRINGS[lang];
}

/**
 * The coverage headline, in the reader's language.
 *
 * Lives here rather than in coverage.ts for the reason this file exists — and it has
 * to take PRIMITIVES rather than a `CoverageReport`, because coverage.ts imports this
 * module and the reverse would be a cycle.
 *
 * It is here at all because the line appears INSIDE the report: a Chinese report that
 * says `59 of 898 file(s) cited (7%)` has an English sentence in the middle of it,
 * which reads as a bug.
 */
export function coverageHeadlineText(
  lang: ReportLanguage,
  cited: number | null,
  total: number | null,
  untouched: number | null,
  truncated: boolean,
  reason: string,
): string {
  if (lang === "en") {
    if (total === null) return `not measured — ${reason}`;
    const pct = total === 0 ? 0 : Math.round((cited! / total) * 100);
    return (
      `${cited} of ${total} file(s) cited (${pct}%)` +
      ((untouched ?? 0) > 0 ? ` — ${untouched} in untouched subtrees` : "") +
      (truncated ? " — a lower bound, the walk hit its budget" : "")
    );
  }
  if (total === null) return `未测量 —— ${reason}`;
  const pct = total === 0 ? 0 : Math.round((cited! / total) * 100);
  return (
    `${cited} / ${total} 个文件被引用过（${pct}%）` +
    ((untouched ?? 0) > 0 ? ` —— 其中 ${untouched} 个位于完全未被触碰的子树中` : "") +
    (truncated ? " —— 这是下界，遍历碰到了预算上限" : "")
  );
}

export const REPORT_STRINGS: Record<ReportLanguage, ReportStrings> = { zh: ZH, en: EN };

export function reportStrings(lang: ReportLanguage): ReportStrings {
  return REPORT_STRINGS[lang];
}
