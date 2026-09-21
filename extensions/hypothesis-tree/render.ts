/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/render.ts
 *
 * Text and JSON projections of the tree. Pure: takes a snapshot, returns
 * strings. No fs, no pi, so every rendering rule is unit-testable and the
 * same output can go to `ctx.ui.notify`, a widget, or a log file.
 *
 * The tree view is the human review surface, so it is designed to answer
 * three questions at a glance without reading the assertions:
 *
 *   1. WHERE is the audit spending its attention? (status glyphs)
 *   2. Is it RABBIT-HOLING? (depth is printed, and a deep chain is visible
 *      as an indented ladder)
 *   3. Is the SEARCH SPACE actually being pruned? (rejected count is shown
 *      as prominently as confirmed — a tree with 0 rejections is a tree that
 *      is not falsifying anything)
 */

import type { Hypothesis, HypothesisStatus, TreeSnapshot } from "./types.js";
import { summarize } from "./tree.js";
import { SCHEDULER_LIMITS, buildContext } from "./scheduler.js";

/** One-character status glyph. ASCII only: this string ends up in terminals,
 * notifications, and log files whose encodings are not under our control. */
export function statusGlyph(status: HypothesisStatus): string {
  switch (status) {
    case "pending":
      return ".";
    case "testing":
      return ">";
    case "confirmed":
      return "!";
    case "rejected":
      return "x";
    case "blocked":
      return "#";
  }
}

/** Pad a status so columns line up in a monospaced terminal. */
function padStatus(status: HypothesisStatus): string {
  return status.padEnd(9);
}

/** Truncate on a word boundary where possible, so a cut assertion is still
 * readable. */
export function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max - 1);
  const space = cut.lastIndexOf(" ");
  return (space > max * 0.6 ? cut.slice(0, space) : cut) + "…";
}

/**
 * One node line: `H-0003 [confirmed] auth-bypass d2 e2  assertion`.
 *
 * `e<n>` is the evidence count. It is on the line because a confirmed node
 * with one `reasoning` entry is a much weaker finding than one with three
 * file slices, and the tree view should not hide that.
 */
export function renderNodeLine(node: Hypothesis, opts: { width?: number; indent?: string } = {}): string {
  const indent = opts.indent ?? "";
  const width = opts.width ?? 120;
  const head = `${indent}${statusGlyph(node.status)} ${node.id} [${padStatus(node.status)}] ${node.category} d${node.depth} e${node.evidence.length}`;
  const room = Math.max(20, width - head.length - 2);
  const reason = node.status === "blocked" && node.statusReason ? `  (blocked: ${clip(node.statusReason, 60)})` : "";
  return `${head}  ${clip(node.description, room)}${reason}`;
}

/**
 * Render the whole tree, depth-first, insertion order within a level.
 *
 * Cycles and orphans cannot be rendered as a tree, so they are collected and
 * reported at the end instead of being silently dropped or causing infinite
 * recursion — a corrupted log must produce a readable warning, not a hang.
 */
export function renderTree(
  snapshot: TreeSnapshot,
  opts: { width?: number; maxNodes?: number; showEvidence?: boolean } = {},
): string[] {
  const lines: string[] = [];
  const maxNodes = opts.maxNodes ?? 200;
  const width = opts.width ?? 120;

  if (!snapshot.rootId) {
    return ["(no hypothesis tree — create one with a root assertion)"];
  }

  const visited = new Set<string>();
  let emitted = 0;
  let truncated = 0;

  const walk = (id: string, indent: string, last: boolean, isRoot: boolean): void => {
    const node = snapshot.byId.get(id);
    if (!node || visited.has(id)) return;
    visited.add(id);
    if (emitted >= maxNodes) {
      truncated++;
      return;
    }
    emitted++;

    const branch = isRoot ? "" : `${last ? "`- " : "|- "}`;
    lines.push(renderNodeLine(node, { width, indent: indent + branch }));
    if (opts.showEvidence && node.evidence.length > 0) {
      const childIndent = indent + (isRoot ? "" : `${last ? "   " : "|  "}`);
      for (const e of node.evidence) {
        const loc = e.location ? ` ${e.location.file}:${e.location.line}` : "";
        lines.push(`${childIndent}    - ${e.kind}${loc}: ${clip(e.detail, Math.max(20, width - childIndent.length - 12))}`);
      }
    }

    const kids = snapshot.nodes.filter((n) => n.parentId === id);
    const childIndent = indent + (isRoot ? "" : `${last ? "   " : "|  "}`);
    kids.forEach((child, index) => walk(child.id, childIndent, index === kids.length - 1, false));
  };

  walk(snapshot.rootId, "", true, true);

  const orphans = snapshot.nodes.filter((n) => !visited.has(n.id));
  if (orphans.length > 0) {
    lines.push("");
    lines.push(`WARNING: ${orphans.length} node(s) are not reachable from the root (orphaned parent or a cycle):`);
    for (const o of orphans.slice(0, 20)) {
      lines.push(renderNodeLine(o, { width, indent: "  " }));
    }
    if (orphans.length > 20) lines.push(`  … and ${orphans.length - 20} more`);
  }
  if (truncated > 0) {
    lines.push("");
    lines.push(`… ${truncated} more node(s) not shown (maxNodes=${maxNodes}); use /hypothesis json for the full tree`);
  }
  return lines;
}

/**
 * The status block. Deliberately reports REJECTED as loudly as CONFIRMED:
 * a hypothesis tree whose rejection count is zero is not falsifying anything,
 * and that is the failure mode this extension exists to prevent.
 */
export function renderSummary(snapshot: TreeSnapshot): string[] {
  if (!snapshot.rootId) return ["No hypothesis tree in this project. Start one with /hypothesis new \"<falsifiable root assertion>\"."];
  const s = summarize(snapshot);
  const total = Math.max(1, s.nodes);
  const pct = (n: number): string => `${Math.round((n / total) * 100)}%`;
  const lines: string[] = [
    `Hypothesis tree ${s.treeId} — ${s.nodes} node(s), depth ${s.maxDepth}, round ${s.rounds}`,
    `Objective: ${clip(s.objective, 160)}`,
    "",
    `  pending   ${String(s.byStatus.pending).padStart(4)}  ${pct(s.byStatus.pending)}`,
    `  testing   ${String(s.byStatus.testing).padStart(4)}  ${pct(s.byStatus.testing)}`,
    `  confirmed ${String(s.byStatus.confirmed).padStart(4)}  ${pct(s.byStatus.confirmed)}   (findings)`,
    `  rejected  ${String(s.byStatus.rejected).padStart(4)}  ${pct(s.byStatus.rejected)}   (pruned branches)`,
    `  blocked   ${String(s.byStatus.blocked).padStart(4)}  ${pct(s.byStatus.blocked)}`,
  ];

  const categories = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]);
  if (categories.length > 0) {
    lines.push("");
    lines.push("  categories:");
    for (const [category, count] of categories.slice(0, 12)) {
      const share = Math.round((count / total) * 100);
      lines.push(`    ${category.padEnd(22)} ${String(count).padStart(4)}  ${share}%`);
    }
  }

  if (s.tornLines > 0) {
    lines.push("");
    lines.push(`  NOTE: ${s.tornLines} torn line(s) in the log were skipped (crash artifact). /hypothesis repair to clean the tail.`);
  }
  if (snapshot.compactions > 0) {
    lines.push(`  log compacted ${snapshot.compactions} time(s)`);
  }

  // Scheduler state: the run lengths are what tell a human whether the audit is
  // currently tunnelling, so they belong in the status block and not only in
  // the decision record.
  const context = buildContext(snapshot, snapshot.rounds + 1);
  lines.push("");
  lines.push(
    `  scheduler: same-node run ${context.sameNodeRun}/${SCHEDULER_LIMITS.MAX_SAME_NODE_ROUNDS}, ` +
      `descent run ${context.descentLevels}/${SCHEDULER_LIMITS.MAX_CONSECUTIVE_DEPTH} level(s), ` +
      `last selected ${context.lastSelectedId ?? "(none)"}`,
  );
  const relaxed = snapshot.selections.filter((r) => r.relaxations.length > 0).length;
  if (relaxed > 0) {
    lines.push(`  ${relaxed} of the last ${snapshot.selections.length} round(s) had to relax a limit — the tree is skewed`);
  }
  if (s.byStatus.rejected === 0 && s.nodes > 3) {
    lines.push("");
    lines.push("  NOTE: nothing has been rejected yet. A hypothesis tree that only confirms is not testing anything — consider assertions phrased so they CAN fail.");
  }
  return lines;
}

/** Machine-readable projection: the folded snapshot without the Map. */
export function toJson(snapshot: TreeSnapshot): string {
  return JSON.stringify(
    {
      treeId: snapshot.treeId,
      objective: snapshot.objective,
      rootId: snapshot.rootId,
      rounds: snapshot.rounds,
      maxNodeSeq: snapshot.maxNodeSeq,
      compactions: snapshot.compactions,
      tornLines: snapshot.tornLines,
      updatedAt: snapshot.updatedAt,
      nodes: snapshot.nodes,
    },
    null,
    2,
  );
}
