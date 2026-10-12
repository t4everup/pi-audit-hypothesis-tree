const fs = require("fs");
const R = "D:/Ai/pi-audit-hypothesis-tree/extensions/hypothesis-tree/";
const read = (f) => fs.readFileSync(R + f, "utf-8").replace(/\r\n/g, "\n");
const write = (f, s) => fs.writeFileSync(R + f, s.replace(/\n/g, "\r\n"), "utf-8");
const must = (c, m) => { if (!c) throw new Error("ANCHOR: " + m); };
const L = (...a) => a.join("\n");

// ============================================================ reportText.ts
{
  let s = read("reportText.ts");
  const a = '  rowSurfaceDigging: string;';
  must(s.includes(a), "SecStrings digging row");
  s = s.replace(a, a + "\n  /** Items examined and left unresolved — not the same as never looked at. */\n  rowSurfaceAttempted: string;", 1);

  const a2 = '  rowSurfaceDigging: "**仍在深挖（未定论）**",';
  must(s.includes(a2), "zh digging row");
  s = s.replace(a2, a2 + '\n  rowSurfaceAttempted: "**看过但未定论**",', 1);

  const a3 = '  rowSurfaceDigging: "**Still mid-dig (unsettled)**",';
  must(s.includes(a3), "en digging row");
  s = s.replace(a3, a3 + '\n  rowSurfaceAttempted: "**Examined but unsettled**",', 1);

  // split the "not analysed" section
  const a4 = '  surfaceOpenTitle: "## 尚未分析",';
  must(s.includes(a4), "zh open title");
  s = s.replace(a4, '  surfaceOpenTitle: "## 尚未分析",\n  surfaceTouchedTitle: "## 看过但未定论",\n  surfaceTouchedNote:\n    "这些项被分配过轮次，但**既没确认有防护、也没得出结论**。它们不是「没看过」—— 是看过了、没查完。别把这一节和上一节混起来。",', 1);
  const a5 = '  surfaceOpenNote:\n    "这些项在攻击面上，但这次运行没有走到它们。**它们不是干净的，是没看过。**",';
  must(s.includes(a5), "zh open note");
  s = s.replace(a5, '  surfaceOpenNote:\n    "这些项从没被分配过轮次。**它们不是干净的，是没看过。**",', 1);

  const a6 = '  surfaceOpenTitle: "## Not analysed",';
  must(s.includes(a6), "en open title");
  s = s.replace(a6, '  surfaceOpenTitle: "## Not analysed",\n  surfaceTouchedTitle: "## Examined but unsettled",\n  surfaceTouchedNote:\n    "These items were handed rounds and reached **no conclusion** — neither a named guard nor a finding. They are not \\"never looked at\\"; they are looked at and unfinished. Do not read this section as the one above it.",', 1);
  const a7 = '  surfaceOpenNote:\n    "These items are on the attack surface and this run did not get to them. **They are not clean, they are unread.**",';
  must(s.includes(a7), "en open note");
  s = s.replace(a7, '  surfaceOpenNote:\n    "These items were NEVER handed a round. **They are not clean, they are unread.**",', 1);

  write("reportText.ts", s);
  console.log("reportText.ts: the two list titles split");
}

// ============================================================ sec.ts report
{
  let s = read("sec.ts");

  const a = '    lines.push(`| ${t.rowSurfaceDigging} | ${progress.digging} |`);';
  must(s.includes(a), "digging row");
  s = s.replace(a, a + "\n    const unresolved = snapshot.surfaces.filter((x) => x.status === \"open\" && (x.attempts ?? 0) > 0).length;\n    if (unresolved > 0) lines.push(`| ${t.rowSurfaceAttempted} | ${unresolved} |`);", 1);

  const a2 = L(
    "  const openItems = snapshot.surfaces.filter((s) => s.status === \"open\");",
    "  if (openItems.length > 0) {",
    "    lines.push(t.surfaceOpenTitle);",
    "    lines.push(\"\");",
    "    lines.push(t.surfaceOpenNote);",
    "    lines.push(\"\");",
    "    for (const s of openItems) {",
    "      lines.push(t.surfaceOpenLine(s.id, s.kind, s.title, s.location ? `${s.location.file}:${s.location.line}` : \"\"));",
    "    }",
    "    lines.push(\"\");",
    "  }",
  );
  must(s.includes(a2), "open list block");
  s = s.replace(a2, L(
    "  // SPLIT IN TWO, because the old single list was lying. Every `open` item was printed under",
    "  // 尚未分析 with \"没看过\" — including items the run HAD looked at and left unresolved, which is",
    "  // the ordinary outcome of a round that produces nothing. On a run with unproductive rounds",
    "  // that was most of the list, and the section that exists to bound the audit's honesty was",
    "  // making the audit look narrower than it was.",
    "  const openItems = snapshot.surfaces.filter((s) => s.status === \"open\" && (s.attempts ?? 0) === 0);",
    "  if (openItems.length > 0) {",
    "    lines.push(t.surfaceOpenTitle);",
    "    lines.push(\"\");",
    "    lines.push(t.surfaceOpenNote);",
    "    lines.push(\"\");",
    "    for (const s of openItems) {",
    "      lines.push(t.surfaceOpenLine(s.id, s.kind, s.title, s.location ? `${s.location.file}:${s.location.line}` : \"\"));",
    "    }",
    "    lines.push(\"\");",
    "  }",
    "  const touchedItems = snapshot.surfaces.filter((s) => s.status === \"open\" && (s.attempts ?? 0) > 0);",
    "  if (touchedItems.length > 0) {",
    "    lines.push(t.surfaceTouchedTitle);",
    "    lines.push(\"\");",
    "    lines.push(t.surfaceTouchedNote);",
    "    lines.push(\"\");",
    "    for (const s of touchedItems) {",
    "      lines.push(t.surfaceOpenLine(s.id, s.kind, s.title, s.location ? `${s.location.file}:${s.location.line}` : \"\"));",
    "    }",
    "    lines.push(\"\");",
    "  }",
  ), 1);

  write("sec.ts", s);
  console.log("sec.ts: the report splits the open list");
}

// ============================================================ loop.ts
{
  let s = read("loop.ts");
  const a = L(
    "    const wasDigging = assigned?.status === \"digging\";",
    "    if (wasDigging && assigned) {",
    "      updateSurface(projectRoot, assigned.id, { digRounds: (assigned.digRounds ?? 0) + 1 }, at);",
    "    }",
  );
  must(s.includes(a), "dig increment block");
  s = s.replace(a, L(
    "    const wasDigging = assigned?.status === \"digging\";",
    "    if (assigned) {",
    "      // EVERY analyze round counts as an attempt, whether or not it concludes anything — that",
    "      // is what lets the report tell \"never looked at\" from \"looked at and unfinished\".",
    "      // `surfaceExaminedAtStart` is a status count and stays one; the plateau reads that, and",
    "      // widening it would make the day a round is prepared look productive.",
    "      updateSurface(projectRoot, assigned.id, {",
    "        attempts: (assigned.attempts ?? 0) + 1,",
    "        ...(wasDigging ? { digRounds: (assigned.digRounds ?? 0) + 1 } : {}),",
    "      }, at);",
    "    }",
  ), 1);
  write("loop.ts", s);
  console.log("loop.ts: attempts incremented on prepare");
}
