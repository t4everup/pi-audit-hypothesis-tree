const fs = require("fs");
const B = "D:/Ai/pi-audit-hypothesis-tree/extensions/hypothesis-tree/";

function edit(file, fn) {
  const p = B + file;
  const raw = fs.readFileSync(p, "utf-8");
  const crlf = raw.includes("\r\n");
  const before = raw.split("\r\n").join("\n");
  const after = fn(before);
  if (after === before) throw new Error(`${file}: nothing replaced`);
  fs.writeFileSync(p, crlf ? after.split("\n").join("\r\n") : after);
  console.log(file, "ok");
}

// --- types.ts: the loop carries the focus ---
edit("types.ts", (s) =>
  s.replace(
    "  /** Consecutive rounds that produced no new verdict before the loop stops. */\n  plateauWindow: number;",
    "  /**\n"
    + "   * The classes this run is FOR, if the operator narrowed it.\n"
    + "\n"
    + "   * A BIAS, never a filter. Generation is told to spend the round here, and the\n"
    + "   * scheduler prefers these classes — but nothing is refused, because a pre-auth\n"
    + "   * RCE is routinely reached by chaining a finding from somewhere else, and a hard\n"
    + "   * filter would make exactly that chain unfindable.\n"
    + "   */\n"
    + "  focus?: string[];\n"
    + "  /** Consecutive rounds that produced no new verdict before the loop stops. */\n"
    + "  plateauWindow: number;",
    1,
  ),
);

// --- store.ts: normalise it ---
edit("store.ts", (s) =>
  s
    .replace(
      "    plateauWindow: num(o.plateauWindow),",
      "    ...(Array.isArray(o.focus) && o.focus.some((f) => typeof f === \"string\" && !!f)\n"
      + "      ? { focus: (o.focus as unknown[]).filter((f): f is string => typeof f === \"string\" && !!f) }\n"
      + "      : {}),\n"
      + "    plateauWindow: num(o.plateauWindow),",
      1,
    ),
);

// --- scheduler.ts: the boost ---
edit("scheduler.ts", (s) =>
  s
    .replace(
      "  gatesOfConfirmed: Set<string>;\n}",
      "  gatesOfConfirmed: Set<string>;\n"
      + "  /**\n"
      + "   * The classes this run is for, or empty.\n"
      + "\n"
      + "   * A BIAS, not a filter: a node outside the focus is still scheduled when\n"
      + "   * nothing inside it is due, because a pre-auth RCE is routinely reached by\n"
      + "   * chaining a finding from somewhere else.\n"
      + "   */\n"
      + "  focus: Set<string>;\n}",
      1,
    )
    .replace(
      "  testingBoost: 3,\n",
      "  testingBoost: 3,\n"
      + "  /**\n"
      + "   * A node in a class the operator asked for.\n"
      + "\n"
      + "   * Above testingBoost (3) and below gateBoost (14): the operator's stated scope\n"
      + "   * outranks finishing a node mid-examination, and a GATE of a confirmed finding\n"
      + "   * outranks both, because it is the one thing that turns a sink into an exploit.\n"
      + "   */\n"
      + "  focusBoost: 6,\n",
      1,
    )
    .replace(
      "  const gateBoost = context.gatesOfConfirmed.has(node.id) ? w.gateBoost : 0;",
      "  const gateBoost = context.gatesOfConfirmed.has(node.id) ? w.gateBoost : 0;\n"
      + "  // See SchedulingContext.focus: the operator's scope, as a preference.\n"
      + "  const focusBoost = context.focus.size > 0 && context.focus.has(node.category) ? w.focusBoost : 0;",
      1,
    )
    .replace(
      "  const total =\n    novelty + evidence + categoryDiversity + testingBoost + gateBoost - depthPenalty - recencyPenalty - blockedPenalty;\n\n  return { novelty, evidence, categoryDiversity, depthPenalty, recencyPenalty, blockedPenalty, testingBoost, gateBoost, total };",
      "  const total =\n"
      + "    novelty + evidence + categoryDiversity + testingBoost + gateBoost + focusBoost - depthPenalty - recencyPenalty - blockedPenalty;\n\n"
      + "  return {\n"
      + "    novelty,\n"
      + "    evidence,\n"
      + "    categoryDiversity,\n"
      + "    depthPenalty,\n"
      + "    recencyPenalty,\n"
      + "    blockedPenalty,\n"
      + "    testingBoost,\n"
      + "    gateBoost,\n"
      + "    focusBoost,\n"
      + "    total,\n"
      + "  };",
      1,
    )
    .replace(
      "  return {\n    round,\n    lastSelectedId,",
      "  // The operator's focus, if the loop carries one.\n"
      + "  const focus = new Set<string>(snapshot.loop?.focus ?? []);\n\n"
      + "  return {\n    round,\n    lastSelectedId,",
      1,
    )
    .replace("    gatesOfConfirmed,\n  };", "    gatesOfConfirmed,\n    focus,\n  };", 1),
);

// --- types.ts: ScoreBreakdown gains the field ---
edit("types.ts", (s) =>
  s.replace(
    "  /** Bonus for being the GATE of a confirmed finding — see SCORE_WEIGHTS.gateBoost. */\n  gateBoost: number;",
    "  /** Bonus for being the GATE of a confirmed finding — see SCORE_WEIGHTS.gateBoost. */\n"
    + "  gateBoost: number;\n"
    + "  /** Bonus for being in a class the operator asked for — see SCORE_WEIGHTS.focusBoost. */\n"
    + "  focusBoost: number;",
    1,
  ),
);

// --- store.ts + tests: the breakdown literal ---
edit("store.ts", (s) => s.replace("      gateBoost: num(b.gateBoost),", "      gateBoost: num(b.gateBoost),\n      focusBoost: num(b.focusBoost),", 1));
edit("../tests/scheduler.test.ts", (s) =>
  s
    .replace(
      "breakdown: { novelty: 0, evidence: 0, categoryDiversity: 0, depthPenalty: 0, recencyPenalty: 0, blockedPenalty: 0, testingBoost: 0, gateBoost: 0, total: 0 },",
      "breakdown: { novelty: 0, evidence: 0, categoryDiversity: 0, depthPenalty: 0, recencyPenalty: 0, blockedPenalty: 0, testingBoost: 0, gateBoost: 0, focusBoost: 0, total: 0 },",
      1,
    )
    .replace("    gatesOfConfirmed: new Set<string>(),", "    gatesOfConfirmed: new Set<string>(),\n    focus: new Set<string>(),", 1),
);
