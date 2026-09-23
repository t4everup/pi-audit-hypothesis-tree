const fs = require("fs");
const EXT = "D:/Ai/pi-audit-hypothesis-tree/extensions/hypothesis-tree/";
const read = (f) => fs.readFileSync(EXT + f, "utf-8").replace(/\r\n/g, "\n");
const write = (f, s) => fs.writeFileSync(EXT + f, s.replace(/\n/g, "\r\n"), "utf-8");
const must = (c, m) => { if (!c) throw new Error("ASSERT: " + m); };

// --- revert 1: the store allowlist drops the new field again -----------------
{
  const f = "store.ts";
  let s = read(f);
  const line = "    ...(o.reproduces === true ? { reproduces: true } : {}),\n";
  must(s.includes(line), "store line not found");
  s = s.replace(line, "");
  write(f, s);
  console.log("reverted: store.ts drops `reproduces`");
}
// --- revert 2: blocked counted as unexamined again --------------------------
{
  const f = "report.ts";
  let s = read(f);
  const block = `    .filter((n): n is Hypothesis => !!n && (n.status === "pending" || n.status === "testing"));`;
  must(s.includes(block), "schedulerOrder filter not found");
  s = s.replace(block, `    .filter((n): n is Hypothesis => !!n);`);
  write(f, s);
  console.log("reverted: blocked counted as unexamined");
}
// --- revert 3: the derived-hypotheses explanation back onto the heading -----
{
  const f = "report.ts";
  let s = read(f);
  const now = `    lines.push(\`\${t.derived(0)}\`);
    // The explanation goes on its OWN line. Appended to the heading it rendered
    // as part of the heading text — a sentence of small print came out as a
    // section title, which is the opposite of what italics were asked for.
    lines.push(t.noDerived);
    lines.push("");`;
  must(s.includes(now), "derived block not found");
  s = s.replace(now, `    lines.push(\`\${t.derived(0)} \${t.noDerived}\`);
    lines.push("");`);
  write(f, s);
  console.log("reverted: derived explanation glued to the heading");
}
// --- revert 4: any command-output counts as reproduced ----------------------
{
  const f = "types.ts";
  let s = read(f);
  const now = `  if (node.evidence.some((e) => ran(e) && e.reproduces === true)) return "reproduced";
  if (node.evidence.some(ran)) return "command-ran";`;
  must(s.includes(now), "verificationTier not found");
  s = s.replace(now, `  if (node.evidence.some(ran)) return "reproduced";`);
  write(f, s);
  console.log("reverted: any command counts as reproduced");
}
