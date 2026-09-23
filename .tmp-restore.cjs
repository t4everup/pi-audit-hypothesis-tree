const fs = require("fs");
const EXT = "D:/Ai/pi-audit-hypothesis-tree/extensions/hypothesis-tree/";
const read = (f) => fs.readFileSync(EXT + f, "utf-8").replace(/\r\n/g, "\n");
const write = (f, s) => fs.writeFileSync(EXT + f, s.replace(/\n/g, "\r\n"), "utf-8");
const must = (c, m) => { if (!c) throw new Error("ASSERT: " + m); };

{
  const f = "store.ts";
  let s = read(f);
  const anchor = `    ...(typeof o.command === "string" && o.command ? { command: o.command } : {}),\n    detail: o.detail,`;
  must(s.includes(anchor), "store anchor not found");
  s = s.replace(anchor, `    ...(typeof o.command === "string" && o.command ? { command: o.command } : {}),\n    // A FIELD ALLOWLIST, so a new Evidence field is invisible until it is added\n    // here. This bit the \`reproduces\` flag: it was written to the log, dropped on\n    // the way back in, and the tier it exists to control could never change — with\n    // no error anywhere, because the record that lost it still validated.\n    ...(o.reproduces === true ? { reproduces: true } : {}),\n    detail: o.detail,`);
  write(f, s);
  console.log("restored: store.ts");
}
{
  const f = "report.ts";
  let s = read(f);
  const a = `    .filter((n): n is Hypothesis => !!n);`;
  must(s.includes(a), "schedulerOrder anchor not found");
  s = s.replace(a, `    .filter((n): n is Hypothesis => !!n && (n.status === "pending" || n.status === "testing"));`);
  const b = `    lines.push(\`\${t.derived(0)} \${t.noDerived}\`);
    lines.push("");`;
  must(s.includes(b), "derived anchor not found");
  s = s.replace(b, `    lines.push(\`\${t.derived(0)}\`);
    // The explanation goes on its OWN line. Appended to the heading it rendered
    // as part of the heading text — a sentence of small print came out as a
    // section title, which is the opposite of what italics were asked for.
    lines.push(t.noDerived);
    lines.push("");`);
  write(f, s);
  console.log("restored: report.ts");
}
{
  const f = "types.ts";
  let s = read(f);
  const a = `  if (node.evidence.some(ran)) return "reproduced";`;
  must(s.includes(a), "verificationTier anchor not found");
  s = s.replace(a, `  if (node.evidence.some((e) => ran(e) && e.reproduces === true)) return "reproduced";\n  if (node.evidence.some(ran)) return "command-ran";`);
  write(f, s);
  console.log("restored: types.ts");
}
