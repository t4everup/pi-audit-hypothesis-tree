// Where the per-class exploitation ladder must plug in.
const fs = require("fs");
const P = "D:/Ai/pi-audit-hypothesis-tree/extensions/hypothesis-tree/";
const read = (f) => fs.readFileSync(P + f, "utf-8");

const out = [];
const t = read("types.ts");

// 1. The closed category set the ladder has to be keyed by.
const cat = t.match(/export const HYPOTHESIS_CATEGORIES[\s\S]{0,700}?\] as const;/);
out.push("=== HYPOTHESIS_CATEGORIES ===");
out.push(cat ? cat[0] : "NOT FOUND");

// 2. The pursue brief — the natural home for "which axes did you check".
const loop = read("loop.ts");
const pb = loop.indexOf("export function renderPursueBrief");
out.push("\n=== renderPursueBrief: the question list ===");
const pbBody = loop.slice(pb, loop.indexOf("\nexport function", pb + 10));
pbBody.split("\n").forEach((l) => {
  if (/lines\.push\(/.test(l) && /问|question|HOW FAR|WHAT ELSE|WHO CALLS|combine|3\.|4\./.test(l)) {
    out.push("  " + l.trim().slice(0, 150));
  }
});

// 3. The confirmation nudge in hypothesis_record.
const tools = read("tools.ts");
out.push("\n=== the confirmation nudge ===");
const nudge = tools.indexOf("UNTRACKED PRECONDITIONS");
out.push(tools.slice(nudge - 900, nudge + 200).split("\n").filter((l) => /untracked|chainTail|const |lines\.push/.test(l)).map((l) => "  " + l.trim().slice(0, 130)).join("\n"));

// 4. Is there any existing per-category knowledge anywhere?
out.push("\n=== existing per-category knowledge ===");
for (const f of fs.readdirSync(P).filter((x) => x.endsWith(".ts"))) {
  const src = read(f);
  if (/CATEGORY_[A-Z]|LADDER|AXES|PLAYBOOK/.test(src)) out.push("  " + f + ": yes");
}
out.push("  (empty above = none)");

fs.writeFileSync("D:/Ai/pi-audit-hypothesis-tree/.tmp-ladder.txt", out.join("\n"), "utf-8");
console.log(out.join("\n"));
