// Where does an "auto-pause after N more rounds" budget plug in?
const fs = require("fs");
const P = "D:/Ai/pi-audit-hypothesis-tree/extensions/hypothesis-tree/";
const read = (f) => fs.readFileSync(P + f, "utf-8");
const out = [];

const loop = read("loop.ts");

out.push("=== tickLoop: the check order ===");
const t = loop.slice(loop.indexOf("export function tickLoop"), loop.indexOf("export function tickLoop") + 3200);
t.split("\n").forEach((l, i) => {
  if (/^\s*\/\/ \d\.|^  if \(|return \{ action: "(complete|stopped|paused|idle)"|let current = loop/.test(l)) {
    out.push(`  ${l.trim().slice(0, 110)}`);
  }
});

out.push("\n=== pauseLoop / resumeLoop signatures ===");
for (const m of loop.matchAll(/export function (pauseLoop|resumeLoop|stopLoop)\(([\s\S]{0,220}?)\): LoopControlResult/g)) {
  out.push(`  ${m[1]}(${m[2].replace(/\s+/g, " ").slice(0, 150)})`);
}

out.push("\n=== index.ts: the pause / resume verb handlers ===");
const idx = read("index.ts");
const pi = idx.indexOf('case "pause":');
out.push(idx.slice(pi, pi + 1400));

out.push("\n=== renderLoopStatus: the round line ===");
const rs = loop.indexOf("export function renderLoopStatus");
out.push(loop.slice(rs, rs + 900));

fs.writeFileSync("D:/Ai/pi-audit-hypothesis-tree/.tmp-p.txt", out.join("\n"), "utf-8");
console.log(out.join("\n"));
