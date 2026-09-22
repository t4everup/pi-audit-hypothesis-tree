const fs = require("fs");
const p = "D:/Ai/pi-audit-hypothesis-tree/tests/combination.test.ts";
let s = fs.readFileSync(p, "utf-8");
const before = s;
s = s.replace(
  "  assert.match(plan.reason, /1 new finding\(s\) since the pass at round 0/);",
  "  assert.match(plan.reason, /2 new finding\(s\) since the pass at round 0 \(threshold 2\)/);",
);
if (s === before) throw new Error("nothing replaced");
fs.writeFileSync(p, s);
console.log("ok");
