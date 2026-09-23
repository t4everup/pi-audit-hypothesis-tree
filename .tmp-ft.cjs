const fs = require("fs");
const R = "D:/Ai/pi-audit-hypothesis-tree/tests/";

function edit(p, pairs) {
  const raw = fs.readFileSync(p, "utf-8");
  const crlf = raw.includes("\r\n");
  let s = raw.split("\r\n").join("\n");
  const before = s;
  for (const [bad, good] of pairs) {
    if (!s.includes(bad)) throw new Error(`${p}: not found: ${bad}`);
    s = s.split(bad).join(good);
  }
  if (s === before) throw new Error(`${p}: nothing replaced`);
  fs.writeFileSync(p, crlf ? s.split("\n").join("\r\n") : s);
  console.log(p.split("/").pop(), "ok");
}

edit(R + "report.test.ts", [
  [
    'assert.match(text, /\\| \\*\\*Confirmed\\*\\* \\| \\*\\*2\\*\\* \\|/);',
    '// The count is split by the contract\'s severity floor, so a report for a\n'
    + '  // "high" goal cannot read as though the target was met.\n'
    + '  assert.match(text, /\\| Confirmed \\| 2 \\|/);\n'
    + '  assert.match(text, /\\| \\*\\*Confirmed \\(at target: >= high\\)\\*\\* \\| \\*\\*1\\*\\* \\|/);\n'
    + '  assert.match(text, /\\| Confirmed \\(below high, or unrated\\) \\| 1 \\|/);',
  ],
]);

edit(R + "notes.test.ts", [
  [
    'assert.match(text, /\\*\\*Confirmed\\*\\* \\| \\*\\*1\\*\\*/);',
    'assert.match(text, /\\| Confirmed \\| 1 \\|/);\n'
    + '  assert.match(text, /\\| \\*\\*Confirmed \\(at target: >= medium\\)\\*\\* \\| \\*\\*1\\*\\* \\|/);',
  ],
]);

edit(R + "finding-dossier.test.ts", [
  [
    'assert.match(text, /## 已确认 \\(0\\)/);',
    'assert.match(text, /## 已确认发现（达标：≥ medium，0 条）/);',
  ],
]);
