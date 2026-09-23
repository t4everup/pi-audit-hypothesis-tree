// Where do the refutation field and the severity split go?
const fs = require("fs");
const P = "D:/Ai/pi-audit-hypothesis-tree/extensions/hypothesis-tree/";
const read = (f) => fs.readFileSync(P + f, "utf-8");
const out = [];

// 1. NodePatch: where to add `refutation`
const store = read("store.ts");
out.push("=== NodePatch fields (store.ts) ===");
const np = store.slice(store.indexOf("export interface NodePatch"), store.indexOf("\n}", store.indexOf("export interface NodePatch")) + 2);
out.push(np.split("\n").filter((l) => /^\s{2}\w/.test(l)).map((l) => "  " + l.trim()).join("\n"));

// 2. normalizePatch: where the null/boolean handling lives
out.push("\n=== normalizePatch tail ===");
const npt = store.slice(store.indexOf("function normalizePatch"), store.indexOf("\n}", store.indexOf("function normalizePatch")) + 2);
out.push(npt.split("\n").slice(-22).join("\n"));

// 3. normalizeNode: the spread of optional fields
out.push("\n=== normalizeNode: the optional-field spreads ===");
const nn = store.slice(store.indexOf("function normalizeNode"), store.indexOf("\n}", store.indexOf("function normalizeNode")) + 2);
out.push(nn.split("\n").filter((l) => /\.\.\.\(/.test(l)).map((l) => "  " + l.trim().slice(0, 110)).join("\n"));

// 4. The report's confirmed section + summary rows
const rep = read("report.ts");
out.push("\n=== report: the confirmed section ===");
const cs = rep.indexOf("// ---- confirmed");
out.push(rep.slice(cs, cs + 700));

out.push("\n=== report: the summary rows for confirmed ===");
rep.split("\n").forEach((l, i) => {
  if (/rowConfirmed|rowExploitable|rowPreAuth|rowDossier/.test(l)) out.push(`  ${i + 1}  ${l.trim().slice(0, 120)}`);
});

// 5. hypothesis_record: the refusal block for a falsified probe
const tools = read("tools.ts");
out.push("\n=== hypothesis_record: the existing refusal ===");
const rr = tools.indexOf("was REFUTED by its own probes");
out.push(tools.slice(rr - 700, rr + 120).split("\n").filter((l) => /const |if \(|params\.|return text|status ===/.test(l)).map((l) => "  " + l.trim().slice(0, 110)).join("\n"));

fs.writeFileSync("D:/Ai/pi-audit-hypothesis-tree/.tmp-w.txt", out.join("\n"), "utf-8");
console.log(out.join("\n"));
