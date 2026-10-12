const fs = require("fs");
const P = "D:/Ai/pi-audit-hypothesis-tree/extensions/hypothesis-tree/tools.ts";
let s = fs.readFileSync(P, "utf-8").replace(/\r\n/g, "\n");
const must = (c, m) => { if (!c) throw new Error("ANCHOR: " + m); };

// 1. sec_surface gains `priority`, right after `categories`.
const a1 = `        categories: Type.Optional(
          Type.Array(Type.String(), { description: "Classes worth checking here, e.g. [\\"rce\\", \\"path-traversal\\"]." }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const result = recordSurface(root, {`;
must(s.includes(a1), "sec_surface categories");
s = s.replace(a1, `        categories: Type.Optional(
          Type.Array(Type.String(), { description: "Classes worth checking here, e.g. [\\"rce\\", \\"path-traversal\\"]." }),
        ),
        priority: Type.Optional(
          Type.Number({
            description:
              "Raise to look at this SOONER than the plan. 1 means 'next'; higher jumps ahead of that. Leave it unset for anything found while reading the project, and use it when the ANALYSIS revealed something more promising than what is left on the list — you know things in round 15 you did not know in round 2, and a plan written before you knew anything should not override that. Do NOT promote everything: the brief reports how many items are queued ahead of the plan.",
          }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const result = recordSurface(root, {`, 1);

// 2. pass it through to recordSurface
const a2 = `          ...(params.categories && params.categories.length > 0 ? { categories: params.categories } : {}),
        });`;
must(s.includes(a2), "recordSurface call");
s = s.replace(a2, `          ...(params.categories && params.categories.length > 0 ? { categories: params.categories } : {}),
          ...(typeof params.priority === "number" ? { priority: params.priority } : {}),
        });`, 1);

// 3. sec_update gains `priority`
const a3 = `        reasoning: Type.Optional(Type.String()),
        poc: Type.Optional(Type.String()),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const patch: SecFindingPatch = {};`;
must(s.includes(a3), "sec_update params");
s = s.replace(a3, `        reasoning: Type.Optional(Type.String()),
        poc: Type.Optional(Type.String()),
        priority: Type.Optional(
          Type.Number({
            description:
              "Raise to analyse this item SOONER than the plan says; 0 puts it back in plan order. Use it when what you have read since made an item you already listed more promising than you thought.",
          }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const patch: SecFindingPatch = {};`, 1);

// 4. sec_update needs a surfaceId-style path — it patches a SURFACE item, so route priority there.
const a4 = `        const result = updateFinding(root, params.id, patch);`;
must(s.includes(a4), "update call");
s = s.replace(a4, `        // `priority` is a SURFACE field, not a finding one. `sec_update` corrects a finding,
        // so a priority here means "the surface item this finding came from" — which is what
        // the model has in hand when it decides an item deserves to jump the queue.
        if (typeof params.priority === "number") {
          const owner = load(root).snapshot.findings.find((f) => f.id === params.id)?.surfaceId;
          if (owner) {
            updateSurface(root, owner, { priority: params.priority });
          } else {
            return text(
              `${params.id} is a finding, not a surface item, and it is not linked to one (no \\`surfaceId\\`) — so there is nothing to re-prioritise.`,
            );
          }
        }
        const result = updateFinding(root, params.id, patch);`, 1);

fs.writeFileSync(P, s.replace(/\n/g, "\r\n"), "utf-8");
console.log("tools.ts: priority on sec_surface and sec_update");
