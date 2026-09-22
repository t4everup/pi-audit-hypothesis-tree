/**
 * pi-audit-hypothesis-tree — extensions/hypothesis-tree/ladders.ts
 *
 * The exploitation ladder for each vulnerability class.
 *
 * -----------------------------------------------------------------------
 * Why this is in the extension and not in a skill
 * -----------------------------------------------------------------------
 *
 * The extension is a MECHANISM: it has an opinion about how a claim is recorded
 * and falsified, and none about what a PHP type-juggling bug looks like. That is
 * deliberate — a tool that shipped a vulnerability encyclopedia would be wrong
 * about most of it.
 *
 * But there is one thing it must know: **the standard axes of depth for a class.**
 * Not how to exploit anything — just the questions. Without them a confirmed SSRF
 * is examined until the model's own recall runs out, and the axes it happens not
 * to think of are never asked about:
 *
 *   confirmed: the server fetches a caller-directed URL, file:// included
 *   never asked: is the response reflected back? (the echo channel)
 *
 * An unasked axis is not a gap in the report — it is a gap the report cannot see.
 * That is what this file fixes, and it is the smallest amount of domain knowledge
 * that closes it.
 *
 * -----------------------------------------------------------------------
 * The shape of an axis
 * -----------------------------------------------------------------------
 *
 * Every axis is phrased as a QUESTION that can be answered by reading code, and
 * the answer is meant to become a GATE hypothesis (`Hypothesis.requires`) rather
 * than prose. The ladder does not report anything itself: it feeds the two
 * moments where the model can still act on it — the confirmation of a finding,
 * and the round that goes deeper on one.
 *
 * `keyAxis` is the one that decides whether the finding is worth anything at all.
 * An SSRF with no echo channel and no out-of-band path is a much weaker finding
 * than the same code with one, and the difference is not visible in the sink.
 */

import type { HypothesisCategory } from "./types.js";

export interface Ladder {
  /**
   * The depth axes, in the order worth checking.
   *
   * Each is a question answerable from source, phrased so that a "no" is as
   * useful as a "yes" — the point is to settle it, not to confirm it.
   */
  axes: string[];
  /**
   * The axis that decides whether the finding is USABLE, as opposed to merely
   * real. If only one is checked, it should be this one.
   */
  keyAxis: string;
}

/**
 * The ladders.
 *
 * Scoped to the classes that carry pre-auth high-severity findings. A class with
 * no entry gets a generic fallback rather than nothing — see `ladderFor`.
 */
export const LADDERS: Partial<Record<HypothesisCategory, Ladder>> = {
  ssrf: {
    keyAxis:
      "ECHO CHANNEL — is any part of the fetched response reflected to the attacker (body, status, headers, timing, error text)? Full echo / semi-blind / fully blind decides whether this is a file-read primitive or a port-scan at best.",
    axes: [
      "ECHO CHANNEL — is any part of the fetched response reflected back (body, status, headers, timing, error text)? Full echo / semi-blind / fully blind.",
      "PROTOCOL ALLOWLIST — is the URL scheme restricted? file:// (local file read), gopher:// and dict:// (protocol smuggling to internal services), ftp://, jar://.",
      "REDIRECTS — does the fetcher follow 3xx? A redirect to an internal address walks straight past a hostname allowlist.",
      "INTERNAL REACH — can it reach 127.0.0.1, RFC1918 ranges, 169.254.169.254 (cloud metadata), or a Docker/container socket?",
      "BLIND EXFIL — with no echo, can the result leave any other way (DNS, a second request, an error message, timing)?",
      "REQUEST SHAPE — are method, headers or body attacker-controlled (CRLF injection, Host override, custom auth headers)?",
    ],
  },
  deserialization: {
    keyAxis:
      "GADGET CHAIN — is a usable gadget actually on the classpath, at the right version? Without one this is a crash, not an RCE.",
    axes: [
      "GADGET CHAIN — is a usable gadget on the classpath at the right version (commons-collections, beanutils, spring, hibernate, snakeyaml, …)?",
      "TYPE RESTRICTION — is there an ObjectInputFilter, resolveClass override, allowed-types list or safe-mode, and does it actually cover this path?",
      "INPUT CONTROL — are the bytes fully attacker-controlled, or encoded / signed / encrypted / re-serialized before they reach readObject?",
      "ENTRY PRECONDITION — what does it take to reach this entry point (authentication, a writable row, an uploaded file, a queue message)?",
      "ENGINE — which deserializer is it (Java native, Jackson default typing, SnakeYAML, pickle, PHP unserialize, .NET BinaryFormatter), and does that change the gadget set?",
      "ESCALATION — if the payload cannot execute, can it still be used (file write, SSRF via URL fields, auth bypass via type confusion)?",
    ],
  },
  "command-injection": {
    keyAxis:
      "SHELL REACH — does the value actually reach a shell, or is it passed as an argv element to exec without a shell? The latter is not injectable.",
    axes: [
      "SHELL REACH — does the value reach a shell (`sh -c`, `system`, backticks) or an argv element of exec? Only the first is injectable.",
      "SEPARATORS — are ; | & ` $() newline filtered, and is the filter applied before or after decoding?",
      "QUOTE ESCAPE — can the value close an existing quote and escape into the command?",
      "ALLOWLIST BYPASS — is the blocklist bypassable (encoding, wildcards, variable expansion, path prefixes, argument injection with a leading dash)?",
      "BLIND CONFIRMATION — with no echo, can execution be confirmed at all (timing, DNS, a file it writes, an error code)?",
      "PRIVILEGE — which user does the process run as, and what does that reach?",
    ],
  },
  "path-traversal": {
    keyAxis:
      "READ OR WRITE — a write primitive is usually RCE (config, cron, template, plugin); a read primitive is disclosure. They are different findings with different impact.",
    axes: [
      "READ OR WRITE — is this a read or a write primitive? A write is usually RCE; a read is disclosure.",
      "ENCODING BYPASS — are %2e%2e, ..%2f, double-encoding, UTF-8 overlong, backslash or a trailing dot stripped by a filter that runs before decoding?",
      "ABSOLUTE PATH — does a leading / or a scheme-qualified path bypass the base directory entirely?",
      "PREFIX BYPASS — can a prefix check be walked past (/var/www/../../etc/passwd, or a sibling directory sharing the prefix)?",
      "SYMLINKS — is there a writable directory whose symlink the traversal can follow?",
      "DOWNSTREAM PARSING — is the read content parsed afterwards (a template, a config, an image library)? That turns a read into code execution or injection.",
    ],
  },
  "arbitrary-file-read": {
    keyAxis:
      "WHAT IS ACTUALLY READABLE — which files does the process user own or have read access to, and is any of them a credential store?",
    axes: [
      "SCOPE — which files can actually be read (process user's permissions, container filesystem, mounted secrets)?",
      "SECRETS — are credentials, keys, tokens or connection strings reachable (.env, config, keytabs, cloud metadata files)?",
      "EXFIL — is the file content returned, or only a derived value (a length, a hash, an error)?",
      "BYPASS — encoding, absolute path, symlink, or a prefix check that can be walked past?",
      "CHAIN — does a readable file unlock the next step (a private key, a session secret, a password that grants admin)?",
    ],
  },
  "arbitrary-file-write": {
    keyAxis:
      "WHERE DOES IT LAND — a write into a web-served, executable, or config-read directory is RCE; a write into a temp directory is usually not.",
    axes: [
      "DESTINATION — where does the write land? Web-served, auto-included, config-parsed, cron-read, or template-scanned directories are the RCE paths.",
      "CONTENT CONTROL — is the written content fully attacker-controlled, or wrapped in a template/header?",
      "EXTENSION — can the name be chosen, or is it fixed?",
      "TRAVERSAL — can the path escape the intended directory?",
      "TRIGGER — what makes the written file execute or get read (a request, a restart, a scheduled job)?",
    ],
  },
  "file-upload": {
    keyAxis:
      "EXECUTABILITY — can the uploaded file be requested and executed? Everything else is a step toward that or a separate finding.",
    axes: [
      "EXECUTABILITY — is the upload directory web-served, and will the server execute the uploaded type?",
      "TYPE CHECK BYPASS — is the extension/content-type/magic-byte check bypassable (double extension, null byte, polyglot, content-type spoof, .htaccess)?",
      "FILENAME CONTROL — is the name attacker-chosen, and can it traverse (../) or overwrite an existing file?",
      "PARSING — does an image/document library parse it (ImageMagick, Ghostscript, a PDF parser)? That is its own RCE path.",
      "AUTH — does reaching the upload require authentication?",
    ],
  },
  xxe: {
    keyAxis:
      "ENTITY RESOLUTION — is external entity resolution actually enabled on this parser instance? Most modern defaults disable it, and that settles the finding.",
    axes: [
      "RESOLUTION — is DOCTYPE/external-entity resolution enabled (disallow-doctype-decl false, external-general-entities true, no secure processing)?",
      "ECHO — does the entity's value appear in the response? Blind XXE needs out-of-band.",
      "OUT-OF-BAND — can an external DTD plus a parameter entity exfiltrate the content?",
      "FILE READ — does file:// work from the entity, and what is readable?",
      "SSRF — can the entity point at internal services or cloud metadata? That is the SSRF ladder from here.",
      "BILLION LAUGHS — is entity expansion bounded (a DoS finding, lower value but real)?",
    ],
  },
  sqli: {
    keyAxis:
      "REAL PARAMETERIZATION — is the value bound as a parameter, or interpolated into the string? Partial parameterization (ORDER BY, LIMIT, table names) is still injectable.",
    axes: [
      "PARAMETERIZATION — bound parameter or string interpolation? ORDER BY / LIMIT / identifiers are the places that stay injectable.",
      "INJECTION TYPE — string, numeric, ORDER BY, LIMIT, IN, LIKE? Each needs a different payload shape.",
      "ECHO — UNION / error-based / boolean-blind / time-blind? What is actually visible?",
      "DB PRIVILEGE — can the DB user read files, write files, stack queries, or reach other schemas?",
      "SECOND ORDER — is the value stored and later used in a query (a profile field, a log, a cached key)?",
      "PRE-AUTH — is the endpoint reachable without authentication?",
    ],
  },
  ssti: {
    keyAxis:
      "SANDBOX — is the template engine running sandboxed? An unsandboxed Jinja2/Twig/Freemarker expression is RCE; a sandboxed one is usually not.",
    axes: [
      "ENGINE AND VERSION — which engine, which version? The escape set is version-specific.",
      "SANDBOX — is SandboxedEnvironment / a restricted mode enabled, and does it block attribute access and dunder traversal?",
      "ECHO — is the rendered output returned to the attacker? Blind SSTI needs a different confirmation.",
      "REACH — can the expression reach os/exec, a file read, or an environment variable?",
      "INPUT PATH — is the template SOURCE attacker-controlled, or only a value interpolated into a fixed template?",
    ],
  },
  "auth-bypass": {
    keyAxis:
      "GLOBAL ENFORCEMENT — is there a parent class, middleware, framework default or listener that applies a check the controller itself does not? Reading the controller alone cannot settle this.",
    axes: [
      "GLOBAL ENFORCEMENT — a parent class, middleware, framework default or event listener that applies a check this handler does not (denyAccessUnlessGranted, #[IsGranted], a firewall rule, an auth middleware)?",
      "ENTRY POINT — does the firewall / gateway / entry_point reject before the handler is reached (a token API, an IP allowlist, a base authenticator)?",
      "ROUTE ALIASES — is the same handler reachable by another path, method, version prefix, or with a trailing slash / different case?",
      "NORMALIZATION — can a path or header be normalized differently by the proxy and the app (//admin, /admin/../admin, %2f, X-Forwarded-*)?",
      "THE SAME CLASS — do OTHER handlers extending the same base class or sharing the same helper also skip the check?",
      "DEFAULT DENY — is authorization opt-in per handler (so the next handler forgets it) or deny-by-default?",
    ],
  },
  idor: {
    keyAxis:
      "OWNERSHIP CHECK — is the object's owner compared to the caller, or is the id simply looked up? The check must exist, not be implied by the id being unguessable.",
    axes: [
      "OWNERSHIP — is the owner compared to the caller, or is the object fetched by id alone?",
      "ID SHAPE — sequential integer, UUID, or hashed? Unguessable is not authorization.",
      "ENUMERATION — can ids be listed or derived, and is there any rate limit?",
      "READ OR WRITE — can the object be modified or deleted, not just read?",
      "TRANSITIVE — does the leaked object carry an id that unlocks another object (a tenant, an account, a file)?",
    ],
  },
  "privilege-escalation": {
    keyAxis:
      "WHAT THE NEXT ROLE BUYS — which privilege boundary is actually crossed, and what does the other side of it reach?",
    axes: [
      "BOUNDARY — which privilege boundary is crossed (anonymous→user, user→admin, tenant→tenant, user→service)?",
      "WHAT IT BUYS — what does the other side reach that the current side does not?",
      "ENFORCEMENT SITE — where is the check applied, per-route or globally, and can the route be reached without it?",
      "PERSISTENCE — does the escalation persist, or only for the current request?",
      "CHAIN — does it combine with an authenticated RCE to become pre-auth?",
    ],
  },
  "info-disclosure": {
    keyAxis:
      "WHAT IT UNLOCKS — is the disclosed value usable for the next step (a credential, a path, a version with a known bug, a token), or is it only noise?",
    axes: [
      "CONTENT — credentials, tokens, internal paths, version numbers, stack traces, or personal data?",
      "NEXT STEP — does it unlock something (a known-CVE version, a private key, a session secret, an internal hostname)?",
      "PRE-AUTH — is it reachable without authentication?",
      "BULK — can it be enumerated at scale, or is it one record?",
      "ECHO — does the response confirm the disclosure, or is it inferred?",
    ],
  },
  "hardcoded-secret": {
    keyAxis:
      "IS IT STILL LIVE — a secret in a public repo is only a finding if it still authenticates. Test the scope before rating it.",
    axes: [
      "LIVENESS — does the credential still authenticate?",
      "SCOPE — what does it reach (which service, which tenant, which permission level)?",
      "EXPOSURE — is it in the shipped artefact, the image, the client bundle, or version history?",
      "ROTATION — is it the same secret in production, or a development default that is overridden?",
    ],
  },
  "open-redirect": {
    keyAxis:
      "WHAT IT CHAINS WITH — a bare redirect is low; a redirect that carries a token, a code or a session to an attacker host is account takeover.",
    axes: [
      "TARGET CONTROL — is the destination fully attacker-chosen, or restricted to a path?",
      "BYPASS — //evil.com, /\\evil.com, @evil.com, a subdomain suffix match, a backslash, a scheme-relative URL?",
      "CREDENTIAL CARRY — does the redirect carry a token, a code, a cookie or a header to the target?",
      "CHAIN — does it feed an SSRF (server follows it) or an XSS (javascript: target)?",
    ],
  },
  "race-condition": {
    keyAxis:
      "WINDOW AND REPETITION — is the window wide enough to hit, and can the action be repeated enough times to matter?",
    axes: [
      "WINDOW — how wide is the gap between check and use, and is it hit in practice?",
      "CONCURRENCY — how many parallel requests are needed, and is there a lock or rate limit?",
      "EFFECT — what does winning the race buy (double spend, quota bypass, privilege grant, TOCTOU on a file)?",
      "PERSISTENCE — is the effect durable or overwritten by the loser?",
    ],
  },
  rce: {
    keyAxis:
      "THE LAST STEP — what turns this into code execution, and is that step actually reachable from here?",
    axes: [
      "SINK — which exact call executes (eval, system, deserialize, template, native)?",
      "INPUT PATH — how does attacker input reach it, and is any part of it constrained?",
      "CONSTRAINTS — length, charset, encoding, escaping, or an allowlist that has to be worked around?",
      "PRE-AUTH — is the entry reachable without authentication?",
      "GATES — what else must hold for this to work, and has each been verified?",
    ],
  },
  misconfiguration: {
    keyAxis:
      "REACHABILITY — is the misconfigured thing actually reachable from the position the attacker occupies?",
    axes: [
      "REACHABILITY — is it exposed to the attacker's position (network, authentication, deployment)?",
      "DEFAULT VS OVERRIDDEN — is this the shipped default, or is it overridden in the real deployment?",
      "IMPACT — what does it enable (anonymous access, debug output, directory listing, an open admin interface)?",
      "CHAIN — does it unlock a further step?",
    ],
  },
};

/**
 * The ladder for a class, or a generic fallback.
 *
 * A fallback rather than null: a class with no curated ladder still benefits from
 * being asked what it depends on. Returning null would make the absence of
 * knowledge look like the absence of a question.
 */
export function ladderFor(category: HypothesisCategory): Ladder {
  const curated = LADDERS[category];
  if (curated) return curated;
  return {
    keyAxis:
      "WHAT IT DEPENDS ON — what must hold for this to be exploitable, and has each of those been verified rather than assumed?",
    axes: [
      "WHAT IT DEPENDS ON — what must hold for this to be exploitable, and has each been verified?",
      "HOW FAR — what does the impact recorded above unlock next?",
      "WHERE ELSE — does the same root cause hold at other endpoints, handlers or callers?",
      "WHO REACHES IT — is there a path from an unauthenticated or more privileged position?",
    ],
  };
}

/**
 * The ladder as a brief block.
 *
 * Phrased as an instruction to settle each axis, and to settle it as a GATE
 * rather than as prose: prose is recorded and never tested, while a gate gets
 * scheduled, confirmed or refuted, and shows up in the chain state.
 */
export function renderLadder(category: HypothesisCategory, nodeId: string, lang: "zh" | "en" = "en"): string {
  const ladder = ladderFor(category);
  const lines: string[] = [];
  if (lang === "zh") {
    lines.push(`## ${category} 的深度轴`);
    lines.push("");
    lines.push("每一轴都要**settle 掉**——读代码得出「是」或「否」，两者同样有用。");
    lines.push("**没有 settle 的轴，就变成一条 gate 假设**（`requires`），而不是散文。");
    lines.push("散文会被记录、被打印，然后**没有任何东西去检验它**。");
    lines.push("");
    lines.push(`**最关键的一轴（只查一条就查它）：**`);
    lines.push(`  ${ladder.keyAxis}`);
    lines.push("");
    lines.push("全部轴：");
    for (const axis of ladder.axes) lines.push(`  - ${axis}`);
    lines.push("");
    lines.push(`把没 settle 的每一轴写成假设，再用 \`hypothesis_vector ${nodeId} requires=[...]\` 挂上去。`);
    return lines.join("\n");
  }
  lines.push(`## The depth axes for ${category}`);
  lines.push("");
  lines.push("Settle EACH axis by reading code — \"no\" is as useful an answer as \"yes\".");
  lines.push("**An axis you cannot settle becomes a GATE hypothesis** (`requires`), not prose.");
  lines.push("Prose is recorded, printed, and then tested by nothing.");
  lines.push("");
  lines.push("**The one that matters most — if you check only one, check this:**");
  lines.push(`  ${ladder.keyAxis}`);
  lines.push("");
  lines.push("All of them:");
  for (const axis of ladder.axes) lines.push(`  - ${axis}`);
  lines.push("");
  lines.push(`Write each unsettled axis as its own hypothesis, then link it with \`hypothesis_vector ${nodeId} requires=[...]\`.`);
  return lines.join("\n");
}

/** One-line summary for a tool response. */
export function ladderSummary(category: HypothesisCategory): string {
  const ladder = ladderFor(category);
  return `${ladder.axes.length} depth axes for ${category}; the decisive one is: ${ladder.keyAxis.split(" — ")[0]}`;
}
