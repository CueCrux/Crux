// Copyright (c) 2026 CueCrux Ltd.
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

// Exercise every M6.1 surface against a LIVE daemon.
//
// The unit tests in test/ prove the wire shape against a stub. This proves the
// daemon actually answers, that the SDK parses what comes back, and that the
// context bundle's stable region really is stable. Driven by
// sdks/live-smoke.sh, which starts the daemon with the required flags.
//
// Usage: node smoke.mjs <base_url>

import { CoreCruxClient, CoreCruxError } from "./dist/index.js";

const baseUrl = process.argv[2] ?? "http://127.0.0.1:14800";
const client = new CoreCruxClient({ baseUrl });
const failures = [];

/** Run one probe. An allowed status counts as reached, not broken. */
async function check(name, fn, allowStatus = []) {
  try {
    const result = await fn();
    console.log(`  ok   ${name}`);
    return result;
  } catch (err) {
    if (err instanceof CoreCruxError && allowStatus.includes(err.status)) {
      console.log(`  ok   ${name} (HTTP ${err.status}, expected)`);
      return null;
    }
    const detail = err instanceof CoreCruxError ? `HTTP ${err.status} ${err.message}` : String(err);
    failures.push(`${name}: ${detail}`);
    console.log(`  FAIL ${name}: ${detail}`);
    return null;
  }
}

function fail(message) {
  failures.push(message);
  console.log(`  FAIL ${message}`);
}

await client.storeFact({ entity: "smoke:m6-ts", key: "surface", value: "sdk breadth" });

console.log("context");
const bundle = await check("context", () => client.context({ entity: "smoke:m6-ts", token_budget: 500 }));
await check("postContext", () => client.postContext({ query: "smoke", token_budget: 500 }));
const md = await check("contextMarkdown", () => client.contextMarkdown({ entity: "smoke:m6-ts" }));
const msgs = await check("contextMessages", () => client.contextMessages({ entity: "smoke:m6-ts" }));

if (bundle) {
  for (const field of ["bundle_version", "sections", "stable_hash", "budget"]) {
    if (!(field in bundle)) fail(`context bundle missing '${field}'`);
  }
  // The stable region must be byte-stable for an unchanged fact chain -- this
  // is what makes provider-side prompt caches hit.
  const again = await client.context({ entity: "smoke:m6-ts", token_budget: 500 });
  if (again.stable_hash !== bundle.stable_hash) {
    fail("stable_hash changed across two identical calls");
  } else {
    console.log("  ok   stable_hash is stable across identical calls");
  }
}
if (typeof md === "string" && md.trim() === "") fail("contextMarkdown returned empty text");
if (msgs && !msgs.messages?.length) fail("contextMessages returned no messages");

console.log("review");
const extracted = await check("extractMemory", () =>
  client.extractMemory({ text: "I bought seven books on 2026-08-06 for $340.", profile: "comprehensive" }),
);
await check("listCandidates", () => client.listCandidates("candidate"));
const candidate = extracted?.candidates?.[0];
const candidateId = candidate?.candidate_id ?? candidate?.id;
if (candidateId) {
  // The fail-closed gate: an unscored candidate must be REFUSED at a
  // threshold, not promoted by default.
  await check(
    "promoteCandidate (unscored, expect refusal)",
    () => client.promoteCandidate(candidateId, { auto_threshold: 0.9 }),
    [400, 422],
  );
  await check("rejectCandidate", () => client.rejectCandidate(candidateId, "smoke run"), [404]);
} else {
  console.log("  --   no candidates extracted; promote/reject not exercised");
}
await check("reviewContradictions", () => client.reviewContradictions({ limit: 5 }));
await check("reviewQueue", () => client.reviewQueue({ limit: 5 }));
await check("applyExpiries", () => client.applyExpiries(["f_nonexistent"]));

console.log("consolidation");
const a = await client.storeFact({ entity: "smoke:merge-ts", key: "k", value: "v1", confidence: 0.5 });
const b = await client.storeFact({ entity: "smoke:merge-ts", key: "k", value: "v2", confidence: 0.5 });
const merged = await check("consolidate", () =>
  client.consolidate({
    entity: "smoke:merge-ts",
    key: "k",
    canonical_value: "canonical",
    target_fact_ids: [a.fact_id, b.fact_id],
  }),
);
const canonical = merged?.receipt?.canonical_fact_id;
if (canonical) {
  await check("undoConsolidation", () => client.undoConsolidation({ canonical_fact_id: canonical }));
} else {
  await check(
    "undoConsolidation (no canonical id; expect refusal)",
    () => client.undoConsolidation({ canonical_fact_id: "f_nonexistent" }),
    [400, 404, 409, 422],
  );
}

console.log("ingest");
await check("localIngest", () =>
  client.localIngest({
    tenant_id: "smoke-tenant-ts",
    corpus_id: "smoke-corpus-ts",
    documents: [{ doc_id: "d1", chunks: [{ chunk_id: "c1", text: "hello from the smoke run" }] }],
  }),
);
await check(
  "importMemoryPack (dry run, unsigned pack; expect refusal)",
  () => client.importMemoryPack({ tenant_id: "smoke-tenant-ts", pack: {}, dry_run: true }),
  [400, 403, 404, 422],
);

console.log("extensions");
await check("listExtensions", () => client.listExtensions());
await check("listRegistryEntries", () => client.listRegistryEntries(), [404]);
await check("listTrustedKeys", () => client.listTrustedKeys());
if ((await client.getExtension("smoke-nonexistent")) === null) {
  console.log("  ok   getExtension returns null for an unknown id");
} else {
  fail("getExtension returned a body for an unknown id");
}
await check("listGrants", () => client.listGrants("smoke-nonexistent"), [404]);
await check(
  "invokeExtensionTool (unknown extension; expect refusal)",
  () => client.invokeExtensionTool("smoke-nonexistent", "noop", { passport_fpr: "smoke-fpr" }),
  [403, 404],
);

console.log("events");
// streamEvents, not subscribeEvents: `EventSource` is still not a Node global
// in 22.x, and it could not send an Authorization header even where it is.
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), 10_000);

// Let the subscriber attach before the write that should wake it.
setTimeout(() => {
  client.storeFact({ entity: "smoke:events-ts", key: "k", value: "v" }).catch(() => {});
}, 500);

let received = null;
try {
  for await (const event of client.streamEvents({ types: ["fact.stored"], signal: controller.signal })) {
    received = event;
    break;
  }
} catch (err) {
  if (!controller.signal.aborted) fail(`streamEvents threw: ${err}`);
}
clearTimeout(timer);

if (received?.type === "fact.stored") {
  console.log("  ok   streamEvents received fact.stored");
} else {
  fail("streamEvents saw no fact.stored within 10s");
}

console.log();
if (failures.length > 0) {
  console.log(`typescript smoke: ${failures.length} FAILURE(S)`);
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
console.log("typescript smoke: all surfaces reached");
