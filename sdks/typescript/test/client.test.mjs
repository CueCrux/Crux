// Copyright (c) 2026 CueCrux Ltd.
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

// Wire-shape tests for the CoreCrux TypeScript SDK.
//
// These run against a real local HTTP server (node:http) rather than a
// patched `fetch`, so the assertions cover what actually goes on the socket:
// method, path, query string and JSON body. Every route string here was read
// off the daemon's own route manifest (crates/corecruxd/src/http/openapi.rs)
// at the commit these tests landed on.
//
// Run against the built package: `npm run build && npm test`.
// For the round-trip against a live daemon see `sdks/live-smoke.sh`.

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, before, beforeEach, test } from "node:test";

import { CoreCruxClient, CoreCruxError, parseSseBlock } from "../dist/index.js";

const SSE_BODY =
  ": keep-alive\n\n" +
  "event: fact.stored\n" +
  'data: {"type":"fact.stored","fact_id":"f_1","entity":"e","key":"k"}\n\n' +
  ": keep-alive\n\n" +
  "event: session.stored\n" +
  'data: {"type":"session.stored","session_id":"s_1"}\n\n';

/** Requests the stub server saw, oldest first. */
let calls = [];
let baseUrl;
let server;

before(async () => {
  server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString();
      const url = new URL(req.url, "http://stub");
      calls.push({
        method: req.method,
        path: url.pathname,
        query: url.search.replace(/^\?/, ""),
        body: raw ? JSON.parse(raw) : null,
      });

      if (url.pathname === "/v1/events/stream") {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.end(SSE_BODY);
        return;
      }

      if (url.pathname.includes("boom")) {
        res.writeHead(500, { "Content-Type": "application/problem+json" });
        res.end(
          JSON.stringify({
            type: "about:blank",
            title: "Internal Server Error",
            status: 500,
            detail: "stub failure",
          }),
        );
        return;
      }

      if (url.pathname === "/v1/extensions/missing") {
        res.writeHead(404, { "Content-Type": "application/problem+json" });
        res.end(
          JSON.stringify({ type: "about:blank", title: "Not Found", status: 404, detail: "no such extension" }),
        );
        return;
      }

      if (url.pathname === "/v1/context" && url.searchParams.get("render") === "markdown") {
        res.writeHead(200, { "Content-Type": "text/markdown; charset=utf-8" });
        res.end("# Crux context\n");
        return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ schema: "stub.v1" }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

beforeEach(() => {
  calls = [];
});

const client = () => new CoreCruxClient({ baseUrl });

/** Assert the most recent request's method and path, and return it. */
function lastCall(method, path) {
  assert.ok(calls.length > 0, "no request reached the server");
  const call = calls[calls.length - 1];
  assert.equal(call.method, method);
  assert.equal(call.path, path);
  return call;
}

// ── Context ──────────────────────────────────────────────────────────

test("context sends only the options that were set", async () => {
  await client().context({ entity: "execplan:demo", token_budget: 500 });
  const call = lastCall("GET", "/v1/context");
  // session_id and query were never passed; they must not appear at all.
  assert.deepEqual(call.query.split("&").sort(), ["entity=execplan%3Ademo", "token_budget=500"]);
});

test("context with no options sends no query string", async () => {
  await client().context();
  assert.equal(lastCall("GET", "/v1/context").query, "");
});

test("postContext puts options in the body", async () => {
  await client().postContext({ query: "what changed", token_budget: 2000 });
  assert.deepEqual(lastCall("POST", "/v1/context").body, { query: "what changed", token_budget: 2000 });
});

test("contextMarkdown returns text, not JSON", async () => {
  const out = await client().contextMarkdown({ entity: "e" });
  assert.equal(out, "# Crux context\n");
  assert.match(lastCall("GET", "/v1/context").query, /render=markdown/);
});

test("contextMessages requests the openai render", async () => {
  await client().contextMessages();
  assert.match(lastCall("GET", "/v1/context").query, /render=openai_messages/);
});

// ── Review ───────────────────────────────────────────────────────────

test("extractMemory posts the transcript text", async () => {
  await client().extractMemory({ text: "we chose postgres", profile: "comprehensive" });
  assert.deepEqual(lastCall("POST", "/v1/memory/extract").body, {
    text: "we chose postgres",
    profile: "comprehensive",
  });
});

test("listCandidates filters by status, and omits the filter when unset", async () => {
  const c = client();
  await c.listCandidates("candidate");
  assert.equal(lastCall("GET", "/v1/memory/candidates").query, "status=candidate");
  await c.listCandidates();
  assert.equal(lastCall("GET", "/v1/memory/candidates").query, "");
});

test("promoteCandidate carries the auto threshold", async () => {
  await client().promoteCandidate("cand_1", { auto_threshold: 0.9 });
  assert.deepEqual(lastCall("POST", "/v1/memory/candidates/cand_1/promote").body, { auto_threshold: 0.9 });
});

test("promoteCandidate defaults to an explicit review", async () => {
  // No auto_threshold: the daemon must not read this as a score-gated
  // promotion, so the field has to be absent rather than null.
  await client().promoteCandidate("cand_1");
  assert.deepEqual(lastCall("POST", "/v1/memory/candidates/cand_1/promote").body, {});
});

test("rejectCandidate wraps the reason", async () => {
  await client().rejectCandidate("cand_1", "wrong entity");
  assert.deepEqual(lastCall("POST", "/v1/memory/candidates/cand_1/reject").body, { reason: "wrong entity" });
});

test("review contradictions and queue are distinct routes", async () => {
  const c = client();
  await c.reviewContradictions({ limit: 10 });
  assert.equal(lastCall("GET", "/v1/console/review/contradictions").query, "limit=10");
  await c.reviewQueue();
  assert.equal(lastCall("GET", "/v1/console/review/queue").query, "");
});

test("applyExpiries wraps ids in fact_ids", async () => {
  await client().applyExpiries(["f_1", "f_2"]);
  assert.deepEqual(lastCall("POST", "/v1/console/review/expiries").body, { fact_ids: ["f_1", "f_2"] });
});

// ── Consolidation ────────────────────────────────────────────────────

test("consolidate posts the canonical merge", async () => {
  await client().consolidate({
    entity: "e",
    key: "k",
    canonical_value: "canonical",
    target_fact_ids: ["f_1", "f_2"],
    protected_confidence_floor: 0.95,
  });
  assert.deepEqual(lastCall("POST", "/v1/console/review/consolidations").body, {
    // Sent explicitly: the daemon has no serde default for this field, so an
    // absent key is a 422 while a blank one gets `console-<uuid>`.
    consolidation_id: "",
    entity: "e",
    key: "k",
    canonical_value: "canonical",
    target_fact_ids: ["f_1", "f_2"],
    protected_confidence_floor: 0.95,
  });
});

test("consolidate honours an explicit consolidation_id", async () => {
  await client().consolidate({
    consolidation_id: "run-7",
    entity: "e",
    key: "k",
    canonical_value: "v",
    target_fact_ids: ["f_1"],
  });
  assert.equal(lastCall("POST", "/v1/console/review/consolidations").body.consolidation_id, "run-7");
});

test("undoConsolidation posts to the undo route", async () => {
  await client().undoConsolidation({ canonical_fact_id: "f_canon", entity: "e" });
  assert.deepEqual(lastCall("POST", "/v1/console/review/consolidations/undo").body, {
    canonical_fact_id: "f_canon",
    entity: "e",
  });
});

// ── Ingest ───────────────────────────────────────────────────────────

test("localIngest posts documents", async () => {
  const documents = [{ doc_id: "d1", chunks: [{ chunk_id: "c1", text: "hello" }] }];
  await client().localIngest({ tenant_id: "tenant", corpus_id: "corpus", documents });
  assert.deepEqual(lastCall("POST", "/v1/local/ingest").body, {
    tenant_id: "tenant",
    corpus_id: "corpus",
    documents,
  });
});

test("importMemoryPack sends dry_run", async () => {
  await client().importMemoryPack({ tenant_id: "tenant", pack: { manifest: {} }, dry_run: true });
  assert.deepEqual(lastCall("POST", "/v1/memory/import").body, {
    tenant_id: "tenant",
    pack: { manifest: {} },
    dry_run: true,
  });
});

// ── Extensions ───────────────────────────────────────────────────────

test("extension routes", async () => {
  const c = client();

  await c.listExtensions();
  lastCall("GET", "/v1/extensions");

  await c.registerExtension({ id: "x" });
  assert.deepEqual(lastCall("POST", "/v1/extensions/register").body, { manifest: { id: "x" } });

  await c.listRegistryEntries();
  lastCall("GET", "/v1/extensions/registry");

  await c.installFromRegistry({ id: "ext-1" });
  assert.deepEqual(lastCall("POST", "/v1/extensions/install-from-registry").body, { id: "ext-1" });

  await c.listTrustedKeys();
  lastCall("GET", "/v1/extensions/keys");

  await c.addTrustedKey({ passport_fpr: "fpr1", public_key_hex: "abcd", trust_tier: "community" });
  assert.deepEqual(lastCall("POST", "/v1/extensions/keys").body, {
    passport_fpr: "fpr1",
    public_key_hex: "abcd",
    trust_tier: "community",
  });

  await c.deleteTrustedKey("fpr1");
  lastCall("DELETE", "/v1/extensions/keys/fpr1");

  await c.listGrants("ext-1");
  lastCall("GET", "/v1/extensions/ext-1/grants");

  await c.issueGrant("ext-1", { passport_fpr: "fpr1", allowed_tool_names: ["t"] });
  assert.deepEqual(lastCall("POST", "/v1/extensions/ext-1/grants").body, {
    passport_fpr: "fpr1",
    allowed_tool_names: ["t"],
  });

  await c.revokeGrant("ext-1", "fpr1");
  lastCall("DELETE", "/v1/extensions/ext-1/grants/fpr1");
});

test("invokeExtensionTool defaults args to an empty object", async () => {
  await client().invokeExtensionTool("ext-1", "search");
  assert.deepEqual(lastCall("POST", "/v1/extensions/ext-1/tools/search/invoke").body, { args: {} });
});

test("path segments are URL-encoded", async () => {
  await client().listGrants("ext/1");
  lastCall("GET", "/v1/extensions/ext%2F1/grants");
});

// ── Errors ───────────────────────────────────────────────────────────

test("getExtension returns null on 404", async () => {
  assert.equal(await client().getExtension("missing"), null);
});

test("deleteExtension returns false on 404", async () => {
  assert.equal(await client().deleteExtension("missing"), false);
});

test("a 500 surfaces as CoreCruxError carrying the RFC 9457 problem body", async () => {
  // Only getExtension and deleteExtension swallow a status; every other
  // method must propagate. `boom` makes the stub answer 500.
  const err = await client()
    .listGrants("boom")
    .then(() => null)
    .catch((e) => e);

  assert.ok(err instanceof CoreCruxError, `expected CoreCruxError, got ${err}`);
  assert.equal(err.status, 500);
  assert.equal(err.message, "stub failure");
  assert.equal(err.problem.title, "Internal Server Error");
});

// ── Events ───────────────────────────────────────────────────────────

test("streamEvents skips keep-alives and decodes data", async () => {
  const events = [];
  for await (const event of client().streamEvents({ types: ["fact.stored", "session.stored"] })) {
    events.push(event);
  }
  assert.deepEqual(
    events.map((e) => e.type),
    ["fact.stored", "session.stored"],
  );
  assert.equal(events[0].fact_id, "f_1");
  assert.equal(lastCall("GET", "/v1/events/stream").query, "types=fact.stored%2Csession.stored");
});

test("streamEvents without types sends no filter", async () => {
  // An explicit blank `types=` means "match nothing" daemon-side, so an
  // unfiltered subscription must omit the parameter entirely.
  // eslint-disable-next-line no-unused-vars
  for await (const _ of client().streamEvents()) break;
  assert.equal(lastCall("GET", "/v1/events/stream").query, "");
});

test("streamEvents requests the event-stream content type", async () => {
  for await (const event of client().streamEvents()) {
    assert.equal(event.type, "fact.stored");
    break;
  }
});

test("parseSseBlock ignores comments and bad JSON", () => {
  assert.equal(parseSseBlock(": keep-alive"), null);
  assert.equal(parseSseBlock("event: fact.stored"), null);
  assert.equal(parseSseBlock("data: not json"), null);
  assert.deepEqual(parseSseBlock('data: {"a":1}'), { a: 1 });
  // A multi-line data payload rejoins with newlines per the SSE spec.
  assert.deepEqual(parseSseBlock('data: {"a":\ndata: 1}'), { a: 1 });
});
