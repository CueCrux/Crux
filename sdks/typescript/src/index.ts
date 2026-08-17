// Copyright (c) 2026 CueCrux Ltd.
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

export * from "./types.js";

import type {
  AddTrustedKeyRequest,
  CandidateListResult,
  CandidateStatus,
  ConsolidationRequest,
  ConsolidationResult,
  ConsolidationUndoRequest,
  ContextBundle,
  ContextMessages,
  ContextOptions,
  CueCruxOptions,
  CruxEvent,
  ExpiryApplyResult,
  ExtractOptions,
  ExtractResult,
  Fact,
  FactExportOptions,
  FactExportResult,
  FactQueryOptions,
  FactQueryResult,
  GraphExpandOptions,
  GraphExpandResult,
  HealthzResponse,
  InstallFromRegistryRequest,
  InvokeToolOptions,
  IssueGrantRequest,
  LocalIngestRequest,
  MemoryImportRequest,
  MemoryImportResult,
  ProblemDetails,
  PromoteOptions,
  ReadyzResponse,
  ReviewQueueOptions,
  SessionState,
  StoreFact,
  TextSearchExpandOptions,
  TextSearchExpandResult,
  TextSearchOptions,
  TextSearchResult,
  TimeRangeOptions,
  TimeRangeResult,
  VersionResponse,
} from "./types.js";

// ── Error class ─────────────────────────────────────────────────────

/**
 * Error thrown when the CueCrux API returns a non-2xx response.
 * Carries the RFC 9457 Problem Details body when available.
 */
export class CueCruxError extends Error {
  public readonly status: number;
  public readonly problem: ProblemDetails | null;

  constructor(status: number, message: string, problem: ProblemDetails | null = null) {
    super(message);
    this.name = "CueCruxError";
    this.status = status;
    this.problem = problem;
  }
}

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Build a `?a=b&c=d` suffix, dropping `undefined` and `null` entries.
 * Returns `""` when nothing survives, so it is safe to append unconditionally.
 */
function qs(params?: object): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

/**
 * Decode one SSE block into its JSON `data` payload.
 *
 * Returns `null` for keep-alive comments and for any block without a `data:`
 * field — the daemon sends a comment every 15s to hold the connection open,
 * and those must not surface as events.
 */
export function parseSseBlock(block: string): unknown | null {
  const dataLines = block
    .split("\n")
    .filter((line) => line === "data" || line.startsWith("data:"))
    .map((line) => (line === "data" ? "" : line.slice(5).replace(/^ /, "")));
  if (dataLines.length === 0) return null;
  try {
    return JSON.parse(dataLines.join("\n"));
  } catch {
    return null;
  }
}

// ── Client ──────────────────────────────────────────────────────────

export class CueCruxClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor(options: CueCruxOptions) {
    // Strip trailing slash for consistent path joining.
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.headers = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (options.token) {
      this.headers["Authorization"] = `Bearer ${options.token}`;
    }
  }

  // ── Health ──────────────────────────────────────────────────────

  /** `GET /healthz` — node health status. */
  async healthz(): Promise<HealthzResponse> {
    return this.request<HealthzResponse>("GET", "/healthz");
  }

  /** `GET /readyz` — node readiness check. */
  async readyz(): Promise<ReadyzResponse> {
    return this.request<ReadyzResponse>("GET", "/readyz");
  }

  /** `GET /v1/version` — build version and feature flags. */
  async version(): Promise<VersionResponse> {
    return this.request<VersionResponse>("GET", "/v1/version");
  }

  // ── Facts ──────────────────────────────────────────────────────

  /** `PUT /v1/facts` — store a single fact. */
  async storeFact(fact: StoreFact): Promise<Fact> {
    return this.request<Fact>("PUT", "/v1/facts", fact);
  }

  /** `PUT /v1/facts/bulk` — store multiple facts at once. */
  async storeFacts(facts: StoreFact[]): Promise<Fact[]> {
    const result = await this.request<{ facts: Fact[] }>("PUT", "/v1/facts/bulk", facts);
    return result.facts;
  }

  /** `GET /v1/facts/{factId}` — retrieve a single fact by ID. Returns `null` if not found. */
  async getFact(factId: string): Promise<Fact | null> {
    try {
      return await this.request<Fact>("GET", `/v1/facts/${encodeURIComponent(factId)}`);
    } catch (err) {
      if (err instanceof CueCruxError && err.status === 404) {
        return null;
      }
      throw err;
    }
  }

  /** `DELETE /v1/facts/{factId}` — soft-delete a fact. Returns `true` if deleted, `false` if not found. */
  async deleteFact(factId: string): Promise<boolean> {
    try {
      await this.request<{ deleted: boolean }>("DELETE", `/v1/facts/${encodeURIComponent(factId)}`);
      return true;
    } catch (err) {
      if (err instanceof CueCruxError && err.status === 404) {
        return false;
      }
      throw err;
    }
  }

  /** `GET /v1/facts/entity/{entity}` — all facts for an entity. */
  async getFactsByEntity(entity: string): Promise<{ facts: Fact[] }> {
    return this.request<{ facts: Fact[] }>("GET", `/v1/facts/entity/${encodeURIComponent(entity)}`);
  }

  /** `GET /v1/facts` — query facts with optional BM25 search, entity filter, and token budget. */
  async queryFacts(options?: FactQueryOptions): Promise<FactQueryResult> {
    const params = new URLSearchParams();
    if (options?.query) params.set("query", options.query);
    if (options?.entity) params.set("entity", options.entity);
    if (options?.entity_prefix) params.set("entity_prefix", options.entity_prefix);
    if (options?.top_k !== undefined) params.set("top_k", String(options.top_k));
    if (options?.token_budget !== undefined) params.set("token_budget", String(options.token_budget));
    const qs = params.toString();
    return this.request<FactQueryResult>("GET", `/v1/facts${qs ? `?${qs}` : ""}`);
  }

  /** `GET /v1/facts/export` — paginated fact export. */
  async exportFacts(options?: FactExportOptions): Promise<FactExportResult> {
    const params = new URLSearchParams();
    if (options?.since) params.set("since", options.since);
    if (options?.cursor) params.set("cursor", options.cursor);
    if (options?.limit !== undefined) params.set("limit", String(options.limit));
    const qs = params.toString();
    return this.request<FactExportResult>("GET", `/v1/facts/export${qs ? `?${qs}` : ""}`);
  }

  // ── Sessions ───────────────────────────────────────────────────

  /** `PUT /v1/sessions/{sessionId}/state` — store session state. */
  async putSession(sessionId: string, state: unknown): Promise<SessionState> {
    return this.request<SessionState>("PUT", `/v1/sessions/${encodeURIComponent(sessionId)}/state`, state);
  }

  /** `GET /v1/sessions/{sessionId}/state` — retrieve session state. Returns `null` if not found. */
  async getSession(sessionId: string): Promise<SessionState | null> {
    try {
      return await this.request<SessionState>(
        "GET",
        `/v1/sessions/${encodeURIComponent(sessionId)}/state`,
      );
    } catch (err) {
      if (err instanceof CueCruxError && err.status === 404) {
        return null;
      }
      throw err;
    }
  }

  // ── Query: Text Search ─────────────────────────────────────────

  /** `POST /v1/query/text-search` — BM25 text search over indexed segments. */
  async textSearch(options: TextSearchOptions): Promise<TextSearchResult> {
    return this.request<TextSearchResult>("POST", "/v1/query/text-search", options);
  }

  /** `POST /v1/query/text-search/expand` — expand scan-mode results to full chunks. */
  async textSearchExpand(options: TextSearchExpandOptions): Promise<TextSearchExpandResult> {
    return this.request<TextSearchExpandResult>("POST", "/v1/query/text-search/expand", options);
  }

  // ── Query: Graph Expand ────────────────────────────────────────

  /** `POST /v1/query/graph-expand` — graph traversal from seed artifacts. */
  async graphExpand(options: GraphExpandOptions): Promise<GraphExpandResult> {
    return this.request<GraphExpandResult>("POST", "/v1/query/graph-expand", options);
  }

  // ── Query: Time Range ──────────────────────────────────────────

  /** `POST /v1/query/time-range` — artifacts changed within a time window. */
  async timeRange(options: TimeRangeOptions): Promise<TimeRangeResult> {
    return this.request<TimeRangeResult>("POST", "/v1/query/time-range", options);
  }

  // ── Context ────────────────────────────────────────────────────

  /**
   * `GET /v1/context` — the provider-neutral injection bundle.
   *
   * Requires `CORECRUXD_CONTEXT_SURFACE=1` on the daemon; the route 404s when
   * the surface is off, so the capability is invisible rather than half-alive.
   */
  async context(options?: ContextOptions): Promise<ContextBundle> {
    return this.request<ContextBundle>("GET", `/v1/context${qs(options)}`);
  }

  /**
   * `POST /v1/context` — same bundle, options in the body rather than the
   * query string. Prefer this when `query` is long enough to strain a URL.
   */
  async postContext(options?: ContextOptions): Promise<ContextBundle> {
    return this.request<ContextBundle>("POST", "/v1/context", options ?? {});
  }

  /**
   * `GET /v1/context?render=markdown` — the boot-banner rendering.
   *
   * Returns `text/markdown`, not JSON, so this bypasses the JSON parse path.
   */
  async contextMarkdown(options?: ContextOptions): Promise<string> {
    return this.requestText("GET", `/v1/context${qs({ ...options, render: "markdown" })}`);
  }

  /**
   * `GET /v1/context?render=openai_messages` — a messages-array fragment for
   * OpenAI-SDK-shaped harnesses.
   */
  async contextMessages(options?: ContextOptions): Promise<ContextMessages> {
    return this.request<ContextMessages>(
      "GET",
      `/v1/context${qs({ ...options, render: "openai_messages" })}`,
    );
  }

  // ── Review: auto-capture candidates ────────────────────────────

  /**
   * `POST /v1/memory/extract` — mine transcript text into review candidates.
   *
   * Candidates land in the `__candidate_fact__::` review namespace and never
   * appear in `queryFacts` recall until promoted. Requires
   * `CORECRUXD_AUTO_CAPTURE=1`.
   */
  async extractMemory(options: ExtractOptions): Promise<ExtractResult> {
    return this.request<ExtractResult>("POST", "/v1/memory/extract", options);
  }

  /** `GET /v1/memory/candidates` — list review candidates, optionally by status. */
  async listCandidates(status?: CandidateStatus): Promise<CandidateListResult> {
    return this.request<CandidateListResult>("GET", `/v1/memory/candidates${qs({ status })}`);
  }

  /**
   * `POST /v1/memory/candidates/{id}/promote` — promote a candidate to a real fact.
   *
   * The gate is fail-closed: an unscored or below-threshold candidate is
   * refused (422) when `auto_threshold` is set, rather than promoted by default.
   */
  async promoteCandidate(id: string, options?: PromoteOptions): Promise<Record<string, unknown>> {
    return this.request("POST", `/v1/memory/candidates/${encodeURIComponent(id)}/promote`, options ?? {});
  }

  /** `POST /v1/memory/candidates/{id}/reject` — reject a candidate with a reason. */
  async rejectCandidate(id: string, reason: string): Promise<Record<string, unknown>> {
    return this.request("POST", `/v1/memory/candidates/${encodeURIComponent(id)}/reject`, { reason });
  }

  // ── Review: contradictions, queue, expiries ────────────────────

  /** `GET /v1/console/review/contradictions` — run a LIVE contradiction pass. */
  async reviewContradictions(options?: ReviewQueueOptions): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/console/review/contradictions${qs(options)}`);
  }

  /**
   * `GET /v1/console/review/queue` — surfaced review receipts from the
   * (default-OFF) consolidation scheduler, newest first.
   *
   * Distinct from {@link reviewContradictions}, which runs a live pass.
   */
  async reviewQueue(options?: ReviewQueueOptions): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/console/review/queue${qs(options)}`);
  }

  /**
   * `POST /v1/console/review/expiries` — apply reviewed expiry proposals.
   *
   * Every id is re-validated at apply time; ids that became protected, were
   * re-verified fresh, or gained confidence are skipped, never deleted.
   * Capped at 500 ids per request.
   */
  async applyExpiries(factIds: string[]): Promise<ExpiryApplyResult> {
    return this.request<ExpiryApplyResult>("POST", "/v1/console/review/expiries", { fact_ids: factIds });
  }

  // ── Consolidation ──────────────────────────────────────────────

  /**
   * `POST /v1/console/review/consolidations` — merge facts into one canonical
   * value, atomically, with an Ed25519-signed diff receipt.
   *
   * Facts at or above `protected_confidence_floor` (0.99 by default) are never
   * merged. The scheduler itself stays proposal-only — this is the operator's
   * explicit commit.
   */
  async consolidate(request: ConsolidationRequest): Promise<ConsolidationResult> {
    // `consolidation_id` has no serde default daemon-side, so omitting it is a
    // 422 even though the handler generates one for a BLANK value. Send the
    // empty string and let the daemon mint `console-<uuid>`.
    return this.request<ConsolidationResult>("POST", "/v1/console/review/consolidations", {
      consolidation_id: "",
      ...request,
    });
  }

  /**
   * `POST /v1/console/review/consolidations/undo` — atomically reverse a
   * consolidation and emit a signed undo receipt.
   *
   * Idempotent: undoing an already-undone consolidation returns
   * `status = "already_undone"` rather than failing.
   */
  async undoConsolidation(request: ConsolidationUndoRequest): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/console/review/consolidations/undo", request);
  }

  // ── Ingest ─────────────────────────────────────────────────────

  /**
   * `POST /v1/local/ingest` — ingest documents into a local corpus.
   *
   * Chunks without a `dense_vector` are embedded server-side, so this works
   * offline with no external embedder. Caps: 4096 documents and 65536 chunks
   * per request, 4 MiB per chunk.
   */
  async localIngest(request: LocalIngestRequest): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/local/ingest", request);
  }

  /**
   * `POST /v1/memory/import` — import a signed `CruxPack`.
   *
   * Requires `CRUX_MEMORY_IMPORT=1`. Pass `dry_run` to verify and plan without
   * writing. `tenant_id` must equal the pack manifest's tenant — there is no
   * override.
   */
  async importMemoryPack(request: MemoryImportRequest): Promise<MemoryImportResult> {
    return this.request<MemoryImportResult>("POST", "/v1/memory/import", request);
  }

  // ── Extensions ─────────────────────────────────────────────────

  /** `GET /v1/extensions` — list installed extensions. */
  async listExtensions(): Promise<Record<string, unknown>> {
    return this.request("GET", "/v1/extensions");
  }

  /** `GET /v1/extensions/{id}` — one installed extension. Returns `null` if absent. */
  async getExtension(id: string): Promise<Record<string, unknown> | null> {
    try {
      return await this.request<Record<string, unknown>>("GET", `/v1/extensions/${encodeURIComponent(id)}`);
    } catch (err) {
      if (err instanceof CueCruxError && err.status === 404) {
        return null;
      }
      throw err;
    }
  }

  /** `POST /v1/extensions/register` — register a signed `crux.integration.v1` manifest. */
  async registerExtension(manifest: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/extensions/register", { manifest });
  }

  /** `DELETE /v1/extensions/{id}` — uninstall. Returns `false` if it was not installed. */
  async deleteExtension(id: string): Promise<boolean> {
    try {
      await this.request("DELETE", `/v1/extensions/${encodeURIComponent(id)}`);
      return true;
    } catch (err) {
      if (err instanceof CueCruxError && err.status === 404) {
        return false;
      }
      throw err;
    }
  }

  /** `GET /v1/extensions/registry` — entries in the curator-signed community index. */
  async listRegistryEntries(): Promise<Record<string, unknown>> {
    return this.request("GET", "/v1/extensions/registry");
  }

  /** `POST /v1/extensions/install-from-registry` — install from the cached index. */
  async installFromRegistry(request: InstallFromRegistryRequest): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/extensions/install-from-registry", request);
  }

  /** `GET /v1/extensions/keys` — trusted signing keys. */
  async listTrustedKeys(): Promise<Record<string, unknown>> {
    return this.request("GET", "/v1/extensions/keys");
  }

  /** `POST /v1/extensions/keys` — trust a signing key at a tier. */
  async addTrustedKey(request: AddTrustedKeyRequest): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/extensions/keys", request);
  }

  /** `DELETE /v1/extensions/keys/{passportFpr}` — untrust a signing key. */
  async deleteTrustedKey(passportFpr: string): Promise<Record<string, unknown>> {
    return this.request("DELETE", `/v1/extensions/keys/${encodeURIComponent(passportFpr)}`);
  }

  /** `GET /v1/extensions/{id}/grants` — capability grants issued for an extension. */
  async listGrants(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/extensions/${encodeURIComponent(id)}/grants`);
  }

  /** `POST /v1/extensions/{id}/grants` — issue a per-passport capability grant. */
  async issueGrant(id: string, request: IssueGrantRequest): Promise<Record<string, unknown>> {
    return this.request("POST", `/v1/extensions/${encodeURIComponent(id)}/grants`, request);
  }

  /** `DELETE /v1/extensions/{id}/grants/{passportFpr}` — revoke a grant. */
  async revokeGrant(id: string, passportFpr: string): Promise<Record<string, unknown>> {
    return this.request(
      "DELETE",
      `/v1/extensions/${encodeURIComponent(id)}/grants/${encodeURIComponent(passportFpr)}`,
    );
  }

  /**
   * `POST /v1/extensions/{id}/tools/{toolName}/invoke` — dispatch one extension tool.
   *
   * The caller's passport must hold a grant naming this tool.
   */
  async invokeExtensionTool(
    id: string,
    toolName: string,
    options?: InvokeToolOptions,
  ): Promise<Record<string, unknown>> {
    return this.request(
      "POST",
      `/v1/extensions/${encodeURIComponent(id)}/tools/${encodeURIComponent(toolName)}/invoke`,
      { args: {}, ...options },
    );
  }

  // ── Events (SSE) ───────────────────────────────────────────────

  /**
   * Subscribe to real-time mutation events via Server-Sent Events.
   *
   * Returns a native `EventSource` instance. In Node.js (>=18), you may need
   * a polyfill such as `eventsource` since `EventSource` is not available in
   * the global scope until Node 22.
   *
   * @example
   * ```ts
   * const es = client.subscribeEvents({ types: ["fact.stored"] });
   * es.addEventListener("fact.stored", (e) => {
   *   console.log(JSON.parse(e.data));
   * });
   * es.onerror = (err) => console.error("SSE error", err);
   * ```
   */
  /**
   * Stream real-time mutation events over `GET /v1/events/stream`.
   *
   * Prefer this over {@link subscribeEvents}: it is built on `fetch`, so it
   * works anywhere `fetch` does (Node 18+, browsers, workers) with no
   * `EventSource` global and no polyfill, and — unlike `EventSource` — it can
   * send the `Authorization` header, so it works against a daemon with auth on.
   *
   * The stream is infinite. `break` out of the loop, or pass an `AbortSignal`,
   * to disconnect. Keep-alive comments are skipped.
   *
   * @example
   * ```ts
   * for await (const event of client.streamEvents({ types: ["fact.stored"] })) {
   *   console.log(event);
   *   break;
   * }
   * ```
   */
  async *streamEvents(options?: {
    types?: string[];
    signal?: AbortSignal;
  }): AsyncGenerator<CruxEvent, void, undefined> {
    // An explicit blank `types=` means "match nothing" daemon-side, so an
    // unfiltered subscription must omit the parameter entirely.
    const path = `/v1/events/stream${qs({ types: options?.types?.length ? options.types.join(",") : undefined })}`;
    const response = await this.send("GET", path, undefined, {
      accept: "text/event-stream",
      signal: options?.signal,
    });

    if (!response.body) {
      throw new CueCruxError(response.status, "event stream response had no body");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // SSE blocks are separated by a blank line; \r\n is legal too.
        let split: number;
        while ((split = buffer.search(/\r?\n\r?\n/)) !== -1) {
          const block = buffer.slice(0, split);
          buffer = buffer.slice(split + buffer.slice(split).match(/^\r?\n\r?\n/)![0].length);
          const event = parseSseBlock(block);
          if (event !== null) yield event as CruxEvent;
        }
      }
      const tail = parseSseBlock(buffer);
      if (tail !== null) yield tail as CruxEvent;
    } finally {
      // Covers `break` out of the for-await as well as normal completion.
      await reader.cancel().catch(() => {});
    }
  }

  /**
   * Subscribe to mutation events via the browser `EventSource` API.
   *
   * Two limitations are inherent to `EventSource` and are why
   * {@link streamEvents} is the recommended path: it cannot send custom
   * headers, so it cannot authenticate against a daemon with auth on; and the
   * global is not available in Node (still absent in 22.x without a flag), so
   * server-side callers need a polyfill.
   *
   * @example
   * ```ts
   * const es = client.subscribeEvents({ types: ["fact.stored"] });
   * es.addEventListener("fact.stored", (e) => {
   *   console.log(JSON.parse(e.data));
   * });
   * es.onerror = (err) => console.error("SSE error", err);
   * ```
   */
  subscribeEvents(options?: { types?: string[] }): EventSource {
    const params = new URLSearchParams();
    if (options?.types?.length) {
      params.set("types", options.types.join(","));
    }
    const qs = params.toString();
    const url = `${this.baseUrl}/v1/events/stream${qs ? `?${qs}` : ""}`;

    // EventSource does not support custom headers natively. For authenticated
    // SSE the token must be passed as a query parameter or via a polyfill that
    // supports headers.
    return new EventSource(url);
  }

  // ── Private helpers ────────────────────────────────────────────

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await this.send(method, path, body);

    // 204 No Content
    if (response.status === 204) {
      return undefined as unknown as T;
    }

    return (await response.json()) as T;
  }

  /** Like {@link request}, but for routes that answer with text rather than JSON. */
  private async requestText(method: string, path: string, body?: unknown): Promise<string> {
    const response = await this.send(method, path, body);
    return response.status === 204 ? "" : await response.text();
  }

  /** Issue the request and turn a non-2xx into a {@link CueCruxError}. */
  private async send(
    method: string,
    path: string,
    body?: unknown,
    options?: { accept?: string; signal?: AbortSignal },
  ): Promise<Response> {
    const url = `${this.baseUrl}${path}`;

    const headers = { ...this.headers };
    if (options?.accept) headers["Accept"] = options.accept;

    const init: RequestInit = {
      method,
      headers,
      signal: options?.signal,
    };

    if (body !== undefined && method !== "GET" && method !== "HEAD") {
      init.body = JSON.stringify(body);
    }

    const response = await fetch(url, init);

    if (!response.ok) {
      let problem: ProblemDetails | null = null;
      let message = `CueCrux API error: ${response.status} ${response.statusText}`;

      try {
        const contentType = response.headers.get("content-type") ?? "";
        if (contentType.includes("json")) {
          const parsed = (await response.json()) as Record<string, unknown>;
          if (parsed.title && parsed.status) {
            problem = parsed as unknown as ProblemDetails;
            message = problem.detail ?? problem.title;
          }
        }
      } catch {
        // Ignore JSON parse failures — the status/statusText message is sufficient.
      }

      throw new CueCruxError(response.status, message, problem);
    }

    return response;
  }
}
