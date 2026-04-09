// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

export * from "./types.js";

import type {
  CoreCruxOptions,
  Fact,
  FactExportOptions,
  FactExportResult,
  FactQueryOptions,
  FactQueryResult,
  GraphExpandOptions,
  GraphExpandResult,
  HealthzResponse,
  ProblemDetails,
  ReadyzResponse,
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
 * Error thrown when the CoreCrux API returns a non-2xx response.
 * Carries the RFC 9457 Problem Details body when available.
 */
export class CoreCruxError extends Error {
  public readonly status: number;
  public readonly problem: ProblemDetails | null;

  constructor(status: number, message: string, problem: ProblemDetails | null = null) {
    super(message);
    this.name = "CoreCruxError";
    this.status = status;
    this.problem = problem;
  }
}

// ── Client ──────────────────────────────────────────────────────────

export class CoreCruxClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor(options: CoreCruxOptions) {
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
      if (err instanceof CoreCruxError && err.status === 404) {
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
      if (err instanceof CoreCruxError && err.status === 404) {
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
      if (err instanceof CoreCruxError && err.status === 404) {
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
    const url = `${this.baseUrl}${path}`;

    const init: RequestInit = {
      method,
      headers: { ...this.headers },
    };

    if (body !== undefined && method !== "GET" && method !== "HEAD") {
      init.body = JSON.stringify(body);
    }

    const response = await fetch(url, init);

    if (!response.ok) {
      let problem: ProblemDetails | null = null;
      let message = `CoreCrux API error: ${response.status} ${response.statusText}`;

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

      throw new CoreCruxError(response.status, message, problem);
    }

    // 204 No Content
    if (response.status === 204) {
      return undefined as unknown as T;
    }

    return (await response.json()) as T;
  }
}
