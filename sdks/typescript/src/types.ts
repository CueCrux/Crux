// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

// ── Client options ──────────────────────────────────────────────────

export interface CoreCruxOptions {
  /** Base URL of the CoreCrux daemon (e.g. `http://localhost:14800`). */
  baseUrl: string;
  /** Bearer token for authentication. */
  token?: string;
}

// ── Facts ───────────────────────────────────────────────────────────

export interface Fact {
  fact_id: string;
  entity: string;
  key: string;
  value: string;
  source_receipt: string | null;
  confidence: number;
  stored_at: string;
  tokens: number;
  deleted: boolean;
  version: number;
  supersedes: string | null;
  private: boolean;
}

export interface StoreFact {
  entity: string;
  key: string;
  value: string;
  source_receipt?: string;
  confidence?: number;
  private?: boolean;
}

export interface FactQueryOptions {
  query?: string;
  entity?: string;
  entity_prefix?: string;
  top_k?: number;
  token_budget?: number;
}

export interface FactQueryResult {
  facts: Fact[];
  total_tokens: number;
}

export interface FactExportOptions {
  since?: string;
  cursor?: string;
  limit?: number;
}

export interface FactExportResult {
  facts: Fact[];
  next_cursor: string | null;
  has_more: boolean;
  exported_at: string;
}

// ── Sessions ────────────────────────────────────────────────────────

export interface SessionState {
  session_id: string;
  state: unknown;
  updated_at: string;
  total_tokens: number;
  expires_at: string | null;
}

// ── Health ──────────────────────────────────────────────────────────

export interface BuildInfo {
  version: string;
  commit: string;
}

export interface HealthzResponse {
  ok: boolean;
  build: BuildInfo;
  compat: Record<string, unknown>;
  sdk_version: string;
  routing: Record<string, unknown> | null;
  valves: Record<string, unknown> | null;
}

export interface ReadyzResponse {
  ok: boolean;
  checks?: ReadyzCheck[];
}

export interface ReadyzCheck {
  name: string;
  ok: boolean;
  error: string | null;
}

export interface VersionResponse {
  version: string;
  commit: string;
  msrv: string;
  features: {
    text_search: boolean;
    graph_expand: boolean;
    self_observe: boolean;
    mcp: boolean;
  };
  sync?: {
    mode: string;
    configured: boolean;
    background_sync_enabled: boolean;
    remote_url: string;
    api_key_configured: boolean;
    degraded: boolean;
    degraded_reason?: string | null;
  };
  update?: {
    enabled: boolean;
    state:
      | "disabled"
      | "current"
      | "behind"
      | "ahead"
      | "diverged"
      | "unavailable"
      | "error";
    remote: string;
    ref: string;
    tracking_ref: string;
    repo_dir?: string | null;
    current_commit?: string | null;
    latest_commit?: string | null;
    ahead_by: number;
    behind_by: number;
    checked_at?: string | null;
    error?: string | null;
    comparison_stale?: boolean;
    /** Which ref the primary ahead_by/behind_by/current_commit describe: the running binary or the source checkout. Commit fields (binary_commit/checkout_commit) are admin-only. */
    basis?: "binary" | "checkout" | string;
    binary_commit?: string | null;
    checkout_commit?: string | null;
    checkout_ahead_by?: number;
    checkout_behind_by?: number;
    upgrade_hint: string;
  };
}

// ── Query: Text Search ──────────────────────────────────────────────

export interface TextSearchOptions {
  tenant_id: string;
  query: string;
  limit?: number;
  token_budget?: number;
  min_score?: number;
  mode?: "normal" | "scan";
}

export interface TextSearchHit {
  segment_index: number;
  doc_id: number;
  score: number;
  frame_offset: number;
  token_count: number;
}

export interface TextSearchCoverage {
  score: number;
  gaps: TextSearchGap[];
  below_floor: number;
}

export interface TextSearchGap {
  query_terms: string[];
  match_quality: string;
  suggestion: string;
}

export interface TextSearchResult {
  results: TextSearchHit[];
  coverage: TextSearchCoverage;
  meta: {
    backend: string;
    took_ms: number;
    segments_searched: number;
    total_docs: number;
    total_candidates?: number;
  };
  tokens_used?: number;
  tokens_available?: number;
  results_omitted?: number;
  scan_mode?: boolean;
}

// ── Query: Text Search Expand ───────────────────────────────────────

export interface TextSearchExpandOptions {
  tenant_id: string;
  result_ids: { segment_index: number; doc_id: number }[];
}

export interface TextSearchExpandResult {
  chunks: {
    segment_index: number;
    doc_id: number;
    frame_offset: number;
    token_count: number;
  }[];
  tokens_loaded: number;
}

// ── Query: Graph Expand ─────────────────────────────────────────────

export interface GraphExpandOptions {
  tenant_id: string;
  seed_artifact_ids: number[];
  edge_types?: string[];
  max_hops?: number;
  budget?: number;
  min_confidence?: number;
  include_state?: boolean;
}

export interface GraphExpandArtifact {
  artifact_id: number;
  score: number;
  hop_distance: number;
  edge_types_used: string[];
  state?: {
    living_status: string;
    confidence: number;
    updated_at_micros: number;
    trunk_tier: number;
  };
}

export interface GraphExpandResult {
  artifacts: GraphExpandArtifact[];
  traversal_stats: {
    nodes_visited: number;
    hops_used: number;
    budget_remaining: number;
    edges_traversed: number;
  };
}

// ── Query: Time Range ───────────────────────────────────────────────

export interface TimeRangeOptions {
  tenant_id: string;
  start_micros: number;
  end_micros: number;
  artifact_ids?: number[];
  include_relations?: boolean;
  limit?: number;
}

export interface TimeRangeArtifact {
  artifact_id: number;
  living_status: string;
  confidence: number;
  updated_at_micros: number;
  relations_changed: {
    src_artifact_id: number;
    dst_artifact_id: number;
    relation_type: string;
    confidence: number;
    created_at_micros: number;
    updated_at_micros: number;
  }[];
  relation_change_count: number;
}

export interface TimeRangeResult {
  artifacts_changed: TimeRangeArtifact[];
  scan_stats: {
    artifacts_scanned: number;
    relations_scanned: number;
    total_changes: number;
  };
}

// ── Events (SSE) ────────────────────────────────────────────────────

export type CruxEventType = "fact.stored" | "fact.deleted" | "session.stored" | "session.deleted";

export interface CruxEventFactStored {
  type: "fact.stored";
  fact_id: string;
  entity: string;
  key: string;
}

export interface CruxEventFactDeleted {
  type: "fact.deleted";
  fact_id: string;
}

export interface CruxEventSessionStored {
  type: "session.stored";
  session_id: string;
}

export interface CruxEventSessionDeleted {
  type: "session.deleted";
  session_id: string;
}

export type CruxEvent =
  | CruxEventFactStored
  | CruxEventFactDeleted
  | CruxEventSessionStored
  | CruxEventSessionDeleted;

// ── Error ───────────────────────────────────────────────────────────

/** RFC 9457 Problem Details returned by the CoreCrux API on error. */
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  extensions?: Record<string, unknown>;
}
