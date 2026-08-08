// Copyright (c) 2026 CueCrux Ltd.
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

// ── Client options ──────────────────────────────────────────────────

export interface CueCruxOptions {
  /** Base URL of the CueCrux daemon (e.g. `http://localhost:14800`). */
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

export interface CruxEventSessionArchived {
  type: "session.archived";
  session_id: string;
}

export interface CruxEventAuditStep {
  type: "observe.audit_step";
  [key: string]: unknown;
}

export interface CruxEventOrchestratorChanged {
  type: "orchestrator.changed";
  [key: string]: unknown;
}

export interface CruxEventPunchcardChanged {
  type: "punchcard.changed";
  [key: string]: unknown;
}

export interface CruxEventActivityAppended {
  type: "activity.appended";
  [key: string]: unknown;
}

export type CruxEvent =
  | CruxEventFactStored
  | CruxEventFactDeleted
  | CruxEventSessionStored
  | CruxEventSessionDeleted
  | CruxEventSessionArchived
  | CruxEventAuditStep
  | CruxEventOrchestratorChanged
  | CruxEventPunchcardChanged
  | CruxEventActivityAppended;

/**
 * Every event type the daemon emits on `GET /v1/events/stream`.
 *
 * These strings travel twice on the wire — once as the SSE `event:` name and
 * once as the JSON `type` field — and the daemon pins the two together in
 * `events::tests::sse_names_match_the_serde_tags`.
 */
export const CRUX_EVENT_TYPES = [
  "fact.stored",
  "fact.deleted",
  "session.stored",
  "session.deleted",
  "session.archived",
  "observe.audit_step",
  "orchestrator.changed",
  "punchcard.changed",
  "activity.appended",
] as const;

export type CruxEventType = (typeof CRUX_EVENT_TYPES)[number];

// ── Error ───────────────────────────────────────────────────────────

/** RFC 9457 Problem Details returned by the CueCrux API on error. */
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  extensions?: Record<string, unknown>;
}

// ── Context bundle (`context_bundle/v1`) ────────────────────────────

export type SectionKind = "facts" | "dossier" | "session_state" | "work_table" | "coord";
export type Freshness = "fresh" | "stale" | "unknown";
export type HorizonClass = "volatile" | "medium" | "stable" | "none";
export type ContextRender = "json" | "markdown" | "openai_messages";

export interface ContextOptions {
  /** Include the saved state for this consumer session as a `session_state` section. */
  session_id?: string;
  /** Typed address resolved first (`execplan:<slug>`, `bench:<id>`, …). */
  entity?: string;
  /** Keyword recall over fact values/keys/entities. */
  query?: string;
  /** `budget.requested`. Defaults to 2000, hard-capped by the tier ceiling (8000 free/local). */
  token_budget?: number;
}

/** One fact inside the byte-stable region. Stale items are annotated, never dropped. */
export interface StableFactItem {
  fact_id: string;
  entity: string;
  key: string;
  value: string;
  confidence: number;
  horizon_class: HorizonClass;
  freshness: Freshness;
  est_tokens: number;
}

export interface AuxItem {
  id: string;
  text: string;
  est_tokens?: number | null;
}

export interface StableSection {
  kind: SectionKind;
  /** Present on the `facts` section; ordered by (entity, key, fact_id). */
  facts?: StableFactItem[];
  /** Present on non-fact sections; ordered by id. */
  items?: AuxItem[];
  est_tokens: number;
}

/** Items that did not fit the budget. Truncation is explicit, never silent. */
export interface DroppedReport {
  kind: SectionKind;
  count: number;
  reason: string;
}

export interface BudgetReport {
  requested: number;
  ceiling: number;
  spent_est: number;
  dropped?: DroppedReport[];
}

/**
 * The `GET/POST /v1/context` JSON body.
 *
 * Note this is the flattened wire envelope, not the daemon's internal
 * `ContextBundle` struct: `sections` sits at the top level rather than under
 * a `stable` key. `stable_hash` covers the stable region only — the
 * `bundle_version` + ordered `sections` — so it is byte-stable across calls
 * for an unchanged fact-chain head. Everything else here is volatile.
 */
export interface ContextBundle {
  bundle_version: string;
  passport: string | null;
  session_id: string | null;
  assembled_at: string;
  budget: BudgetReport;
  sections: StableSection[];
  stable_hash: string;
  receipt_ref: string | null;
  /** Present only when receipt minting failed; the bundle is still served. */
  receipt_error?: string;
}

/** The `render=openai_messages` fragment — drop `messages` into an OpenAI-SDK call. */
export interface ContextMessages {
  bundle_version: string;
  messages: Array<{ role: "system"; content: string }>;
  metadata: {
    stable_hash: string;
    assembled_at: string;
    receipt_ref: string | null;
    budget: BudgetReport;
  };
}

// ── Review: auto-capture candidates + contradictions + expiries ─────

export type CandidateStatus = "candidate" | "promoted" | "rejected";

export interface ExtractOptions {
  /** Raw session/transcript text to mine. */
  text: string;
  /** Recorded as candidate provenance. */
  session_id?: string;
  /** `comprehensive` | `money` | `counts` | `dates` | `version_chains`. */
  profile?: string;
  /** ISO date used to fill the year on month-day dates. */
  session_date?: string;
}

export interface ExtractResult {
  schema: string;
  extracted: number;
  written: number;
  skipped_existing: number;
  candidates: Array<Record<string, unknown>>;
}

export interface CandidateListResult {
  schema: string;
  count: number;
  candidates: Array<Record<string, unknown>>;
}

export interface PromoteOptions {
  /** Reviewer identity recorded on the promoted fact. */
  reviewer?: string;
  /**
   * Score-gated automatic promotion at this threshold instead of an explicit
   * review. The daemon refuses unscored or below-threshold candidates (422) —
   * the fail-closed gate. Omit for an explicit operator promotion.
   */
  auto_threshold?: number;
}

export interface ReviewQueueOptions {
  /** Defaults to 50 daemon-side, capped at 250. */
  limit?: number;
}

export interface ExpiryApplyResult {
  schema: string;
  expired_count: number;
  skipped_count: number;
  expired: unknown[];
  skipped: unknown[];
  actor: string;
}

// ── Consolidation ───────────────────────────────────────────────────

export interface ConsolidationRequest {
  /**
   * Omit to let the daemon mint `console-<uuid>`. The SDK sends an empty
   * string on your behalf: the field has no serde default daemon-side, so a
   * genuinely absent key is rejected (422) even though a blank one is filled in.
   */
  consolidation_id?: string;
  entity: string;
  key: string;
  canonical_value: string;
  target_fact_ids: string[];
  protected_fact_ids?: string[];
  confidence?: number;
  source_receipt?: string;
  /** Defaults daemon-side to the caller's console actor. */
  actor?: string;
  horizon_class?: HorizonClass;
  /** Facts at or above this confidence are never merged. Defaults to 0.99. */
  protected_confidence_floor?: number;
}

export interface ConsolidationResult {
  schema: string;
  status: string;
  receipt: Record<string, unknown>;
  /** Ed25519-signed, offline-verifiable diff receipt. */
  signed_receipt: Record<string, unknown> | null;
}

export interface ConsolidationUndoRequest {
  canonical_fact_id: string;
  source_fact_ids?: string[];
  entity?: string;
  key?: string;
}

// ── Ingest ──────────────────────────────────────────────────────────

export interface LocalIngestChunk {
  chunk_id: string;
  text: string;
  chunk_index?: number;
  /**
   * Precomputed dense vector. Omit to let the daemon embed server-side.
   * A batch whose declared `semantic_profile` fingerprint differs from the
   * node's is refused with 422 rather than stored unqueryable.
   */
  dense_vector?: number[];
  metadata?: Record<string, unknown>;
}

export interface LocalIngestDocument {
  doc_id: string;
  title?: string;
  url?: string;
  source_timestamp?: string;
  chunks: LocalIngestChunk[];
}

export interface LocalIngestRequest {
  tenant_id: string;
  corpus_id: string;
  documents: LocalIngestDocument[];
  /** Declared profile for caller-supplied `dense_vector`s. */
  semantic_profile?: Record<string, unknown>;
}

export interface MemoryImportRequest {
  /** Must equal the pack manifest's `tenant_id` — there is no override. */
  tenant_id: string;
  /** Verify and plan only; write nothing. */
  dry_run?: boolean;
  /** Principal remap table (`src` actor → `dst` actor). */
  principal_map?: Record<string, string>;
  /** A `CruxPack` as produced by `corecruxctl memory pack`. */
  pack: Record<string, unknown>;
}

export interface MemoryImportResult {
  ok: boolean;
  dry_run: boolean;
  pack_hash: string;
  pack_passport_fpr: string;
  imported_facts: number;
  collisions_superseded: number;
  skipped_duplicate_facts: number;
  imported_sessions: number;
  skipped_sessions: number;
  private_facts: number;
}

// ── Extensions ──────────────────────────────────────────────────────

export type TrustTier = "official" | "verified" | "community";

export interface IssueGrantRequest {
  passport_fpr: string;
  allowed_tool_names?: string[];
  allowed_prefixes_read?: string[];
  allowed_prefixes_write?: string[];
  rate_limit_per_min?: number;
}

export interface AddTrustedKeyRequest {
  passport_fpr: string;
  public_key_hex: string;
  trust_tier: TrustTier;
  added_by?: string;
}

export interface InstallFromRegistryRequest {
  id: string;
  /** Alternate cached index path; relative paths resolve under `data_dir`. */
  index_path?: string;
}

export interface InvokeToolOptions {
  /** Defaults to the `X-Corecrux-Passport-Id` header when omitted. */
  passport_fpr?: string;
  /** Forwarded to the extension endpoint as-is. */
  args?: Record<string, unknown>;
}
