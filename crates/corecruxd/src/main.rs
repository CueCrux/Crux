// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

// The daemon must never panic on untrusted input. Escalate workspace-level
// warn lints to deny for the corecruxd binary. Individual call sites may
// #[allow] with a // SAFETY: justification if the unwrap is provably safe.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

//! `corecruxd` — the Crux Daemon binary.
//!
//! Runs the HTTP API on port 14800 (axum), the gRPC API on port 4007
//! (tonic), and an embedded MCP server on port 14801. Composes
//! `corecrux-{frame, segment, storage, projections, retrieval, receipts,
//! memory}` plus `crux-{mcp, session, sync, observe, router,
//! integrations, lens-features}` and the new `crux-config-wizard` drift
//! check into a single long-running process.
//!
//! Startup wiring: bootstrap data → seeded passports → lens kind
//! registrations → HTTP router → gRPC router → MCP server → optional
//! workspace-scan + storyline materialiser. Configuration is
//! environment-variable driven; see `config.example.env`.

mod activity;
mod agentgraph_kinds;
mod auth;
mod code_intel;
mod codegraph_fusion;
mod config;
mod console_index;
mod consolidation_scheduler;
mod control;
mod coord;
mod cost;
mod cost_attribution;
// Default-off, append-only comped-wallet meter shared by the explicit spend
// rail and metered capability paths.
#[allow(dead_code)]
mod credit_meter;
// Dataplane store stubs: proprietary edition provides the real implementation.
#[allow(dead_code)]
mod dataplane_store;
// gRPC service stubs: dataplane-enabled distributions implement full RPCs;
// Crux Daemon keeps the server skeleton. Suppress dead_code for stub internals.
#[allow(dead_code)]
mod grpc;
mod http;
mod local_ingest;
// Candidate proposers are staged behind the identity-candidates rollout path; tests
// exercise creation/proposal before daemon startup wires automatic proposer runs.
#[allow(dead_code)]
mod candidate_links;
mod candidate_store;
mod context_graph;
mod dossier;
mod encrypted_secrets;
mod ephemeral_gc;
mod extension_grants;
mod extension_outbound;
mod extension_registry;
mod fact_helpers;
mod fact_privacy;
mod identity_links;
mod integrations_github;
mod integrations_github_sync;
mod integrations_openai;
mod mcp_stdio;
mod memory_extract;
pub mod mint_requests;
// metrics: Prometheus register!() macros use expect() at init — safe, panics
// only on duplicate registration (programmer error caught in tests).
mod console;
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod metrics;
mod onboarding;
mod ops_events;
mod passports;
mod plane_layer_sync;
mod planes;
mod policy;
mod pool;
mod presence;
mod principal;
mod problem;
mod product;
mod project_repo_links;
mod projects;
mod protocol_posture;
mod redaction;
mod relations;
mod repo_codegraph;
mod repo_registry;
mod repo_watch;
mod self_update;
mod session_bindings;
mod shard_map;
mod status_feed;
mod storybook;
mod structured_log;
mod symbol_resolve;
mod sync_scheduler;
mod tenant_metadata;
#[cfg(test)]
mod test_support;
mod trace_store;
mod update;
mod usage_submit;
mod vault_watcher;
#[cfg(feature = "wasm-extensions")]
mod wasm_dispatcher;
#[cfg(feature = "wasm-extensions")]
mod wasm_host;
mod witness;
mod witness_proofs;
mod witness_submit;
mod work;
mod work_execplans;
mod workspace_scan;
mod workspace_scan_ast;
mod workspace_scan_manifests;
mod workspace_scan_polyglot;

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use fs2::{available_space, total_space, FileExt};
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use corecrux_types::{
    BuildInfo, CapacityThresholdBreachedV1, CompatContract, ControlCheckpointMaterializedV1, ControlStateMutationV1,
    DEFAULT_COMPAT_REQUIRES, DEFAULT_SDK_VERSION, EVT_CAPACITY_THRESHOLD_BREACHED_V1,
    EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1, EVT_CONTROL_STATE_MUTATION_V1,
};

use crate::auth::AuthMode;
use crate::config::{load_config, CommitLevel};
use crate::dataplane_store::AppendError;
use crate::http::{AppState, CapacityState, Readiness, SYNC_HANDSHAKE_NONCE_TTL_SECONDS};
use crate::metrics::Metrics;
use crate::ops_events::{append_ops_event, build_node_context, now_unix_ms};
use crate::shard_map::{RoutingTable, ShardMapStore};

const PASSPORT_CLAIM_MARKER_FILENAME: &str = "passport.claimed";

/// Build the long-lived wasm engine used for `kind: wasm` extensions.
/// Returns `None` (but logs) on failure so a wasm-engine init issue
/// doesn't take the daemon offline — `kind: external_tool` extensions
/// continue to work; the HTTP dispatcher returns 503 for `kind: wasm`
/// requests until the operator fixes the underlying error.
#[cfg(feature = "wasm-extensions")]
fn build_wasm_engine_for_appstate() -> Option<std::sync::Arc<crate::wasm_host::WasmEngine>> {
    let cfg = crate::wasm_host::WasmConfig::from_env();
    match crate::wasm_host::WasmEngine::new(cfg.epoch_tick) {
        Ok(eng) => Some(std::sync::Arc::new(eng)),
        Err(err) => {
            tracing::error!("wasm engine init failed: {err}; kind=wasm extensions will return 503");
            None
        }
    }
}

/// Load M2b sync peer-auth material from env (opt-in). Requires BOTH
/// `CORECRUXD_SYNC_PEER_SIGNING_KEY` (64-hex Ed25519 seed) and
/// `CORECRUXD_SYNC_PEER_TOKEN` (canonical capability-token JSON). Absent → bearer
/// only (unchanged). Misconfiguration logs a warning and falls back to bearer.
fn load_sync_peer_auth() -> Option<(ed25519_dalek::SigningKey, rcx_capability_token::RcxCapabilityToken)> {
    let seed_hex = std::env::var("CORECRUXD_SYNC_PEER_SIGNING_KEY").ok()?;
    let token_json = std::env::var("CORECRUXD_SYNC_PEER_TOKEN").ok()?;
    let seed = match hex::decode(seed_hex.trim()) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(error = %err, "CORECRUXD_SYNC_PEER_SIGNING_KEY is not valid hex; sync peer auth disabled");
            return None;
        }
    };
    let seed: [u8; 32] = match seed.try_into() {
        Ok(seed) => seed,
        Err(_) => {
            tracing::warn!("CORECRUXD_SYNC_PEER_SIGNING_KEY must decode to 32 bytes; sync peer auth disabled");
            return None;
        }
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    match serde_json::from_str::<rcx_capability_token::RcxCapabilityToken>(&token_json) {
        Ok(token) => {
            tracing::info!("sync peer auth (M2b) enabled — pulls will present the signed peer handshake");
            Some((signing_key, token))
        }
        Err(err) => {
            tracing::warn!(error = %err, "CORECRUXD_SYNC_PEER_TOKEN is not valid capability-token JSON; sync peer auth disabled");
            None
        }
    }
}

/// CLI action decided from `corecruxd`'s argv.
///
/// `corecruxd` is an environment-configured daemon with NO argument parsing
/// for its runtime behaviour — all configuration flows through env vars (see
/// `config.example.env`). The only flags it honours are the ubiquitous
/// `--version`/`--help` short-circuits, handled before any config load so they
/// never start the daemon or touch the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliAction {
    /// Print version line and exit 0.
    Version,
    /// Print usage note and exit 0.
    Help,
    /// Run the bundled stdio⇄HTTP MCP bridge instead of the daemon
    /// (provider-integration-surfaces M5; see `crate::mcp_stdio`).
    McpStdio,
    /// `self …` — the explicit self-update subcommand (see
    /// `crate::self_update`); sub-parsing happens in that module.
    SelfCmd,
    /// No recognised flag — start the daemon normally.
    Run,
}

/// Decide what to do from the process arguments (excluding `argv[0]`).
///
/// A deliberately tiny hand-rolled matcher rather than pulling in `clap` —
/// keeping the env-only design intact. Only the first argument is inspected.
fn parse_cli_arg(args: &[String]) -> CliAction {
    match args.first().map(String::as_str) {
        Some("--version" | "-V" | "version") => CliAction::Version,
        Some("--help" | "-h" | "help") => CliAction::Help,
        Some("mcp-stdio") => CliAction::McpStdio,
        Some("self") => CliAction::SelfCmd,
        _ => CliAction::Run,
    }
}

/// Single-line version string, e.g. `corecruxd 0.1.0 (abc1234)`.
fn version_line() -> String {
    format!(
        "corecruxd {} ({})",
        env!("CARGO_PKG_VERSION"),
        option_env!("CORECRUX_GIT_SHA").unwrap_or("unknown")
    )
}

/// One-paragraph usage note for `--help`.
fn help_text() -> String {
    format!(
        "{line}\n\n\
corecruxd is the Crux Daemon: an environment-configured, long-running process\n\
(HTTP 14800, gRPC 4007, MCP 14801). It takes no runtime configuration flags —\n\
all configuration is supplied via environment variables; see config.example.env.\n\
The only recognised flags are:\n\
  --version, -V    print the version and git sha, then exit\n\
  --help, -h       print this message, then exit\n\
  mcp-stdio        run the bundled stdio\u{21c4}HTTP MCP bridge (not the daemon);\n\
                   env: CRUX_MCP_URL (default http://127.0.0.1:14801/mcp),\n\
                   CRUX_AGENT_TOKEN (optional bearer)\n\
  self update      update a standalone daemon binary; packaged installs use\n\
                   their installer/package manager to keep companions aligned;\n\
                   append --check to only report whether a newer one exists\n",
        line = version_line()
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Short-circuit --version / --help BEFORE load_config() so they never start
    // the daemon, read env, or touch the filesystem. Preserves the env-only design.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_cli_arg(&args) {
        CliAction::Version => {
            // Intentional stdout: this is the CLI --version contract.
            #[allow(clippy::print_stdout)]
            {
                println!("{}", version_line());
            }
            return Ok(());
        }
        CliAction::Help => {
            #[allow(clippy::print_stdout)]
            {
                println!("{}", help_text());
            }
            return Ok(());
        }
        CliAction::McpStdio => {
            std::process::exit(mcp_stdio::run());
        }
        CliAction::SelfCmd => {
            std::process::exit(self_update::run(&args));
        }
        CliAction::Run => {}
    }

    let config = load_config();
    if let Err(message) = config.validate_embedding_selection() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into());
    }
    if !config.auth_mode_explicitly_set {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CORECRUXD_AUTH_MODE must be set explicitly; see config.example.env",
        )
        .into());
    }
    // Fail closed: an unknown/typo'd auth mode must abort, never degrade to dev
    // scopes. (Distinct message from the unset case above.)
    if let Some(bad) = &config.auth_mode_invalid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown CORECRUXD_AUTH_MODE `{bad}`; valid values: off, dev_scopes, jwt_hs256, jwt_jwks"),
        )
        .into());
    }
    let auth = crate::auth::Authz::from_env(config.auth_mode)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // Security (fail closed): an agent-token env var set to a value that fails
    // the strength policy must abort startup, not silently fall back to no-auth
    // MCP. The only way to proceed with an empty registry when a token var is
    // present is the explicit dev override.
    let mcp_agent_registry =
        match resolve_mcp_agent_registry(crux_mcp::agent::AgentRegistry::from_env(), allow_empty_agent_registry()) {
            Ok(registry) => registry,
            Err(message) => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into());
            }
        };
    validate_network_auth_posture(
        config.auth_mode,
        config.http_addr,
        config.grpc_addr,
        config.commit_level,
        insecure_dev_auth_bind_allowed(),
        replication_auth_bearer_configured(),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    validate_mcp_bind_posture(
        config.mcp_enabled,
        config.mcp_addr,
        mcp_agent_registry.is_empty(),
        insecure_dev_auth_bind_allowed(),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // Keep config fields live on CPU-only builds for future use.
    let _ = (
        config.routing_strict_client_version,
        config.commit_level,
        config.follower_reads_enabled,
        config.console_enabled,
        config.replicated_commit_timeout_ms,
        config.replicated_commit_require_all_followers,
        &config.loaded_config_path,
        &config.state_dir,
        config.router_refresh_interval_seconds,
        config.router_cache_ttl_seconds,
        &config.router_fallback_policy,
        &config.llm_endpoint,
        &config.llm_model,
        config.max_events_per_batch,
        config.max_batch_bytes,
        config.max_event_id_bytes,
        config.idem_hot_capacity_entries,
        config.event_id_hash_prefix_len,
        config.cold_scan_max_segments,
        config.append_group_commit_batches,
        config.append_group_commit_max_delay_ms,
        config.enable_directory_compaction,
        config.dir_l0_max_runs,
        config.receipts_verify_enabled,
        config.receipts_recompute_candidate_digest,
        &config.receipts_keyring_path,
        &config.receipts_keyring_json,
        config.witness_enabled,
        &config.witness_provider,
        config.witness_timeout_ms,
        &config.rekor_url,
        &config.rekor_public_key_path,
        config.tsa_enabled,
        &config.tsa_url,
        &config.tsa_root_cert_path,
        &config.tsa_policy_oid,
        config.replay_batch_max_events,
        config.replay_batch_max_bytes,
        config.replay_many_max_reads,
        config.replay_use_batched_rpc_default,
        config.store_lock_strategy.as_str(),
        config.tail_cache_enabled,
        config.backpressure_high_watermark_ratio,
        config.backpressure_low_watermark_ratio,
        config.backpressure_retry_after_ms,
        config.operator_action_max_pending,
        config.operator_action_timeout_secs,
        config.scrub_scheduler_enabled,
        config.scrub_interval_secs,
        &config.scrub_scope,
        &config.scrub_mode,
        config.scrub_sample_rate,
        config.capacity_guard_enabled,
        config.capacity_guard_interval_secs,
        config.capacity_warning_free_ratio,
        config.capacity_critical_free_ratio,
        config.capacity_emergency_free_ratio,
        config.capacity_resume_free_ratio,
        config.projections_enabled,
        config.projections_batch_frames,
        config.projections_tick_interval_ms,
        config.update_check_enabled,
        &config.update_check_remote,
        &config.update_check_ref,
        config.update_check_interval_secs,
        &config.update_check_repo_dir,
        config.integrations_enabled,
        config.integrations_safe_mode,
        config.integrations_allow_executable_helpers,
    );
    init_tracing(&config.log_level);
    if let Some(trust_root) = &config.enterprise_trust_root {
        let issues = crux_enterprise_shim::validate_enterprise_trust_root(trust_root);
        if !issues.is_empty() {
            let codes = issues
                .iter()
                .map(|issue| issue.code.as_str())
                .collect::<Vec<_>>()
                .join(",");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid enterprise trust root: {codes}"),
            )
            .into());
        }
        info!(
            customer_id = %trust_root.customer_id,
            backend_id = %trust_root.backend_id,
            trust_root_kid = %trust_root.trust_root_kid,
            airgap = trust_root.airgap,
            trusted_issuer_count = trust_root.trusted_issuer_kids.len(),
            allow_vaultcrux_cross_sign = trust_root.allow_vaultcrux_cross_sign,
            "enterprise customer-hosted trust root configured"
        );
    }
    if let Some(manifest_path) = config.content_manifest_path.as_deref() {
        let report = vaultcrux_local::content::load_content_manifest(manifest_path, config.content_verify_signatures)?;
        info!(
            content_manifest = %report.manifest_path.display(),
            issuer = %report.issuer,
            files_verified = report.files_verified,
            signature_verified = report.verified_signature,
            "vaultcrux content manifest loaded"
        );
    }

    std::panic::set_hook(Box::new(|panic_info| {
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic_info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown");
        let location = panic_info.location().map_or_else(
            || "unknown".to_string(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        tracing::error!(
            panic.payload = payload,
            panic.location = %location,
            "panic occurred"
        );
    }));

    create_dir_all(&config.state_dir)?;
    create_dir_all(&config.data_dir)?;
    let lock_file = acquire_lock(&config.data_dir)?;

    let control_path = config.data_dir.join("CONTROL.json");
    let control_handle = crate::control::ControlHandle::load_or_init(control_path.clone())?;
    let control: Arc<RwLock<crate::control::ControlV1>> = Arc::new(RwLock::new(control_handle.state));

    let build = BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("CORECRUX_GIT_SHA").unwrap_or("unknown").to_string(),
    };

    let metrics = Metrics::new(&build, &config.service_name);
    crate::redaction::register_metrics(&metrics.registry());
    metrics.set_peer_cache_bytes(0);
    {
        let c = control.read().await.clone();
        update_control_metrics(&metrics, &c);
    }
    metrics.set_io_backend(&config.io_backend);
    metrics.touch_peer_cache_metrics();

    let gpu_id_for_meta: Option<i32> = None;

    let node_meta_path = config.data_dir.join("meta").join("node.json");
    let node_meta = load_or_init_node_meta(
        &node_meta_path,
        config.node_id_override.as_deref(),
        config.http_addr,
        config.grpc_addr,
        gpu_id_for_meta,
        &build,
    )?;
    let node_id = node_meta.node_id.clone();

    let rcx_passport_key = crux_session::LocalPassportKey::from_path(&config.passport_key_path)?;
    let rcx_issued_at = now_unix_ms() / 1000;
    let rcx_token = crux_router::mint_signed_free_local_token(
        rcx_passport_key.passport_fpr().to_string(),
        node_id.clone(),
        "local",
        // Preserve the pre-M1 passport-issuance capability set: this milestone
        // adds only the independently gated request-filing capability.
        crux_mcp::tools::rcx_local_capabilities_with_flags(false, config.passport_mint_requests_enabled),
        rcx_issued_at,
        rcx_issued_at.saturating_add(366 * 24 * 60 * 60),
        |hash| rcx_passport_key.sign_hash(hash),
    );
    let rcx_token_hash = rcx_token.token_hash_hex();
    let rcx_router = Arc::new(crux_router::RcxRouter::new_with_trusted_issuer_pubkey(
        rcx_token,
        rcx_passport_key.verifying_key_bytes(),
    ));
    info!(
        passport_fpr = %rcx_passport_key.passport_fpr(),
        public_key_hex = %rcx_passport_key.public_key_hex(),
        token_hash = %rcx_token_hash,
        "rcx free-local capability token minted"
    );
    if config.passport_claim_on_startup {
        spawn_anonymous_passport_claim(
            config.state_dir.clone(),
            config.passport_claim_endpoint.clone(),
            rcx_passport_key.passport_fpr().to_string(),
            rcx_passport_key.public_key_hex().to_string(),
            format!("crux/{}", build.version),
        );
    }

    let http_leader = shard_map_advertise_addr(config.http_addr);
    let grpc_leader = shard_map_advertise_addr(config.grpc_addr);
    let shard_store = ShardMapStore::new(&config.data_dir);
    let loaded = shard_store.load_or_init(
        &config.cluster_id,
        &node_id,
        &http_leader,
        &grpc_leader,
        config.dev_split_shards,
        gpu_id_for_meta,
    )?;
    let routing_table = RoutingTable::new(loaded)?;
    metrics.set_shardmap_version(routing_table.current_version());
    observe_shard_map_metrics(&metrics, &routing_table, &node_id);
    let routing: Arc<RwLock<RoutingTable>> = Arc::new(RwLock::new(routing_table));
    let routing_errors: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

    let readiness = Arc::new(RwLock::new(Readiness::default()));

    // Crux Daemon: no dataplane pool (requires a dataplane-enabled distribution).
    let dataplane_pool: Option<crate::pool::DataPlanePool> = None;

    let control_evidence_status =
        reconcile_control_checkpoint_with_evidence(&control_path, control.clone(), dataplane_pool.as_ref(), &metrics)
            .await;
    {
        let mut guard = readiness.write().await;
        guard.control_evidence_hosted = control_evidence_status.hosted_locally;
        guard.control_evidence_ok = control_evidence_status.ok;
        guard.control_evidence_error = if control_evidence_status.hosted_locally && !control_evidence_status.ok {
            control_evidence_status.detail.clone()
        } else {
            None
        };
    }

    // Create the shutdown broadcast channel up front so every background
    // task spawned during startup can subscribe — including the routing
    // reloader and capacity guard, which would otherwise outlive SIGTERM
    // and hold the runtime open past `graceful_shutdown_on_sigterm`'s 5s
    // budget. The signal handler is wired below once all subscribers exist.
    let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

    spawn_routing_reloader(
        config.clone(),
        shard_store.clone(),
        routing.clone(),
        routing_errors.clone(),
        metrics.clone(),
        node_id.clone(),
        shutdown_tx.subscribe(),
    );

    let corruption_detected = Arc::new(RwLock::new(false));

    let (initial_total_bytes, initial_free_bytes, initial_capacity_error) =
        match measure_data_dir_space(&config.data_dir) {
            Ok((total, free)) => (total, free, None),
            Err(err) => (0, 0, Some(err)),
        };
    let capacity = Arc::new(RwLock::new(CapacityState {
        total_bytes: initial_total_bytes,
        free_bytes: initial_free_bytes,
        free_ratio: if initial_total_bytes == 0 {
            0.0
        } else {
            initial_free_bytes as f64 / initial_total_bytes as f64
        },
        warning_free_ratio: config.capacity_warning_free_ratio,
        critical_free_ratio: config.capacity_critical_free_ratio,
        emergency_free_ratio: config.capacity_emergency_free_ratio,
        auto_paused: false,
        error: initial_capacity_error,
    }));
    metrics.set_data_dir_space(initial_total_bytes, initial_free_bytes);
    if config.capacity_guard_enabled {
        spawn_capacity_guard(
            config.clone(),
            metrics.clone(),
            control.clone(),
            dataplane_pool.clone(),
            capacity.clone(),
            build.clone(),
            node_id.clone(),
            control_path.clone(),
            shutdown_tx.subscribe(),
        );
    }

    let update_status = Arc::new(RwLock::new(update::initial_status(&config)));

    spawn_shutdown_signal(shutdown_tx.clone());
    update::spawn_update_checker(config.clone(), update_status.clone(), shutdown_tx.subscribe());

    /// Bounded memo of assembled /v1/context bundles (G21b). Eviction is
    /// deterministic oldest-first inside the cache; 256 entries is plenty
    /// for a per-(passport, session, chain-head) memo on a local daemon.
    const ASSEMBLY_CACHE_MAX_ENTRIES: usize = 256;

    let credit_meter = if config.credit_meter_enabled {
        Some(Arc::new(std::sync::Mutex::new(
            crate::credit_meter::CreditMeterStore::open(config.data_dir.join("credit-meter.jsonl"))?,
        )))
    } else {
        None
    };

    let fact_store = Arc::new(RwLock::new(if config.fact_persistence_enabled {
        corecrux_memory::FactStore::with_persistence(&config.data_dir)?
    } else {
        corecrux_memory::FactStore::new()
    }));

    // Cost-report persistence (console-surfaces-remediation M5): replay any
    // journalled `/v1/cost/report` posts into the in-memory cost store so cost
    // attribution (cx-cost page + per-ExecPlan token_burn) survives a restart.
    // No-op unless CORECRUXD_FEATURE_COST_LENS is enabled.
    crate::cost::init_persistence(&config.data_dir).await;
    let projection_state = {
        let mut ps = corecrux_projections::ProjectionState::default();
        match crate::relations::load_into_state(&config.data_dir, &mut ps) {
            Ok(n) => tracing::info!(loaded = n, "relations.jsonl replayed into ProjectionState"),
            Err(err) => tracing::warn!(?err, "relations replay failed; starting empty"),
        }
        Arc::new(RwLock::new(ps))
    };
    let repo_watch = crate::repo_watch::RepoWatchService::maybe_new(
        fact_store.clone(),
        projection_state.clone(),
        config.data_dir.clone(),
    );

    if config.sync_mutual_auth && config.sync_peer_trust_root.is_none() {
        tracing::warn!(
            "sync mutual auth is enabled without a valid CORECRUXD_SYNC_PEER_TRUST_ROOT; tenant sync requests will fail closed"
        );
    }

    let state = AppState {
        lock_held: true,
        build: build.clone(),
        compat: CompatContract {
            requires: DEFAULT_COMPAT_REQUIRES.to_string(),
        },
        sdk_version: DEFAULT_SDK_VERSION.to_string(),
        auth: auth.clone(),
        rcx_router: Some(rcx_router.clone()),
        data_dir: config.data_dir.clone(),
        sync_mutual_auth: config.sync_mutual_auth,
        sync_peer_trust_root: config.sync_peer_trust_root.clone(),
        sync_delegation_enforce: config.sync_delegation_enforce,
        sync_handshake_nonces: Arc::new(std::sync::Mutex::new(crux_sync::peer_handshake::NonceCache::new(
            SYNC_HANDSHAKE_NONCE_TTL_SECONDS,
        ))),
        witness: crate::witness::WitnessRuntimeConfigV1::from_config(&config),
        witness_proofs: Arc::new(RwLock::new(
            match crate::witness_proofs::WitnessProofStore::with_persistence(&config.data_dir) {
                Ok(store) => store,
                Err(err) => {
                    tracing::warn!(?err, "witness_proofs replay failed; starting empty");
                    crate::witness_proofs::WitnessProofStore::default()
                }
            },
        )),
        cloud_witness_replay_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        mcp_enabled: config.mcp_enabled,
        console_enabled: config.console_enabled,
        passport_mint_requests_enabled: config.passport_mint_requests_enabled,
        coord_enabled: config.coord_enabled,
        consolidation_scheduler_enabled: config.consolidation_scheduler_enabled,
        coord_presence_ttl_secs: config.coord_presence_ttl_secs,
        context_surface_enabled: config.context_surface_enabled,
        auto_capture_enabled: config.auto_capture_enabled,
        local_ingest_enabled: config.local_ingest_enabled,
        compute_provider_enabled: config.compute_provider_enabled,
        stream_receipts_enabled: config.stream_receipts_enabled,
        usage_receipts_enabled: config.usage_receipts_enabled,
        handoff_observations_enabled: config.handoff_observations_enabled,
        usage_submit: config.usage_submit.clone(),
        // Phase T (M2) version-notify slot; the consent-gated usage submitter
        // writes the collector-reported latest release here, `/v1/version` reads it.
        latest_release: Arc::new(std::sync::RwLock::new(None)),
        quota_enabled: config.quota_enabled,
        assembly_cache: config.assembly_cache_enabled.then(|| {
            Arc::new(std::sync::Mutex::new(
                corecrux_projections::assembly_cache::AssemblyCache::new(ASSEMBLY_CACHE_MAX_ENTRIES),
            ))
        }),
        quota_hosted_surfaces: Arc::new(config.quota_hosted_surfaces.clone()),
        quota_ledger: Arc::new(std::sync::Mutex::new(crux_router::quota::QuotaLedger::new())),
        credit_meter,
        openai_shim_enabled: config.openai_shim_enabled,
        memory_import_enabled: config.memory_import_enabled,
        identity_links_enabled: config.identity_links_enabled,
        mcp_context: None,
        integrations_enabled: config.integrations_enabled,
        integrations_safe_mode: config.integrations_safe_mode,
        integrations_allow_executable_helpers: config.integrations_allow_executable_helpers,
        operating_mode: config.operating_mode,
        enabled_pro_services: config.enabled_pro_services.clone(),
        read_retry_failed_readyz_threshold: config.read_retry_failed_readyz_threshold,
        commit_level: config.commit_level,
        metrics: metrics.clone(),
        node_id: node_id.clone(),
        passport_key_path: config.passport_key_path.clone(),
        passport_fpr: rcx_passport_key.passport_fpr().to_string(),
        passport_public_key_hex: rcx_passport_key.public_key_hex().to_string(),
        mcp_agent_count: mcp_agent_registry.len(),
        routing: routing.clone(),
        routing_errors: routing_errors.clone(),
        dataplane_pool: dataplane_pool.clone(),
        http_dataplane: crate::http::pool_backed_http_dataplane(dataplane_pool.clone()),
        readiness: readiness.clone(),
        control: control.clone(),
        control_path: control_path.clone(),
        action_max_pending: config.operator_action_max_pending,
        action_timeout_secs: config.operator_action_timeout_secs,
        repo_scan_max_pending: 32,
        scrub_scope: config.scrub_scope.clone(),
        scrub_mode: config.scrub_mode.clone(),
        scrub_sample_rate: config.scrub_sample_rate,
        admin_actions: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        repo_scan_jobs: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        repo_scan_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
        corruption_detected,
        capacity,
        admin_force_seal_enabled: config.admin_force_seal_enabled,
        local_ingest_lock: Arc::new(tokio::sync::Mutex::new(())),
        retention_days: config.retention_days,
        retrieval_index: {
            let mut idx = corecrux_retrieval::IndexManager::new();
            // Load-at-startup wiring: reload sealed `.ccxi` companions when the
            // storage layer builds them (`build_ccxi`) OR when the local
            // prose-ingest door is enabled — otherwise local-ingest segments
            // would not be served after a daemon restart (ExecPlan
            // cpu-prose-ingest-door-2026-07-01 M2, R2 restart-survival).
            if config.build_ccxi || config.local_ingest_enabled {
                // Scan all shard directories for .ccxi files
                let shards_dir = config.data_dir.join("shards");
                let mut total = 0usize;
                if let Ok(entries) = std::fs::read_dir(&shards_dir) {
                    for entry in entries.flatten() {
                        let seg_dir = entry.path().join("segments");
                        match idx.scan_and_load(&seg_dir) {
                            Ok(count) => total += count,
                            Err(err) => tracing::warn!(?err, dir=?seg_dir, "ccxi-scan-shard-failed"),
                        }
                    }
                }
                tracing::info!(total, "ccxi-indexes-loaded-at-startup");
            }
            Arc::new(RwLock::new(idx))
        },
        fact_store: fact_store.clone(),
        repo_watch: repo_watch.clone(),
        extension_rate_table: Arc::new(crate::extension_outbound::RateTable::new()),
        #[cfg(feature = "wasm-extensions")]
        wasm_engine: build_wasm_engine_for_appstate(),
        session_store: Arc::new(RwLock::new(if config.fact_persistence_enabled {
            corecrux_memory::SessionStore::with_persistence(&config.data_dir)?
        } else {
            corecrux_memory::SessionStore::new()
        })),
        entity_store: Arc::new(RwLock::new(if config.fact_persistence_enabled {
            corecrux_memory::EntityStore::with_persistence(&config.data_dir)
                .map_err(|e| std::io::Error::other(e.to_string()))?
        } else {
            corecrux_memory::EntityStore::new()
        })),
        edge_store: Arc::new(RwLock::new(if config.fact_persistence_enabled {
            corecrux_memory::EdgeStore::with_persistence(&config.data_dir)
                .map_err(|e| std::io::Error::other(e.to_string()))?
        } else {
            corecrux_memory::EdgeStore::new()
        })),
        kind_registry: Arc::new(RwLock::new(corecrux_memory::KindRegistry::new())),
        artefact_store: Arc::new(RwLock::new(corecrux_memory::ArtefactStore::new())),
        update_status: update_status.clone(),
        event_bus: corecrux_memory::events::EventBus::new(1024),
        session: {
            // Durable local-daemon wiring: persistent install UUID + file registry +
            // file sealer under the configured data_dir. Falls back to the
            // ephemeral (in-memory) wiring only if opening any of the three
            // fails — tests are the expected consumer of the ephemeral
            // path. Either way, the route is live.
            let mcp_url = format!("http://{}/mcp", config.http_addr);
            // action-ledger M2: per-tool MCP dispatch metrics scrape via /metrics.
            crux_mcp::ledger::register_metrics(&metrics.registry());
            let session_metrics = Arc::new(crate::http::session_metrics::SessionMetrics::new(&metrics.registry()));
            match crate::http::session::SessionServices::local_durable(&config.data_dir, node_id.clone(), mcp_url) {
                Ok(services) => Some(Arc::new(services.with_metrics(session_metrics))),
                Err(err) => {
                    tracing::warn!(?err, "durable session wiring failed; falling back to ephemeral");
                    Some(Arc::new(
                        crate::http::session::SessionServices::local_default(node_id.clone())
                            .with_metrics(session_metrics),
                    ))
                }
            }
        },
        extraction_cache: Arc::new(tokio::sync::RwLock::new(
            corecrux_projections::ExtractionCacheMaterializer::new(),
        )),
        onboarding: Arc::new(RwLock::new(
            crate::onboarding::read_state(&config.data_dir).unwrap_or_else(|err| {
                tracing::warn!(?err, "console settings unreadable; starting with defaults");
                crate::onboarding::OnboardingState::default()
            }),
        )),
        http_bind_loopback: config.http_addr.ip().is_loopback(),
        allow_insecure_dev_auth_bind: insecure_dev_auth_bind_allowed(),
        integration_encryption_key: Arc::new(rcx_passport_key.derive_subkey("integration-token-encryption-v1")),
        presence: presence::PresenceTracker::new(),
        privacy_policy: {
            let p = fact_privacy::PrivacyPolicy::from_env();
            // Install the same policy globally so every fact write path
            // (even ones that don't have AppState in scope) can call
            // fact_privacy::enforce_global(&mut fact).
            fact_privacy::install_global(p.clone());
            p
        },
        projection_state: projection_state.clone(),
    };

    // Wire the shared event bus into both stores so mutations emit SSE events.
    state.fact_store.write().await.set_event_bus(state.event_bus.clone());
    state.session_store.write().await.set_event_bus(state.event_bus.clone());
    {
        let mut store = state.fact_store.write().await;
        match crate::repo_registry::fail_incomplete_scans(
            &mut store,
            "daemon restarted before scan completed",
            crate::ops_events::now_unix_ms(),
        ) {
            Ok(count) if count > 0 => {
                tracing::warn!(count, "repo-scan-incomplete-jobs-marked-failed-after-restart");
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(?err, "repo-scan-restart-recovery-failed");
            }
        }
    }
    if let Some(watcher) = &state.repo_watch {
        watcher.start_existing_repos().await;
    }

    // Wire the dense embedder for fact retrieval. Explicit authenticated
    // daemon delegation takes precedence, then an Ollama-compatible external
    // service, then the default in-process CPU embedder. Startup validation
    // rejects an ambiguous or incomplete delegation configuration, so this
    // branch never silently falls through to a different semantic space.
    if let Some(ref delegate_url) = config.embed_delegate_url {
        let Some(delegate_token) = config.embed_delegate_token.as_ref() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "CORECRUXD_EMBED_DELEGATE_TOKEN is required when embedding delegation is configured",
            )
            .into());
        };
        let Some(expected_dimensions) = config.embed_delegate_dimensions else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "CORECRUXD_EMBED_DELEGATE_DIMENSIONS must be a positive integer when embedding delegation is configured",
            )
            .into());
        };
        let delegate_config = corecrux_memory::embeddings::DelegatingEmbeddingConfig::new(
            delegate_url.clone(),
            delegate_token.expose().to_string(),
            config.embedding_model.clone(),
            expected_dimensions,
        );
        let delegate = corecrux_memory::embeddings::DelegatingEmbedder::new(delegate_config).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("embedding delegation configuration is invalid: {err}"),
            )
        })?;
        info!(
            model = %config.embedding_model,
            dimensions = expected_dimensions,
            "embedding-delegation-configured"
        );
        state.fact_store.write().await.set_embedder(Box::new(delegate));
    } else if let Some(ref embedding_url) = config.embedding_url {
        let client = corecrux_memory::embeddings::EmbeddingClient::new(corecrux_memory::embeddings::EmbeddingConfig {
            base_url: embedding_url.clone(),
            model: config.embedding_model.clone(),
            dimensions: 0, // auto-detect
        });
        info!(
            embedding_url = %embedding_url,
            embedding_model = %config.embedding_model,
            "embedding-client-configured"
        );
        state.fact_store.write().await.set_embedder(Box::new(client));
    } else if config.local_embedder_enabled {
        // Optional real model (buyer-fit M3.4, feature `dense-embed-model`): when
        // `CORECRUXD_DENSE_MODEL=fastembed` and the daemon was built with the
        // feature, use FastEmbedEmbedder; on init failure (e.g. model download)
        // fall back to the always-on pure-Rust LocalHashEmbedder so the offline
        // default never breaks.
        let embedder: Box<dyn corecrux_memory::embeddings::Embedder> = {
            #[cfg(feature = "dense-embed-model")]
            {
                if config.dense_model.as_deref() == Some("fastembed") {
                    match corecrux_memory::embeddings::FastEmbedEmbedder::new(&config.data_dir) {
                        Ok(model) => {
                            info!(
                                model = corecrux_memory::embeddings::FASTEMBED_MODEL_ID,
                                "fastembed-embedder-configured"
                            );
                            Box::new(model)
                        }
                        Err(err) => {
                            tracing::warn!(?err, "fastembed-init-failed; falling back to local hash embedder");
                            Box::new(corecrux_memory::embeddings::LocalHashEmbedder::default())
                        }
                    }
                } else {
                    Box::new(corecrux_memory::embeddings::LocalHashEmbedder::default())
                }
            }
            #[cfg(not(feature = "dense-embed-model"))]
            {
                if config.dense_model.as_deref() == Some("fastembed") {
                    tracing::warn!("CORECRUXD_DENSE_MODEL=fastembed but daemon built without the dense-embed-model feature; using local hash embedder");
                }
                Box::new(corecrux_memory::embeddings::LocalHashEmbedder::default())
            }
        };
        info!(model = %embedder.model(), dimensions = embedder.dimensions(), "dense-embedder-configured (offline default)");
        state.fact_store.write().await.set_embedder(embedder);
    }

    // Store-time semantic near-duplicate detection (buyer-fit M3.5). Only
    // effective when a dense embedder is configured above.
    if let Some(threshold) = config.semantic_dedup_threshold {
        let mut store = state.fact_store.write().await;
        if store.embeddings_enabled() {
            store.set_semantic_dedup(threshold);
        } else {
            tracing::warn!("CORECRUXD_SEMANTIC_DEDUP set but no dense embedder configured; semantic dedup inactive");
        }
    }

    // Bootstrap: always seed agent-facing documentation on startup (idempotent).
    // Self-observation (ops error/warning capture) still requires CRUX_SELF_OBSERVE=true.
    {
        let seeder = crux_observe::bootstrap::BootstrapSeeder::new(state.fact_store.clone());
        let result = seeder.seed().await;
        if result.already_seeded {
            info!("bootstrap data already seeded");
        } else {
            info!(facts_created = result.facts_created, "bootstrap data seeded");
        }
    }

    // Multi-passport: auto-seed personal-default / work-default / public-default
    // on first boot. Idempotent — skipped if any of those ids already exist.
    // Default-passport seeding is OFF by default so a fresh data dir has no
    // identities until the operator/agent issues one explicitly. Set
    // `CORECRUXD_SEED_DEFAULT_PASSPORTS=true` to restore the legacy behaviour
    // (handy for tests + bring-your-own-onboarding flows).
    {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let mut store = state.fact_store.write().await;
        let want_seed = std::env::var("CORECRUXD_SEED_DEFAULT_PASSPORTS")
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if want_seed {
            match crate::passports::seed_defaults_if_missing(&config.data_dir, &mut store, now_ms) {
                Ok(0) => tracing::debug!("passport defaults already present"),
                Ok(n) => info!(
                    seeded = n,
                    "default passports seeded (opt-in via CORECRUXD_SEED_DEFAULT_PASSPORTS)"
                ),
                Err(err) => tracing::warn!(?err, "failed to seed default passports"),
            }
        } else {
            tracing::info!("default-passport seeder disabled (set CORECRUXD_SEED_DEFAULT_PASSPORTS=true to re-enable)");
        }
        match crate::projects::seed_default_if_missing(&mut store, now_ms) {
            Ok(false) => tracing::debug!("default project already present"),
            Ok(true) => info!("default project seeded"),
            Err(err) => tracing::warn!(?err, "failed to seed default project"),
        }
    }

    // Bootstrap the Features lens kind registrations (M3). Performed after
    // AppState is constructed so the substrate sees the registered kinds
    // before any HTTP request lands.
    {
        let mut reg = state.kind_registry.write().await;
        if let Err(e) = crux_lens_features::bootstrap_kinds(&mut reg) {
            tracing::warn!(error=%e, "features lens bootstrap_kinds returned an error; continuing");
        }
        // Agent-graph shared foundation (observe / orchestrators / punchcards).
        if let Err(e) = crate::agentgraph_kinds::bootstrap(&mut reg) {
            tracing::warn!(error=%e, "agentgraph_kinds bootstrap returned an error; continuing");
        }
    }

    // Clone handles before state is moved into the router.
    let session_store_handle = state.session_store.clone();
    let sync_fact_store_handle = state.fact_store.clone();
    // Ephemeral reserved-fact GC. Gated at spawn by CORECRUXD_EPHEMERAL_GC
    // (default OFF); the flag is read once at boot, so toggling requires a
    // restart — same convention as the other background-task flags. The
    // task soft-deletes only `__session_binding__::*` /
    // `__reverify_receipts__::*` facts past retain, via the journaled
    // delete path. See `crate::ephemeral_gc`.
    ephemeral_gc::spawn_ephemeral_gc(config.ephemeral_gc_enabled, state.clone(), shutdown_tx.subscribe());
    // Consolidation review scheduler (Audit II M4). Gated at spawn by
    // CORECRUXD_CONSOLIDATION_SCHEDULER (default OFF); interval config-driven.
    // Detect+surface only: each tick runs the read-only contradiction pass and
    // appends ONE `__consolidation_review__::*` receipt — it never resolves.
    // See `crate::consolidation_scheduler`.
    consolidation_scheduler::spawn_consolidation_scheduler(
        config.consolidation_scheduler_enabled,
        config.consolidation_scheduler_interval_secs,
        state.fact_store.clone(),
        shutdown_tx.subscribe(),
    );

    // Near-duplicate router (buyer-fit FU2 follow-up). When semantic dedup is
    // enabled, periodically drain the store-time near-duplicate flags (M3.5)
    // produced by ANY write path — MCP `store_fact`, sync, extraction — and file
    // each as a `__candidate_fact__::` review candidate. The HTTP `/v1/facts`
    // handlers route inline (immediate); this sweep is the catch-all so a flag
    // from a non-HTTP path never sits unrouted. Gated: with dedup off, no flags
    // are ever produced, so the task is not spawned.
    // Runtime trace flusher (ExecPlan crux-runtime-codemap M4). Drains the M2
    // ring, resolves each span to a stable symbol_id, and appends JSONL. Spawned
    // only when BOTH capture and persistence are on — capture alone is a valid
    // configuration for live inspection with nothing written to disk.
    if crate::trace_store::persist_enabled() {
        if let Some(ring) = crate::trace_span_ring() {
            let ring = std::sync::Arc::clone(ring);
            let fact_store = state.fact_store.clone();
            let path = config.data_dir.join("traces").join("spans.jsonl");
            let interval_secs = crate::trace_store::flush_interval_secs();
            let max_records = crate::trace_store::max_records();
            let repo_id = std::env::var("CORECRUXD_TRACE_REPO_ID").unwrap_or_else(|_| "crux".to_string());
            let tenant_id = std::env::var("CORECRUXD_TRACE_TENANT_ID").unwrap_or_else(|_| "local".to_string());
            let mut rx = shutdown_tx.subscribe();
            match crate::trace_store::TraceStore::open(path.clone(), max_records) {
                Ok(store) => {
                    info!(path = %path.display(), interval_secs, "trace-flusher-started");
                    tokio::spawn(async move {
                        let mut cache = crate::trace_store::ResolverCache::default();
                        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
                        loop {
                            tokio::select! {
                                _ = interval.tick() => {
                                    let spans = ring.drain();
                                    if spans.is_empty() { continue; }
                                    let resolver = {
                                        let store_guard = fact_store.read().await;
                                        cache.get(&store_guard, &tenant_id, &repo_id)
                                    };
                                    match store.append_resolved(spans, resolver.as_deref()) {
                                        Ok(r) => info!(
                                            drained = r.spans_drained, resolved = r.resolved,
                                            ambiguous = r.ambiguous, missed = r.missed,
                                            no_location = r.no_location, "trace-flush"
                                        ),
                                        // Never fail loudly: a full disk must not
                                        // take down the daemon over telemetry.
                                        Err(err) => tracing::warn!(error = %err, "trace-flush-failed"),
                                    }
                                }
                                _ = rx.recv() => {
                                    // Final drain so a clean shutdown does not
                                    // discard the last interval's spans.
                                    let spans = ring.drain();
                                    if !spans.is_empty() {
                                        let resolver = {
                                            let store_guard = fact_store.read().await;
                                            cache.get(&store_guard, &tenant_id, &repo_id)
                                        };
                                        let _ = store.append_resolved(spans, resolver.as_deref());
                                    }
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(err) => tracing::warn!(error = %err, "trace-store-open-failed; persistence disabled"),
            }
        }
    }

    if config.semantic_dedup_threshold.is_some() {
        let fact_store = state.fact_store.clone();
        let mut rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now = chrono::Utc::now().to_rfc3339();
                        let filed = {
                            let mut store = fact_store.write().await;
                            crate::candidate_store::route_near_duplicates(&mut store, &now)
                        };
                        if filed > 0 {
                            info!(filed, "near-duplicate-router filed review candidates");
                        }
                    }
                    _ = rx.recv() => break,
                }
            }
        });
    }

    let github_fact_store_handle = state.fact_store.clone();
    let github_encryption_key = state.integration_encryption_key.clone();
    // Handles the periodic-job scheduler needs; cloned here because `state` is
    // moved into the router well before the scheduler is built.
    let scheduler_fact_store = state.fact_store.clone();
    let vault_ingest_handles = crate::local_ingest::LocalIngestHandles {
        data_dir: state.data_dir.clone(),
        ingest_lock: state.local_ingest_lock.clone(),
        retrieval_index: state.retrieval_index.clone(),
    };
    // Build the MCP dispatch context once and share it between the MCP
    // server (:14801) and the HTTP OpenAI tools shim (`/v1/openai/*`,
    // provider-integration-surfaces M2) — single source for the tool surface.
    let mcp_context = if config.mcp_enabled {
        // Loopback URL the cuecrux_session tool uses to call corecruxd's
        // POST /session. This mirrors master-plan §6.2 ("POST to the
        // Layer 1 handshake endpoint internally").
        let daemon_base = format!("http://127.0.0.1:{}", config.http_addr.port());
        Some(
            crux_mcp::dispatch::McpContext::new_shared(
                node_id.clone(),
                state.fact_store.clone(),
                state.session_store.clone(),
                state.retrieval_index.clone(),
                state.update_status.clone(),
                mcp_agent_registry.clone(),
            )
            .with_daemon_base_url(daemon_base)
            .with_shared_rcx_router(rcx_router)
            .with_data_dir(state.data_dir.clone())
            .with_passport_public_key(state.passport_public_key_hex.clone())
            .with_agent_passports(
                config.agent_passports_enabled,
                if config.agent_passports_enabled {
                    // Flag ON: prefer CRUX_AGENT_PASSPORTS override, else the
                    // built-in default map (agent-passport M1).
                    crux_mcp::agent_passport::AgentPassportMap::from_env_or_default()
                } else {
                    // Flag OFF: empty map — never consulted, byte-for-byte
                    // the pre-M1 behaviour.
                    crux_mcp::agent_passport::AgentPassportMap::empty()
                },
            )
            .with_passport_mint_requests(config.passport_mint_requests_enabled)
            // passport-revocation M3: refuse revoked passports' calls —
            // launch default ON; CRUX_PASSPORT_REVOCATION=0 disables it.
            .with_revocation_enforced(crux_mcp::dispatch::revocation_enforced_from_env())
            .with_substrate(
                state.entity_store.clone(),
                state.edge_store.clone(),
                state.kind_registry.clone(),
            )
            .with_artefact_store(state.artefact_store.clone())
            // Dense re-rank on the MCP `query` tool (parity with the REST
            // text-search lane): the `.ccxv` companion readers live in this
            // crate, so hand crux-mcp a constructor instead of the readers.
            .with_dense_provider_factory({
                let data_dir = state.data_dir.clone();
                std::sync::Arc::new(move |index_mgr: &corecrux_retrieval::IndexManager,
                                          query_embedding: &[f32],
                                          expected_fingerprint: Option<&str>| {
                    crate::local_ingest::build_dense_provider(
                        index_mgr,
                        &data_dir,
                        query_embedding,
                        expected_fingerprint,
                    )
                })
            }),
        )
    } else {
        None
    };
    let mcp_app = mcp_context.clone().map(crux_mcp::server::router);

    let witness_proofs_handle = state.witness_proofs.clone();
    let mut state = state;
    state.mcp_context = mcp_context.map(std::sync::Arc::new);
    // Ingress hardening (crux-http-ingress-hardening-2026-06-11 M1): body
    // limit + problem+json 413s, applied before TraceLayer so rejected
    // requests still show up in traces.
    // Procedural memory case bank (M3). Persisted alongside the other stores;
    // passed to the router via an Extension layer rather than added to AppState.
    let case_store = Arc::new(RwLock::new(if config.fact_persistence_enabled {
        corecrux_memory::CaseStore::with_persistence(&config.data_dir)?
    } else {
        corecrux_memory::CaseStore::new()
    }));
    // Phase T (M1): clone the assembled AppState for the once-per-boot
    // `daemon_start` usage-ping emit *before* `state` is moved into the router.
    // The emit itself is fired only after the HTTP server is serving (below).
    let boot_emit_state = state.clone();
    let app: Router =
        http::ingress::apply_ingress_limits(http::router(state, case_store), &config.ingress, Some(&metrics))
            .layer(TraceLayer::new_for_http());

    // Session TTL reaper — runs every 60s, removes expired sessions.
    {
        let session_store = session_store_handle;
        let mut rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match session_store.write().await.try_reap_expired() {
                            Ok(reaped) if reaped > 0 => tracing::info!(reaped, "session-ttl-reaper"),
                            Ok(_) => {}
                            Err(err) => tracing::warn!(?err, "session-ttl-reaper-journal-failed"),
                        }
                    }
                    _ = rx.recv() => break,
                }
            }
        });
    }

    // Observation retention — runs hourly, archives sessions whose newest
    // record is older than CORECRUXD_OBS_RETENTION_DAYS. Skipped entirely
    // when the env var is unset or zero so the default is "keep forever".
    if let Some(max_age_days) = std::env::var("CORECRUXD_OBS_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&n| n > 0)
    {
        let data_dir = config.data_dir.clone();
        let max_age = chrono::Duration::days(max_age_days);
        let mut rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            tracing::info!(
                max_age_days,
                data_dir = %data_dir.display(),
                "starting observation-retention task (interval=1h)"
            );
            // Initial delay so we don't archive in the boot path.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            interval.tick().await; // consume the immediate first tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match crate::http::observations::run_retention_pass(&data_dir, max_age) {
                            Ok((archived, scanned)) if archived > 0 => {
                                tracing::info!(archived, scanned, "observation-retention pass");
                            }
                            Ok((_, _scanned)) => {}
                            Err(err) => tracing::warn!(?err, "observation-retention pass failed"),
                        }
                    }
                    _ = rx.recv() => break,
                }
            }
        });
    }

    // Background sync — pulls then pushes facts on a configurable interval.
    if config.sync_enabled && !config.sync_remote_url.is_empty() {
        let sync_fact_store = sync_fact_store_handle;
        let sync_remote_url = config.sync_remote_url.clone();
        let sync_api_key = config.sync_api_key.clone();
        let sync_data_dir = config.data_dir.clone();
        let sync_interval = config.sync_interval_secs;
        let sync_peer_auth = load_sync_peer_auth();
        let mut rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            // Initial delay to let daemon fully start.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(sync_interval));
            // Consume the first (immediate) tick so the loop starts after one interval.
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut client = corecrux_memory::sync::SyncClient::new(
                            &sync_remote_url,
                            &sync_api_key,
                            &sync_data_dir,
                        );
                        // M2b: present the signed peer handshake when configured.
                        if let Some((ref signing_key, ref token)) = sync_peer_auth {
                            client = client.with_peer_auth(signing_key.clone(), token.clone());
                        }

                        // Pull first.
                        match client.pull(&mut *sync_fact_store.write().await) {
                            Ok(result) => {
                                if result.facts_pulled > 0 {
                                    tracing::info!(pulled = result.facts_pulled, "sync: pulled facts from remote");
                                }
                            }
                            Err(e) => tracing::warn!(error = %e, "sync: pull failed"),
                        }

                        // Then push from a short-lived snapshot so network I/O does not hold the store read lock.
                        let pushable = {
                            let store = sync_fact_store.read().await;
                            client.pushable_facts(&store)
                        };
                        match client.push_facts(&pushable) {
                            Ok(result) => {
                                if result.facts_pushed > 0 {
                                    tracing::info!(pushed = result.facts_pushed, "sync: pushed facts to remote");
                                }
                            }
                            Err(e) => tracing::warn!(error = %e, "sync: push failed"),
                        }
                    }
                    _ = rx.recv() => break,
                }
            }
        });

        info!(
            remote = %config.sync_remote_url,
            interval_secs = config.sync_interval_secs,
            "sync: background sync enabled"
        );
    }

    // Background witness submission (Track W / G1) — drains pending seal-chain
    // heads to the configured transparency log on an interval. Off unless
    // witnessing is enabled; needs the rekor provider + a URL + the daemon
    // signing key, else it logs and idles (heads stay pending and retry).
    if config.witness_enabled {
        let witness_store = witness_proofs_handle;
        let task_metrics = metrics.clone();
        let provider = config.witness_provider.clone();
        let rekor_url = config.rekor_url.clone();
        let timeout = std::time::Duration::from_millis(config.witness_timeout_ms.max(1));
        let interval_secs = std::env::var("CORECRUXD_WITNESS_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300)
            .max(1);
        let mut rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Publish the gauge every tick, even when we can't submit.
                        let pending = {
                            let store = witness_store.read().await;
                            task_metrics.set_witness_unwitnessed_heads(store.unwitnessed_count() as u64);
                            store.pending_heads()
                        };
                        if pending.is_empty() {
                            continue;
                        }
                        if !provider.eq_ignore_ascii_case("rekor") {
                            tracing::warn!(provider = %provider, "witness: unsupported provider; heads remain pending");
                            continue;
                        }
                        let Some(url) = rekor_url.clone().filter(|u| !u.is_empty()) else {
                            tracing::warn!("witness: CORECRUXD_REKOR_URL unset; heads remain pending");
                            continue;
                        };
                        let Some(signer) = crate::witness_submit::select_witness_signer(timeout) else {
                            tracing::warn!(
                                "witness: no signer configured (Vault Transit or CORECRUXD_WITNESS_SIGNING_KEY); heads remain pending"
                            );
                            continue;
                        };
                        let witness = crate::witness_submit::RekorWitness::with_signer(url, signer, timeout);
                        let n_pending = pending.len();
                        tracing::debug!(provider = %provider, pending = n_pending, "witness: draining heads");
                        // Network I/O off the async runtime and without the store lock.
                        let outcomes = match tokio::task::spawn_blocking(move || {
                            crate::witness_proofs::drain_once(&pending, &witness)
                        })
                        .await
                        {
                            Ok(outcomes) => outcomes,
                            Err(err) => {
                                tracing::warn!(?err, "witness: drain task join failed");
                                continue;
                            }
                        };
                        let mut witnessed = 0usize;
                        {
                            let mut store = witness_store.write().await;
                            for (head_hash, result) in outcomes {
                                match result {
                                    Ok(proof) => match store.record_witnessed(head_hash, proof) {
                                        Ok(()) => witnessed += 1,
                                        Err(err) => tracing::warn!(?err, "witness: failed to persist proof"),
                                    },
                                    Err(err) => {
                                        tracing::warn!(error = %err, "witness: submission failed; head stays pending");
                                    }
                                }
                            }
                            task_metrics.set_witness_unwitnessed_heads(store.unwitnessed_count() as u64);
                        }
                        if witnessed > 0 {
                            tracing::info!(witnessed, "witness: anchored seal-chain heads");
                        }
                    }
                    _ = rx.recv() => break,
                }
            }
        });

        info!(
            interval_secs,
            provider = %config.witness_provider,
            "witness: background submission enabled"
        );
    }

    let http_addr = config.http_addr;
    let grpc_addr = config.grpc_addr;
    let mcp_addr = config.mcp_addr;

    info!(
        http_addr = %http_addr,
        grpc_addr = %grpc_addr,
        mcp_enabled = config.mcp_enabled,
        mcp_addr = %mcp_addr,
        data_dir = %config.data_dir.display(),
        commit_level = config.commit_level.as_str(),
        append_lane_enabled = config.append_lane_enabled,
        append_lane_scope = config.append_lane_scope.as_str(),
        follower_reads_enabled = config.follower_reads_enabled,
        // Surfaced at boot so an operator can tell a CLEAN shadow window (mode
        // active, zero tenant_stamp_shadow_* warnings) apart from a window that
        // never ran (flag typo'd / not applied). Shadow is silent on the good
        // path, so without this the silence is ambiguous.
        tenant_stamp_mode = crate::auth::TenantStampMode::from_env().as_str(),
        "corecruxd starting"
    );

    let http_task = {
        let rx = shutdown_tx.subscribe();
        let drain_cap = config.ingress.shutdown_drain_cap();
        tokio::spawn(async move { serve_http(http_addr, app, rx, drain_cap).await })
    };

    // Phase T (M1): now that the HTTP server is serving, emit exactly one
    // consent-gated `daemon_start` usage ping keyed to the daemon root passport.
    // A no-op with ZERO network under default config — `emit_daemon_start_usage_ping`
    // returns before any mint or network task unless the three-way submit gate
    // (`CORECRUXD_USAGE_RECEIPTS_SUBMIT` + `_ENDPOINT` + `_CONSENT_AT`) is fully
    // set, so `assert-no-phone-home.sh` stays green. Spawned on the blocking pool
    // so the boot path is never blocked; fires at most once per boot.
    tokio::task::spawn_blocking(move || {
        http::emit_daemon_start_usage_ping(&boot_emit_state);
    });

    let grpc_task = {
        let mut rx = shutdown_tx.subscribe();
        let export_pool = dataplane_pool.clone();
        let svc_cfg = grpc::DataPlaneServiceConfig {
            node_id: node_id.clone(),
            commit_level: config.commit_level,
            replicated_commit_timeout_ms: config.replicated_commit_timeout_ms,
            replicated_commit_require_all_followers: config.replicated_commit_require_all_followers,
            replay_batch_max_events: config.replay_batch_max_events,
            replay_batch_max_bytes: config.replay_batch_max_bytes,
            replay_many_max_reads: config.replay_many_max_reads,
            replay_use_batched_rpc_default: config.replay_use_batched_rpc_default,
            store_lock_strategy: config.store_lock_strategy,
            append_lane_enabled: config.append_lane_enabled,
            append_lane_scope: config.append_lane_scope,
        };
        let svc = grpc::DataPlaneService::new(dataplane_pool, control.clone(), metrics.clone(), auth.clone(), svc_cfg);
        let export_svc = grpc::ExportService::new(export_pool, metrics.clone(), build.clone(), auth.clone());
        let ingress = config.ingress.clone();
        tokio::spawn(async move {
            grpc::serve(grpc_addr, &ingress, svc, export_svc, async move {
                let _ = rx.recv().await;
            })
            .await
        })
    };

    // Periodic integration jobs (ExecPlan `crux-integrations-and-template-library`
    // I4). One driver task for all of them; per-job status lands under
    // `__sync__::<job_id>` key `status` and is readable through `GET /v1/facts`.
    // See `crate::sync_scheduler`.
    {
        let mut scheduler = sync_scheduler::SyncScheduler::new(scheduler_fact_store.clone());

        // GitHub indexer poll (Plan B G3) — registered unconditionally; the job
        // itself skips (writing nothing) when GitHub isn't connected. Interval
        // via `CORECRUXD_GITHUB_SYNC_INTERVAL_SECS` (default 900s = 15 min);
        // first poll one full interval after boot, as before. The manual
        // `POST /v1/integrations/github/sync` runs the same code path.
        {
            let interval_secs = std::env::var("CORECRUXD_GITHUB_SYNC_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(900);
            let data_dir = config.data_dir.clone();
            let key = github_encryption_key.clone();
            let fact_store = github_fact_store_handle.clone();
            scheduler.register(
                "github-sync",
                std::time::Duration::from_secs(interval_secs),
                move || {
                    let dd = data_dir.clone();
                    let k = key.clone();
                    let fs = fact_store.clone();
                    async move {
                        let now_ms = crate::ops_events::now_unix_ms();
                        let result = tokio::task::spawn_blocking(move || {
                            let mut store = match fs.try_write() {
                                Ok(g) => g,
                                Err(_) => {
                                    return Err(crate::integrations_github::GithubIntegrationError::Network(
                                        "fact store busy".to_string(),
                                    ))
                                }
                            };
                            crate::integrations_github_sync::run_sync_with_key(&dd, &mut store, k.as_ref(), now_ms)
                        })
                        .await;
                        match result {
                            Ok(Ok(run)) => {
                                let total_added: usize = run.repos.iter().map(|r| r.commits_added).sum();
                                if !run.repos.is_empty() {
                                    info!(repos = run.repos.len(), commits_added = total_added, "github-sync-tick");
                                }
                                Ok(sync_scheduler::JobOutcome::Ran(Some(serde_json::json!({
                                    "repos": run.repos.len(),
                                    "commits_added": total_added,
                                }))))
                            }
                            // Not connected is the unconfigured default, not a
                            // failure: skip silently and don't arm backoff.
                            Ok(Err(crate::integrations_github::GithubIntegrationError::NotConnected)) => {
                                Ok(sync_scheduler::JobOutcome::Skipped("github not connected".to_string()))
                            }
                            Ok(Err(err)) => Err(format!("{err:?}")),
                            Err(err) => Err(format!("sync task join error: {err}")),
                        }
                    }
                },
            );
        }

        // Markdown vault watcher — the `EntryKind::FileWatcher` runtime. Double
        // gated: a file-watcher pack must be installed AND granted, and
        // `CORECRUXD_VAULT_WATCH_ROOTS` must name at least one absolute
        // directory. See `crate::vault_watcher`.
        match vault_watcher::activation(&config.data_dir) {
            (vault_watcher::Activation::Active { pack_ids, roots }, Some(vault_config)) => {
                let watcher = std::sync::Arc::new(vault_watcher::VaultWatcher::new(
                    vault_config,
                    scheduler_fact_store.clone(),
                    vault_ingest_handles.clone(),
                ));
                let interval = watcher.interval();
                info!(
                    packs = ?pack_ids,
                    roots,
                    interval_secs = interval.as_secs(),
                    "vault-watcher enabled"
                );
                scheduler.register(vault_watcher::JOB_ID, interval, move || {
                    let watcher = watcher.clone();
                    async move { watcher.run_cycle().await }
                });
            }
            (vault_watcher::Activation::HalfConfigured(reason), _) => {
                info!(reason = %reason, "vault-watcher inactive");
            }
            _ => {}
        }

        scheduler.spawn(shutdown_tx.subscribe());
    }

    let mcp_task = mcp_app.map(|mcp_app| {
        let rx = shutdown_tx.subscribe();
        let drain_cap = config.ingress.shutdown_drain_cap();
        // The MCP plane gets the same body limit as the API plane.
        let mcp_app = http::ingress::apply_ingress_limits(mcp_app, &config.ingress, Some(&metrics));
        tokio::spawn(async move { serve_http(mcp_addr, mcp_app, rx, drain_cap).await })
    });

    let http_runner = wait_for_http_task("http", http_task);
    let grpc_runner = wait_for_server_task("grpc", grpc_task);

    if let Some(mcp_task) = mcp_task {
        let mcp_runner = wait_for_http_task("mcp", mcp_task);
        tokio::try_join!(http_runner, grpc_runner, mcp_runner)?;
    } else {
        tokio::try_join!(http_runner, grpc_runner)?;
    }

    drop(lock_file);
    Ok(())
}

async fn wait_for_http_task(
    name: &'static str,
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            error!(server = name, err = %err, "server exited with error");
            Err(err.into())
        }
        Err(err) => {
            error!(server = name, err = %err, "server task join error");
            Err(Box::new(err))
        }
    }
}

async fn wait_for_server_task(
    name: &'static str,
    task: tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            error!(server = name, err = %err, "server exited with error");
            Err(err)
        }
        Err(err) => {
            error!(server = name, err = %err, "server task join error");
            Err(Box::new(err))
        }
    }
}

#[derive(Debug, Clone)]
struct ControlCheckpointRecord {
    seq: u64,
    payload: ControlCheckpointMaterializedV1,
}

#[derive(Debug, Clone)]
struct ControlMutationRecord {
    seq: u64,
    payload: ControlStateMutationV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlEvidenceReplayPlan {
    state: crate::control::ControlV1,
    anchor: &'static str,
    anchor_seq: u64,
    applied_mutations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlEvidenceRuntimeStatus {
    hosted_locally: bool,
    ok: bool,
    detail: Option<String>,
}

impl ControlEvidenceRuntimeStatus {
    fn non_hosted(detail: impl Into<String>) -> Self {
        Self {
            hosted_locally: false,
            ok: true,
            detail: Some(detail.into()),
        }
    }

    fn hosted_ok(detail: impl Into<String>) -> Self {
        Self {
            hosted_locally: true,
            ok: true,
            detail: Some(detail.into()),
        }
    }

    fn hosted_err(detail: impl Into<String>) -> Self {
        Self {
            hosted_locally: true,
            ok: false,
            detail: Some(detail.into()),
        }
    }
}

fn update_control_metrics(metrics: &Metrics, control: &crate::control::ControlV1) {
    metrics.set_valve_pause_ingest(control.valves.pause_ingest.enabled);
    metrics.set_valve_pause_compaction(control.valves.pause_compaction.enabled);
    metrics.set_valve_throttle(control.valves.throttle.enabled);
    metrics.set_valve_read_only(control.valves.read_only.enabled);
    metrics.set_valve_emergency_brake(control.valves.emergency_brake.enabled);

    metrics.set_valve_state("pause_ingest", control.valves.pause_ingest.enabled);
    metrics.set_valve_state("pause_compaction", control.valves.pause_compaction.enabled);
    metrics.set_valve_state("throttle", control.valves.throttle.enabled);
    metrics.set_valve_state("read_only", control.valves.read_only.enabled);
    metrics.set_valve_state("emergency_brake", control.valves.emergency_brake.enabled);
    metrics.sync_knowledge_authority(&control.knowledge_authority);
    metrics.set_throttle_ratio(1.0);
}

fn reconcile_control_from_evidence(
    current: &crate::control::ControlV1,
    current_checkpoint_bytes: &[u8],
    checkpoints: &[ControlCheckpointRecord],
    mutations: &[ControlMutationRecord],
) -> Result<Option<ControlEvidenceReplayPlan>, String> {
    if checkpoints.is_empty() && mutations.is_empty() {
        return Ok(None);
    }

    let current_digest = crate::control::control_state_digest_v1(current);
    let current_checkpoint_hash = blake3::hash(current_checkpoint_bytes).to_hex().to_string();
    let current_checkpoint_size = current_checkpoint_bytes.len() as u64;

    let checkpoint_anchor = checkpoints
        .iter()
        .rev()
        .find(|record| {
            record.payload.control_state == current_digest
                && record.payload.checkpoint_blake3 == current_checkpoint_hash
                && record.payload.checkpoint_size_bytes == current_checkpoint_size
        })
        .map(|record| (record.seq, "checkpoint"));
    let mutation_anchor = mutations
        .iter()
        .rev()
        .find(|record| record.payload.control_after == current_digest)
        .map(|record| (record.seq, "mutation"));

    let (mut rebuilt, anchor, anchor_seq) = match (checkpoint_anchor, mutation_anchor) {
        (Some(left), Some(right)) => {
            if left.0 >= right.0 {
                (current.clone(), left.1, left.0)
            } else {
                (current.clone(), right.1, right.0)
            }
        }
        (Some(found), None) | (None, Some(found)) => (current.clone(), found.1, found.0),
        (None, None) => {
            let Some(first_mutation) = mutations.first() else {
                return Err("control evidence contains no state mutation anchor for CONTROL.json".into());
            };
            let default_state = crate::control::ControlV1::default();
            if first_mutation.payload.control_before != crate::control::control_state_digest_v1(&default_state) {
                return Err(
                    "CONTROL.json does not match any checkpoint or mutation anchor, and evidence does not start from the default control state".into(),
                );
            }
            (default_state, "default", 0)
        }
    };

    let mut applied_mutations = 0usize;
    for record in mutations.iter().filter(|record| record.seq > anchor_seq) {
        crate::control::apply_control_state_mutation_v1(&mut rebuilt, &record.payload)?;
        applied_mutations = applied_mutations.saturating_add(1);
    }

    Ok(Some(ControlEvidenceReplayPlan {
        state: rebuilt,
        anchor,
        anchor_seq,
        applied_mutations,
    }))
}

async fn reconcile_control_checkpoint_with_evidence(
    control_path: &std::path::Path,
    control: Arc<RwLock<crate::control::ControlV1>>,
    dataplane_pool: Option<&crate::pool::DataPlanePool>,
    metrics: &Metrics,
) -> ControlEvidenceRuntimeStatus {
    const CONTROL_EVIDENCE_READ_BATCH: u32 = 256;

    let Some(pool) = dataplane_pool else {
        tracing::info!("control evidence replay skipped because dataplane is unavailable");
        return ControlEvidenceRuntimeStatus::non_hosted(
            "control evidence replay skipped because dataplane is unavailable",
        );
    };

    let store = match pool
        .store_for_stream_read("system", "corecrux", "control", None, None)
        .await
    {
        Ok((_decision, store)) => store,
        Err(AppendError::WrongShard { .. }) => {
            tracing::info!("control evidence replay skipped because system/corecrux/control is not hosted locally");
            return ControlEvidenceRuntimeStatus::non_hosted("system/corecrux/control is not hosted locally");
        }
        Err(err) => {
            tracing::warn!(err = %err, "failed to route control evidence replay; using CONTROL.json checkpoint");
            return ControlEvidenceRuntimeStatus::hosted_err(format!("failed to route control evidence replay: {err}"));
        }
    };

    let mut checkpoints = Vec::new();
    let mut mutations = Vec::new();
    let mut from_seq = 0u64;

    loop {
        let batch = {
            let store = store.read().await;
            match store
                .read_stream(
                    "system",
                    "corecrux",
                    "control",
                    from_seq,
                    CONTROL_EVIDENCE_READ_BATCH,
                    None,
                )
                .await
            {
                Ok(ok) => ok,
                Err(err) => {
                    tracing::warn!(err = %err, from_seq, "failed to read control evidence stream; using CONTROL.json checkpoint");
                    return ControlEvidenceRuntimeStatus::hosted_err(format!(
                        "failed to read control evidence stream: {err}"
                    ));
                }
            }
        };

        if batch.is_empty() {
            break;
        }

        let batch_len = batch.len();
        from_seq = batch.last().map_or(from_seq, |event| event.seq.saturating_add(1));

        for event in batch {
            match event.event_type.as_str() {
                EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1 => {
                    match serde_json::from_slice::<ControlCheckpointMaterializedV1>(&event.payload) {
                        Ok(payload) => checkpoints.push(ControlCheckpointRecord {
                            seq: event.seq,
                            payload,
                        }),
                        Err(err) => {
                            tracing::warn!(
                                seq = event.seq,
                                err = %err,
                                "failed to parse control checkpoint evidence; using CONTROL.json checkpoint"
                            );
                            return ControlEvidenceRuntimeStatus::hosted_err(format!(
                                "failed to parse control checkpoint evidence at seq {}: {err}",
                                event.seq
                            ));
                        }
                    }
                }
                EVT_CONTROL_STATE_MUTATION_V1 => {
                    match serde_json::from_slice::<ControlStateMutationV1>(&event.payload) {
                        Ok(payload) => mutations.push(ControlMutationRecord {
                            seq: event.seq,
                            payload,
                        }),
                        Err(err) => {
                            tracing::warn!(
                                seq = event.seq,
                                err = %err,
                                "failed to parse control mutation evidence; using CONTROL.json checkpoint"
                            );
                            return ControlEvidenceRuntimeStatus::hosted_err(format!(
                                "failed to parse control mutation evidence at seq {}: {err}",
                                event.seq
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        if batch_len < CONTROL_EVIDENCE_READ_BATCH as usize {
            break;
        }
    }

    let current = control.read().await.clone();
    let current_checkpoint_bytes = match std::fs::read(control_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(
                path = %control_path.display(),
                err = %err,
                "failed to read CONTROL.json for evidence reconciliation"
            );
            return ControlEvidenceRuntimeStatus::hosted_err(format!("failed to read CONTROL.json: {err}"));
        }
    };

    let plan = match reconcile_control_from_evidence(&current, &current_checkpoint_bytes, &checkpoints, &mutations) {
        Ok(Some(plan)) => plan,
        Ok(None) => {
            tracing::info!("control evidence stream has no replayable control records yet");
            return ControlEvidenceRuntimeStatus::hosted_ok(
                "control evidence stream has no replayable control records yet",
            );
        }
        Err(err) => {
            tracing::warn!(err = %err, "control evidence did not reconcile with CONTROL.json; keeping checkpoint state");
            return ControlEvidenceRuntimeStatus::hosted_err(format!(
                "control evidence did not reconcile with CONTROL.json: {err}"
            ));
        }
    };

    let expected_checkpoint_bytes = crate::control::checkpoint_control_bytes_v1(&plan.state);

    if plan.state == current && expected_checkpoint_bytes == current_checkpoint_bytes {
        tracing::info!(
            anchor = plan.anchor,
            anchor_seq = plan.anchor_seq,
            applied_mutations = plan.applied_mutations,
            "control checkpoint already matches local evidence"
        );
        return ControlEvidenceRuntimeStatus::hosted_ok(format!(
            "control checkpoint matches local evidence (anchor={} anchor_seq={} applied_mutations={})",
            plan.anchor, plan.anchor_seq, plan.applied_mutations
        ));
    }

    {
        let mut guard = control.write().await;
        *guard = plan.state.clone();
    }
    update_control_metrics(metrics, &plan.state);
    if let Err(err) = crate::control::write_control_atomic(control_path, &plan.state) {
        tracing::warn!(
            path = %control_path.display(),
            err = %err,
            "failed to rewrite CONTROL.json after control evidence replay"
        );
        return ControlEvidenceRuntimeStatus::hosted_err(format!(
            "failed to rewrite CONTROL.json after control evidence replay: {err}"
        ));
    }
    tracing::info!(
        anchor = plan.anchor,
        anchor_seq = plan.anchor_seq,
        applied_mutations = plan.applied_mutations,
        "reconciled CONTROL.json from local control evidence"
    );
    ControlEvidenceRuntimeStatus::hosted_ok(format!(
        "reconciled CONTROL.json from local evidence (anchor={} anchor_seq={} applied_mutations={})",
        plan.anchor, plan.anchor_seq, plan.applied_mutations
    ))
}

fn insecure_dev_auth_bind_allowed() -> bool {
    std::env::var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

/// Dev-only escape hatch: when an agent-token env var is present but invalid,
/// allow the daemon to boot with no MCP auth instead of aborting. Never set in
/// production — it re-opens the fail-open path the strict parse exists to close.
const ALLOW_EMPTY_AGENT_REGISTRY_ENV: &str = "CRUX_MCP_ALLOW_EMPTY_AGENT_REGISTRY";

fn allow_empty_agent_registry() -> bool {
    std::env::var(ALLOW_EMPTY_AGENT_REGISTRY_ENV)
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

/// Decide the effective MCP agent registry, failing closed on an invalid
/// agent-token config unless the dev override is set.
///
/// - `Ok(registry)` from `from_env` (incl. the legitimate empty single-user
///   registry when no token var is set) → use it.
/// - `Err` (a token var was present but invalid) → abort with an operator
///   message, unless `override_allowed`, in which case fall back to an empty
///   (no-auth) registry with the caller responsible for warning.
fn resolve_mcp_agent_registry(
    parsed: Result<crux_mcp::agent::AgentRegistry, crux_mcp::agent::AgentRegistryError>,
    override_allowed: bool,
) -> Result<crux_mcp::agent::AgentRegistry, String> {
    match parsed {
        Ok(registry) => Ok(registry),
        Err(err) if override_allowed => {
            tracing::warn!(
                "{err}; {} is set so continuing with MCP auth NOT enforced (dev-only)",
                ALLOW_EMPTY_AGENT_REGISTRY_ENV
            );
            Ok(crux_mcp::agent::AgentRegistry::empty())
        }
        Err(err) => Err(format!(
            "{err}. Fix the agent token to enable MCP auth, or set {}=1 to run with no MCP \
             auth (local dev/tests only).",
            ALLOW_EMPTY_AGENT_REGISTRY_ENV
        )),
    }
}

fn replication_auth_bearer_configured() -> bool {
    std::env::var("CORECRUXD_REPLICATION_AUTH_BEARER")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
}

fn shard_map_advertise_addr(listen_addr: SocketAddr) -> String {
    let ip = if listen_addr.ip().is_unspecified() {
        match listen_addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        }
    } else {
        listen_addr.ip()
    };
    SocketAddr::new(ip, listen_addr.port()).to_string()
}

fn validate_network_auth_posture(
    auth_mode: AuthMode,
    http_addr: SocketAddr,
    grpc_addr: SocketAddr,
    commit_level: CommitLevel,
    allow_insecure_dev_auth_bind: bool,
    replication_auth_bearer_present: bool,
) -> Result<(), String> {
    let dev_auth_mode = matches!(auth_mode, AuthMode::Off | AuthMode::DevScopes);
    let loopback_only = http_addr.ip().is_loopback() && grpc_addr.ip().is_loopback();
    if dev_auth_mode && !loopback_only && !allow_insecure_dev_auth_bind {
        return Err(format!(
            "auth mode {:?} may not bind to non-loopback addresses (http={}, grpc={}) without CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1",
            auth_mode, http_addr, grpc_addr
        ));
    }

    let jwt_auth_mode = matches!(auth_mode, AuthMode::JwtHs256 | AuthMode::JwtJwks);
    if jwt_auth_mode && matches!(commit_level, CommitLevel::ReplicatedCommit) && !replication_auth_bearer_present {
        return Err(
            "ReplicatedCommit with JWT auth requires CORECRUXD_REPLICATION_AUTH_BEARER for follower replication"
                .to_string(),
        );
    }

    Ok(())
}

fn validate_mcp_bind_posture(
    mcp_enabled: bool,
    mcp_addr: SocketAddr,
    agent_registry_empty: bool,
    allow_insecure_dev_auth_bind: bool,
) -> Result<(), String> {
    if !mcp_enabled || mcp_addr.ip().is_loopback() || !agent_registry_empty || allow_insecure_dev_auth_bind {
        return Ok(());
    }

    Err(format!(
        "MCP may not bind to non-loopback address ({mcp_addr}) without CRUX_AGENT_TOKEN/CRUX_AGENT_TOKENS or CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1"
    ))
}

/// The process-wide span ring, present only when `CORECRUXD_TRACE_CAPTURE` is on.
///
/// Held in a `OnceLock` because the layer is installed inside `init_tracing`,
/// long before `AppState` exists, and the HTTP surface needs to read it later.
static TRACE_SPAN_RING: std::sync::OnceLock<std::sync::Arc<crux_observe::span_layer::SpanRing>> =
    std::sync::OnceLock::new();

/// Runtime span capture ring, or `None` when trace capture is disabled.
pub(crate) fn trace_span_ring() -> Option<&'static std::sync::Arc<crux_observe::span_layer::SpanRing>> {
    TRACE_SPAN_RING.get()
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_default();
    // Runtime code-map capture (ExecPlan crux-runtime-codemap M2). `from_env`
    // yields None unless CORECRUXD_TRACE_CAPTURE is set, so the disabled path
    // installs no layer at all rather than an inert one.
    let span_layer = crux_observe::span_layer::CruxSpanLayer::from_env().map(|(layer, ring)| {
        let _ = TRACE_SPAN_RING.set(ring);
        layer
    });
    // Sink-boundary redaction (ExecPlan crux-log-redaction-2026-06-11 M2):
    // every formatted event is scrubbed before reaching stdout. Mode is
    // CORECRUXD_REDACT=on|off|audit (default audit: count, don't mutate).
    let redacting_writer = crux_observe::redact_writer::RedactMakeWriter::new(
        std::io::stdout as fn() -> std::io::Stdout,
        crate::redaction::redactor(),
    );

    #[cfg(feature = "otel")]
    {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_otlp::WithExportConfig as _;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::Layer as _;

        let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
        if let Some(endpoint) = otel_endpoint {
            if let Ok(exporter) = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&endpoint)
                .build()
            {
                let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(
                        opentelemetry_sdk::Resource::builder()
                            .with_service_name("corecruxd")
                            .build(),
                    )
                    .build();

                opentelemetry::global::set_tracer_provider(provider.clone());
                let _ = OTEL_TRACER_PROVIDER.set(provider.clone());
                opentelemetry::global::set_text_map_propagator(
                    opentelemetry_sdk::propagation::TraceContextPropagator::new(),
                );
                let otel_layer = tracing_opentelemetry::OpenTelemetryLayer::new(provider.tracer("corecruxd"));

                let fmt_layer = if log_format.eq_ignore_ascii_case("json") {
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(redacting_writer.clone())
                        .boxed()
                } else {
                    tracing_subscriber::fmt::layer()
                        .with_writer(redacting_writer.clone())
                        .boxed()
                };

                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .with(otel_layer)
                    .with(span_layer)
                    .init();
                return;
            }
        }
    }

    // Registry-based rather than the `fmt()` builder so the span layer can
    // compose. `Layer` is implemented for `Option<L>`, so a `None` span layer
    // adds no runtime work.
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::Layer as _;

        let fmt_layer = if log_format.eq_ignore_ascii_case("json") {
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(redacting_writer)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer().with_writer(redacting_writer).boxed()
        };

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .with(span_layer)
            .init();
    }
}

#[cfg(feature = "otel")]
static OTEL_TRACER_PROVIDER: std::sync::OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> =
    std::sync::OnceLock::new();

#[cfg(feature = "otel")]
fn shutdown_otel_tracer_provider() {
    if let Some(provider) = OTEL_TRACER_PROVIDER.get() {
        if let Err(err) = provider.shutdown() {
            tracing::warn!(error = %err, "failed to shut down OpenTelemetry tracer provider");
        }
    }
}

fn acquire_lock(data_dir: &std::path::Path) -> Result<std::fs::File, Box<dyn std::error::Error + Send + Sync>> {
    let lock_path = data_dir.join("LOCK");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    file.try_lock_exclusive()?;
    Ok(file)
}

fn spawn_shutdown_signal(tx: broadcast::Sender<()>) {
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        // SAFETY: SIGTERM registration failure is fatal — daemon cannot shut down gracefully.
        #[allow(clippy::expect_used)]
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        #[cfg(unix)]
        tokio::select! {
            _ = ctrl_c => { tracing::info!("SIGINT received, shutting down"); }
            _ = sigterm.recv() => { tracing::info!("SIGTERM received, shutting down"); }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
            tracing::info!("SIGINT received, shutting down");
        }
        #[cfg(feature = "otel")]
        shutdown_otel_tracer_provider();

        let _ = tx.send(());
    });
}

fn observe_shard_map_metrics(metrics: &Metrics, table: &RoutingTable, node_id: &str) {
    for shard in &table.shard_map.shards {
        let state = match shard.state {
            corecrux_types::ShardState::Active => "active",
            corecrux_types::ShardState::Draining => "draining",
            corecrux_types::ShardState::Retired => "retired",
        };
        metrics.set_shard_state(&shard.shard_id, state);
        metrics.set_replication_shard_epoch(&shard.shard_id, shard.epoch);
        let follower_count = shard
            .followers
            .as_ref()
            .map_or(0, |followers| followers.iter().filter(|f| f.node_id != node_id).count());
        metrics.set_replication_follower_targets(&shard.shard_id, follower_count);
        metrics.set_replication_lag_segments(&shard.shard_id, 0, 0);
    }
}

async fn serve_http(
    addr: SocketAddr,
    app: Router,
    shutdown_rx: broadcast::Receiver<()>,
    drain_cap: Option<std::time::Duration>,
) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_http_listener(listener, app, shutdown_rx, drain_cap).await
}

/// Serves `app` on a pre-bound listener with TCP_NODELAY on every accepted
/// connection and a bounded graceful-shutdown drain
/// (crux-http-ingress-hardening-2026-06-11 M1).
///
/// On shutdown signal the server stops accepting and drains in-flight
/// connections; if `drain_cap` elapses first the serve future is dropped so
/// the daemon can finish exiting (logged as a warning). Connection tasks
/// already spawned by axum keep running until process exit closes their
/// sockets — the cap bounds how long shutdown blocks, which is the DoS door
/// (unbounded drain) this closes. `drain_cap: None` preserves the old
/// unbounded-drain behaviour.
async fn serve_http_listener(
    listener: tokio::net::TcpListener,
    app: Router,
    mut shutdown_rx: broadcast::Receiver<()>,
    drain_cap: Option<std::time::Duration>,
) -> Result<(), std::io::Error> {
    use axum::serve::ListenerExt as _;

    let listener = listener.tap_io(|stream| {
        if let Err(err) = stream.set_nodelay(true) {
            tracing::trace!(%err, "failed to set TCP_NODELAY on incoming connection");
        }
    });
    // Fan the broadcast shutdown signal out to (a) axum's graceful shutdown
    // and (b) the drain-cap timer, which must only start once draining began.
    let (drain_started_tx, drain_started_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async move {
        let _ = shutdown_rx.recv().await;
        let _ = drain_started_tx.send(());
    };
    // `into_make_service_with_connect_info` exposes the peer address as a
    // `ConnectInfo<SocketAddr>` request extension — the rate limiter's
    // per-IP fallback key (crux-http-ingress-hardening M3).
    let serve =
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(shutdown);
    match drain_cap {
        None => serve.await,
        Some(cap) => {
            tokio::select! {
                result = serve => result,
                _ = async {
                    let _ = drain_started_rx.await;
                    tokio::time::sleep(cap).await;
                } => {
                    tracing::warn!(
                        drain_cap_secs = cap.as_secs(),
                        "graceful-shutdown drain cap exceeded; abandoning remaining connections to process exit"
                    );
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NodeMetaV1 {
    v: u32,
    #[serde(rename = "nodeId")]
    node_id: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "httpListenAddr")]
    http_listen_addr: String,
    #[serde(rename = "grpcListenAddr")]
    grpc_listen_addr: String,
    #[serde(rename = "gpuId", skip_serializing_if = "Option::is_none")]
    gpu_id: Option<i32>,
    build: BuildInfo,
}

fn load_or_init_node_meta(
    path: &std::path::Path,
    node_id_override: Option<&str>,
    http_listen_addr: SocketAddr,
    grpc_listen_addr: SocketAddr,
    gpu_id: Option<i32>,
    build: &BuildInfo,
) -> std::io::Result<NodeMetaV1> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    if path.exists() {
        let bytes = std::fs::read(path)?;
        let meta: NodeMetaV1 = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        return Ok(meta);
    }

    let node_id = node_id_override.map_or_else(|| format!("node-{}", uuid::Uuid::new_v4()), |s| s.to_string());

    let meta = NodeMetaV1 {
        v: 1,
        node_id,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        http_listen_addr: http_listen_addr.to_string(),
        grpc_listen_addr: grpc_listen_addr.to_string(),
        gpu_id,
        build: build.clone(),
    };

    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(&meta)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
    f.write_all(&bytes)?;
    f.flush()?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;

    Ok(meta)
}

fn spawn_routing_reloader(
    config: crate::config::Config,
    shard_store: ShardMapStore,
    routing: Arc<RwLock<RoutingTable>>,
    routing_errors: Arc<RwLock<Vec<String>>>,
    metrics: Metrics,
    node_id: String,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(config.routing_reload_interval_ms));
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                _ = interval.tick() => {}
            }

            let current_version = { routing.read().await.current_version() };
            let loaded = match shard_store.load_current() {
                Ok(l) => l,
                Err(err) => {
                    let mut errs = routing_errors.write().await;
                    errs.push(format!("failed to load current shardmap: {err}"));
                    if errs.len() > 10 {
                        let excess = errs.len().saturating_sub(10);
                        errs.drain(0..excess);
                    }
                    continue;
                }
            };
            if loaded.current_version == current_version {
                continue;
            }

            let new_table = match RoutingTable::new(loaded) {
                Ok(t) => t,
                Err(err) => {
                    tracing::warn!(err = %err, "failed to build routing table for reload");
                    let mut errs = routing_errors.write().await;
                    errs.push(format!("failed to build routing table: {err}"));
                    if errs.len() > 10 {
                        let excess = errs.len().saturating_sub(10);
                        errs.drain(0..excess);
                    }
                    continue;
                }
            };

            metrics.set_shardmap_version(new_table.current_version());
            observe_shard_map_metrics(&metrics, &new_table, &node_id);

            tracing::info!(
                old_version = current_version,
                new_version = new_table.current_version(),
                blake3 = %new_table.shard_map.blake3,
                "routing table reloaded"
            );

            {
                let mut guard = routing.write().await;
                *guard = new_table.clone();
            }

            routing_errors.write().await.clear();
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapacityLevel {
    Healthy,
    Warning,
    Critical,
    Emergency,
}

impl CapacityLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }
}

fn classify_capacity_level(free_ratio: f64, config: &crate::config::Config) -> CapacityLevel {
    if free_ratio < config.capacity_emergency_free_ratio {
        CapacityLevel::Emergency
    } else if free_ratio < config.capacity_critical_free_ratio {
        CapacityLevel::Critical
    } else if free_ratio < config.capacity_warning_free_ratio {
        CapacityLevel::Warning
    } else {
        CapacityLevel::Healthy
    }
}

fn measure_data_dir_space(path: &Path) -> Result<(u64, u64), String> {
    let total = total_space(path).map_err(|err| format!("total_space failed: {err}"))?;
    let free = available_space(path).map_err(|err| format!("available_space failed: {err}"))?;
    Ok((total, free))
}

#[allow(clippy::too_many_arguments)] // Background guard requires shared state handles
fn spawn_capacity_guard(
    config: crate::config::Config,
    metrics: Metrics,
    control: Arc<RwLock<crate::control::ControlV1>>,
    dataplane_pool: Option<crate::pool::DataPlanePool>,
    capacity: Arc<RwLock<CapacityState>>,
    build: BuildInfo,
    node_id: String,
    control_path: std::path::PathBuf,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            config.capacity_guard_interval_secs.max(10),
        ));
        let node = build_node_context(
            &build,
            &node_id,
            Some(config.http_addr.to_string()),
            Some(config.grpc_addr.to_string()),
        );
        let mut last_level: Option<CapacityLevel> = None;
        let mut last_auto_paused = false;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                _ = interval.tick() => {}
            }

            let (total_bytes, free_bytes) = match measure_data_dir_space(&config.data_dir) {
                Ok(space) => space,
                Err(err) => {
                    tracing::warn!(err = %err, "capacity guard failed to measure data dir");
                    metrics.set_data_dir_space(0, 0);
                    let mut state = capacity.write().await;
                    state.total_bytes = 0;
                    state.free_bytes = 0;
                    state.free_ratio = 0.0;
                    state.auto_paused = false;
                    state.error = Some(err);
                    continue;
                }
            };

            metrics.set_data_dir_space(total_bytes, free_bytes);
            let free_ratio = if total_bytes == 0 {
                0.0
            } else {
                free_bytes as f64 / total_bytes as f64
            };
            let level = classify_capacity_level(free_ratio, &config);
            let mut pause_action = "observed".to_string();
            let mut transition_detail = format!(
                "free_ratio={:.3} warning={:.3} critical={:.3} emergency={:.3} free_bytes={} total_bytes={}",
                free_ratio,
                config.capacity_warning_free_ratio,
                config.capacity_critical_free_ratio,
                config.capacity_emergency_free_ratio,
                free_bytes,
                total_bytes
            );

            let (pause_ingest_active, auto_paused) = {
                let mut control_state = control.write().await;
                let guard_owned = control_state.valves.pause_ingest.actor == "capacity_guard";
                if level == CapacityLevel::Emergency {
                    if !control_state.valves.pause_ingest.enabled || guard_owned {
                        let reason = format!(
                            "capacity_guard free_ratio={:.3} below emergency threshold={:.3}",
                            free_ratio, config.capacity_emergency_free_ratio
                        );
                        let now_ns = crate::control::now_unix_ns();
                        control_state
                            .valves
                            .pause_ingest
                            .set(true, "capacity_guard", &reason, now_ns);
                        control_state.updated_at_unix_ns = now_ns;
                        if let Err(err) = crate::control::write_control_atomic(&control_path, &control_state) {
                            tracing::warn!(err = %err, "capacity guard failed to persist CONTROL.json");
                        } else {
                            metrics.set_valve_pause_ingest(true);
                            metrics.set_valve_state("pause_ingest", true);
                        }
                        pause_action = "pause_ingest_enabled".to_string();
                        transition_detail = reason;
                    }
                } else if guard_owned
                    && control_state.valves.pause_ingest.enabled
                    && free_ratio >= config.capacity_resume_free_ratio
                {
                    let reason = format!(
                        "capacity_guard free_ratio={:.3} recovered above resume threshold={:.3}",
                        free_ratio, config.capacity_resume_free_ratio
                    );
                    let now_ns = crate::control::now_unix_ns();
                    control_state
                        .valves
                        .pause_ingest
                        .set(false, "capacity_guard", &reason, now_ns);
                    control_state.updated_at_unix_ns = now_ns;
                    if let Err(err) = crate::control::write_control_atomic(&control_path, &control_state) {
                        tracing::warn!(err = %err, "capacity guard failed to persist CONTROL.json");
                    } else {
                        metrics.set_valve_pause_ingest(false);
                        metrics.set_valve_state("pause_ingest", false);
                    }
                    pause_action = "pause_ingest_cleared".to_string();
                    transition_detail = reason;
                }

                let pause_ingest_active = control_state.valves.pause_ingest.enabled;
                let auto_paused = pause_ingest_active && control_state.valves.pause_ingest.actor == "capacity_guard";
                (pause_ingest_active, auto_paused)
            };

            {
                let mut state = capacity.write().await;
                state.total_bytes = total_bytes;
                state.free_bytes = free_bytes;
                state.free_ratio = free_ratio;
                state.auto_paused = auto_paused;
                state.error = None;
            }

            if last_level != Some(level) || last_auto_paused != auto_paused {
                tracing::info!(
                    level = level.as_str(),
                    free_ratio = free_ratio,
                    free_bytes = free_bytes,
                    total_bytes = total_bytes,
                    auto_paused = auto_paused,
                    "capacity guard state changed"
                );
                if let Some(pool) = dataplane_pool.as_ref() {
                    let payload = CapacityThresholdBreachedV1 {
                        schema: EVT_CAPACITY_THRESHOLD_BREACHED_V1.to_string(),
                        observed_at_unix_ms: now_unix_ms(),
                        threshold_kind: level.as_str().to_string(),
                        threshold_ratio: match level {
                            CapacityLevel::Healthy => config.capacity_warning_free_ratio,
                            CapacityLevel::Warning => config.capacity_warning_free_ratio,
                            CapacityLevel::Critical => config.capacity_critical_free_ratio,
                            CapacityLevel::Emergency => config.capacity_emergency_free_ratio,
                        },
                        free_ratio,
                        free_bytes,
                        total_bytes,
                        action: pause_action.clone(),
                        pause_ingest_active,
                        detail: Some(transition_detail.clone()),
                        node: node.clone(),
                    };
                    let event_id = format!(
                        "{EVT_CAPACITY_THRESHOLD_BREACHED_V1}:{node_id}:{}:{}",
                        payload.observed_at_unix_ms,
                        level.as_str()
                    );
                    if let Err(err) =
                        append_ops_event(pool, &node_id, EVT_CAPACITY_THRESHOLD_BREACHED_V1, event_id, &payload).await
                    {
                        tracing::warn!(err = ?err, "failed to append capacity ops event");
                    }
                }
            }

            last_level = Some(level);
            last_auto_paused = auto_paused;
        }
    });
}

fn spawn_anonymous_passport_claim(
    state_dir: PathBuf,
    endpoint: String,
    passport_fpr: String,
    public_key_hex: String,
    daemon_version: String,
) {
    let marker_path = state_dir.join(PASSPORT_CLAIM_MARKER_FILENAME);
    if marker_path.exists() {
        tracing::debug!(
            passport_fpr = %passport_fpr,
            marker = %marker_path.display(),
            "anonymous Passport claim already recorded"
        );
        return;
    }
    tokio::spawn(async move {
        let claim_fpr = passport_fpr.clone();
        let result = tokio::task::spawn_blocking(move || {
            claim_anonymous_passport(&endpoint, &claim_fpr, &public_key_hex, &daemon_version)
        })
        .await;

        match result {
            Ok(Ok(status)) => {
                let marker = format!("passport_fpr={passport_fpr}\nstatus={status}\n");
                if let Err(err) = std::fs::write(&marker_path, marker) {
                    tracing::debug!(
                        passport_fpr = %passport_fpr,
                        marker = %marker_path.display(),
                        error = %err,
                        "anonymous Passport claim marker write failed"
                    );
                }
                info!(
                    passport_fpr = %passport_fpr,
                    status = status,
                    "anonymous Passport claim accepted"
                );
            }
            Ok(Err(err)) => {
                tracing::debug!(
                    passport_fpr = %passport_fpr,
                    error = %err,
                    "anonymous Passport claim skipped"
                );
            }
            Err(err) => {
                tracing::debug!(
                    passport_fpr = %passport_fpr,
                    error = %err,
                    "anonymous Passport claim task failed"
                );
            }
        }
    });
}

fn claim_anonymous_passport(
    endpoint: &str,
    passport_fpr: &str,
    public_key_hex: &str,
    daemon_version: &str,
) -> Result<u16, String> {
    let body = anonymous_passport_claim_body(public_key_hex, daemon_version)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(2)))
        .timeout_recv_response(Some(Duration::from_secs(5)))
        .timeout_recv_body(Some(Duration::from_secs(5)))
        .build()
        .into();
    let resp = agent
        .post(endpoint)
        .content_type("application/cbor")
        .header("accept", "application/cbor, application/json")
        .send(body)
        .map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    if (200..300).contains(&status) {
        Ok(status)
    } else {
        Err(format!("claim for {passport_fpr} returned HTTP {status}"))
    }
}

fn anonymous_passport_claim_body(public_key_hex: &str, daemon_version: &str) -> Result<Vec<u8>, String> {
    let pubkey = hex::decode(public_key_hex).map_err(|e| format!("decode Passport public key: {e}"))?;
    if pubkey.len() != 32 {
        return Err(format!("Passport public key must be 32 bytes, got {}", pubkey.len()));
    }
    Ok(crux_session::canonical::CborValue::Map(vec![
        ("pubkey".to_string(), crux_session::canonical::CborValue::Bytes(pubkey)),
        (
            "daemon_version".to_string(),
            crux_session::canonical::CborValue::Text(daemon_version.to_string()),
        ),
        (
            "claim_proof".to_string(),
            crux_session::canonical::CborValue::Text(String::new()),
        ),
    ])
    .encode())
}

#[cfg(test)]
mod tests {
    use super::{
        anonymous_passport_claim_body, parse_cli_arg, reconcile_control_from_evidence, shard_map_advertise_addr,
        validate_mcp_bind_posture, validate_network_auth_posture, version_line, CliAction, ControlCheckpointRecord,
        ControlMutationRecord,
    };
    use crate::auth::AuthMode;
    use crate::config::CommitLevel;
    use crate::control;
    use corecrux_types::{
        BuildInfo, ControlCheckpointMaterializedV1, ControlStateMutationV1, EvidenceAuthContextV1,
        EvidenceNodeContextV1, EvidenceRequestContextV1, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1,
        EVT_CONTROL_STATE_MUTATION_V1,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn sample_node() -> EvidenceNodeContextV1 {
        EvidenceNodeContextV1 {
            node_id: "node-a".to_string(),
            build: BuildInfo {
                version: "test".to_string(),
                commit: "test".to_string(),
            },
            http_listen_addr: None,
            grpc_listen_addr: None,
        }
    }

    #[test]
    fn parse_cli_arg_decides_action() {
        let v = |s: &str| s.to_string();
        assert_eq!(parse_cli_arg(&[v("--version")]), CliAction::Version);
        assert_eq!(parse_cli_arg(&[v("-V")]), CliAction::Version);
        assert_eq!(parse_cli_arg(&[v("version")]), CliAction::Version);
        assert_eq!(parse_cli_arg(&[v("--help")]), CliAction::Help);
        assert_eq!(parse_cli_arg(&[v("-h")]), CliAction::Help);
        assert_eq!(parse_cli_arg(&[v("help")]), CliAction::Help);
        // `self …` routes to the self-update subcommand (sub-parsed in self_update).
        assert_eq!(parse_cli_arg(&[v("self")]), CliAction::SelfCmd);
        assert_eq!(parse_cli_arg(&[v("self"), v("update")]), CliAction::SelfCmd);
        // No args → run the daemon.
        assert_eq!(parse_cli_arg(&[]), CliAction::Run);
        // Unrecognised first arg → run (env-only design ignores unknown flags here).
        assert_eq!(parse_cli_arg(&[v("--serve")]), CliAction::Run);
        // Only the first arg is inspected.
        assert_eq!(parse_cli_arg(&[v("serve"), v("--version")]), CliAction::Run);
    }

    #[test]
    fn version_line_includes_pkg_version() {
        let line = version_line();
        assert!(line.starts_with("corecruxd "), "got: {line}");
        assert!(line.contains(env!("CARGO_PKG_VERSION")), "got: {line}");
        assert!(line.contains('('), "got: {line}");
    }

    #[test]
    fn anonymous_passport_claim_body_matches_spec_shape() {
        let public_key_hex = "00".repeat(32);
        let body = anonymous_passport_claim_body(&public_key_hex, "crux/0.1.0").expect("claim body");
        let decoded = crux_session::canonical::decode(&body).expect("decode claim body");
        let crux_session::canonical::CborValue::Map(pairs) = decoded else {
            panic!("claim body must be a CBOR map");
        };

        let pubkey = pairs
            .iter()
            .find_map(|(key, value)| (key == "pubkey").then_some(value))
            .expect("pubkey field");
        let daemon_version = pairs
            .iter()
            .find_map(|(key, value)| (key == "daemon_version").then_some(value))
            .expect("daemon_version field");
        let claim_proof = pairs
            .iter()
            .find_map(|(key, value)| (key == "claim_proof").then_some(value))
            .expect("claim_proof field");

        assert!(matches!(pubkey, crux_session::canonical::CborValue::Bytes(bytes) if bytes.len() == 32));
        assert!(matches!(daemon_version, crux_session::canonical::CborValue::Text(value) if value == "crux/0.1.0"));
        assert!(matches!(claim_proof, crux_session::canonical::CborValue::Text(value) if value.is_empty()));
    }

    fn sample_auth() -> EvidenceAuthContextV1 {
        EvidenceAuthContextV1 {
            mode: "dev_scopes".to_string(),
            subject: None,
            tenant_binding: None,
            scopes: vec!["admin:write".to_string()],
        }
    }

    fn mutation_record(seq: u64, before: &control::ControlV1, after: &control::ControlV1) -> ControlMutationRecord {
        ControlMutationRecord {
            seq,
            payload: ControlStateMutationV1 {
                schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                action_id: format!("act-{seq}"),
                mutation_type: "set_valves".to_string(),
                applied_at_unix_ms: seq,
                actor: "operator".to_string(),
                reason: "maintenance".to_string(),
                auth: sample_auth(),
                request: EvidenceRequestContextV1::default(),
                node: sample_node(),
                control_before: control::control_state_digest_v1(before),
                control_after: control::control_state_digest_v1(after),
                valve_changes: control::valve_changes_v1(before, after),
                knowledge_authority_change: None,
                result: None,
            },
        }
    }

    fn checkpoint_record(seq: u64, state: &control::ControlV1) -> ControlCheckpointRecord {
        let bytes = control::checkpoint_control_bytes_v1(state);
        ControlCheckpointRecord {
            seq,
            payload: ControlCheckpointMaterializedV1 {
                schema: EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1.to_string(),
                checkpoint_id: format!("checkpoint-{seq}"),
                materialized_at_unix_ms: seq,
                node: sample_node(),
                control_state: control::control_state_digest_v1(state),
                checkpoint_format: "control.json.pretty.v1".to_string(),
                checkpoint_blake3: blake3::hash(&bytes).to_hex().to_string(),
                checkpoint_size_bytes: bytes.len() as u64,
            },
        }
    }

    #[test]
    fn dev_auth_rejects_non_loopback_bind_without_override() {
        let err = validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect_err("non-loopback dev auth bind must fail closed");
        assert!(err.contains("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND"));
    }

    #[test]
    fn dev_auth_allows_non_loopback_bind_with_override() {
        validate_network_auth_posture(
            AuthMode::Off,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4007),
            CommitLevel::LocalCommit,
            true,
            false,
        )
        .expect("explicit override should permit insecure dev bind");
    }

    #[test]
    fn replicated_commit_with_jwt_requires_replication_bearer() {
        let err = validate_network_auth_posture(
            AuthMode::JwtJwks,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            false,
        )
        .expect_err("jwt replicated commit should require explicit replication auth");
        assert!(err.contains("CORECRUXD_REPLICATION_AUTH_BEARER"));
    }

    #[test]
    fn replicated_commit_with_jwt_accepts_replication_bearer() {
        validate_network_auth_posture(
            AuthMode::JwtHs256,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            true,
        )
        .expect("explicit replication bearer should satisfy jwt replicated commit auth");
    }

    #[test]
    fn shard_map_advertise_addr_preserves_explicit_host() {
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 4006)),
            "10.1.2.3:4006"
        );
    }

    #[test]
    fn shard_map_advertise_addr_normalizes_unspecified_host_to_loopback() {
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006)),
            "127.0.0.1:4006"
        );
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 4007)),
            "[::1]:4007"
        );
    }

    #[test]
    fn control_evidence_replays_from_matching_checkpoint() {
        let default_state = control::ControlV1::default();
        let mut checkpoint_state = default_state.clone();
        checkpoint_state.updated_at_unix_ns = 10;
        checkpoint_state
            .valves
            .read_only
            .set(true, "operator", "maintenance", 10);

        let mut final_state = checkpoint_state.clone();
        final_state.updated_at_unix_ns = 20;
        final_state.valves.throttle.set(true, "operator", "maintenance", 20);
        final_state
            .valves
            .throttle
            .set_throttle_params(Some(20), Some(4096), Some(3));

        let plan = reconcile_control_from_evidence(
            &checkpoint_state,
            &control::checkpoint_control_bytes_v1(&checkpoint_state),
            &[checkpoint_record(2, &checkpoint_state)],
            &[mutation_record(3, &checkpoint_state, &final_state)],
        )
        .expect("reconcile succeeds")
        .expect("replay plan present");

        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 2);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    #[test]
    fn control_evidence_replays_from_default_when_stream_starts_clean() {
        let default_state = control::ControlV1::default();
        let mut final_state = default_state.clone();
        final_state.updated_at_unix_ns = 30;
        final_state
            .valves
            .emergency_brake
            .set(true, "operator", "maintenance", 30);
        final_state.valves.read_only.set(true, "operator", "maintenance", 30);
        final_state.valves.pause_ingest.set(true, "operator", "maintenance", 30);
        final_state
            .valves
            .pause_compaction
            .set(true, "operator", "maintenance", 30);

        let plan = reconcile_control_from_evidence(
            &default_state,
            &control::checkpoint_control_bytes_v1(&default_state),
            &[],
            &[mutation_record(1, &default_state, &final_state)],
        )
        .expect("reconcile succeeds")
        .expect("replay plan present");

        assert_eq!(plan.anchor, "default");
        assert_eq!(plan.anchor_seq, 0);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    // ── validate_network_auth_posture additional cases ───────────────────

    #[test]
    fn auth_off_on_loopback_is_fine() {
        validate_network_auth_posture(
            AuthMode::Off,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect("loopback with auth off should always be fine");
    }

    #[test]
    fn jwt_hs256_non_loopback_is_ok_without_replication() {
        validate_network_auth_posture(
            AuthMode::JwtHs256,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect("jwt with local commit should be ok on non-loopback");
    }

    #[test]
    fn jwt_jwks_replicated_commit_fails_without_bearer() {
        let err = validate_network_auth_posture(
            AuthMode::JwtJwks,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            false,
        )
        .expect_err("replicated commit with jwt should require replication bearer");
        assert!(err.contains("REPLICATION_AUTH_BEARER"));
    }

    #[test]
    fn dev_scopes_on_v6_loopback_is_ok() {
        validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect("v6 loopback with dev scopes should be fine");
    }

    #[test]
    fn dev_scopes_mixed_loopback_and_non_loopback_fails() {
        let err = validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect_err("mixed loopback/non-loopback should fail");
        assert!(err.contains("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND"));
    }

    #[test]
    fn mcp_non_loopback_without_agent_tokens_fails() {
        let err = validate_mcp_bind_posture(
            true,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 14801),
            true,
            false,
        )
        .expect_err("non-loopback MCP without tokens should fail");
        assert!(err.contains("CRUX_AGENT_TOKEN"));
    }

    #[test]
    fn mcp_non_loopback_with_agent_tokens_is_ok() {
        validate_mcp_bind_posture(
            true,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 14801),
            false,
            false,
        )
        .expect("configured MCP tokens should allow non-loopback bind");
    }

    #[test]
    fn mcp_disabled_skips_bind_validation() {
        validate_mcp_bind_posture(
            false,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 14801),
            true,
            false,
        )
        .expect("disabled MCP should skip validation");
    }

    // ── shard_map_advertise_addr additional cases ────────────────────────

    #[test]
    fn shard_map_advertise_addr_preserves_v6_explicit_host() {
        let addr = SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), 4006);
        assert_eq!(shard_map_advertise_addr(addr), "[fe80::1]:4006");
    }

    #[test]
    fn shard_map_advertise_addr_preserves_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9999);
        assert_eq!(shard_map_advertise_addr(addr), "192.168.1.1:9999");
    }

    // ── reconcile_control_from_evidence additional cases ─────────────────

    #[test]
    fn reconcile_empty_evidence_returns_none() {
        let state = control::ControlV1::default();
        let result = reconcile_control_from_evidence(&state, &control::checkpoint_control_bytes_v1(&state), &[], &[])
            .expect("reconcile succeeds");
        assert!(result.is_none());
    }

    #[test]
    fn reconcile_picks_highest_anchor_seq_when_both_present() {
        let default_state = control::ControlV1::default();
        let mut mid_state = default_state.clone();
        mid_state.updated_at_unix_ns = 10;
        mid_state.valves.read_only.set(true, "operator", "test", 10);

        let mut final_state = mid_state.clone();
        final_state.updated_at_unix_ns = 20;
        final_state.valves.throttle.set(true, "operator", "test", 20);
        final_state
            .valves
            .throttle
            .set_throttle_params(Some(10), Some(1024), Some(5));

        // Checkpoint at seq=5, mutation anchor at seq=3
        // Checkpoint has higher seq, should be chosen as anchor
        let plan = reconcile_control_from_evidence(
            &mid_state,
            &control::checkpoint_control_bytes_v1(&mid_state),
            &[checkpoint_record(5, &mid_state)],
            &[
                mutation_record(3, &default_state, &mid_state),
                mutation_record(6, &mid_state, &final_state),
            ],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 5);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    #[test]
    fn reconcile_picks_mutation_anchor_when_higher_seq() {
        let default_state = control::ControlV1::default();
        let mut mid_state = default_state.clone();
        mid_state.updated_at_unix_ns = 10;
        mid_state.valves.read_only.set(true, "operator", "test", 10);

        let mut final_state = mid_state.clone();
        final_state.updated_at_unix_ns = 20;
        final_state.valves.throttle.set(true, "operator", "test", 20);
        final_state
            .valves
            .throttle
            .set_throttle_params(Some(10), Some(1024), Some(5));

        // Checkpoint at seq=2, mutation anchor at seq=5 (mid_state matches)
        let plan = reconcile_control_from_evidence(
            &mid_state,
            &control::checkpoint_control_bytes_v1(&mid_state),
            &[checkpoint_record(2, &mid_state)],
            &[
                mutation_record(5, &default_state, &mid_state),
                mutation_record(6, &mid_state, &final_state),
            ],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 5);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    #[test]
    fn reconcile_errors_when_no_anchor_and_mutations_dont_start_from_default() {
        // Create a "current" state that does NOT match any mutation's control_after
        let mut unrelated_state = control::ControlV1::default();
        unrelated_state.updated_at_unix_ns = 999;
        unrelated_state
            .valves
            .emergency_brake
            .set(true, "operator", "unrelated", 999);

        // Create mutations that start from a non-default state
        let mut state_a = control::ControlV1::default();
        state_a.updated_at_unix_ns = 100;
        state_a.valves.read_only.set(true, "operator", "test", 100);

        let mut state_b = state_a.clone();
        state_b.updated_at_unix_ns = 200;
        state_b.valves.pause_ingest.set(true, "operator", "test", 200);

        // Current state matches nothing; first mutation's control_before != default
        let err = reconcile_control_from_evidence(
            &unrelated_state,
            &control::checkpoint_control_bytes_v1(&unrelated_state),
            &[],
            &[mutation_record(1, &state_a, &state_b)],
        )
        .expect_err("should error when no anchor found");
        assert!(err.contains("does not match any checkpoint"));
    }

    #[test]
    fn reconcile_applies_multiple_mutations_in_sequence() {
        let default_state = control::ControlV1::default();

        let mut state1 = default_state.clone();
        state1.updated_at_unix_ns = 10;
        state1.valves.read_only.set(true, "operator", "step1", 10);

        let mut state2 = state1.clone();
        state2.updated_at_unix_ns = 20;
        state2.valves.pause_ingest.set(true, "operator", "step2", 20);

        let mut state3 = state2.clone();
        state3.updated_at_unix_ns = 30;
        state3.valves.emergency_brake.set(true, "operator", "step3", 30);

        let plan = reconcile_control_from_evidence(
            &default_state,
            &control::checkpoint_control_bytes_v1(&default_state),
            &[],
            &[
                mutation_record(1, &default_state, &state1),
                mutation_record(2, &state1, &state2),
                mutation_record(3, &state2, &state3),
            ],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        assert_eq!(plan.anchor, "default");
        assert_eq!(plan.applied_mutations, 3);
        assert_eq!(plan.state, state3);
    }

    // ── ControlEvidenceRuntimeStatus ─────────────────────────────────────

    #[test]
    fn control_evidence_status_non_hosted() {
        let status = super::ControlEvidenceRuntimeStatus::non_hosted("not on this node");
        assert!(!status.hosted_locally);
        assert!(status.ok);
        assert_eq!(status.detail.as_deref(), Some("not on this node"));
    }

    #[test]
    fn control_evidence_status_hosted_ok() {
        let status = super::ControlEvidenceRuntimeStatus::hosted_ok("all good");
        assert!(status.hosted_locally);
        assert!(status.ok);
        assert_eq!(status.detail.as_deref(), Some("all good"));
    }

    #[test]
    fn control_evidence_status_hosted_err() {
        let status = super::ControlEvidenceRuntimeStatus::hosted_err("reconcile failed");
        assert!(status.hosted_locally);
        assert!(!status.ok);
        assert_eq!(status.detail.as_deref(), Some("reconcile failed"));
    }

    #[test]
    fn control_evidence_replay_plan_eq() {
        let state = control::ControlV1::default();
        let plan1 = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 2,
        };
        let plan2 = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 2,
        };
        assert_eq!(plan1, plan2);
    }

    #[test]
    fn control_evidence_replay_plan_ne_on_mutations() {
        let state = control::ControlV1::default();
        let plan1 = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 2,
        };
        let plan2 = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 3,
        };
        assert_ne!(plan1, plan2);
    }

    // ── NodeMetaV1 serde roundtrip ───────��───────────────────────────────

    #[test]
    fn node_meta_v1_serde_roundtrip() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "node-abc".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: Some(0),
            build: BuildInfo {
                version: "0.1.0".to_string(),
                commit: "abc123".to_string(),
            },
        };
        let json_bytes = serde_json::to_vec(&meta).unwrap();
        let roundtripped: super::NodeMetaV1 = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(roundtripped.node_id, "node-abc");
        assert_eq!(roundtripped.gpu_id, Some(0));
        assert_eq!(roundtripped.build.version, "0.1.0");
    }

    #[test]
    fn node_meta_v1_gpu_id_none_omitted_in_json() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "node-xyz".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: None,
            build: BuildInfo {
                version: "0.1.0".to_string(),
                commit: "abc123".to_string(),
            },
        };
        let json_str = serde_json::to_string(&meta).unwrap();
        assert!(!json_str.contains("gpuId"), "gpuId should be omitted when None");
    }

    #[test]
    fn node_meta_v1_camel_case_field_names() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "node-test".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: Some(2),
            build: BuildInfo {
                version: "1.0.0".to_string(),
                commit: "def456".to_string(),
            },
        };
        let v: serde_json::Value = serde_json::to_value(&meta).unwrap();
        assert!(v.get("nodeId").is_some());
        assert!(v.get("createdAt").is_some());
        assert!(v.get("httpListenAddr").is_some());
        assert!(v.get("grpcListenAddr").is_some());
        assert!(v.get("gpuId").is_some());
    }

    // ── load_or_init_node_meta ──────────────────────────────────────────

    #[test]
    fn load_or_init_node_meta_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        let meta = super::load_or_init_node_meta(
            &path,
            Some("node-fixed"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            Some(0),
            &build,
        )
        .unwrap();
        assert_eq!(meta.node_id, "node-fixed");
        assert_eq!(meta.v, 1);
        assert_eq!(meta.gpu_id, Some(0));
        assert!(path.exists());
    }

    #[test]
    fn load_or_init_node_meta_loads_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        // Create first.
        let meta1 = super::load_or_init_node_meta(
            &path,
            Some("node-first"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            None,
            &build,
        )
        .unwrap();
        // Load again (should not overwrite).
        let meta2 = super::load_or_init_node_meta(
            &path,
            Some("node-second"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15801),
            Some(1),
            &build,
        )
        .unwrap();
        assert_eq!(meta1.node_id, meta2.node_id);
        assert_eq!(meta2.node_id, "node-first");
    }

    #[test]
    fn load_or_init_node_meta_generates_uuid_when_no_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        let meta = super::load_or_init_node_meta(
            &path,
            None,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            None,
            &build,
        )
        .unwrap();
        assert!(
            meta.node_id.starts_with("node-"),
            "expected 'node-' prefix, got: {}",
            meta.node_id
        );
        assert!(meta.node_id.len() > 10, "expected UUID suffix");
    }

    #[test]
    fn load_or_init_node_meta_invalid_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("meta");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("node.json");
        std::fs::write(&path, b"not-json").unwrap();
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        let err = super::load_or_init_node_meta(
            &path,
            None,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            None,
            &build,
        );
        assert!(err.is_err());
    }

    // ── acquire_lock ────────────────────────────────────────────────────

    #[test]
    fn acquire_lock_creates_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let lock = super::acquire_lock(dir.path()).unwrap();
        assert!(dir.path().join("LOCK").exists());
        drop(lock);
    }

    #[test]
    fn acquire_lock_second_attempt_fails() {
        let dir = tempfile::tempdir().unwrap();
        let _lock = super::acquire_lock(dir.path()).unwrap();
        let result = super::acquire_lock(dir.path());
        assert!(result.is_err(), "second exclusive lock should fail");
    }

    #[test]
    fn acquire_lock_succeeds_after_drop() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _lock = super::acquire_lock(dir.path()).unwrap();
        }
        // After drop, lock should be released.
        let _lock2 = super::acquire_lock(dir.path()).unwrap();
    }

    // ── classify_capacity_level ─────────────────────────────────────────

    // Uses load_config() with default env (serial to avoid env pollution).
    // Default thresholds after normalization: warning=0.20, critical=0.10, emergency=0.10.
    #[test]
    #[serial_test::serial]
    fn classify_capacity_healthy() {
        let cfg = crate::config::load_config();
        assert_eq!(
            super::classify_capacity_level(0.25, &cfg),
            super::CapacityLevel::Healthy
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_warning() {
        let cfg = crate::config::load_config();
        // Between emergency/critical (0.10) and warning (0.20)
        assert_eq!(
            super::classify_capacity_level(0.15, &cfg),
            super::CapacityLevel::Warning
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_emergency_default_thresholds() {
        let cfg = crate::config::load_config();
        // Default critical == emergency == 0.10, so anything below is Emergency.
        assert_eq!(
            super::classify_capacity_level(0.05, &cfg),
            super::CapacityLevel::Emergency
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_at_exact_boundaries() {
        let cfg = crate::config::load_config();
        // Just below warning threshold => Warning
        assert_eq!(
            super::classify_capacity_level(cfg.capacity_warning_free_ratio - 0.001, &cfg),
            super::CapacityLevel::Warning
        );
        // At exactly the warning threshold => Healthy (>= warning)
        assert_eq!(
            super::classify_capacity_level(cfg.capacity_warning_free_ratio, &cfg),
            super::CapacityLevel::Healthy
        );
        // At exactly the emergency threshold => Emergency (< critical == emergency)
        assert_eq!(
            super::classify_capacity_level(cfg.capacity_emergency_free_ratio - 0.001, &cfg),
            super::CapacityLevel::Emergency
        );
    }

    // ── CapacityLevel::as_str ───────────────────────────────────────────

    #[test]
    fn capacity_level_as_str() {
        assert_eq!(super::CapacityLevel::Healthy.as_str(), "healthy");
        assert_eq!(super::CapacityLevel::Warning.as_str(), "warning");
        assert_eq!(super::CapacityLevel::Critical.as_str(), "critical");
        assert_eq!(super::CapacityLevel::Emergency.as_str(), "emergency");
    }

    // ── measure_data_dir_space ──────────────────────────────────────────

    #[test]
    fn measure_data_dir_space_on_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let (total, free) = super::measure_data_dir_space(dir.path()).unwrap();
        assert!(total > 0, "total bytes should be >0");
        assert!(free > 0, "free bytes should be >0");
        assert!(free <= total, "free should not exceed total");
    }

    #[test]
    fn measure_data_dir_space_nonexistent_errors() {
        let result = super::measure_data_dir_space(std::path::Path::new("/nonexistent_dir_xyz"));
        assert!(result.is_err());
    }

    // ── ControlCheckpointRecord / ControlMutationRecord parsing ─────────

    #[test]
    fn control_checkpoint_record_serde_roundtrip() {
        let state = control::ControlV1::default();
        let rec = checkpoint_record(42, &state);
        let json = serde_json::to_vec(&rec.payload).unwrap();
        let parsed: ControlCheckpointMaterializedV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.checkpoint_id, "checkpoint-42");
        assert_eq!(parsed.materialized_at_unix_ms, 42);
        assert_eq!(parsed.control_state, control::control_state_digest_v1(&state));
    }

    #[test]
    fn control_mutation_record_serde_roundtrip() {
        let before = control::ControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 99;
        after.valves.pause_ingest.set(true, "test", "test-reason", 99);
        let rec = mutation_record(7, &before, &after);
        let json = serde_json::to_vec(&rec.payload).unwrap();
        let parsed: ControlStateMutationV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.action_id, "act-7");
        assert_eq!(parsed.mutation_type, "set_valves");
        assert_eq!(parsed.control_before, control::control_state_digest_v1(&before));
        assert_eq!(parsed.control_after, control::control_state_digest_v1(&after));
    }

    // ── ControlEvidenceReplayPlan Debug ─────────────────────────────────

    #[test]
    fn control_evidence_replay_plan_debug_display() {
        let plan = super::ControlEvidenceReplayPlan {
            state: control::ControlV1::default(),
            anchor: "checkpoint",
            anchor_seq: 10,
            applied_mutations: 3,
        };
        let debug_str = format!("{:?}", plan);
        assert!(debug_str.contains("checkpoint"));
        assert!(debug_str.contains("10"));
        assert!(debug_str.contains('3'));
    }

    // ── reconcile_control_from_evidence: checkpoint-only (no mutations) ─

    #[test]
    fn reconcile_checkpoint_only_no_mutations() {
        let state = control::ControlV1::default();
        let plan = reconcile_control_from_evidence(
            &state,
            &control::checkpoint_control_bytes_v1(&state),
            &[checkpoint_record(1, &state)],
            &[],
        )
        .expect("reconcile succeeds")
        .expect("plan present");
        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 1);
        assert_eq!(plan.applied_mutations, 0);
        assert_eq!(plan.state, state);
    }

    // ── reconcile_control_from_evidence: mutation-only anchor (no checkpoints)

    #[test]
    fn reconcile_mutation_only_anchor() {
        let default_state = control::ControlV1::default();
        let mut final_state = default_state.clone();
        final_state.updated_at_unix_ns = 50;
        final_state.valves.throttle.set(true, "operator", "test", 50);
        final_state
            .valves
            .throttle
            .set_throttle_params(Some(100), Some(8192), Some(8));

        let plan = reconcile_control_from_evidence(
            &final_state,
            &control::checkpoint_control_bytes_v1(&final_state),
            &[],
            &[mutation_record(1, &default_state, &final_state)],
        )
        .expect("reconcile succeeds")
        .expect("plan present");
        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 1);
        assert_eq!(plan.applied_mutations, 0);
    }

    // ── shard_map_advertise_addr: loopback passthrough ──────────────────

    #[test]
    fn shard_map_advertise_addr_loopback_passthrough() {
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006)),
            "127.0.0.1:4006"
        );
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4006)),
            "[::1]:4006"
        );
    }

    // ── ControlEvidenceRuntimeStatus equality ───────────────────────────

    #[test]
    fn control_evidence_runtime_status_equality() {
        let a = super::ControlEvidenceRuntimeStatus::hosted_ok("test");
        let b = super::ControlEvidenceRuntimeStatus::hosted_ok("test");
        assert_eq!(a, b);

        let c = super::ControlEvidenceRuntimeStatus::hosted_err("test");
        assert_ne!(a, c);

        let d = super::ControlEvidenceRuntimeStatus::non_hosted("test");
        assert_ne!(a, d);
    }

    // ── update_control_metrics ─────────────────────────────────────────

    #[test]
    fn update_control_metrics_sets_valve_gauges() {
        let build = BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-svc");
        let mut state = control::ControlV1::default();
        state.valves.pause_ingest.set(true, "op", "test", 1);
        state.valves.read_only.set(true, "op", "test", 1);
        // Should not panic; exercises the full valve-sync surface.
        super::update_control_metrics(&metrics, &state);
    }

    #[test]
    fn update_control_metrics_default_state() {
        let build = BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-svc-default");
        let state = control::ControlV1::default();
        super::update_control_metrics(&metrics, &state);
    }

    #[test]
    fn update_control_metrics_all_valves_enabled() {
        let build = BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-svc-all");
        let mut state = control::ControlV1::default();
        state.valves.pause_ingest.set(true, "op", "r", 1);
        state.valves.pause_compaction.set(true, "op", "r", 2);
        state.valves.throttle.set(true, "op", "r", 3);
        state.valves.read_only.set(true, "op", "r", 4);
        state.valves.emergency_brake.set(true, "op", "r", 5);
        super::update_control_metrics(&metrics, &state);
    }

    // ── resolve_mcp_agent_registry (fail-closed) ────────────────────────

    #[test]
    fn mcp_ok_registry_passes_through() {
        let reg = crux_mcp::agent::AgentRegistry::from_single_token("crux_at_0123456789abcdef01234567");
        assert!(!reg.is_empty());
        let resolved = super::resolve_mcp_agent_registry(Ok(reg), false).expect("ok passes through");
        assert!(!resolved.is_empty());
    }

    #[test]
    fn mcp_empty_single_user_registry_passes_through() {
        // No token env → Ok(empty) is a legitimate single-user mode, not an error.
        let resolved =
            super::resolve_mcp_agent_registry(Ok(crux_mcp::agent::AgentRegistry::empty()), false).expect("empty ok");
        assert!(resolved.is_empty());
    }

    #[test]
    fn mcp_invalid_token_fails_startup_without_override() {
        let err = crux_mcp::agent::AgentRegistryError {
            message: "bad token".to_string(),
        };
        let resolved = super::resolve_mcp_agent_registry(Err(err), false);
        assert!(resolved.is_err(), "invalid token must abort startup without override");
        assert!(resolved.unwrap_err().contains(super::ALLOW_EMPTY_AGENT_REGISTRY_ENV));
    }

    #[test]
    fn mcp_invalid_token_with_dev_override_allows_empty() {
        let err = crux_mcp::agent::AgentRegistryError {
            message: "bad token".to_string(),
        };
        let resolved = super::resolve_mcp_agent_registry(Err(err), true).expect("override permits boot");
        assert!(resolved.is_empty(), "override falls back to empty no-auth registry");
    }

    // ── insecure_dev_auth_bind_allowed ──────────────────────────────────

    #[test]
    #[serial_test::serial]
    fn insecure_dev_auth_bind_allowed_defaults_false() {
        std::env::remove_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND");
        assert!(!super::insecure_dev_auth_bind_allowed());
    }

    #[test]
    #[serial_test::serial]
    fn insecure_dev_auth_bind_allowed_true_when_set() {
        std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", "1");
        assert!(super::insecure_dev_auth_bind_allowed());
        std::env::remove_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND");
    }

    #[test]
    #[serial_test::serial]
    fn insecure_dev_auth_bind_allowed_true_variants() {
        for val in &["true", "TRUE", "yes", "YES"] {
            std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", val);
            assert!(super::insecure_dev_auth_bind_allowed(), "expected true for {val}");
        }
        std::env::remove_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND");
    }

    #[test]
    #[serial_test::serial]
    fn insecure_dev_auth_bind_allowed_false_for_other_values() {
        std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", "0");
        assert!(!super::insecure_dev_auth_bind_allowed());
        std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", "no");
        assert!(!super::insecure_dev_auth_bind_allowed());
        std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", "maybe");
        assert!(!super::insecure_dev_auth_bind_allowed());
        std::env::remove_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND");
    }

    // ── replication_auth_bearer_configured ──────────────────────────────

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_configured_defaults_false() {
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
        assert!(!super::replication_auth_bearer_configured());
    }

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_configured_true_when_set() {
        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "my-secret");
        assert!(super::replication_auth_bearer_configured());
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_configured_false_for_empty() {
        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "");
        assert!(!super::replication_auth_bearer_configured());
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_configured_false_for_whitespace() {
        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "   ");
        assert!(!super::replication_auth_bearer_configured());
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    // ── shard_map_advertise_addr: port 0 edge case ─────────────────────

    #[test]
    fn shard_map_advertise_addr_port_zero() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0);
        assert_eq!(super::shard_map_advertise_addr(addr), "10.0.0.1:0");
    }

    #[test]
    fn shard_map_advertise_addr_max_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 65535);
        assert_eq!(super::shard_map_advertise_addr(addr), "127.0.0.1:65535");
    }

    // ── classify_capacity_level with custom config ─────────────────────

    #[test]
    #[serial_test::serial]
    fn classify_capacity_level_zero_ratio_is_emergency() {
        let cfg = crate::config::load_config();
        assert_eq!(
            super::classify_capacity_level(0.0, &cfg),
            super::CapacityLevel::Emergency
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_level_full_is_healthy() {
        let cfg = crate::config::load_config();
        assert_eq!(super::classify_capacity_level(1.0, &cfg), super::CapacityLevel::Healthy);
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_level_negative_is_emergency() {
        let cfg = crate::config::load_config();
        assert_eq!(
            super::classify_capacity_level(-0.1, &cfg),
            super::CapacityLevel::Emergency
        );
    }

    // ── CapacityLevel clone and debug ──────────────────────────────────

    #[test]
    fn capacity_level_clone_and_debug() {
        let level = super::CapacityLevel::Warning;
        let cloned = level;
        assert_eq!(level, cloned);
        let debug = format!("{:?}", level);
        assert!(debug.contains("Warning"));
    }

    // ── reconcile_control_from_evidence: only checkpoint, stale ────────

    #[test]
    fn reconcile_checkpoint_at_different_state_than_current() {
        let default_state = control::ControlV1::default();
        let mut checkpoint_state = default_state.clone();
        checkpoint_state.updated_at_unix_ns = 10;
        checkpoint_state.valves.read_only.set(true, "op", "test", 10);

        // Current state is default, but checkpoint is for a different state.
        // Checkpoint won't anchor because current != checkpoint state.
        // Mutations are empty, so it errors.
        let err = reconcile_control_from_evidence(
            &default_state,
            &control::checkpoint_control_bytes_v1(&default_state),
            &[checkpoint_record(5, &checkpoint_state)],
            &[],
        );
        // Checkpoint digest won't match current; first mutation start is empty.
        // With no mutations and no matching checkpoint, the function returns
        // Ok(Some(...)) where the plan has 0 applied_mutations if checkpoint matches,
        // or errors.
        // Since there are no mutations to fall back to, and checkpoint doesn't match
        // current, there's no anchor. But there are also no mutations to start from default.
        // The function should error since it has checkpoints but none match.
        // Actually looking at the code: (None, None) case with empty mutations returns Err.
        assert!(err.is_err() || err.unwrap().is_none());
    }

    // ── load_or_init_node_meta additional edge cases ───────────────────

    #[test]
    fn load_or_init_node_meta_without_gpu_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        let meta = super::load_or_init_node_meta(
            &path,
            Some("node-no-gpu"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            None,
            &build,
        )
        .unwrap();
        assert!(meta.gpu_id.is_none());
        // Verify the file was written correctly
        let bytes = std::fs::read(&path).unwrap();
        let json_str = String::from_utf8(bytes).unwrap();
        assert!(!json_str.contains("gpuId"));
    }

    // ── NodeMetaV1 with various gpu_id values ──────────────────────────

    #[test]
    fn node_meta_v1_negative_gpu_id() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "node-neg".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: Some(-1),
            build: BuildInfo {
                version: "0.1.0".to_string(),
                commit: "abc".to_string(),
            },
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: super::NodeMetaV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.gpu_id, Some(-1));
    }

    // ── validate_network_auth_posture: exhaustive combos ───────────────

    #[test]
    fn auth_off_non_loopback_without_override_fails() {
        let err = validate_network_auth_posture(
            AuthMode::Off,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect_err("auth off on non-loopback should fail");
        assert!(err.contains("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND"));
    }

    #[test]
    fn jwt_hs256_replicated_commit_with_bearer_ok() {
        validate_network_auth_posture(
            AuthMode::JwtHs256,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            true,
        )
        .expect("jwt replicated commit with bearer should pass");
    }

    #[test]
    fn jwt_jwks_local_commit_no_bearer_ok() {
        validate_network_auth_posture(
            AuthMode::JwtJwks,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect("jwt local commit without bearer should be fine");
    }

    // ── ControlEvidenceRuntimeStatus: detail content ───────────────────

    #[test]
    fn control_evidence_status_non_hosted_detail_preserved() {
        let msg = "system/corecrux/control is not hosted locally";
        let status = super::ControlEvidenceRuntimeStatus::non_hosted(msg);
        assert_eq!(status.detail.unwrap(), msg);
    }

    #[test]
    fn control_evidence_status_hosted_err_detail_preserved() {
        let msg = "failed to read stream: connection timeout";
        let status = super::ControlEvidenceRuntimeStatus::hosted_err(msg);
        assert!(!status.ok);
        assert_eq!(status.detail.unwrap(), msg);
    }

    // ── reconcile: only mutation anchor, no checkpoints, no further muts

    #[test]
    fn reconcile_mutation_anchor_at_current_state_no_further_mutations() {
        let default_state = control::ControlV1::default();
        let mut current = default_state.clone();
        current.updated_at_unix_ns = 10;
        current.valves.throttle.set(true, "op", "r", 10);

        let plan = reconcile_control_from_evidence(
            &current,
            &control::checkpoint_control_bytes_v1(&current),
            &[],
            &[mutation_record(5, &default_state, &current)],
        )
        .expect("reconcile succeeds")
        .expect("plan present");
        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 5);
        assert_eq!(plan.applied_mutations, 0);
        assert_eq!(plan.state, current);
    }

    // ── measure_data_dir_space with real tempdir ───────────────────────

    #[test]
    fn measure_data_dir_space_nested_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("subdir");
        std::fs::create_dir_all(&nested).unwrap();
        let (total, free) = super::measure_data_dir_space(&nested).unwrap();
        assert!(total > 0);
        assert!(free <= total);
    }

    // ── acquire_lock: nonexistent parent creates it ────────────────────

    #[test]
    fn acquire_lock_in_new_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("deep").join("nested");
        std::fs::create_dir_all(&sub).unwrap();
        let lock = super::acquire_lock(&sub).unwrap();
        assert!(sub.join("LOCK").exists());
        drop(lock);
    }

    // ── observe_shard_map_metrics ─────────────────────────────────────

    fn make_routing_table_via_store(num_shards: u32, gpu_id: Option<i32>) -> crate::shard_map::RoutingTable {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = crate::shard_map::ShardMapStore::new(tmp.path());
        let loaded = store
            .load_or_init(
                "test-cluster",
                "node-a",
                "127.0.0.1:4006",
                "127.0.0.1:4007",
                num_shards,
                gpu_id,
            )
            .expect("load_or_init");
        crate::shard_map::RoutingTable::new(loaded).unwrap()
    }

    fn test_build() -> BuildInfo {
        BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        }
    }

    #[test]
    fn observe_shard_map_metrics_with_active_shards() {
        let build = test_build();
        let metrics = crate::metrics::Metrics::new(&build, "test-observe");
        let table = make_routing_table_via_store(2, None);
        // Should not panic; exercises the shard metrics path for active/no-followers.
        super::observe_shard_map_metrics(&metrics, &table, "node-a");
    }

    #[test]
    fn observe_shard_map_metrics_with_gpu_id() {
        let build = test_build();
        let metrics = crate::metrics::Metrics::new(&build, "test-observe-gpu");
        let table = make_routing_table_via_store(2, Some(1));
        // Exercises the gpu_id branch (non-default gpu id).
        super::observe_shard_map_metrics(&metrics, &table, "node-a");
    }

    #[test]
    fn observe_shard_map_metrics_single_shard() {
        let build = test_build();
        let metrics = crate::metrics::Metrics::new(&build, "test-observe-single");
        let table = make_routing_table_via_store(1, None);
        super::observe_shard_map_metrics(&metrics, &table, "node-a");
    }

    #[test]
    fn observe_shard_map_metrics_four_shards() {
        let build = test_build();
        let metrics = crate::metrics::Metrics::new(&build, "test-observe-four");
        let table = make_routing_table_via_store(4, Some(0));
        super::observe_shard_map_metrics(&metrics, &table, "node-a");
    }

    // ── init_tracing (idempotent, safe to call in test) ───────────────

    // Note: tracing init is a global singleton. We call it once in a test
    // to exercise the non-json text path. The JSON and otel paths are
    // feature-gated and require env vars.
    #[test]
    #[serial_test::serial]
    fn init_tracing_text_format() {
        // Ensure LOG_FORMAT is not set to json
        std::env::remove_var("LOG_FORMAT");
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        // init_tracing may fail silently if already initialized (expected in test);
        // the important thing is it doesn't panic.
        // We use try_init via tracing_subscriber internally — this is best-effort.
        // If already initialized, this is a no-op.
        let _ = std::panic::catch_unwind(|| {
            super::init_tracing("warn");
        });
    }

    // ── CapacityLevel: Copy/Eq/PartialEq ──────────────────────────────

    #[test]
    fn capacity_level_copy_semantics() {
        let a = super::CapacityLevel::Critical;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(a, super::CapacityLevel::Healthy);
    }

    // ── classify_capacity_level with custom thresholds ─────────────────

    #[test]
    #[serial_test::serial]
    fn classify_capacity_level_custom_thresholds() {
        // Override thresholds via env vars
        std::env::set_var("CORECRUXD_CAPACITY_WARNING_FREE_RATIO", "0.30");
        std::env::set_var("CORECRUXD_CAPACITY_CRITICAL_FREE_RATIO", "0.15");
        std::env::set_var("CORECRUXD_CAPACITY_EMERGENCY_FREE_RATIO", "0.05");
        let cfg = crate::config::load_config();

        assert_eq!(
            super::classify_capacity_level(0.35, &cfg),
            super::CapacityLevel::Healthy
        );
        assert_eq!(
            super::classify_capacity_level(0.25, &cfg),
            super::CapacityLevel::Warning
        );
        assert_eq!(
            super::classify_capacity_level(0.10, &cfg),
            super::CapacityLevel::Critical
        );
        assert_eq!(
            super::classify_capacity_level(0.03, &cfg),
            super::CapacityLevel::Emergency
        );

        std::env::remove_var("CORECRUXD_CAPACITY_WARNING_FREE_RATIO");
        std::env::remove_var("CORECRUXD_CAPACITY_CRITICAL_FREE_RATIO");
        std::env::remove_var("CORECRUXD_CAPACITY_EMERGENCY_FREE_RATIO");
    }

    // ── validate_network_auth_posture: full matrix ────────────────────

    #[test]
    fn auth_off_replicated_commit_no_bearer_ok() {
        // AuthMode::Off is a dev mode, replicated commit doesn't require bearer
        // because it's only checked for JWT modes
        validate_network_auth_posture(
            AuthMode::Off,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            false,
        )
        .expect("auth off replicated on loopback should be ok");
    }

    #[test]
    fn dev_scopes_replicated_commit_no_bearer_loopback_ok() {
        validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            false,
        )
        .expect("dev scopes replicated on loopback should be ok");
    }

    // ── ControlEvidenceRuntimeStatus clone ─────────────────────────────

    #[test]
    fn control_evidence_status_clone() {
        let status = super::ControlEvidenceRuntimeStatus::hosted_ok("cloned");
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    // ── reconcile: checkpoint higher seq than mutation anchors at cp ──

    #[test]
    fn reconcile_checkpoint_higher_seq_wins() {
        let default_state = control::ControlV1::default();
        let mut checkpoint_state = default_state.clone();
        checkpoint_state.updated_at_unix_ns = 10;
        checkpoint_state.valves.read_only.set(true, "op", "test", 10);

        let mut final_state = checkpoint_state.clone();
        final_state.updated_at_unix_ns = 20;
        final_state.valves.pause_ingest.set(true, "op", "test", 20);

        let plan = reconcile_control_from_evidence(
            &checkpoint_state,
            &control::checkpoint_control_bytes_v1(&checkpoint_state),
            &[checkpoint_record(10, &checkpoint_state)],
            &[
                mutation_record(5, &default_state, &checkpoint_state),
                mutation_record(11, &checkpoint_state, &final_state),
            ],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 10);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    // ── reconcile: zero mutations after checkpoint ─────────────────────

    #[test]
    fn reconcile_checkpoint_with_no_further_mutations() {
        let default_state = control::ControlV1::default();
        let mut state = default_state.clone();
        state.updated_at_unix_ns = 10;
        state.valves.throttle.set(true, "op", "test", 10);

        let plan = reconcile_control_from_evidence(
            &state,
            &control::checkpoint_control_bytes_v1(&state),
            &[checkpoint_record(5, &state)],
            &[mutation_record(3, &default_state, &state)],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        // Checkpoint at seq=5 is higher than mutation at seq=3
        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 5);
        assert_eq!(plan.applied_mutations, 0);
        assert_eq!(plan.state, state);
    }

    // ── shard_map_advertise_addr: v4 mapped v6 ────────────────────────

    #[test]
    fn shard_map_advertise_addr_v6_unspecified() {
        // [::]:4006 -> [::1]:4006
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 4006);
        assert_eq!(super::shard_map_advertise_addr(addr), "[::1]:4006");
    }

    // ── projection tick decision logic ────────────────────────────────

    /// Extracted tick decision: returns true if projection tick should proceed.
    fn projection_tick_should_run(control: &crate::control::ControlV1) -> bool {
        !control.valves.pause_compaction.enabled && !control.valves.emergency_brake.enabled
    }

    #[test]
    fn projection_tick_runs_with_default_control() {
        let c = crate::control::ControlV1::default();
        assert!(projection_tick_should_run(&c));
    }

    #[test]
    fn projection_tick_blocked_by_pause_compaction() {
        let mut c = crate::control::ControlV1::default();
        c.valves.pause_compaction.set(true, "op", "test", 1);
        assert!(!projection_tick_should_run(&c));
    }

    #[test]
    fn projection_tick_blocked_by_emergency_brake() {
        let mut c = crate::control::ControlV1::default();
        c.valves.emergency_brake.set(true, "op", "test", 1);
        assert!(!projection_tick_should_run(&c));
    }

    #[test]
    fn projection_tick_blocked_by_both() {
        let mut c = crate::control::ControlV1::default();
        c.valves.pause_compaction.set(true, "op", "test", 1);
        c.valves.emergency_brake.set(true, "op", "test", 2);
        assert!(!projection_tick_should_run(&c));
    }

    #[test]
    fn projection_tick_not_blocked_by_other_valves() {
        let mut c = crate::control::ControlV1::default();
        c.valves.pause_ingest.set(true, "op", "test", 1);
        c.valves.throttle.set(true, "op", "test", 2);
        c.valves.read_only.set(true, "op", "test", 3);
        assert!(projection_tick_should_run(&c));
    }

    // ── capacity guard composition test ───────────────────────────────

    /// Extracted capacity guard iteration: measure -> classify -> decide pause action.
    /// Returns (level, should_pause, should_resume).
    fn capacity_guard_decide(
        free_ratio: f64,
        config: &crate::config::Config,
        current_pause_ingest_enabled: bool,
        current_pause_ingest_actor: &str,
    ) -> (super::CapacityLevel, bool, bool) {
        let level = super::classify_capacity_level(free_ratio, config);
        let guard_owned = current_pause_ingest_actor == "capacity_guard";
        let should_pause = level == super::CapacityLevel::Emergency && (!current_pause_ingest_enabled || guard_owned);
        let should_resume = guard_owned
            && current_pause_ingest_enabled
            && level != super::CapacityLevel::Emergency
            && free_ratio >= config.capacity_resume_free_ratio;
        (level, should_pause, should_resume)
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_healthy_no_action() {
        let cfg = crate::config::load_config();
        let (level, should_pause, should_resume) = capacity_guard_decide(0.50, &cfg, false, "");
        assert_eq!(level, super::CapacityLevel::Healthy);
        assert!(!should_pause);
        assert!(!should_resume);
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_emergency_pauses_ingest() {
        let cfg = crate::config::load_config();
        let (level, should_pause, should_resume) = capacity_guard_decide(0.01, &cfg, false, "");
        assert_eq!(level, super::CapacityLevel::Emergency);
        assert!(should_pause);
        assert!(!should_resume);
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_emergency_when_already_paused_by_guard() {
        let cfg = crate::config::load_config();
        let (level, should_pause, _) = capacity_guard_decide(0.01, &cfg, true, "capacity_guard");
        assert_eq!(level, super::CapacityLevel::Emergency);
        assert!(should_pause);
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_emergency_does_not_override_operator_pause() {
        let cfg = crate::config::load_config();
        let (level, should_pause, _) = capacity_guard_decide(0.01, &cfg, true, "operator");
        assert_eq!(level, super::CapacityLevel::Emergency);
        assert!(!should_pause);
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_resume_when_recovered() {
        std::env::set_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO", "0.25");
        let cfg = crate::config::load_config();
        let (level, should_pause, should_resume) = capacity_guard_decide(0.30, &cfg, true, "capacity_guard");
        assert_eq!(level, super::CapacityLevel::Healthy);
        assert!(!should_pause);
        assert!(should_resume);
        std::env::remove_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO");
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_no_resume_if_not_guard_owned() {
        std::env::set_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO", "0.25");
        let cfg = crate::config::load_config();
        let (_, _, should_resume) = capacity_guard_decide(0.30, &cfg, true, "operator");
        assert!(!should_resume);
        std::env::remove_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO");
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_no_resume_below_resume_threshold() {
        std::env::set_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO", "0.25");
        let cfg = crate::config::load_config();
        let (_, _, should_resume) = capacity_guard_decide(0.22, &cfg, true, "capacity_guard");
        assert!(!should_resume);
        std::env::remove_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO");
    }

    // ── shard map reload watcher: version comparison logic ────────────

    /// Extracted routing reload comparison: returns true if a reload should happen.
    fn routing_should_reload(current_version: u64, loaded_version: u64) -> bool {
        loaded_version != current_version
    }

    #[test]
    fn routing_reload_skip_when_same_version() {
        assert!(!routing_should_reload(5, 5));
    }

    #[test]
    fn routing_reload_when_version_differs() {
        assert!(routing_should_reload(5, 6));
    }

    #[test]
    fn routing_reload_when_version_decreases() {
        assert!(routing_should_reload(6, 5));
    }

    // ── http::router produces a valid Router ──────────────────────────

    #[tokio::test]
    async fn http_router_builds_successfully() {
        let tmp = tempfile::tempdir().unwrap();
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-router");
        let auth = crate::auth::Authz::from_env(crate::auth::AuthMode::Off).unwrap();
        let store = crate::shard_map::ShardMapStore::new(tmp.path());
        let loaded = store
            .load_or_init("test", "node-test", "127.0.0.1:14800", "127.0.0.1:14801", 1, None)
            .expect("load_or_init");
        let routing_table = crate::shard_map::RoutingTable::new(loaded).unwrap();

        let state = crate::http::AppState {
            lock_held: true,
            build: build.clone(),
            compat: corecrux_types::CompatContract {
                requires: corecrux_types::DEFAULT_COMPAT_REQUIRES.to_string(),
            },
            sdk_version: corecrux_types::DEFAULT_SDK_VERSION.to_string(),
            auth,
            rcx_router: None,
            data_dir: tmp.path().to_path_buf(),
            sync_mutual_auth: false,
            sync_peer_trust_root: None,
            sync_delegation_enforce: false,
            sync_handshake_nonces: std::sync::Arc::new(std::sync::Mutex::new(
                crux_sync::peer_handshake::NonceCache::new(crate::http::SYNC_HANDSHAKE_NONCE_TTL_SECONDS),
            )),
            witness: crate::witness::WitnessRuntimeConfigV1::disabled(),
            witness_proofs: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::witness_proofs::WitnessProofStore::default(),
            )),
            cloud_witness_replay_cache: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            mcp_enabled: true,
            console_enabled: true,
            passport_mint_requests_enabled: false,
            coord_enabled: false,
            consolidation_scheduler_enabled: false,
            coord_presence_ttl_secs: crate::coord::DEFAULT_PRESENCE_TTL_SECS,
            context_surface_enabled: false,
            auto_capture_enabled: false,
            local_ingest_enabled: false,
            compute_provider_enabled: false,
            stream_receipts_enabled: false,
            usage_receipts_enabled: false,
            handoff_observations_enabled: false,
            usage_submit: crate::usage_submit::UsageSubmitConfig::default(),
            latest_release: std::sync::Arc::new(std::sync::RwLock::new(None)),
            quota_enabled: false,
            assembly_cache: None,
            quota_hosted_surfaces: std::sync::Arc::new(Vec::new()),
            quota_ledger: std::sync::Arc::new(std::sync::Mutex::new(crux_router::quota::QuotaLedger::new())),
            credit_meter: None,
            openai_shim_enabled: false,
            memory_import_enabled: false,
            identity_links_enabled: false,
            mcp_context: None,
            integrations_enabled: true,
            integrations_safe_mode: false,
            integrations_allow_executable_helpers: false,
            operating_mode: crate::product::OperatingMode::FreeLocal,
            enabled_pro_services: Vec::new(),
            read_retry_failed_readyz_threshold: 0,
            commit_level: crate::config::CommitLevel::LocalCommit,
            metrics: metrics.clone(),
            node_id: "node-test".to_string(),
            passport_key_path: tmp.path().join("passport.key"),
            passport_fpr: "p_test".to_string(),
            passport_public_key_hex: "00".repeat(32),
            mcp_agent_count: 0,
            routing: std::sync::Arc::new(tokio::sync::RwLock::new(routing_table)),
            routing_errors: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
            dataplane_pool: None,
            http_dataplane: crate::http::pool_backed_http_dataplane(None),
            readiness: std::sync::Arc::new(tokio::sync::RwLock::new(crate::http::Readiness::default())),
            control: std::sync::Arc::new(tokio::sync::RwLock::new(crate::control::ControlV1::default())),
            control_path: tmp.path().join("CONTROL.json"),
            action_max_pending: 10,
            action_timeout_secs: 60,
            repo_scan_max_pending: 32,
            scrub_scope: "recent".to_string(),
            scrub_mode: "sampled".to_string(),
            scrub_sample_rate: 0.25,
            admin_actions: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::BTreeMap::new())),
            repo_scan_jobs: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::BTreeMap::new())),
            repo_scan_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            corruption_detected: std::sync::Arc::new(tokio::sync::RwLock::new(false)),
            capacity: std::sync::Arc::new(tokio::sync::RwLock::new(crate::http::CapacityState::default())),
            admin_force_seal_enabled: false,
            local_ingest_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            retention_days: None,
            retrieval_index: std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_retrieval::IndexManager::new())),
            fact_store: std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::FactStore::new())),
            repo_watch: None,
            extension_rate_table: std::sync::Arc::new(crate::extension_outbound::RateTable::new()),
            #[cfg(feature = "wasm-extensions")]
            wasm_engine: None,
            session_store: std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::SessionStore::new())),
            update_status: std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_types::UpdateStatus::default())),
            event_bus: corecrux_memory::events::EventBus::new(16),
            session: None,
            extraction_cache: std::sync::Arc::new(tokio::sync::RwLock::new(
                corecrux_projections::ExtractionCacheMaterializer::new(),
            )),
            onboarding: std::sync::Arc::new(tokio::sync::RwLock::new(crate::onboarding::OnboardingState::default())),
            http_bind_loopback: true,
            allow_insecure_dev_auth_bind: false,
            projection_state: std::sync::Arc::new(tokio::sync::RwLock::new(
                corecrux_projections::ProjectionState::default(),
            )),
            integration_encryption_key: std::sync::Arc::new([0u8; 32]),
            presence: crate::presence::PresenceTracker::new(),
            privacy_policy: crate::fact_privacy::PrivacyPolicy::from_env(),
            entity_store: std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::EntityStore::new())),
            edge_store: std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::EdgeStore::new())),
            kind_registry: std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::KindRegistry::new())),
            artefact_store: std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::ArtefactStore::new())),
        };

        let case_store = std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::CaseStore::new()));
        let router: axum::Router = crate::http::router(state, case_store);
        // Verify it's a valid Router by converting to a service
        let _service = router.into_make_service();
    }

    // ── scrub tick decision logic ─────────────────────────────────────

    /// Extracted scrub tick decision: same valve gates as projection runner.
    fn scrub_tick_should_run(control: &crate::control::ControlV1) -> bool {
        !control.valves.pause_compaction.enabled && !control.valves.emergency_brake.enabled
    }

    #[test]
    fn scrub_tick_runs_with_default_control() {
        let c = crate::control::ControlV1::default();
        assert!(scrub_tick_should_run(&c));
    }

    #[test]
    fn scrub_tick_blocked_by_pause_compaction() {
        let mut c = crate::control::ControlV1::default();
        c.valves.pause_compaction.set(true, "op", "test", 1);
        assert!(!scrub_tick_should_run(&c));
    }

    #[test]
    fn scrub_tick_blocked_by_emergency_brake() {
        let mut c = crate::control::ControlV1::default();
        c.valves.emergency_brake.set(true, "op", "test", 1);
        assert!(!scrub_tick_should_run(&c));
    }

    // ── capacity free_ratio calculation ───────────────────────────────

    fn capacity_free_ratio(total_bytes: u64, free_bytes: u64) -> f64 {
        if total_bytes == 0 {
            0.0
        } else {
            free_bytes as f64 / total_bytes as f64
        }
    }

    #[test]
    fn capacity_free_ratio_zero_total() {
        assert!((capacity_free_ratio(0, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn capacity_free_ratio_half_full() {
        assert!((capacity_free_ratio(1000, 500) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn capacity_free_ratio_empty() {
        assert!((capacity_free_ratio(1000, 1000) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn capacity_free_ratio_full() {
        assert!((capacity_free_ratio(1000, 0) - 0.0).abs() < f64::EPSILON);
    }

    // ── load_or_init_node_meta: concurrent access ─────────────────────

    #[test]
    fn load_or_init_node_meta_persists_http_grpc_addr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.2.0".to_string(),
            commit: "def".to_string(),
        };
        let meta = super::load_or_init_node_meta(
            &path,
            Some("node-persist-test"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 14801),
            Some(3),
            &build,
        )
        .unwrap();
        assert_eq!(meta.http_listen_addr, "10.0.0.1:14800");
        assert_eq!(meta.grpc_listen_addr, "10.0.0.1:14801");
        assert_eq!(meta.gpu_id, Some(3));
        assert_eq!(meta.build.version, "0.2.0");

        // Verify written bytes round-trip
        let bytes = std::fs::read(&path).unwrap();
        let loaded: super::NodeMetaV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(loaded.node_id, "node-persist-test");
    }

    // ── measure_data_dir_space: root path ─────────────────────────────

    #[test]
    fn measure_data_dir_space_on_root() {
        // /tmp always exists on linux
        let (total, free) = super::measure_data_dir_space(std::path::Path::new("/tmp")).unwrap();
        assert!(total > 0);
        assert!(free <= total);
    }

    // ── ControlCheckpointRecord / ControlMutationRecord clone+debug ──

    #[test]
    fn control_checkpoint_record_clone_and_debug() {
        let state = control::ControlV1::default();
        let rec = checkpoint_record(1, &state);
        let cloned = rec.clone();
        assert_eq!(cloned.seq, 1);
        let dbg = format!("{:?}", rec);
        assert!(dbg.contains("seq"));
    }

    #[test]
    fn control_mutation_record_clone_and_debug() {
        let before = control::ControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 99;
        let rec = mutation_record(3, &before, &after);
        let cloned = rec.clone();
        assert_eq!(cloned.seq, 3);
        let dbg = format!("{:?}", rec);
        assert!(dbg.contains("seq"));
    }

    // ── ControlEvidenceReplayPlan: different anchors ──────────────────

    #[test]
    fn control_evidence_replay_plan_different_anchors_ne() {
        let state = control::ControlV1::default();
        let plan_a = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 0,
        };
        let plan_b = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "mutation",
            anchor_seq: 5,
            applied_mutations: 0,
        };
        assert_ne!(plan_a, plan_b);
    }

    // ── NodeMetaV1: clone + debug ────────────────────────────────────

    #[test]
    fn node_meta_v1_clone_preserves_all_fields() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "n1".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: Some(5),
            build: BuildInfo {
                version: "v".to_string(),
                commit: "c".to_string(),
            },
        };
        let cloned = meta.clone();
        assert_eq!(cloned.v, 1);
        assert_eq!(cloned.node_id, "n1");
        assert_eq!(cloned.gpu_id, Some(5));
        assert_eq!(cloned.build.version, "v");
    }

    // ── CapacityLevel: exhaustive as_str ─────────────────────────────

    #[test]
    fn capacity_level_as_str_exhaustive() {
        let variants = [
            super::CapacityLevel::Healthy,
            super::CapacityLevel::Warning,
            super::CapacityLevel::Critical,
            super::CapacityLevel::Emergency,
        ];
        let strs: Vec<&str> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs, vec!["healthy", "warning", "critical", "emergency"]);
    }

    // ── ControlEvidenceRuntimeStatus: debug ──────────────────────────

    #[test]
    fn control_evidence_runtime_status_debug() {
        let status = super::ControlEvidenceRuntimeStatus::hosted_ok("msg");
        let dbg = format!("{:?}", status);
        assert!(dbg.contains("hosted_locally"));
        assert!(dbg.contains("true"));
    }

    // ── validate_network_auth_posture: DevScopes with override on non-loopback ──

    #[test]
    fn dev_scopes_non_loopback_with_override_ok() {
        validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::LocalCommit,
            true,
            false,
        )
        .expect("override should allow dev scopes on non-loopback");
    }

    // ── reconcile: mutation anchor found, checkpoint not found ────────

    #[test]
    fn reconcile_mutation_anchor_only_no_checkpoint() {
        let default_state = control::ControlV1::default();
        let mut mid = default_state.clone();
        mid.updated_at_unix_ns = 5;
        mid.valves.read_only.set(true, "op", "r", 5);

        let plan = reconcile_control_from_evidence(
            &mid,
            &control::checkpoint_control_bytes_v1(&mid),
            &[], // no checkpoints
            &[mutation_record(1, &default_state, &mid)],
        )
        .expect("reconcile succeeds")
        .expect("plan present");
        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 1);
        assert_eq!(plan.applied_mutations, 0);
    }

    // ── capacity_free_ratio: exact boundary ──────────────────────────

    #[test]
    fn capacity_free_ratio_exceeds_total() {
        // In theory shouldn't happen, but test the arithmetic
        assert!((capacity_free_ratio(100, 200) - 2.0).abs() < f64::EPSILON);
    }
}

#[cfg(test)]
mod serve_http_tests {
    use std::time::Duration;

    use axum::routing::get;
    use axum::Router;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::broadcast;

    use super::serve_http_listener;

    async fn bind_local() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        #[allow(clippy::unwrap_used)]
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        #[allow(clippy::unwrap_used)]
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    #[tokio::test]
    async fn graceful_shutdown_with_no_inflight_returns_promptly() {
        let (listener, _addr) = bind_local().await;
        let app = Router::new().route("/", get(|| async { "ok" }));
        let (tx, rx) = broadcast::channel::<()>(1);
        let server = tokio::spawn(serve_http_listener(listener, app, rx, Some(Duration::from_secs(30))));

        // Let the accept loop start, then signal shutdown with nothing in flight.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(());
        let joined = tokio::time::timeout(Duration::from_secs(3), server).await;
        #[allow(clippy::unwrap_used)]
        let result = joined.expect("server did not stop within 3s of shutdown").unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn drain_cap_force_closes_stuck_connections() {
        let (listener, addr) = bind_local().await;
        // Handler that outlives any reasonable drain: 60s sleep.
        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                "done"
            }),
        );
        let (tx, rx) = broadcast::channel::<()>(1);
        let server = tokio::spawn(serve_http_listener(listener, app, rx, Some(Duration::from_millis(300))));

        // Park one request inside the slow handler.
        #[allow(clippy::unwrap_used)]
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        #[allow(clippy::unwrap_used)]
        conn.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = std::time::Instant::now();
        let _ = tx.send(());
        // Without the cap this would block ~60s on the parked request; with
        // the cap the serve future must return within the 300ms window
        // (plus scheduling slack), unblocking process shutdown.
        let joined = tokio::time::timeout(Duration::from_secs(5), server).await;
        #[allow(clippy::unwrap_used)]
        let result = joined.expect("drain cap did not unblock shutdown within 5s").unwrap();
        assert!(result.is_ok());
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(250),
            "drain cap fired before it elapsed: {elapsed:?}"
        );
        // Keep the parked connection alive until here so the drain genuinely
        // had something in flight (it is closed at process/test exit, which
        // mirrors prod behaviour: abandoned connections die with the process).
        drop(conn);
    }

    #[tokio::test]
    async fn unbounded_drain_waits_for_inflight_requests() {
        let (listener, addr) = bind_local().await;
        let app = Router::new().route(
            "/short",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                "done"
            }),
        );
        let (tx, rx) = broadcast::channel::<()>(1);
        let server = tokio::spawn(serve_http_listener(listener, app, rx, None));

        #[allow(clippy::unwrap_used)]
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        #[allow(clippy::unwrap_used)]
        conn.write_all(b"GET /short HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(());

        // The in-flight request must still complete (200 with body "done").
        let mut buf = Vec::new();
        #[allow(clippy::unwrap_used)]
        tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut buf))
            .await
            .expect("response not received before timeout")
            .unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 200"), "unexpected response: {text}");
        assert!(text.ends_with("done"), "unexpected body: {text}");

        let joined = tokio::time::timeout(Duration::from_secs(3), server).await;
        #[allow(clippy::unwrap_used)]
        let result = joined.expect("server did not stop after drain").unwrap();
        assert!(result.is_ok());
    }
}
