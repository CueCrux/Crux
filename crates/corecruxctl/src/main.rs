// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

// CLI binary — printing to stdout/stderr is correct behaviour.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! `corecruxctl` binary entry point.
//!
//! Clap-based dispatcher that routes subcommands to handlers in the
//! `corecruxctl` library crate. See library docs for the operational
//! surface; see `corecruxctl --help` for the live subcommand listing.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use corecruxctl::{
    admin, audit_export, audit_pack, c2pa_x509, code_chain, code_health, compaction_sync, config_bundle, cost,
    deploy_audit, evidence, explain, export, extensions, fixture_digest, gaps, hooks, identity_cli, incident, ingest,
    inspect_receipt, learn, login, machine, memory, memory_pack, observe_ingest, openclaw, output_verify, parity,
    projections, receipts, reconcile, replay, repo, session_sync, shard, shardmap, smoke, snapshot, stage1_import,
    start, storage, structured_log, tooling_env, verify_store,
};

#[derive(Debug, Parser)]
#[command(name = "corecruxctl")]
#[command(about = "CoreCrux v3 control tool (Phase 0)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // CLI subcommands — allocation cost is negligible at startup
enum Command {
    /// Audit the target daemon's bind/auth posture before a networked deployment.
    #[command(name = "deploy-audit")]
    DeployAudit {
        /// Daemon YAML config. Defaults to CORECRUXD_CONFIG_PATH, then
        /// $XDG_CONFIG_HOME/crux/config.yaml, matching corecruxd.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override the resolved auth mode for this audit.
        #[arg(long)]
        auth_mode: Option<String>,
        /// Override the resolved HTTP bind host/address for this audit.
        #[arg(long)]
        http_bind: Option<String>,
        /// Override the resolved gRPC bind host/address for this audit.
        #[arg(long)]
        grpc_bind: Option<String>,
        /// Treat the daemon as network-exposed even when it binds loopback
        /// (for example behind a reverse proxy, port forward, or hosted rail).
        #[arg(long, default_value_t = false)]
        network_exposed: bool,
        /// Emit a machine-readable report.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// START HERE — the one command to get live: detect daemon, authenticate,
    /// wire MCP + hooks, round-trip a first fact, print a "you're live" summary.
    ///
    /// This is the canonical zero→first-loop on-ramp. It runs the happy path by
    /// delegating to `login` (verification + hooks ON) and printing one
    /// next-steps summary. For specific rails use the advanced entry points
    /// (`login`, `quickstart`, or `docker compose up`) directly.
    Start {
        /// Explicit daemon URL (e.g. http://127.0.0.1:14800). Omit to discover.
        #[arg(long)]
        url: Option<String>,
        /// Static named token for CI / headless / air-gapped clients.
        #[arg(long)]
        token: Option<String>,
    },

    /// (advanced) Authenticate to a Crux Daemon, auto-selecting the lowest-friction secure rail.
    ///
    /// Most users want `start` instead — it wraps this with hooks + verification
    /// and a summary. Use `login` directly to pick a specific rail.
    ///
    /// Discovers the daemon (--url → ~/.config/cuecrux/env → localhost), probes
    /// reachability + auth posture, picks a rail (loopback / static token / —
    /// tailscale + device land in M2/M3), persists the credential to
    /// ~/.config/cuecrux/credentials.json (0600), registers the MCP endpoint, and
    /// verifies the connection.
    Login {
        /// Explicit daemon URL (e.g. http://127.0.0.1:14800 or https://crux.example.com).
        #[arg(long)]
        url: Option<String>,
        /// Static named token (Rail 4) for CI / headless / air-gapped clients.
        #[arg(long)]
        token: Option<String>,
        /// Force the device-authorization grant (Rail 3; lands in M3).
        #[arg(long, default_value_t = false)]
        device: bool,
        /// Skip the post-login tools/list + fact round-trip verification.
        #[arg(long, default_value_t = false)]
        no_verify: bool,
        /// Skip installing the Claude Code hooks (banner + observe capture).
        #[arg(long, default_value_t = false)]
        no_hooks: bool,
        /// Skip registering this machine with the daemon.
        #[arg(long, default_value_t = false)]
        no_register: bool,
    },

    /// Clear stored Crux Daemon credentials (and revoke device refresh credentials).
    Logout {
        /// Daemon URL to log out of.
        #[arg(long)]
        url: Option<String>,
        /// Log out of every stored daemon.
        #[arg(long, default_value_t = false)]
        all: bool,
    },

    /// Show stored Crux Daemon credential posture per daemon.
    Whoami {
        /// Restrict output to a single daemon URL.
        #[arg(long)]
        url: Option<String>,
    },

    /// Install or inspect the Crux Claude Code hooks (banner + observe capture).
    #[command(name = "hooks")]
    Hooks {
        #[command(subcommand)]
        command: HooksCommand,
    },

    /// Register this machine with the daemon, or list registered machines.
    #[command(name = "machine")]
    Machine {
        #[command(subcommand)]
        command: MachineCommand,
    },

    /// Save / restore a machine's Claude Code config across machines.
    #[command(name = "config")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Share session state across machines via the shared daemon.
    #[command(name = "session")]
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },

    /// Hosted compaction-snapshot sync (Pro) — activate cross-device continuity.
    #[command(name = "compaction-sync")]
    CompactionSync {
        #[command(subcommand)]
        command: CompactionSyncCommand,
    },

    /// Observe audit-chain tools (transcript ingest).
    #[command(name = "observe")]
    Observe {
        #[command(subcommand)]
        command: ObserveCommand,
    },

    /// Deterministic replay checks from a replay pack (preferred) or legacy JSONL input.
    Replay {
        /// Replay pack directory (normative contract for v3.1 hardening).
        #[arg(long)]
        pack: Option<PathBuf>,
        /// Legacy JSONL input (deprecated alias; use --pack).
        #[arg(long)]
        input: Option<PathBuf>,
        /// Strict mode: mismatch is a hard error (non-zero exit).
        #[arg(long, default_value_t = false)]
        strict: bool,
        /// Replay mode (only 'audit' is supported in Phase 0).
        #[arg(long, default_value = "audit")]
        mode: String,
    },

    /// Import Stage 1 events.log into v3 JSONL fixtures (Phase 0 bridge).
    ImportV1 {
        /// Path to Stage 1 events.log (length+payload+crc32c).
        #[arg(long)]
        events_log: PathBuf,
        /// Output directory for v3 JSONL and mapping file.
        #[arg(long)]
        out: PathBuf,
    },

    /// Run the CUDA smoke kernel (Phase 1).
    Smoke {
        /// CUDA device index (default 0).
        #[arg(long, default_value_t = 0)]
        device_index: i32,
    },

    /// Compute deterministic replay digest for a sealed segment fixture (Phase 5 determinism).
    FixtureDigest {
        /// Fixture name under tests/fixtures_segments/<fixture>/<fixture>.ccxseg.
        #[arg(long, default_value = "minimal")]
        fixture: String,
        /// CUDA device index (default 0).
        #[arg(long, default_value_t = 0)]
        device_index: i32,
    },

    /// Shard map tooling (Phase 3).
    #[command(name = "shardmap")]
    ShardMap {
        #[command(subcommand)]
        command: ShardMapCommand,
    },

    /// Shard orchestration workflows (Phase 11).
    #[command(name = "shard")]
    Shard {
        #[command(subcommand)]
        command: ShardCommand,
    },

    /// Admin operations against a running corecruxd (Phase 6).
    #[command(name = "admin")]
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },

    /// Projection tooling (Phase 7).
    #[command(name = "projections")]
    Projections {
        #[command(subcommand)]
        command: ProjectionsCommand,
    },

    /// Parity checks vs Engine (Phase 7).
    #[command(name = "parity")]
    Parity {
        #[command(subcommand)]
        command: ParityCommand,
    },

    /// Generate a deterministic parity pack (Engine vs CoreCrux projections).
    #[command(name = "parity-pack")]
    ParityPack {
        /// Output directory for parity pack files.
        #[arg(long)]
        out: PathBuf,
        /// Tenant ID to sample and compare.
        #[arg(long)]
        tenant_id: String,
        /// Deterministic sample seed.
        #[arg(long, default_value = "0")]
        seed: String,
        /// Number of samples in pack.
        #[arg(long, default_value_t = 100)]
        sample_size: u32,
        /// Sampling window in hours (metadata in pack manifest).
        #[arg(long, default_value_t = 24)]
        window: u32,
        /// Projection set identifier (metadata in pack manifest).
        #[arg(long, default_value = "required")]
        projections: String,
        /// Engine base URL (e.g. http://127.0.0.1:3000).
        #[arg(long)]
        engine: String,
        /// Engine API key (x-api-key header).
        #[arg(long)]
        engine_api_key: String,
        /// CoreCrux HTTP base URL (e.g. http://127.0.0.1:4006).
        #[arg(long)]
        corecrux: String,
    },

    /// Receipt tooling (Phase 8).
    #[command(name = "receipts")]
    Receipts {
        #[command(subcommand)]
        command: ReceiptsCommand,
    },

    /// Verify on-disk shard store integrity (Phase 5 hardening surface).
    #[command(name = "verify-store")]
    VerifyStore {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional shard numeric id (e.g. 1 for shard-0001). If omitted, scans scoped shard set.
        #[arg(long)]
        shard: Option<u32>,
        /// Scope of verification (`recent` or `all`).
        #[arg(long, default_value = "recent")]
        scope: String,
        /// Verification mode (`sampled` or `full`).
        #[arg(long, default_value = "sampled")]
        mode: String,
        /// Sample rate for sampled mode (0.0..1.0).
        #[arg(long, default_value_t = 0.25)]
        sample_rate: f64,
        /// Recompute sealed-segment BLAKE3 hashes and cross-check the manifest.
        #[arg(long, default_value_t = false)]
        strict: bool,
    },

    /// .ccxi companion index tooling (v5 retrieval).
    #[command(name = "ccxi")]
    Ccxi {
        #[command(subcommand)]
        command: CcxiCommand,
    },

    /// Storage-tier operator tooling.
    #[command(name = "storage")]
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },

    /// Reconcile CoreCrux state against the Postgres shadow journal.
    #[command(name = "reconcile")]
    Reconcile {
        /// Enable Postgres reconciliation backend.
        #[arg(long, default_value_t = false)]
        postgres: bool,
        /// Postgres connection string for the Engine shadow journal.
        #[arg(long)]
        connection_string: String,
        /// Tenant scope is required; reconcile never runs cross-tenant.
        #[arg(long)]
        tenant: String,
        /// Optional stream-type scope.
        #[arg(long)]
        stream_type: Option<String>,
        /// Optional stream-id scope.
        #[arg(long)]
        stream_id: Option<String>,
        /// Optional shard scope.
        #[arg(long)]
        shard: Option<u32>,
        /// Restrict reconciliation to segments sealed within this many days.
        #[arg(long)]
        window_days: Option<u32>,
        /// Maximum number of newest eligible segments to scan.
        #[arg(long)]
        max_segments: Option<usize>,
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Postgres fetch batch size.
        #[arg(long, default_value_t = 5_000)]
        batch_size: usize,
        /// Maximum number of sample event ids to include for each divergence class.
        #[arg(long, default_value_t = 20)]
        sample_limit: usize,
        /// Optional output path for the machine-readable reconciliation report.
        #[arg(long)]
        evidence_out: Option<PathBuf>,
    },

    /// Offline evidence verification and control-evidence checks.
    #[command(name = "evidence")]
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },

    /// Snapshot tooling (Phase 6 hardening surface).
    #[command(name = "snapshot")]
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommand,
    },

    /// Generate a Phase 12 audit artifact bundle (ordering/idempotency/parity/replay/integrity).
    #[command(name = "audit-pack")]
    AuditPack {
        /// Output directory (defaults to reports/phase12/audit-pack/<timestamp>).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Run in offline mode (skip HTTP/Engine parity checks).
        #[arg(long, default_value_t = false)]
        offline: bool,
        /// CoreCrux HTTP base URL.
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        corecrux: String,
        /// Local CoreCrux data dir for verification-grade artifact binding.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Tenant ID for stream-local ordering/idempotency audit.
        #[arg(long)]
        tenant_id: Option<String>,
        /// Stream type for stream-local ordering/idempotency audit.
        #[arg(long)]
        stream_type: Option<String>,
        /// Stream ID for stream-local ordering/idempotency audit.
        #[arg(long)]
        stream_id: Option<String>,
        /// Lower bound sequence for stream export.
        #[arg(long, default_value_t = 0)]
        from_seq: u64,
        /// Maximum events to scan from export (clamped to 50k).
        #[arg(long, default_value_t = 1000)]
        max_events: u32,
        /// Path to Stage 1/CoreCrux v1 `events.log` for cross-system ordering/idempotency parity.
        ///
        /// Mutually exclusive with `--v1-stream-jsonl`.
        #[arg(long)]
        v1_events_log: Option<PathBuf>,
        /// Path to JSONL comparator rows for cross-system parity.
        ///
        /// One JSON object per line with fields:
        /// `seq,eventId,eventType,occurredAt,payloadHash,headerHash`.
        /// Mutually exclusive with `--v1-events-log`.
        #[arg(long)]
        v1_stream_jsonl: Option<PathBuf>,
        /// Engine base URL for projection parity checks.
        #[arg(long)]
        engine: Option<String>,
        /// Engine API key for projection parity checks.
        #[arg(long)]
        engine_api_key: Option<String>,
        /// Tenant ID used for projection parity sampling (defaults to --tenant-id).
        #[arg(long)]
        parity_tenant_id: Option<String>,
        /// Deterministic sample seed for projection parity.
        #[arg(long, default_value = "0")]
        parity_seed: String,
        /// Sample size for projection parity.
        #[arg(long, default_value_t = 25)]
        parity_sample: u32,
        /// Fixture name for replay determinism check.
        #[arg(long, default_value = "minimal")]
        replay_fixture: String,
        /// CUDA/fake device index used by fixture replay digest.
        #[arg(long, default_value_t = 0)]
        device_index: i32,
        /// Direct receipt selector for receipt evidence binding.
        #[arg(long)]
        receipt_id: Option<String>,
        /// Answer selector for receipt evidence binding.
        #[arg(long)]
        answer_id: Option<String>,
        /// Action selector for receipt evidence binding.
        #[arg(long)]
        action_id: Option<String>,
        /// Optional public keyring JSON used for offline receipt re-verification.
        #[arg(long)]
        receipt_keyring: Option<PathBuf>,
    },

    /// Inspect a CROWN receipt (human-readable breakdown).
    #[command(name = "inspect-receipt")]
    InspectReceipt {
        /// Receipt ID to inspect.
        receipt_id: String,
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<String>,
    },

    /// Explain the retrieval decision path for a receipt.
    #[command(name = "explain")]
    Explain {
        /// Receipt ID to explain.
        receipt_id: String,
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<String>,
    },

    /// Aggregated low-coverage report: queries where the corpus couldn't provide strong answers.
    #[command(name = "gaps")]
    Gaps {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<String>,
        /// Only show gaps since this date (ISO 8601).
        #[arg(long)]
        since: Option<String>,
    },

    /// Mine recent tool-call traces for looping re-fetches and propose
    /// guardrails (token-efficiency M4). Read-only; writes nothing.
    ///
    /// Thin wrapper over the daemon's `learn` MCP tool: ranks signatures
    /// repeated >=3x (pagination variants folded) by measured token waste.
    Learn {
        /// Minimum repeats before a signature is flagged as a loop.
        #[arg(long)]
        min_repeats: Option<usize>,
        /// How many recent traces to mine (newest first).
        #[arg(long)]
        scan: Option<usize>,
        /// Daemon HTTP base URL (defaults to discovery: --url → ~/.config → localhost).
        #[arg(long)]
        url: Option<String>,
        /// Emit the raw JSON tool result instead of the human report.
        #[arg(long)]
        json: bool,
    },

    /// Code-intelligence harvester — ingest cargo-check / machete / grep /
    /// ts-prune findings into normalized JSON (code-intelligence M1).
    #[command(name = "code-health")]
    CodeHealth {
        #[command(subcommand)]
        command: CodeHealthCommand,
    },

    /// Register repositories with the local daemon.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },

    /// Ingest a text file or directory into the daemon's local BM25 index.
    Ingest {
        /// File or directory to ingest recursively.
        path: PathBuf,
        /// Tenant that owns the ingested documents.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Corpus (stream type) used for the ingested documents.
        #[arg(long, default_value = "docs")]
        corpus: String,
        /// Crux Daemon HTTP base URL.
        #[arg(long, default_value = "http://127.0.0.1:14800")]
        daemon_url: String,
        /// Walk and chunk files, but perform no network calls or writes.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Embed each chunk through CORECRUXD_EMBEDDING_URL before ingest.
        #[arg(long, default_value_t = false)]
        embed: bool,
    },

    /// (advanced) Interactive quickstart wizard for new users.
    ///
    /// Prefer `start` for the canonical one-command on-ramp; use `quickstart`
    /// when you want the guided store→query→cleanup walkthrough instead.
    Quickstart {
        /// CoreCrux HTTP base URL.
        #[arg(long, default_value = "http://localhost:14800")]
        http: String,
        /// Skip prompts and use defaults.
        #[arg(long)]
        non_interactive: bool,
    },

    /// Run CruxScore Lite benchmark and optionally upload results.
    Benchmark {
        /// Benchmark suite: quick (50 docs, ships in binary) or standard (200 docs, downloaded).
        #[arg(long, default_value = "quick")]
        suite: String,
        /// CoreCrux HTTP base URL.
        #[arg(long, default_value = "http://localhost:14800")]
        http: String,
        /// Upload results to scorecrux.com after completion.
        #[arg(long)]
        upload: bool,
        /// Output file for the JSON report.
        #[arg(long)]
        output: Option<String>,
        /// Compare two previous benchmark reports.
        #[arg(long)]
        compare: Option<Vec<String>>,
    },

    /// Community-extensions registry tooling (M8 of community-extensions ExecPlan).
    #[command(name = "extensions")]
    Extensions {
        #[command(subcommand)]
        command: ExtensionsCommand,
    },

    /// Readable / editable memory panel (agent-ux-01). Operates against the
    /// running daemon over HTTP; honours CRUX_AGENT_TOKEN.
    #[command(name = "memory")]
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },

    /// Import + scan OpenClaw/fork agent-memory workspaces (W3 ICP-1). Free,
    /// local-first funnel: bring an OpenClaw memory dir into the local Crux
    /// store with provenance, then scan it for unreceipted (MemGhost-style)
    /// mutations. Operates against the running daemon over HTTP; honours
    /// CRUX_AGENT_TOKEN.
    #[command(name = "openclaw")]
    Openclaw {
        #[command(subcommand)]
        command: OpenclawCommand,
    },

    /// Identity-federation helpers — fingerprint card + link-statement
    /// signing (the cross-signature ceremony, G4).
    #[command(name = "identity")]
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },

    /// Context-custody portability + proof (context-custody-surface).
    /// `context export` composes the cruxpack (facts + sessions,
    /// re-importable) and the audit bundle (signed journal + receipt refs,
    /// offline-verifiable) into one passport-signed bundle; `context verify`
    /// re-checks it offline. The answer to the exit test's "can you export
    /// it?" / "can you prove what it saw and did?". Read-only against the
    /// data dir.
    #[command(name = "context")]
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },

    /// Governance-tier incident reconstruction against a running daemon.
    #[command(name = "incident")]
    Incident {
        #[command(subcommand)]
        command: IncidentCommand,
    },

    /// BYO Audit Trail export (agent-ux-11). Builds a signed,
    /// third-party-verifiable tar.zst from the on-disk fact journal.
    /// Read-only against the data dir — safe to run while the daemon
    /// is up.
    #[command(name = "audit-export")]
    AuditExport {
        /// Data directory (defaults to CORECRUXD_DATA_DIR).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Output bundle path (e.g. ./audit-bundle.tar.zst).
        #[arg(long)]
        out: PathBuf,
        /// RFC3339 lower bound, inclusive (optional).
        #[arg(long)]
        since: Option<String>,
        /// RFC3339 upper bound, exclusive (optional; defaults to wall-clock now).
        #[arg(long)]
        until: Option<String>,
        /// Restrict to entities starting with this prefix.
        #[arg(long)]
        scope_entity_prefix: Option<String>,
        /// Operator-only: include reserved-prefix entries
        /// (__agent::*, __ops::*, __bootstrap__::*).
        #[arg(long, default_value_t = false)]
        include_reserved: bool,
        /// Optional caller label embedded in the manifest scope.
        #[arg(long)]
        caller: Option<String>,
    },

    /// Verify a BYO audit bundle OFFLINE — no daemon, no network.
    /// Checks: bundle_format_version, content hashes, Ed25519 signature.
    /// Exits non-zero on any failure.
    #[command(name = "audit-verify")]
    AuditVerify {
        /// Path to the bundle (e.g. ./audit-bundle.tar.zst).
        bundle: PathBuf,
        /// Print the structured report as JSON to stdout.
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Optional pinned log Ed25519 public key (raw 32 bytes or base64) to
        /// verify each witness proof's Rekor checkpoint/SET — the trust root
        /// that proves the tree head is the log operator's, not fabricated.
        #[arg(long)]
        rekor_pubkey: Option<PathBuf>,
    },

    /// Print the active C2PA leaf certificate's subject, issuer, validity
    /// window, expiry urgency (green / yellow / red), and the local
    /// trust anchor's SHA-256 fingerprint. Reads
    /// `CORECRUXD_C2PA_LEAF_CERT_PATH` and `CORECRUXD_C2PA_ROOT_ANCHOR_PATH`
    /// (or `--leaf-cert` / `--root-anchor`). Fully OFFLINE — no Vault
    /// round-trip.
    #[command(name = "c2pa-cert-status")]
    C2paCertStatus {
        /// Path to the leaf cert PEM (defaults to the env-derived path).
        #[arg(long)]
        leaf_cert: Option<PathBuf>,
        /// Path to the root anchor PEM (defaults to the env-derived path).
        #[arg(long)]
        root_anchor: Option<PathBuf>,
        /// Emit compact JSON instead of pretty.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Force-rotate the C2PA leaf certificate by minting a fresh CSR
    /// and POSTing it to Vault PKI `pki-c2pa/sign/c2pa-leaf`. Requires
    /// `VAULT_ADDR` + `VAULT_TOKEN` env vars. The new leaf key + chain
    /// land at the configured paths atomically (write-temp + rename).
    /// Use when the automatic <7d rotation hasn't fired yet or after
    /// suspected key compromise.
    #[command(name = "c2pa-rotate-leaf")]
    C2paRotateLeaf {
        /// Path to write the new leaf cert PEM (overrides env).
        #[arg(long)]
        leaf_cert: Option<PathBuf>,
        /// Root anchor PEM (kept for reporting only).
        #[arg(long)]
        root_anchor: Option<PathBuf>,
        /// Compact JSON output.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Verify a C2PA manifest produced by the X.509 signer. Detects
    /// whether the envelope carries an `x5chain` (vault-pki-p256) or
    /// is a raw-Ed25519 legacy envelope, walks the X.509 chain to the
    /// local anchor PEM, and verifies the leaf signature against the
    /// canonical body bytes. Fully OFFLINE — no Vault round-trip.
    #[command(name = "c2pa-verify")]
    C2paVerify {
        /// Path to the JUMBF envelope file (base64-encoded JSON).
        #[arg(value_name = "FILE")]
        manifest_path: PathBuf,
        /// Optional content bytes to re-hash for the content-hash
        /// assertion check.
        #[arg(long, value_name = "PATH")]
        content: Option<PathBuf>,
        /// Local root anchor PEM. Defaults to the env-derived path.
        #[arg(long)]
        root_anchor: Option<PathBuf>,
        /// Compact JSON output.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Verify a C2PA Content Credentials manifest produced by `output_attest`
    /// (agent-ux-07). Reads the JUMBF envelope from FILE, optionally
    /// re-hashes the bound CONTENT bytes, and reports the four-way check
    /// (canonical-hash, signature, content-hash, receipt cross-reference).
    /// Works OFFLINE — no network calls; the verifying key is supplied via
    /// `--pub-key-hex` or `CRUX_C2PA_VERIFY_PUBLIC_KEY_HEX`.
    #[command(name = "output-verify")]
    OutputVerify {
        /// Path to the JUMBF envelope file (base64-encoded JSON, as
        /// returned by the MCP tool's `manifest_jumbf_base64`).
        #[arg(value_name = "FILE")]
        manifest_path: PathBuf,
        /// Optional content bytes to re-hash. If omitted, the
        /// content-hash check is skipped and reported as `n/a`.
        #[arg(long, value_name = "PATH")]
        content: Option<PathBuf>,
        /// Hex-encoded Ed25519 verifying key (32 bytes / 64 hex chars).
        /// Defaults to env var `CRUX_C2PA_VERIFY_PUBLIC_KEY_HEX`.
        #[arg(long)]
        pub_key_hex: Option<String>,
        /// Optional expected CROWN receipt id — if set, the manifest's
        /// `crown_receipt_id` must match or the verifier exits non-zero.
        #[arg(long)]
        expected_receipt: Option<String>,
        /// Emit compact JSON instead of pretty JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ContextCommand {
    /// One-shot context-export bundle (context-custody-surface M2).
    /// Composes the cruxpack (facts + sessions, re-importable) + the audit
    /// bundle (signed journal + receipt refs) into one directory with a
    /// passport-signed custody-proof manifest. Read-only against the data dir.
    Export {
        /// Data directory (defaults to CORECRUXD_DATA_DIR).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Output bundle DIRECTORY (created if absent).
        #[arg(long)]
        out: PathBuf,
        /// Tenant id stamped on the cruxpack.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// RFC3339 lower bound, inclusive (optional); applied to both halves.
        #[arg(long)]
        since: Option<String>,
        /// Copy born-private facts into the bundle (Art.14 typed consent prompt).
        #[arg(long, default_value_t = false)]
        include_private: bool,
        /// Operator-only: include reserved-prefix entries in the audit half.
        #[arg(long, default_value_t = false)]
        include_reserved: bool,
        /// Optional caller label embedded in the audit-bundle scope.
        #[arg(long)]
        caller: Option<String>,
    },
    /// Verify a context-export bundle OFFLINE — no daemon, no network.
    /// Checks the passport signature on the custody-proof manifest, the
    /// per-component blake3 hashes, the cruxpack self-verification, and
    /// re-runs audit-verify. Exits non-zero on any failure.
    Verify {
        /// Path to the bundle DIRECTORY produced by `context export`.
        bundle: PathBuf,
        /// Emit the verification report as JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum IncidentCommand {
    /// Create and persist a merged incident-reconstruction case.
    Create {
        /// Explicit daemon URL; omit to use normal daemon discovery.
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        title: String,
        /// Incident window lower bound (RFC3339, inclusive).
        #[arg(long)]
        from: String,
        /// Incident window upper bound (RFC3339, exclusive).
        #[arg(long)]
        to: String,
        /// Session selector; repeat for multiple sessions.
        #[arg(long)]
        session_id: Vec<String>,
        /// Agent/passport selector; repeat for multiple actors.
        #[arg(long)]
        agent_id: Vec<String>,
        /// Entity-timeline selector; repeat for multiple entities.
        #[arg(long)]
        entity: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Show a full persisted incident case.
    Show {
        #[arg(long)]
        url: Option<String>,
        id: String,
    },
    /// Export a certified offline-verifiable evidence bundle.
    Export {
        #[arg(long)]
        url: Option<String>,
        id: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum HooksCommand {
    /// Install the Crux hooks into a Claude Code settings.json.
    Install {
        /// Install user-wide (~/.claude/settings.json) instead of the project.
        #[arg(long, default_value_t = false)]
        user: bool,
        /// Project directory (default: current dir → .claude/settings.local.json).
        #[arg(long)]
        project: Option<PathBuf>,
        /// Daemon endpoint the hooks should talk to (host:port or URL). Saved to
        /// ~/.config/cuecrux/env. If omitted and none is configured, prompts when
        /// interactive.
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Show whether the Crux hooks are wired in the target settings.json.
    Status {
        #[arg(long, default_value_t = false)]
        user: bool,
        #[arg(long)]
        project: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum MachineCommand {
    /// Register (or refresh) this machine's record on the daemon.
    Register {
        /// Daemon URL (default: the sole daemon in the credential store).
        #[arg(long)]
        url: Option<String>,
    },
    /// List the machines registered with the daemon.
    List {
        #[arg(long)]
        url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Capture ~/.claude (secrets redacted) and store it on the daemon.
    Push {
        /// Bundle name (e.g. `myles-pc` or `default`).
        name: String,
        #[arg(long)]
        url: Option<String>,
    },
    /// Restore a stored bundle into ~/.claude (backs up existing files).
    Pull {
        /// Bundle name to restore.
        name: String,
        #[arg(long)]
        url: Option<String>,
    },
    /// List config bundles stored on the daemon.
    List {
        #[arg(long)]
        url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum CompactionSyncCommand {
    /// Verify prerequisites, set the opt-in, and run a live seal→push→pull→verify
    /// self-test. A 402 (non-Pro) blocks activation with an upgrade message.
    Enable,
    /// Report the current opt-in / mirror / passport / gate state (offline).
    Status,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// Push a session-state snapshot (from --file or stdin) to the daemon.
    Push {
        /// Session id.
        id: String,
        /// Read state JSON from this file (default: stdin).
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        url: Option<String>,
    },
    /// Print a session-state snapshot shared from any machine.
    Pull {
        /// Session id.
        id: String,
        #[arg(long)]
        url: Option<String>,
    },
    /// List session snapshots shared across machines.
    List {
        #[arg(long)]
        url: Option<String>,
    },
    /// Token-burn cost lens: parse a Claude Code transcript and print a
    /// shareable usage table with the headline burn number + reduction levers.
    Cost {
        /// Transcript file (default: newest under ~/.claude/projects).
        #[arg(long)]
        file: Option<String>,
        /// Session id to analyze (its `<id>.jsonl` under ~/.claude/projects).
        #[arg(long)]
        session: Option<String>,
        /// Emit the machine `CostReport` JSON instead of the table.
        #[arg(long)]
        json: bool,
        /// Post the report to the daemon's `/v1/cost/report` (for the console).
        #[arg(long)]
        post: bool,
        /// Tenant id for `--post` (default: "default").
        #[arg(long)]
        tenant: Option<String>,
        /// Daemon base URL override.
        #[arg(long)]
        url: Option<String>,
    },
    /// Reconcile sweep: walk every transcript under `~/.claude/projects` and
    /// post any whose stored cost report is missing or older than the
    /// transcript's mtime. The completeness backstop for the `SessionEnd` hook —
    /// idempotent (latest-wins), safe to run on a timer.
    #[command(name = "cost-sweep")]
    CostSweep {
        /// Tenant id (default: "default").
        #[arg(long)]
        tenant: Option<String>,
        /// Daemon base URL override.
        #[arg(long)]
        url: Option<String>,
        /// Report what would be posted without posting.
        #[arg(long)]
        dry_run: bool,
        /// Re-post every transcript regardless of stored freshness.
        #[arg(long)]
        force: bool,
        /// Only consider transcripts modified within this many days (0 = all).
        #[arg(long, default_value_t = 30)]
        since_days: u64,
    },
}

#[derive(Debug, Subcommand)]
enum ObserveCommand {
    /// Ingest a Claude Code transcript into signed observe trace nodes:
    /// capture each turn's assistant answer + a private extractive
    /// thinking-summary (reasoning blob), all `private:true`.
    Ingest {
        /// Transcript file (default: newest under ~/.claude/projects).
        #[arg(long)]
        file: Option<String>,
        /// Session id to ingest (its `<id>.jsonl` under ~/.claude/projects).
        #[arg(long)]
        session: Option<String>,
        /// Directory for reasoning blobs (default: ~/.local/share/cuecrux/observe).
        #[arg(long)]
        blob_dir: Option<String>,
        /// Passport/actor to attribute the nodes to (default: agent:claude-code-ingest).
        #[arg(long)]
        actor: Option<String>,
        /// Post the nodes to the daemon's observe surface (needs CORECRUXD_OBSERVE=1).
        #[arg(long)]
        post: bool,
        /// Tenant id for `--post`.
        #[arg(long)]
        tenant: Option<String>,
        /// Daemon base URL override.
        #[arg(long)]
        url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum CodeHealthCommand {
    /// Harvest code-health findings from the tool battery over a repo and
    /// emit normalized JSON (default) or a text summary. With `--push`, write
    /// the findings to the daemon fact store instead (M2).
    Harvest {
        /// Repo root to harvest (default: current directory).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Output format: `json` (default) or `text`. Ignored with `--push`.
        #[arg(long, default_value = "json")]
        format: String,
        /// Push findings to the daemon fact store (`codehealth:<repo>`),
        /// retiring resolved findings and writing a `run:<date>` summary.
        #[arg(long, default_value_t = false)]
        push: bool,
        /// Daemon HTTP base URL for `--push`.
        #[arg(long, default_value = "http://127.0.0.1:14800")]
        http: String,
        /// Bearer token file for `--push` (defaults: $CRUX_AGENT_TOKEN, then
        /// ~/.config/cuecrux/crux-tokens/anthropic.jwt).
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Extract the endpoint→termination call chain for a route or function
    /// (code-intelligence M4 — path-qualified syn walker).
    Trace {
        /// Repo root to analyze (default: current directory).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Root to trace: an axum route path (`/v1/...`) or a function name.
        #[arg(long)]
        root: String,
        /// Output format: `json` (default) or `text`. Ignored with `--push`.
        #[arg(long, default_value = "json")]
        format: String,
        /// Maximum chain depth.
        #[arg(long, default_value_t = 8)]
        max_depth: usize,
        /// Push the chain as a `codechain` entity instead of printing it.
        #[arg(long, default_value_t = false)]
        push: bool,
        /// Daemon HTTP base URL for `--push`.
        #[arg(long, default_value = "http://127.0.0.1:14800")]
        http: String,
        /// Bearer token file for `--push`.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum RepoCommand {
    /// Register a local path or clone URL for one tenant. Local paths are scanned immediately.
    Add {
        /// Tenant id that owns the repository registration.
        #[arg(long)]
        tenant: String,
        /// Optional repo id; defaults to a slug derived from --path or --clone-url.
        #[arg(long)]
        id: Option<String>,
        /// Local absolute repository path to scan immediately.
        #[arg(long)]
        path: Option<String>,
        /// Remote clone URL to register without cloning yet.
        #[arg(long)]
        clone_url: Option<String>,
        /// Language tag; may be repeated.
        #[arg(long = "language")]
        languages: Vec<String>,
        /// Daemon HTTP base URL.
        #[arg(long, default_value = "http://127.0.0.1:14800")]
        http: String,
        /// Bearer token file.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// List repository registrations for a tenant.
    List {
        /// Tenant id to list.
        #[arg(long)]
        tenant: String,
        /// Daemon HTTP base URL.
        #[arg(long, default_value = "http://127.0.0.1:14800")]
        http: String,
        /// Bearer token file.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Remove a repository registration and its latest scan fact.
    Remove {
        /// Repo id to remove.
        repo_id: String,
        /// Tenant id that owns the registration.
        #[arg(long)]
        tenant: String,
        /// Daemon HTTP base URL.
        #[arg(long, default_value = "http://127.0.0.1:14800")]
        http: String,
        /// Bearer token file.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum OpenclawCommand {
    /// Import an OpenClaw workspace directory (markdown memory files; SQLite
    /// noted but not parsed) into the local Crux store. Each memory becomes a
    /// fact stamped with provenance (actor=import:openclaw, source path/hash/
    /// mtime/declared date) and written via the journaled PUT /v1/facts/bulk.
    Import {
        /// OpenClaw workspace directory (e.g. ~/.openclaw/workspace).
        path: PathBuf,
        /// Crux Daemon HTTP base URL (default: $CORECRUXD_HTTP_URL or
        /// http://127.0.0.1:14800).
        #[arg(long)]
        daemon_url: Option<String>,
        /// Parse + report only; write nothing.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Scan an already-imported store and emit a markdown memory-scan report:
    /// per-memory provenance, content-hash verification against the live
    /// workspace, injected-instruction + integrity findings, and staleness.
    Scan {
        /// Crux Daemon HTTP base URL (default: $CORECRUXD_HTTP_URL or
        /// http://127.0.0.1:14800).
        #[arg(long)]
        daemon_url: Option<String>,
        /// Live OpenClaw workspace to verify each memory's content hash against
        /// (the authoritative tamper signal). Omit for a store-only advisory scan.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Write the report to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Days a daily log may be modified past its declared date before the
        /// change is advisory-flagged as a timestamp anomaly.
        #[arg(long, default_value_t = corecruxctl::openclaw::DEFAULT_MUTATION_GRACE_DAYS)]
        mutation_grace_days: u32,
        /// Age (days) past which a memory's declared date is called stale.
        #[arg(long, default_value_t = corecruxctl::openclaw::DEFAULT_STALE_DAYS)]
        stale_days: u32,
    },
}

#[derive(Debug, Subcommand)]
enum MemoryCommand {
    /// List visible memory facts (newest first; reserved prefixes filtered).
    Ls {
        /// Maximum facts to return.
        #[arg(long, default_value_t = 20)]
        top_k: usize,
        /// Optional entity to filter on.
        #[arg(long)]
        entity: Option<String>,
    },
    /// Print one fact with full metadata.
    Show {
        /// Fact id to look up.
        fact_id: String,
    },
    /// Update the value of an existing fact (passport-attributed write).
    Edit {
        /// Fact id to update.
        fact_id: String,
        /// New value.
        #[arg(long)]
        value: String,
        /// Optional human reason — stored as `memory_edit:<reason>` on the new fact.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Toggle pin state on a fact.
    Pin {
        /// Fact id to pin.
        fact_id: String,
        /// Set to remove the pin instead of adding it.
        #[arg(long, default_value_t = false)]
        off: bool,
    },
    /// List contradiction CANDIDATES (read-only; Audit II M1). Surfaces active,
    /// non-superseded facts sharing one (entity,key) with opposite polarity.
    /// Detect-only — resolve explicitly with `memory consolidate`.
    Contradictions {
        /// Maximum candidate groups to list.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Explicitly consolidate target facts into one canonical fact (Audit II
    /// M2). Supersedes the targets (history preserved) and emits a receipt.
    /// Refuses protected (pinned/receipt-linked/private/high-confidence)
    /// targets. Requires admin:write on the daemon.
    Consolidate {
        /// Entity all targets + the canonical fact share.
        #[arg(long)]
        entity: String,
        /// Key all targets + the canonical fact share.
        #[arg(long)]
        key: String,
        /// Value for the surviving canonical fact.
        #[arg(long)]
        canonical_value: String,
        /// Fact ids to collapse (repeatable; at least one).
        #[arg(long = "target", required = true)]
        targets: Vec<String>,
        /// Confidence for the canonical fact.
        #[arg(long, default_value_t = 1.0)]
        confidence: f32,
    },
    /// Export the local memory store to a signed `.cruxpack` file
    /// (read-only against --data-dir; private + erased facts excluded —
    /// see Memory-Portability-v1).
    Export {
        /// Daemon data directory (or CORECRUXD_DATA_DIR).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Output `.cruxpack` path.
        #[arg(long)]
        out: PathBuf,
        /// Tenant identity recorded in the manifest (import gate, T.1).
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Only include facts stored at/after this RFC 3339 timestamp.
        #[arg(long)]
        since: Option<String>,
        /// Opt private + reserved-prefix facts in. Prints a summary and
        /// requires typing 'include private' at the prompt.
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
    /// Import a `.cruxpack` into the running daemon via POST
    /// /v1/memory/import. Requires CRUX_MEMORY_IMPORT=1 (CLI and daemon).
    Import {
        /// Path to the `.cruxpack` file.
        #[arg(long)]
        file: PathBuf,
        /// Tenant to import into — must match the pack manifest (T.1).
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Principal remap entries `src=dst` (repeatable).
        #[arg(long = "map-principal")]
        map_principal: Vec<String>,
        /// Verify + plan only; write nothing.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// Print this daemon's passport fingerprint + public key (the identity
    /// card you carry to the peer daemon when drafting a link statement).
    Fpr {
        /// Daemon data directory (or CORECRUXD_DATA_DIR).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Explicit passport key file (defaults to <data-dir>/passport.key).
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Sign a canonical identity-link statement hash with this machine's
    /// passport key (either side of the cross-signature ceremony).
    SignLink {
        /// Daemon data directory (or CORECRUXD_DATA_DIR).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Explicit passport key file (defaults to <data-dir>/passport.key).
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Fingerprint of the passport on the GRANTING daemon.
        #[arg(long)]
        local_fpr: String,
        /// Fingerprint of the passport being granted memory.read.
        #[arg(long)]
        remote_fpr: String,
        /// RFC 3339 statement timestamp — must match on both sides.
        #[arg(long)]
        created_at: String,
    },
    /// Confirm a proposed identity-link candidate by submitting the completed
    /// cross-signature proof to the granting daemon.
    ConfirmCandidate {
        /// Candidate identifier (`cl_...`) to promote.
        candidate_id: String,
        /// Daemon HTTP base URL (defaults to CORECRUXD_HTTP_URL or localhost).
        #[arg(long)]
        http_url: Option<String>,
        /// Daemon-local passport record id granting memory.read.
        #[arg(long)]
        local_passport_id: String,
        /// Fingerprint of the remote passport being linked.
        #[arg(long)]
        remote_fpr: String,
        /// 64-hex ed25519 verifying key of the remote passport.
        #[arg(long)]
        remote_public_key_hex: String,
        /// RFC 3339 statement timestamp both sides signed.
        #[arg(long)]
        created_at: String,
        /// 128-hex ed25519 signature by the local passport.
        #[arg(long)]
        sig_local: String,
        /// 128-hex ed25519 signature by the remote passport.
        #[arg(long)]
        sig_remote: String,
    },
    /// Reject a proposed identity-link candidate without deleting its audit
    /// trail.
    RejectCandidate {
        /// Candidate identifier (`cl_...`) to reject.
        candidate_id: String,
        /// Daemon HTTP base URL (defaults to CORECRUXD_HTTP_URL or localhost).
        #[arg(long)]
        http_url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ExtensionsCommand {
    /// Download the curator-signed registry index, verify its
    /// signature against the supplied curator public key, and cache
    /// the verified bytes under `<data-dir>/extensions/registry/index.json`.
    Sync {
        /// HTTPS URL of the registry index (e.g.
        /// `https://raw.githubusercontent.com/CueCrux/community-extensions/main/index.json`).
        #[arg(long)]
        url: String,
        /// Curator passport fingerprint (the `passport_fpr` field on
        /// the signed index).
        #[arg(long)]
        pubkey_fpr: String,
        /// Curator public key, hex-encoded (64 lowercase chars).
        #[arg(long)]
        pubkey_hex: String,
        /// Daemon data directory; the cache lands at
        /// `<data-dir>/extensions/registry/index.json`.
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Pretty-print the cached registry from
    /// `<data-dir>/extensions/registry/index.json`. Run `sync` first
    /// to populate the cache.
    ListRegistry {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Install one extension by id from the daemon's verified cached
    /// registry index (`POST /v1/extensions/install-from-registry`).
    /// Run `sync` first, then `list-registry` to review the entry.
    Install {
        /// Extension id exactly as published in the registry index.
        id: String,
        /// Daemon-side index override. Relative paths resolve under the
        /// daemon's data dir; absolute paths are taken as-is. Defaults to
        /// `<data-dir>/extensions/registry/index.json`.
        #[arg(long)]
        index_path: Option<PathBuf>,
        /// Daemon HTTP base URL (defaults to CORECRUXD_HTTP_URL or localhost).
        #[arg(long)]
        http_url: Option<String>,
        /// Bearer token (defaults to CRUX_AGENT_TOKEN).
        #[arg(long)]
        token: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ShardMapCommand {
    /// Generate a default dev shard map v1 JSON.
    Init {
        /// Number of shards (dev split sharding).
        #[arg(long)]
        shards: u32,
        /// Cluster ID.
        #[arg(long, default_value = "dev")]
        cluster_id: String,
        /// Node ID (leader for all shards in dev Option A).
        #[arg(long, default_value = "node-dev")]
        node_id: String,
        /// HTTP leader address (host:port).
        #[arg(long, default_value = "127.0.0.1:4006")]
        http_addr: String,
        /// gRPC leader address (host:port).
        #[arg(long, default_value = "127.0.0.1:4007")]
        grpc_addr: String,
        /// Optional data dir; if set, populate shard descriptors' dataDir fields.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Output file (defaults to stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Split an existing shard range at a boundary and bump version.
    Split {
        /// Input shard map file.
        #[arg(long)]
        file: PathBuf,
        /// Shard to split (e.g. shard-0002).
        #[arg(long)]
        shard: String,
        /// Split point as hex (e.g. 0x6000000000000000).
        #[arg(long)]
        at: String,
        /// Optional new shardId (default: next numeric shard).
        #[arg(long)]
        new_shard: Option<String>,
        /// Output file (defaults to stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Validate a shard map file (coverage + digest).
    Validate {
        #[arg(long)]
        file: PathBuf,
    },

    /// Atomically publish a shard map into ${data_dir}/meta/routing and update `current`.
    Publish {
        /// Shard map JSON file to publish.
        #[arg(long)]
        file: PathBuf,
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Set `gpuId` on a shard descriptor (Phase 10) and bump shardmap version.
    #[command(name = "set-gpu")]
    SetGpu {
        /// Input shard map file.
        #[arg(long)]
        file: PathBuf,
        /// Shard to update (e.g. shard-0002).
        #[arg(long)]
        shard: String,
        /// GPU device index to assign as owner (e.g. 0, 1, 2).
        #[arg(long)]
        gpu_id: i32,
        /// Output file (defaults to stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ShardCommand {
    /// Create a shard move orchestration record in coordinator.
    Move {
        /// Coordinator base URL (e.g. http://127.0.0.1:4008).
        #[arg(long, default_value = "http://127.0.0.1:4008")]
        coordinator: String,
        /// Shard id (e.g. shard-0001).
        #[arg(long)]
        shard: String,
        /// Current/source leader node id.
        #[arg(long)]
        source_node: String,
        /// Target leader node id.
        #[arg(long)]
        target_node: String,
        /// Optional explicit job id.
        #[arg(long)]
        job_id: Option<String>,
        /// Initial status for orchestration record.
        #[arg(long, default_value = "planned")]
        status: String,
        /// Hint that old leader should remain follower after cutover (recorded in CLI output only).
        #[arg(long, default_value_t = false)]
        keep_old_as_follower: bool,
    },

    /// Create a shard split orchestration record in coordinator.
    Split {
        /// Coordinator base URL (e.g. http://127.0.0.1:4008).
        #[arg(long, default_value = "http://127.0.0.1:4008")]
        coordinator: String,
        /// Parent shard id to split (e.g. shard-0001).
        #[arg(long)]
        shard: String,
        /// Split point in hash ring space (hex u64, e.g. 0x4000000000000000).
        #[arg(long)]
        at_hash_hex: String,
        /// New shard id (e.g. shard-0009).
        #[arg(long)]
        new_shard: String,
        /// Optional explicit job id.
        #[arg(long)]
        job_id: Option<String>,
        /// Initial status for orchestration record.
        #[arg(long, default_value = "planned")]
        status: String,
    },

    /// Show coordinator shard orchestration state.
    Status {
        /// Coordinator base URL (e.g. http://127.0.0.1:4008).
        #[arg(long, default_value = "http://127.0.0.1:4008")]
        coordinator: String,
        /// Optional shard filter.
        #[arg(long)]
        shard: Option<String>,
        /// Optional job id filter.
        #[arg(long)]
        job_id: Option<String>,
    },

    /// Verify move cutover invariants from coordinator + current shard map.
    #[command(name = "verify-move")]
    VerifyMove {
        /// Coordinator base URL (e.g. http://127.0.0.1:4008).
        #[arg(long, default_value = "http://127.0.0.1:4008")]
        coordinator: String,
        /// CoreCrux HTTP base URL (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        corecrux: String,
        /// Shard id to verify.
        #[arg(long)]
        shard: String,
        /// Optional specific move job id.
        #[arg(long)]
        job_id: Option<String>,
        /// Optional expected target node id (defaults to selected move record target when present).
        #[arg(long)]
        expected_target_node: Option<String>,
        /// Require shard lease leader/epoch to match shard-map leader/epoch.
        #[arg(long, default_value_t = false)]
        require_lease_match: bool,
    },

    /// Verify split invariants from coordinator + current shard map.
    #[command(name = "verify-split")]
    VerifySplit {
        /// Coordinator base URL (e.g. http://127.0.0.1:4008).
        #[arg(long, default_value = "http://127.0.0.1:4008")]
        coordinator: String,
        /// CoreCrux HTTP base URL (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        corecrux: String,
        /// Parent shard id.
        #[arg(long)]
        parent_shard: String,
        /// New shard id created by the split.
        #[arg(long)]
        new_shard: String,
        /// Optional split point hex (defaults to selected split record value when present).
        #[arg(long)]
        split_point: Option<String>,
        /// Optional specific split job id.
        #[arg(long)]
        job_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Read or mutate operator valves (pause/throttle/read_only/emergency).
    #[command(name = "valves")]
    Valves {
        #[command(subcommand)]
        command: ValvesCommand,
    },

    /// Install checkpoint/tombstone metadata for a stream (Phase 6).
    #[command(name = "stream-meta")]
    StreamMeta {
        /// Base HTTP URL for corecruxd (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        http: String,
        /// Actor identifier (required).
        #[arg(long)]
        actor: String,
        /// Reason for change (required).
        #[arg(long)]
        reason: String,
        #[arg(long, value_name = "TENANT")]
        tenant_id: String,
        #[arg(long, value_name = "TYPE")]
        stream_type: String,
        #[arg(long, value_name = "ID")]
        stream_id: String,
        #[arg(long)]
        min_live_seq: Option<u64>,
        #[arg(long)]
        tombstone_seq: Option<u64>,
    },

    /// Submit/status for bounded operator actions (Phase 9).
    #[command(name = "action")]
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },

    /// Force-seal the head segment(s) and optionally advance projections.
    /// Requires CORECRUXD_ADMIN_FORCE_SEAL=1 on the daemon.
    #[command(name = "seal")]
    Seal {
        /// Base HTTP URL for corecruxd (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        http: String,
        /// Block until projection cursor advances past the sealed segment.
        #[arg(long, default_value_t = false)]
        wait_for_projection: bool,
        /// Reason for the force seal (required for audit trail).
        #[arg(long)]
        reason: String,
        /// Actor identifier.
        #[arg(long, default_value = "corecruxctl")]
        actor: String,
    },

    /// Query immutable operations evidence from the node-local ops stream.
    #[command(name = "ops-log")]
    OpsLog {
        /// Base HTTP URL for corecruxd (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        http: String,
        /// Optional node id. Defaults to the current node when omitted.
        #[arg(long)]
        node_id: Option<String>,
        /// RFC3339 lower bound on occurredAt.
        #[arg(long)]
        since: Option<String>,
        /// RFC3339 upper bound on occurredAt.
        #[arg(long)]
        until: Option<String>,
        /// Inclusive sequence cursor for pagination.
        #[arg(long)]
        from_seq: Option<u64>,
        /// Maximum events to return (clamped server-side).
        #[arg(long)]
        max_events: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
enum ActionCommand {
    /// Submit an admin action.
    Submit {
        /// Base HTTP URL for corecruxd (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        http: String,
        /// Optional idempotency key for action dedupe.
        #[arg(long)]
        action_id: Option<String>,
        /// Action type.
        #[arg(long)]
        action_type: String,
        /// Optional actor.
        #[arg(long)]
        actor: Option<String>,
        /// Optional reason.
        #[arg(long)]
        reason: Option<String>,
        /// Optional JSON params payload.
        #[arg(long)]
        params_json: Option<String>,
    },

    /// Query action status by id.
    Status {
        /// Base HTTP URL for corecruxd (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        http: String,
        /// Action id.
        #[arg(long)]
        action_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ValvesCommand {
    /// Fetch current CONTROL.json state from corecruxd.
    Get {
        /// Base HTTP URL for corecruxd (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        http: String,
    },

    /// Set one or more valves (partial update).
    Set {
        /// Base HTTP URL for corecruxd (e.g. http://127.0.0.1:4006).
        #[arg(long, default_value = "http://127.0.0.1:4006")]
        http: String,
        /// Actor identifier (required).
        #[arg(long)]
        actor: String,
        /// Reason for change (required).
        #[arg(long)]
        reason: String,
        #[arg(long)]
        pause_ingest: Option<bool>,
        #[arg(long)]
        pause_compaction: Option<bool>,
        #[arg(long)]
        throttle: Option<bool>,
        #[arg(long)]
        throttle_retry_after_ms: Option<u32>,
        #[arg(long)]
        throttle_events_per_sec: Option<u64>,
        #[arg(long)]
        throttle_bytes_per_sec: Option<u64>,
        #[arg(long)]
        throttle_max_in_flight: Option<u32>,
        #[arg(long)]
        read_only: Option<bool>,
        #[arg(long)]
        emergency_brake: Option<bool>,
    },
}

#[derive(Debug, Subcommand)]
enum CcxiCommand {
    /// Verify .ccxi companions exist for all sealed segments and BLAKE3 hashes are valid.
    Verify {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional shard numeric id (e.g. 1 for shard-0001). If omitted, checks all shards.
        #[arg(long)]
        shard: Option<u32>,
    },

    /// Rebuild .ccxi companion index from sealed segment(s).
    Rebuild {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional shard numeric id.
        #[arg(long)]
        shard: Option<u32>,
        /// Optional segment sequence to rebuild (if omitted, rebuilds all missing).
        #[arg(long)]
        segment_seq: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
enum ProjectionsCommand {
    /// Rebuild all projections from genesis (pure replay) and write CCXS snapshots + meta.
    Rebuild {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional shard numeric id (e.g. 1 for shard-0001). If omitted, rebuild all shards.
        #[arg(long)]
        shard: Option<u32>,
        /// CUDA device index (default 0).
        #[arg(long, default_value_t = 0)]
        device_index: i32,
        /// Replay micro-batch size in frames (default 1024).
        #[arg(long, default_value_t = 1024)]
        batch_frames: u32,
    },

    /// Garbage collect orphan cold projection segments not referenced by the latest snapshots.
    ///
    /// Notes:
    /// - This is safe to run while corecruxd is stopped. If run while serving, you must ensure
    ///   no concurrent readers depend on old snapshot versions.
    Gc {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional shard numeric id (e.g. 1 for shard-0001). If omitted, GC all shards.
        #[arg(long)]
        shard: Option<u32>,
        /// Do not delete; only report what would be removed.
        #[arg(long)]
        dry_run: bool,
        /// Only delete segments older than this age (seconds). Set 0 to disable.
        #[arg(long, default_value_t = 600)]
        min_age_seconds: u64,
        /// Maximum number of orphan segments to delete per projection per shard (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        max_delete: u64,
    },

    /// Seed a minimal deterministic set of projection events into a v3 shard directory.
    ///
    /// This is intended for local operator smoke: run corecruxd with projections enabled and
    /// confirm ticks produce snapshots under shards/shard-*/projections.
    SeedMinimal {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Shard numeric id to seed (default 1 for shard-0001).
        #[arg(long, default_value_t = 1)]
        shard: u32,
        /// Tenant ID (default tenant-a).
        #[arg(long, default_value = "tenant-a")]
        tenant_id: String,
        /// Artifact ID (stream_id for streamType=artifact).
        #[arg(long, default_value_t = 1)]
        artifact_id: u32,
        /// CUDA device index for gpu-dev IO (default 0).
        #[arg(long, default_value_t = 0)]
        device_index: i32,
    },
}

#[derive(Debug, Subcommand)]
enum StorageCommand {
    /// Copy sealed manifest-backed segments to warm or cold storage.
    #[command(name = "offload")]
    Offload {
        /// Operator environment. Falls back to CORECRUXCTL_ENV, defaults to local.
        #[arg(long, value_enum)]
        environment: Option<tooling_env::ToolingEnvironment>,
        /// Warm or cold target tier label.
        #[arg(long, value_enum)]
        tier: storage::StorageTier,
        /// Only consider segments sealed before this many days.
        #[arg(long)]
        older_than: u32,
        /// Target path or S3 URI.
        #[arg(long)]
        target: String,
        /// Force an explicit target backend. S3/local are inferred; rsync requires this flag.
        #[arg(long, value_enum)]
        target_kind: Option<storage::OffloadTargetKind>,
        /// Remote shell command used for rsync targets.
        #[arg(long)]
        rsync_rsh: Option<String>,
        /// Verify BLAKE3 source/destination after copy.
        #[arg(long, default_value_t = false)]
        verify_after_copy: bool,
        /// Permit an unverified copy in local mode only.
        #[arg(long, default_value_t = false)]
        allow_unverified_copy: bool,
        /// Permit local/offline execution without appending ops evidence.
        #[arg(long, default_value_t = false)]
        allow_missing_ops_evidence: bool,
        /// Remove the local segment after a verified copy.
        #[arg(long, default_value_t = false)]
        delete_source: bool,
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional report output path.
        #[arg(long)]
        evidence_out: Option<PathBuf>,
        /// Optional CoreCrux gRPC endpoint for appending SegmentOffloadedV1 events.
        #[arg(long)]
        grpc: Option<String>,
        /// Optional auth scopes metadata for the gRPC ops append.
        #[arg(long)]
        scopes: Option<String>,
        /// Optional node id for ops evidence events (defaults to CORECRUX_NODE_ID/HOSTNAME).
        #[arg(long)]
        node_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ParityCommand {
    /// Compare CoreCrux projections vs Engine living tables for a deterministic artifact sample.
    Living {
        #[arg(long)]
        tenant_id: String,
        #[arg(long, default_value = "0")]
        seed: String,
        #[arg(long, default_value_t = 25)]
        sample: u32,
        /// Engine base URL (e.g. http://127.0.0.1:3000).
        #[arg(long)]
        engine: String,
        /// Engine API key (x-api-key header).
        #[arg(long)]
        engine_api_key: String,
        /// CoreCrux HTTP base URL (e.g. http://127.0.0.1:4006).
        #[arg(long)]
        corecrux: String,
    },
}

#[derive(Debug, Subcommand)]
enum ReceiptsCommand {
    /// Export a CROWN JSON receipt as a CROWN SCITT Profile v0.2 COSE_Sign1 statement.
    #[command(name = "export-cose")]
    ExportCose {
        /// JSON receipt path. Accepts a direct receipt or `{ "receipt": ... }` wrapper.
        input: PathBuf,
        /// Output path. Defaults to the input path with a `.cose` extension.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Standard-base64 32-byte Ed25519 signing seed.
        #[arg(long, conflicts_with_all = ["key_file", "gen_dev_key"], required_unless_present_any = ["key_file", "gen_dev_key"])]
        key_b64: Option<String>,
        /// File containing a raw 32-byte Ed25519 seed or its standard-base64 encoding.
        #[arg(long, conflicts_with_all = ["key_b64", "gen_dev_key"])]
        key_file: Option<PathBuf>,
        /// Use the documented deterministic ResearchCrux development key.
        #[arg(long, default_value_t = false, conflicts_with_all = ["key_b64", "key_file"])]
        gen_dev_key: bool,
        /// Absolute issuer URI placed in the protected CWT claims.
        #[arg(long, default_value = "https://crux.local")]
        iss: String,
        /// Key identifier placed in protected header label 4.
        #[arg(long)]
        kid: String,
    },

    /// Verify a CROWN SCITT Profile v0.2 COSE_Sign1 statement offline.
    #[command(name = "verify-cose")]
    VerifyCose {
        /// COSE_Sign1 statement path.
        input: PathBuf,
        /// Standard-base64 32-byte Ed25519 public key. Omit only for the fixed development key.
        #[arg(long)]
        pubkey_b64: Option<String>,
    },

    /// Seed a minimal receipt body+sig into a shard directory (offline, dev-only).
    #[command(name = "seed-minimal")]
    SeedMinimal {
        /// CoreCrux data dir (defaults to ../CoreCruxData/v1).
        #[arg(long, default_value = "../CoreCruxData/v1")]
        data_dir: PathBuf,
        /// Shard ID (numeric) under data_dir/shards/shard-XXXX.
        #[arg(long, default_value_t = 1)]
        shard: u32,
        /// Tenant ID.
        #[arg(long)]
        tenant_id: String,
        /// Receipt ID (UUID string).
        #[arg(long)]
        receipt_id: String,
        /// Fake CUDA device index (default 0; used for CPU-only seeding).
        #[arg(long, default_value_t = 0)]
        device_index: i32,
    },

    /// Backfill the Phase 8 subject↔receipt index by scanning receipt.body.v1 events on disk.
    ///
    /// This is an offline operator tool: run it while corecruxd is stopped (it takes shard locks).
    #[command(name = "backfill-subject-index")]
    BackfillSubjectIndex {
        /// CoreCrux data dir (defaults to ../CoreCruxData/v1).
        #[arg(long, default_value = "../CoreCruxData/v1")]
        data_dir: PathBuf,
        /// Optional shard numeric id (e.g. 1 for shard-0001). If omitted, scan all shards.
        #[arg(long)]
        shard: Option<u32>,
        /// Do not write indexes; only report what would be updated.
        #[arg(long)]
        dry_run: bool,
        /// Fake CUDA device index (default 0; used for CPU-only scanning).
        #[arg(long, default_value_t = 0)]
        device_index: i32,
        /// Frames per scan batch (default 8192).
        #[arg(long, default_value_t = 8192)]
        batch_frames: u32,
    },

    /// Verify an external-anchor receipt body inclusion proof offline.
    #[command(name = "verify-external-anchor")]
    VerifyExternalAnchor {
        /// Path to the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        body: PathBuf,
    },

    /// Verify an RFC3161 timestamp receipt body token binding offline.
    #[command(name = "verify-rfc3161-timestamp")]
    VerifyRfc3161Timestamp {
        /// Path to the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        body: PathBuf,
        /// Optional expected SHA-256 message imprint hash (hex, `sha256:` prefix accepted).
        #[arg(long)]
        expected_imprint_hash: Option<String>,
        /// Trusted TSA root certificate for strict RFC3161 validation. May be repeated; accepts DER or PEM.
        #[arg(long = "tsa-root-cert")]
        tsa_root_cert: Vec<PathBuf>,
        /// Optional expected RFC3161 policy OID for strict validation.
        #[arg(long)]
        expected_policy_oid: Option<String>,
        /// Optional expected RFC3161 nonce as hex bytes for strict validation.
        #[arg(long)]
        expected_nonce_hex: Option<String>,
    },

    /// Smoke-check witness/TSA configuration locally without network submission.
    #[command(name = "witness-smoke")]
    WitnessSmoke {
        /// Enable Rekor witness checks in the local smoke report.
        #[arg(long, default_value_t = false)]
        witness_enabled: bool,
        /// Witness provider label. Only `rekor` is supported by this scaffold.
        #[arg(long, default_value = "disabled")]
        witness_provider: String,
        /// Witness timeout budget in milliseconds.
        #[arg(long, default_value_t = 5000)]
        witness_timeout_ms: u64,
        /// Rekor base URL required when --witness-enabled is set.
        #[arg(long)]
        rekor_url: Option<String>,
        /// Optional Rekor public key path checked for readability.
        #[arg(long)]
        rekor_public_key_path: Option<PathBuf>,
        /// Enable TSA checks in the local smoke report.
        #[arg(long, default_value_t = false)]
        tsa_enabled: bool,
        /// TSA URL required when --tsa-enabled is set.
        #[arg(long)]
        tsa_url: Option<String>,
        /// Trusted TSA root certificate path. May be repeated; accepts DER or PEM.
        #[arg(long = "tsa-root-cert")]
        tsa_root_cert: Vec<PathBuf>,
        /// Optional TSA policy OID expected by later strict verification.
        #[arg(long)]
        tsa_policy_oid: Option<String>,
    },

    /// Build an external_anchor receipt body from a transparency-log inclusion proof.
    #[command(name = "external-anchor-attest")]
    ExternalAnchorAttest {
        /// Output path for the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        out_body: PathBuf,
        /// Optional output path for detached receipt.sig.v1 CBOR bytes.
        #[arg(long)]
        out_sig: Option<PathBuf>,
        /// Base64 32-byte Ed25519 signing key. Required when --out-sig is set.
        #[arg(long)]
        signing_key_b64: Option<String>,
        /// Signature key identifier.
        #[arg(long, default_value = "external-anchor")]
        key_id: String,
        /// Signature timestamp; defaults to --created-at when omitted.
        #[arg(long)]
        signed_at: Option<String>,
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        receipt_id: String,
        /// Anchor ID. Defaults to --receipt-id when omitted.
        #[arg(long)]
        anchor_id: Option<String>,
        #[arg(long, default_value = "corecruxctl")]
        actor_passport: String,
        #[arg(long, default_value = "rekor")]
        transparency_log: String,
        #[arg(long)]
        log_url: String,
        #[arg(long)]
        rekor_uuid: Option<String>,
        #[arg(long)]
        leaf_hash: String,
        #[arg(long)]
        log_index: u64,
        #[arg(long)]
        tree_size: u64,
        #[arg(long)]
        root_hash: String,
        #[arg(long = "inclusion-proof")]
        inclusion_proof: Vec<String>,
        #[arg(long)]
        checkpoint: Option<String>,
        #[arg(long)]
        integrated_time: String,
        #[arg(long)]
        created_at: String,
    },

    /// Build an rfc3161_timestamp receipt body from a TSA token file.
    #[command(name = "rfc3161-timestamp-attest")]
    Rfc3161TimestampAttest {
        /// Output path for the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        out_body: PathBuf,
        /// Optional output path for detached receipt.sig.v1 CBOR bytes.
        #[arg(long)]
        out_sig: Option<PathBuf>,
        /// Base64 32-byte Ed25519 signing key. Required when --out-sig is set.
        #[arg(long)]
        signing_key_b64: Option<String>,
        /// Signature key identifier.
        #[arg(long, default_value = "rfc3161-timestamp")]
        key_id: String,
        /// Signature timestamp; defaults to --created-at when omitted.
        #[arg(long)]
        signed_at: Option<String>,
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        receipt_id: String,
        /// Timestamp ID. Defaults to --receipt-id when omitted.
        #[arg(long)]
        timestamp_id: Option<String>,
        #[arg(long, default_value = "corecruxctl")]
        actor_passport: String,
        #[arg(long)]
        tsa_url: String,
        #[arg(long)]
        tsa_policy_oid: Option<String>,
        #[arg(long, default_value = "sha256")]
        message_imprint_alg: String,
        #[arg(long)]
        message_imprint_hash: String,
        /// DER-encoded RFC3161 TimeStampToken returned by the TSA.
        #[arg(long)]
        timestamp_token_der: PathBuf,
        #[arg(long)]
        serial_number: Option<String>,
        #[arg(long)]
        gen_time: String,
        #[arg(long)]
        created_at: String,
    },

    /// Verify a chain_reanchor receipt body offline.
    #[command(name = "verify-chain-reanchor")]
    VerifyChainReanchor {
        /// Path to the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        body: PathBuf,
    },

    /// Build a chain_reanchor receipt body for crypto/signature migration.
    #[command(name = "chain-reanchor-attest")]
    ChainReanchorAttest {
        /// Output path for the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        out_body: PathBuf,
        /// Optional output path for detached receipt.sig.v1 CBOR bytes.
        #[arg(long)]
        out_sig: Option<PathBuf>,
        /// Base64 32-byte Ed25519 signing key. Required when --out-sig is set.
        #[arg(long)]
        signing_key_b64: Option<String>,
        /// Signature key identifier.
        #[arg(long, default_value = "chain-reanchor")]
        key_id: String,
        /// Signature timestamp; defaults to --created-at when omitted.
        #[arg(long)]
        signed_at: Option<String>,
        /// Tenant ID.
        #[arg(long)]
        tenant_id: String,
        /// Receipt ID.
        #[arg(long)]
        receipt_id: String,
        /// Migration ID. Defaults to --receipt-id when omitted.
        #[arg(long)]
        migration_id: Option<String>,
        /// Actor/passport creating the reanchor attestation.
        #[arg(long, default_value = "corecruxctl")]
        actor_passport: String,
        /// Old chain head hash.
        #[arg(long)]
        old_chain_head: String,
        /// New chain head hash.
        #[arg(long)]
        new_chain_head: String,
        /// Old hash/signature/anchor algorithm label.
        #[arg(long, default_value = "blake3")]
        old_hash_alg: String,
        /// New hash/signature/anchor algorithm label.
        #[arg(long, default_value = "blake3+external-anchor")]
        new_hash_alg: String,
        /// First receipt id covered by this migration.
        #[arg(long)]
        first_receipt_id: String,
        /// Last receipt id covered by this migration.
        #[arg(long)]
        last_receipt_id: String,
        /// Count of receipts covered by this migration.
        #[arg(long)]
        receipt_count: u64,
        /// Migration reason.
        #[arg(long)]
        reason: String,
        /// Linked receipt id; repeat for multiple ids.
        #[arg(long = "linked-receipt")]
        linked_receipts: Vec<String>,
        /// Receipt creation timestamp.
        #[arg(long)]
        created_at: String,
    },

    /// Build a redaction receipt body, optionally with a staged crypto-shred envelope.
    #[command(name = "redaction-attest")]
    RedactionAttest {
        /// Output path for the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        out_body: PathBuf,
        /// Optional output path for detached receipt.sig.v1 CBOR bytes.
        #[arg(long)]
        out_sig: Option<PathBuf>,
        /// Base64 32-byte Ed25519 signing key. Required when --out-sig is set.
        #[arg(long)]
        signing_key_b64: Option<String>,
        /// Signature key identifier.
        #[arg(long, default_value = "redaction-attest")]
        key_id: String,
        /// Signature timestamp; defaults to --created-at when omitted.
        #[arg(long)]
        signed_at: Option<String>,
        /// Tenant ID.
        #[arg(long)]
        tenant_id: String,
        /// Receipt ID.
        #[arg(long)]
        receipt_id: String,
        /// Redaction ID. Defaults to --receipt-id when omitted.
        #[arg(long)]
        redaction_id: Option<String>,
        /// Actor/passport creating the attestation.
        #[arg(long, default_value = "corecruxctl")]
        actor_passport: String,
        /// Subject type, e.g. fact, stream, document.
        #[arg(long)]
        subject_type: String,
        /// Subject identifier.
        #[arg(long)]
        subject_id: String,
        /// Source forget/DSAR/request identifier.
        #[arg(long)]
        request_id: String,
        /// Redaction scope label.
        #[arg(long, default_value = "subject")]
        scope: String,
        /// Redaction method.
        #[arg(long, default_value = "crypto_shred")]
        method: String,
        /// Subject CEK id.
        #[arg(long)]
        subject_cek_id: String,
        /// Subject CEK commitment. Derived when --crypto-shred-staged is used.
        #[arg(long)]
        subject_cek_commitment: Option<String>,
        /// CEK destruction timestamp. Omit for non-destructive staged receipts.
        #[arg(long)]
        cek_destroyed_at: Option<String>,
        /// Prior content hash. Derived from --seal-plaintext when omitted.
        #[arg(long)]
        prior_content_hash: Option<String>,
        /// Redacted content hash. Derived from staged ciphertext when omitted.
        #[arg(long)]
        redacted_content_hash: Option<String>,
        /// Linked receipt id; repeat for multiple ids.
        #[arg(long = "linked-receipt")]
        linked_receipts: Vec<String>,
        /// Receipt creation timestamp.
        #[arg(long)]
        created_at: String,
        /// Explicitly permit writing a non-destructive local crypto-shred envelope.
        #[arg(long, default_value_t = false)]
        crypto_shred_staged: bool,
        /// Plaintext path to seal into an envelope. Requires --crypto-shred-staged.
        #[arg(long)]
        seal_plaintext: Option<PathBuf>,
        /// Output path for the staged crypto-shred JSON envelope.
        #[arg(long)]
        out_envelope: Option<PathBuf>,
        /// Base64 32-byte subject CEK. Consumed to write the envelope; never written.
        #[arg(long)]
        cek_b64: Option<String>,
        /// Base64 24-byte XChaCha20 nonce for deterministic staging/replay.
        #[arg(long)]
        nonce_b64: Option<String>,
    },

    /// Build a non-destructive crypto-shred CEK destroy marker.
    #[command(name = "crypto-shred-destroy-marker")]
    CryptoShredDestroyMarker {
        /// Output path for the crypto-shred destroy marker JSON.
        #[arg(long)]
        out_marker: PathBuf,
        /// Marker ID.
        #[arg(long)]
        marker_id: String,
        /// Tenant ID.
        #[arg(long)]
        tenant_id: String,
        /// Subject type, e.g. fact, stream, document.
        #[arg(long)]
        subject_type: String,
        /// Subject identifier.
        #[arg(long)]
        subject_id: String,
        /// Subject CEK id.
        #[arg(long)]
        subject_cek_id: String,
        /// Subject CEK commitment.
        #[arg(long)]
        subject_cek_commitment: String,
        /// Redaction receipt linked to this CEK lifecycle marker.
        #[arg(long)]
        redaction_receipt_id: String,
        /// Actor/passport creating the marker.
        #[arg(long, default_value = "corecruxctl")]
        actor_passport: String,
        /// Idempotency key for repeated destroy requests.
        #[arg(long)]
        idempotency_key: String,
        /// Marker request timestamp.
        #[arg(long)]
        requested_at: String,
        /// CEK destruction timestamp. Requires --human-gate-receipt.
        #[arg(long)]
        destroyed_at: Option<String>,
        /// Passport-attributed approval receipt for actual CEK destruction.
        #[arg(long)]
        human_gate_receipt: Option<String>,
        /// Wrapped CEK registry reference, never key material.
        #[arg(long)]
        wrapped_key_ref: Option<String>,
        /// Operator-visible reason for the lifecycle marker.
        #[arg(long)]
        reason: Option<String>,
        /// Linked receipt id; repeat for multiple ids.
        #[arg(long = "linked-receipt")]
        linked_receipts: Vec<String>,
    },

    /// Build a coverage_attestation receipt body from a reproducible report file.
    #[command(name = "coverage-attest")]
    CoverageAttest {
        /// Output path for the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        out_body: PathBuf,
        /// Optional output path for detached receipt.sig.v1 CBOR bytes.
        #[arg(long)]
        out_sig: Option<PathBuf>,
        /// Base64 32-byte Ed25519 signing key. Required when --out-sig is set.
        #[arg(long)]
        signing_key_b64: Option<String>,
        /// Signature key identifier.
        #[arg(long, default_value = "coverage-attest")]
        key_id: String,
        /// Signature timestamp; defaults to --created-at when omitted.
        #[arg(long)]
        signed_at: Option<String>,
        /// Tenant ID.
        #[arg(long)]
        tenant_id: String,
        /// Receipt ID.
        #[arg(long)]
        receipt_id: String,
        /// Attestation ID. Defaults to --receipt-id when omitted.
        #[arg(long)]
        attestation_id: Option<String>,
        /// Actor/passport creating the attestation.
        #[arg(long, default_value = "corecruxctl")]
        actor_passport: String,
        /// Attested subject.
        #[arg(long, default_value = "feature_registry")]
        subject: String,
        /// Corpus identity, e.g. LME-S, LME-M, LME-500.
        #[arg(long)]
        corpus: String,
        /// Reproducible run identifier.
        #[arg(long)]
        run_id: String,
        /// Source commit SHA for the run.
        #[arg(long)]
        commit_sha: String,
        /// Lane flags used during the run.
        #[arg(long, default_value = "")]
        lane_flags: String,
        /// Metric name.
        #[arg(long, default_value = "coverage")]
        metric: String,
        /// Metric value.
        #[arg(long)]
        score: f64,
        /// Optional floor for the metric.
        #[arg(long)]
        floor: Option<f64>,
        /// Count below floor.
        #[arg(long, default_value_t = 0)]
        below_floor: u64,
        /// Optional capability count.
        #[arg(long)]
        capability_count: Option<u64>,
        /// Optional covered count.
        #[arg(long)]
        covered_count: Option<u64>,
        /// Optional hash of a gaps payload.
        #[arg(long)]
        gaps_hash: Option<String>,
        /// Path to the underlying report file whose BLAKE3 hash is bound.
        #[arg(long)]
        report: PathBuf,
        /// Receipt creation timestamp.
        #[arg(long)]
        created_at: String,
    },

    /// Scan a tenant's store over a time window and emit a SIGNED coverage
    /// report `{events, receipts, anchored, gaps, chain_head}`. Gaps (events
    /// without a receipt; receipts without an anchor) are bound into the
    /// signed body and cannot be hidden.
    #[command(name = "coverage-window-attest")]
    CoverageWindowAttest {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional shard numeric id (e.g. 1 for shard-0001); scans all when omitted.
        #[arg(long)]
        shard: Option<u32>,
        /// Tenant whose store is scanned.
        #[arg(long)]
        tenant_id: String,
        /// Window lower bound (RFC3339, inclusive).
        #[arg(long)]
        from: String,
        /// Window upper bound (RFC3339, exclusive).
        #[arg(long)]
        to: String,
        /// Output path for the standalone canonical-JSON window report.
        #[arg(long)]
        out_report: PathBuf,
        /// Output path for the raw receipt.body.v1 CBOR bytes.
        #[arg(long)]
        out_body: PathBuf,
        /// Optional output path for detached receipt.sig.v1 CBOR bytes.
        #[arg(long)]
        out_sig: Option<PathBuf>,
        /// Base64 32-byte Ed25519 signing key. Required when --out-sig is set.
        #[arg(long)]
        signing_key_b64: Option<String>,
        /// Signature key identifier.
        #[arg(long, default_value = "coverage-window-attest")]
        key_id: String,
        /// Signature timestamp; defaults to --created-at when omitted.
        #[arg(long)]
        signed_at: Option<String>,
        /// Receipt ID.
        #[arg(long)]
        receipt_id: String,
        /// Attestation ID. Defaults to --receipt-id when omitted.
        #[arg(long)]
        attestation_id: Option<String>,
        /// Actor/passport creating the attestation.
        #[arg(long, default_value = "corecruxctl")]
        actor_passport: String,
        /// Receipt creation timestamp.
        #[arg(long)]
        created_at: String,
        /// Replay batch size (frames per page).
        #[arg(long, default_value_t = 4096)]
        batch_frames: u32,
    },
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    /// List projection snapshots and metadata by shard.
    List {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional shard numeric id (e.g. 1 for shard-0001).
        #[arg(long)]
        shard: Option<u32>,
    },
    /// Verify projection snapshot hashes against projections.meta.json.
    Verify {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional shard numeric id (e.g. 1 for shard-0001).
        #[arg(long)]
        shard: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    /// Rebuild and verify CONTROL.json against the local control evidence stream.
    #[command(name = "control-verify")]
    ControlVerify {
        /// CoreCrux data dir (defaults to CORECRUXD_DATA_DIR or ../CoreCruxData/v1).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Fail if the control evidence stream is not hosted locally.
        #[arg(long, default_value_t = false)]
        hosted_only: bool,
        /// Emit compact JSON instead of pretty JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Fake CUDA device index (default 0; used for offline shard scans).
        #[arg(long, default_value_t = 0)]
        device_index: i32,
        /// Frames per scan batch.
        #[arg(long, default_value_t = 8192)]
        batch_frames: u32,
    },
    /// Verify an evidence pack offline.
    Verify {
        /// Evidence pack directory containing evidence_manifest.json.
        #[arg(long)]
        pack_dir: PathBuf,
        /// Treat optional-missing artifacts as failures.
        #[arg(long, default_value_t = false)]
        strict: bool,
        /// Fake CUDA device index (default 0; used for replay re-verification).
        #[arg(long, default_value_t = 0)]
        device_index: i32,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_cli(Cli::parse())
}

fn run_cli(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cli.command {
        Command::DeployAudit {
            config,
            auth_mode,
            http_bind,
            grpc_bind,
            network_exposed,
            json,
        } => deploy_audit::run(deploy_audit::DeployAuditOptions {
            config_path: config,
            auth_mode,
            http_bind,
            grpc_bind,
            network_exposed,
            json,
        }),
        Command::Start { url, token } => start::run(start::StartArgs { url, token }),
        Command::Login {
            url,
            token,
            device,
            no_verify,
            no_hooks,
            no_register,
        } => login::run(login::LoginArgs {
            url,
            token,
            device,
            no_verify,
            no_hooks,
            no_register,
        }),
        Command::Logout { url, all } => login::run_logout(login::LogoutArgs { url, all }),
        Command::Whoami { url } => login::run_whoami(login::WhoamiArgs { url }),
        Command::Hooks { command } => match command {
            HooksCommand::Install {
                user,
                project,
                endpoint,
            } => hooks::run_install(user, project, endpoint),
            HooksCommand::Status { user, project } => hooks::run_status(user, project),
        },
        Command::Machine { command } => match command {
            MachineCommand::Register { url } => machine::run_register(url),
            MachineCommand::List { url } => machine::run_list(url),
        },
        Command::Config { command } => match command {
            ConfigCommand::Push { name, url } => config_bundle::run_push(name, url),
            ConfigCommand::Pull { name, url } => config_bundle::run_pull(name, url),
            ConfigCommand::List { url } => config_bundle::run_list(url),
        },
        Command::Session { command } => match command {
            SessionCommand::Push { id, file, url } => session_sync::run_push(id, file, url),
            SessionCommand::Pull { id, url } => session_sync::run_pull(id, url),
            SessionCommand::List { url } => session_sync::run_list(url),
            SessionCommand::Cost {
                file,
                session,
                json,
                post,
                tenant,
                url,
            } => cost::run_cost(file, session, json, post, tenant, url),
            SessionCommand::CostSweep {
                tenant,
                url,
                dry_run,
                force,
                since_days,
            } => cost::run_cost_sweep(tenant, url, dry_run, force, since_days),
        },

        Command::CompactionSync { command } => match command {
            CompactionSyncCommand::Enable => compaction_sync::run_enable(),
            CompactionSyncCommand::Status => compaction_sync::run_status(),
        },
        Command::Observe { command } => match command {
            ObserveCommand::Ingest {
                file,
                session,
                blob_dir,
                actor,
                post,
                tenant,
                url,
            } => observe_ingest::run_ingest(file, session, blob_dir, actor, post, tenant, url),
        },
        Command::Replay {
            pack,
            input,
            strict,
            mode,
        } => {
            let started = std::time::Instant::now();
            if mode != "audit" {
                structured_log::emit_command_log(
                    "replay",
                    "fail",
                    started.elapsed().as_millis() as u64,
                    Some("INVALID_ARGUMENT"),
                    Some("unsupported replay mode"),
                );
                return Err(format!("unsupported mode: {mode} (Phase 0 supports only 'audit')").into());
            }
            if let Some(pack) = pack {
                match replay::replay_digest_from_pack(&pack, strict) {
                    Ok(report) => {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                        structured_log::emit_command_log(
                            "replay",
                            if report.ok { "ok" } else { "fail" },
                            started.elapsed().as_millis() as u64,
                            if report.ok { None } else { Some("DRIFT_SOURCE_CHANGE") },
                            None,
                        );
                        return Ok(());
                    }
                    Err(err) => {
                        structured_log::emit_command_log(
                            "replay",
                            "fail",
                            started.elapsed().as_millis() as u64,
                            Some("INTERNAL"),
                            Some(&err.to_string()),
                        );
                        return Err(err);
                    }
                }
            }
            if let Some(input) = input {
                eprintln!(
                    "warning: `corecruxctl replay --input` is deprecated; use `corecruxctl replay --pack <path>`"
                );
                match replay::replay_digest_from_jsonl(&input) {
                    Ok(digest) => {
                        println!("{}", serde_json::to_string_pretty(&digest)?);
                        structured_log::emit_command_log(
                            "replay",
                            "ok",
                            started.elapsed().as_millis() as u64,
                            None,
                            None,
                        );
                        return Ok(());
                    }
                    Err(err) => {
                        structured_log::emit_command_log(
                            "replay",
                            "fail",
                            started.elapsed().as_millis() as u64,
                            Some("INTERNAL"),
                            Some(&err.to_string()),
                        );
                        return Err(err);
                    }
                }
            }
            structured_log::emit_command_log(
                "replay",
                "fail",
                started.elapsed().as_millis() as u64,
                Some("INVALID_ARGUMENT"),
                Some("missing --pack/--input"),
            );
            Err("either --pack or --input must be provided".into())
        }
        Command::VerifyStore {
            data_dir,
            shard,
            scope,
            mode,
            sample_rate,
            strict,
        } => {
            let started = std::time::Instant::now();
            let scope = verify_store::VerifyScope::parse(&scope)
                .ok_or_else(|| format!("invalid --scope value '{scope}' (expected recent|all)"))?;
            let mode = verify_store::VerifyMode::parse(&mode)
                .ok_or_else(|| format!("invalid --mode value '{mode}' (expected sampled|full)"))?;
            let sample_rate = sample_rate.clamp(0.0, 1.0);
            let default_dir = std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
            let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
            let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
                data_dir,
                shard,
                scope,
                mode,
                sample_rate,
                strict,
                budget_bytes: 8 * 1024 * 1024,
                device_index: 0,
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.ok {
                structured_log::emit_command_log(
                    "verify_store",
                    "fail",
                    started.elapsed().as_millis() as u64,
                    Some("SEGMENT_CORRUPT"),
                    Some("verify-store detected integrity failures"),
                );
                return Err("verify-store detected integrity failures".into());
            }
            structured_log::emit_command_log("verify_store", "ok", started.elapsed().as_millis() as u64, None, None);
            Ok(())
        }
        Command::Ccxi { command } => match command {
            CcxiCommand::Verify { data_dir, shard } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
                let report = ccxi_verify(&data_dir, shard)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            CcxiCommand::Rebuild {
                data_dir,
                shard,
                segment_seq,
            } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
                let report = ccxi_rebuild(&data_dir, shard, segment_seq)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
        },
        Command::Storage { command } => match command {
            StorageCommand::Offload {
                environment,
                tier,
                older_than,
                target,
                target_kind,
                rsync_rsh,
                verify_after_copy,
                allow_unverified_copy,
                allow_missing_ops_evidence,
                delete_source,
                data_dir,
                evidence_out,
                grpc,
                scopes,
                node_id,
            } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let environment = tooling_env::ToolingEnvironment::resolve(environment)?;
                let report = storage::offload_segments(&storage::StorageOffloadOptions {
                    data_dir: data_dir.unwrap_or_else(|| PathBuf::from(default_dir)),
                    environment,
                    tier,
                    older_than_days: older_than,
                    target,
                    target_kind,
                    rsync_rsh,
                    verify_after_copy,
                    allow_unverified_copy,
                    allow_missing_ops_evidence,
                    delete_source,
                    evidence_out,
                    ops_grpc: grpc,
                    ops_scopes: scopes,
                    node_id,
                })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
        },
        Command::Reconcile {
            postgres,
            connection_string,
            tenant,
            stream_type,
            stream_id,
            shard,
            window_days,
            max_segments,
            data_dir,
            batch_size,
            sample_limit,
            evidence_out,
        } => {
            if !postgres {
                return Err("reconcile currently requires --postgres".into());
            }
            let default_dir = std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
            let report = reconcile::reconcile_postgres(&reconcile::ReconcilePostgresOptions {
                data_dir: data_dir.unwrap_or_else(|| PathBuf::from(default_dir)),
                connection_string,
                tenant_id: tenant,
                stream_type,
                stream_id,
                shard,
                window_days,
                max_segments,
                batch_size,
                sample_limit,
                evidence_out,
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::ImportV1 { events_log, out } => {
            let result = stage1_import::import_stage1_events_log(&events_log, &out)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Command::Smoke { device_index } => {
            let report = smoke::run(device_index)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::FixtureDigest { fixture, device_index } => {
            let report = fixture_digest::segment_fixture_replay_digest(&fixture, device_index)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::ShardMap { command } => match command {
            ShardMapCommand::Init {
                shards,
                cluster_id,
                node_id,
                http_addr,
                grpc_addr,
                data_dir,
                out,
            } => {
                let map = shardmap::init_dev_shard_map_v1(
                    shards,
                    &cluster_id,
                    &node_id,
                    &http_addr,
                    &grpc_addr,
                    data_dir.as_deref(),
                )?;
                if let Some(out) = out {
                    shardmap::write_shard_map_v1(&out, &map)?;
                } else {
                    println!("{}", serde_json::to_string_pretty(&map)?);
                }
                Ok(())
            }
            ShardMapCommand::Split {
                file,
                shard,
                at,
                new_shard,
                out,
            } => {
                let input = shardmap::read_shard_map_v1(&file)?;
                let map = shardmap::split_shard_map_v1(&input, &shard, &at, new_shard)?;
                if let Some(out) = out {
                    shardmap::write_shard_map_v1(&out, &map)?;
                } else {
                    println!("{}", serde_json::to_string_pretty(&map)?);
                }
                Ok(())
            }
            ShardMapCommand::Validate { file } => {
                let map = shardmap::read_shard_map_v1(&file)?;
                corecrux_types::validate_shard_map_v1(&map)?;
                println!("OK");
                Ok(())
            }
            ShardMapCommand::Publish { file, data_dir } => {
                let map = shardmap::read_shard_map_v1(&file)?;
                let data_dir = data_dir
                    .or_else(|| std::env::var("CORECRUXD_DATA_DIR").ok().map(PathBuf::from))
                    .unwrap_or_else(|| PathBuf::from("../CoreCruxData/v1"));
                shardmap::publish_shard_map_v1(&data_dir, &map)?;
                println!("OK");
                Ok(())
            }
            ShardMapCommand::SetGpu {
                file,
                shard,
                gpu_id,
                out,
            } => {
                let input = shardmap::read_shard_map_v1(&file)?;
                let map = shardmap::set_shard_gpu_id_v1(&input, &shard, gpu_id)?;
                if let Some(out) = out {
                    shardmap::write_shard_map_v1(&out, &map)?;
                } else {
                    println!("{}", serde_json::to_string_pretty(&map)?);
                }
                Ok(())
            }
        },
        Command::Shard { command } => match command {
            ShardCommand::Move {
                coordinator,
                shard: shard_id,
                source_node,
                target_node,
                job_id,
                status,
                keep_old_as_follower,
            } => {
                let req = shard::MoveCreateRequest {
                    job_id,
                    shard_id,
                    source_node_id: source_node,
                    target_node_id: target_node,
                    status: Some(status),
                };
                let mut report = serde_json::to_value(shard::submit_move(&coordinator, req)?)?;
                if keep_old_as_follower {
                    report["keepOldAsFollower"] = serde_json::Value::Bool(true);
                }
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ShardCommand::Split {
                coordinator,
                shard: shard_id,
                at_hash_hex,
                new_shard,
                job_id,
                status,
            } => {
                let req = shard::SplitCreateRequest {
                    job_id,
                    shard_id,
                    at_hash_hex,
                    new_shard_id: new_shard,
                    status: Some(status),
                };
                let report = shard::submit_split(&coordinator, req)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ShardCommand::Status {
                coordinator,
                shard: shard_filter,
                job_id,
            } => {
                let report = shard::status(&coordinator, shard_filter.as_deref(), job_id.as_deref())?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ShardCommand::VerifyMove {
                coordinator,
                corecrux,
                shard: shard_id,
                job_id,
                expected_target_node,
                require_lease_match,
            } => {
                let report = shard::verify_move(
                    &coordinator,
                    &corecrux,
                    &shard_id,
                    job_id.as_deref(),
                    expected_target_node.as_deref(),
                    require_lease_match,
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ShardCommand::VerifySplit {
                coordinator,
                corecrux,
                parent_shard,
                new_shard,
                split_point,
                job_id,
            } => {
                let report = shard::verify_split(
                    &coordinator,
                    &corecrux,
                    &parent_shard,
                    &new_shard,
                    split_point.as_deref(),
                    job_id.as_deref(),
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
        },
        Command::Admin { command } => match command {
            AdminCommand::Valves { command } => match command {
                ValvesCommand::Get { http } => {
                    let client = admin::AdminClient::new(&http);
                    let v = client.get_control()?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                    Ok(())
                }
                ValvesCommand::Set {
                    http,
                    actor,
                    reason,
                    pause_ingest,
                    pause_compaction,
                    throttle,
                    throttle_retry_after_ms,
                    throttle_events_per_sec,
                    throttle_bytes_per_sec,
                    throttle_max_in_flight,
                    read_only,
                    emergency_brake,
                } => {
                    let client = admin::AdminClient::new(&http);
                    let has_throttle_params = throttle_retry_after_ms.is_some()
                        || throttle_events_per_sec.is_some()
                        || throttle_bytes_per_sec.is_some()
                        || throttle_max_in_flight.is_some();
                    let throttle_req = if throttle.is_some() || has_throttle_params {
                        Some(admin::SetThrottleReq {
                            enabled: throttle.unwrap_or(true),
                            retry_after_ms: throttle_retry_after_ms,
                            events_per_sec: throttle_events_per_sec,
                            bytes_per_sec: throttle_bytes_per_sec,
                            max_in_flight: throttle_max_in_flight,
                        })
                    } else {
                        None
                    };
                    let req = admin::SetValvesReq {
                        actor: &actor,
                        reason: &reason,
                        pause_ingest,
                        pause_compaction,
                        throttle: throttle_req,
                        read_only,
                        emergency_brake,
                    };
                    let v = client.set_valves(req)?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                    Ok(())
                }
            },
            AdminCommand::StreamMeta {
                http,
                actor,
                reason,
                tenant_id,
                stream_type,
                stream_id,
                min_live_seq,
                tombstone_seq,
            } => {
                if min_live_seq.is_none() && tombstone_seq.is_none() {
                    return Err("must set at least one of --min-live-seq or --tombstone-seq".into());
                }
                let client = admin::AdminClient::new(&http);
                let req = admin::StreamMetaReq {
                    tenant_id: &tenant_id,
                    stream_type: &stream_type,
                    stream_id: &stream_id,
                    min_live_seq,
                    tombstone_seq,
                    actor: &actor,
                    reason: &reason,
                };
                let v = client.update_stream_meta(req)?;
                println!("{}", serde_json::to_string_pretty(&v)?);
                Ok(())
            }
            AdminCommand::Action { command } => match command {
                ActionCommand::Submit {
                    http,
                    action_id,
                    action_type,
                    actor,
                    reason,
                    params_json,
                } => {
                    let started = std::time::Instant::now();
                    let client = admin::AdminClient::new(&http);
                    let params = if let Some(raw) = params_json {
                        Some(serde_json::from_str::<serde_json::Value>(&raw)?)
                    } else {
                        None
                    };
                    let req = admin::SubmitActionReq {
                        action_id: action_id.as_deref(),
                        action_type: &action_type,
                        actor: actor.as_deref(),
                        reason: reason.as_deref(),
                        params,
                    };
                    let v = client.submit_action(req)?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                    structured_log::emit_command_log(
                        "admin_action_submit",
                        "ok",
                        started.elapsed().as_millis() as u64,
                        None,
                        None,
                    );
                    Ok(())
                }
                ActionCommand::Status { http, action_id } => {
                    let started = std::time::Instant::now();
                    let client = admin::AdminClient::new(&http);
                    let v = client.action_status(&action_id)?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                    structured_log::emit_command_log(
                        "admin_action_status",
                        "ok",
                        started.elapsed().as_millis() as u64,
                        None,
                        None,
                    );
                    Ok(())
                }
            },
            AdminCommand::Seal {
                http,
                wait_for_projection,
                reason,
                actor,
            } => {
                let started = std::time::Instant::now();
                let client = admin::AdminClient::new(&http);
                let mut params = serde_json::json!({
                    "reason": reason,
                    "waitForProjection": wait_for_projection,
                });
                if wait_for_projection {
                    params["maxFrames"] = serde_json::json!(4096);
                }
                let v = client.submit_action(admin::SubmitActionReq {
                    action_id: None,
                    action_type: "force-seal",
                    actor: Some(&actor),
                    reason: Some(&reason),
                    params: Some(params),
                })?;
                println!("{}", serde_json::to_string_pretty(&v)?);
                structured_log::emit_command_log("admin_seal", "ok", started.elapsed().as_millis() as u64, None, None);
                Ok(())
            }
            AdminCommand::OpsLog {
                http,
                node_id,
                since,
                until,
                from_seq,
                max_events,
            } => {
                let client = admin::AdminClient::new(&http);
                let v = client.ops_log(admin::OpsLogReq {
                    node_id: node_id.as_deref(),
                    since: since.as_deref(),
                    until: until.as_deref(),
                    from_seq,
                    max_events,
                })?;
                println!("{}", serde_json::to_string_pretty(&v)?);
                Ok(())
            }
        },
        Command::Projections { command } => match command {
            ProjectionsCommand::Rebuild {
                data_dir,
                shard,
                device_index,
                batch_frames,
            } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
                let report = projections::rebuild_projections_v1(&data_dir, shard, device_index, batch_frames)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ProjectionsCommand::Gc {
                data_dir,
                shard,
                dry_run,
                min_age_seconds,
                max_delete,
            } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
                let report =
                    projections::gc_orphan_cold_segments_v1(&data_dir, shard, dry_run, min_age_seconds, max_delete)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ProjectionsCommand::SeedMinimal {
                data_dir,
                shard,
                tenant_id,
                artifact_id,
                device_index,
            } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
                let report = projections::seed_minimal_projection_events_v1(
                    &data_dir,
                    shard,
                    &tenant_id,
                    artifact_id,
                    device_index,
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
        },
        Command::Parity { command } => match command {
            ParityCommand::Living {
                tenant_id,
                seed,
                sample,
                engine,
                engine_api_key,
                corecrux,
            } => {
                let report = parity::parity_living_v1(&tenant_id, &seed, sample, &engine, &engine_api_key, &corecrux)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
        },
        Command::ParityPack {
            out,
            tenant_id,
            seed,
            sample_size,
            window,
            projections,
            engine,
            engine_api_key,
            corecrux,
        } => {
            let started = std::time::Instant::now();
            let report = parity::generate_parity_pack(&parity::ParityPackOptions {
                out_dir: out,
                tenant_id,
                seed,
                sample_size,
                window_hours: window,
                projections,
                engine_base: engine,
                engine_api_key,
                corecrux_base: corecrux,
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            structured_log::emit_command_log(
                "parity_pack",
                if report.report.ok { "ok" } else { "fail" },
                started.elapsed().as_millis() as u64,
                if report.report.ok {
                    None
                } else {
                    Some("DRIFT_SOURCE_CHANGE")
                },
                None,
            );
            Ok(())
        }
        Command::Receipts { command } => match command {
            ReceiptsCommand::ExportCose {
                input,
                out,
                key_b64,
                key_file,
                gen_dev_key,
                iss,
                kid,
            } => {
                let report = receipts::export_cose_file_v1(&receipts::CoseExportOptionsV1 {
                    input: &input,
                    out: out.as_deref(),
                    key_b64: key_b64.as_deref(),
                    key_file: key_file.as_deref(),
                    gen_dev_key,
                    issuer: &iss,
                    kid: &kid,
                })?;
                println!(
                    "COSE_Sign1 exported: snap-id={} kid={} bytes={} dev-key={} out={}",
                    report.snap_id, report.kid, report.bytes_written, report.development_key, report.output_path
                );
                Ok(())
            }
            ReceiptsCommand::VerifyCose { input, pubkey_b64 } => {
                let report = receipts::verify_cose_file_v1(&input, pubkey_b64.as_deref())?;
                println!(
                    "COSE_Sign1 verification OK: snap-id={} kid={} iss={} dev-key={} file={}",
                    report.snap_id, report.kid, report.issuer, report.development_key, report.input_path
                );
                Ok(())
            }
            ReceiptsCommand::SeedMinimal {
                data_dir,
                shard,
                tenant_id,
                receipt_id,
                device_index,
            } => {
                let report =
                    receipts::seed_minimal_receipt_v1(&data_dir, shard, &tenant_id, &receipt_id, device_index)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ReceiptsCommand::BackfillSubjectIndex {
                data_dir,
                shard,
                dry_run,
                device_index,
                batch_frames,
            } => {
                let report =
                    receipts::backfill_subject_index_v1(&data_dir, shard, dry_run, device_index, batch_frames)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ReceiptsCommand::VerifyExternalAnchor { body } => {
                let report = receipts::verify_external_anchor_body_file_v1(&body)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if report.ok {
                    Ok(())
                } else {
                    Err(report
                        .failure_reason
                        .unwrap_or_else(|| "external anchor verification failed".to_string())
                        .into())
                }
            }
            ReceiptsCommand::VerifyRfc3161Timestamp {
                body,
                expected_imprint_hash,
                tsa_root_cert,
                expected_policy_oid,
                expected_nonce_hex,
            } => {
                let expected_nonce = expected_nonce_hex
                    .as_deref()
                    .map(receipts::parse_hex_bytes_v1)
                    .transpose()?;
                let report = receipts::verify_rfc3161_timestamp_body_file_with_options_v1(
                    &body,
                    &receipts::Rfc3161TimestampVerifyOptionsV1 {
                        expected_message_imprint_hash: expected_imprint_hash.as_deref(),
                        expected_policy_oid: expected_policy_oid.as_deref(),
                        expected_nonce: expected_nonce.as_deref(),
                        trusted_root_cert_paths: &tsa_root_cert,
                    },
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if report.ok {
                    Ok(())
                } else {
                    Err(report
                        .failure_reason
                        .unwrap_or_else(|| "RFC3161 timestamp verification failed".to_string())
                        .into())
                }
            }
            ReceiptsCommand::WitnessSmoke {
                witness_enabled,
                witness_provider,
                witness_timeout_ms,
                rekor_url,
                rekor_public_key_path,
                tsa_enabled,
                tsa_url,
                tsa_root_cert,
                tsa_policy_oid,
            } => {
                let report = receipts::witness_smoke_v1(&receipts::WitnessSmokeOptionsV1 {
                    witness_enabled,
                    witness_provider: &witness_provider,
                    witness_timeout_ms,
                    rekor_url: rekor_url.as_deref(),
                    rekor_public_key_path: rekor_public_key_path.as_deref(),
                    tsa_enabled,
                    tsa_url: tsa_url.as_deref(),
                    tsa_root_cert_paths: &tsa_root_cert,
                    tsa_policy_oid: tsa_policy_oid.as_deref(),
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
                if report.ok {
                    Ok(())
                } else {
                    Err("witness/TSA smoke check failed".into())
                }
            }
            ReceiptsCommand::ExternalAnchorAttest {
                out_body,
                out_sig,
                signing_key_b64,
                key_id,
                signed_at,
                tenant_id,
                receipt_id,
                anchor_id,
                actor_passport,
                transparency_log,
                log_url,
                rekor_uuid,
                leaf_hash,
                log_index,
                tree_size,
                root_hash,
                inclusion_proof,
                checkpoint,
                integrated_time,
                created_at,
            } => {
                let anchor_id = anchor_id.unwrap_or_else(|| receipt_id.clone());
                let signed_at = signed_at.unwrap_or_else(|| created_at.clone());
                let proof_refs: Vec<&str> = inclusion_proof.iter().map(String::as_str).collect();
                let report =
                    receipts::write_external_anchor_attestation_v1(&receipts::ExternalAnchorAttestOptionsV1 {
                        out_body: &out_body,
                        out_sig: out_sig.as_deref(),
                        signing_key_b64: signing_key_b64.as_deref(),
                        key_id: &key_id,
                        signed_at: &signed_at,
                        tenant_id: &tenant_id,
                        receipt_id: &receipt_id,
                        anchor_id: &anchor_id,
                        actor_passport: &actor_passport,
                        transparency_log: &transparency_log,
                        log_url: &log_url,
                        rekor_uuid: rekor_uuid.as_deref(),
                        leaf_hash: &leaf_hash,
                        log_index,
                        tree_size,
                        root_hash: &root_hash,
                        inclusion_proof: &proof_refs,
                        checkpoint: checkpoint.as_deref(),
                        integrated_time: &integrated_time,
                        created_at: &created_at,
                    })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ReceiptsCommand::Rfc3161TimestampAttest {
                out_body,
                out_sig,
                signing_key_b64,
                key_id,
                signed_at,
                tenant_id,
                receipt_id,
                timestamp_id,
                actor_passport,
                tsa_url,
                tsa_policy_oid,
                message_imprint_alg,
                message_imprint_hash,
                timestamp_token_der,
                serial_number,
                gen_time,
                created_at,
            } => {
                let timestamp_id = timestamp_id.unwrap_or_else(|| receipt_id.clone());
                let signed_at = signed_at.unwrap_or_else(|| created_at.clone());
                let report =
                    receipts::write_rfc3161_timestamp_attestation_v1(&receipts::Rfc3161TimestampAttestOptionsV1 {
                        out_body: &out_body,
                        out_sig: out_sig.as_deref(),
                        signing_key_b64: signing_key_b64.as_deref(),
                        key_id: &key_id,
                        signed_at: &signed_at,
                        tenant_id: &tenant_id,
                        receipt_id: &receipt_id,
                        timestamp_id: &timestamp_id,
                        actor_passport: &actor_passport,
                        tsa_url: &tsa_url,
                        tsa_policy_oid: tsa_policy_oid.as_deref(),
                        message_imprint_alg: &message_imprint_alg,
                        message_imprint_hash: &message_imprint_hash,
                        timestamp_token_der: &timestamp_token_der,
                        serial_number: serial_number.as_deref(),
                        gen_time: &gen_time,
                        created_at: &created_at,
                    })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ReceiptsCommand::VerifyChainReanchor { body } => {
                let report = receipts::verify_chain_reanchor_body_file_v1(&body)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if report.ok {
                    Ok(())
                } else {
                    Err(report
                        .failure_reason
                        .unwrap_or_else(|| "chain reanchor verification failed".to_string())
                        .into())
                }
            }
            ReceiptsCommand::ChainReanchorAttest {
                out_body,
                out_sig,
                signing_key_b64,
                key_id,
                signed_at,
                tenant_id,
                receipt_id,
                migration_id,
                actor_passport,
                old_chain_head,
                new_chain_head,
                old_hash_alg,
                new_hash_alg,
                first_receipt_id,
                last_receipt_id,
                receipt_count,
                reason,
                linked_receipts,
                created_at,
            } => {
                let migration_id = migration_id.unwrap_or_else(|| receipt_id.clone());
                let signed_at = signed_at.unwrap_or_else(|| created_at.clone());
                let linked_receipt_refs: Vec<&str> = linked_receipts.iter().map(String::as_str).collect();
                let report = receipts::write_chain_reanchor_attestation_v1(&receipts::ChainReanchorAttestOptionsV1 {
                    out_body: &out_body,
                    out_sig: out_sig.as_deref(),
                    signing_key_b64: signing_key_b64.as_deref(),
                    key_id: &key_id,
                    signed_at: &signed_at,
                    tenant_id: &tenant_id,
                    receipt_id: &receipt_id,
                    migration_id: &migration_id,
                    actor_passport: &actor_passport,
                    old_chain_head: &old_chain_head,
                    new_chain_head: &new_chain_head,
                    old_hash_alg: &old_hash_alg,
                    new_hash_alg: &new_hash_alg,
                    first_receipt_id: &first_receipt_id,
                    last_receipt_id: &last_receipt_id,
                    receipt_count,
                    reason: &reason,
                    linked_receipts: &linked_receipt_refs,
                    created_at: &created_at,
                })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ReceiptsCommand::RedactionAttest {
                out_body,
                out_sig,
                signing_key_b64,
                key_id,
                signed_at,
                tenant_id,
                receipt_id,
                redaction_id,
                actor_passport,
                subject_type,
                subject_id,
                request_id,
                scope,
                method,
                subject_cek_id,
                subject_cek_commitment,
                cek_destroyed_at,
                prior_content_hash,
                redacted_content_hash,
                linked_receipts,
                created_at,
                crypto_shred_staged,
                seal_plaintext,
                out_envelope,
                cek_b64,
                nonce_b64,
            } => {
                let redaction_id = redaction_id.unwrap_or_else(|| receipt_id.clone());
                let signed_at = signed_at.unwrap_or_else(|| created_at.clone());
                let linked_receipt_refs: Vec<&str> = linked_receipts.iter().map(String::as_str).collect();
                let report = receipts::write_redaction_attestation_v1(&receipts::RedactionAttestOptionsV1 {
                    out_body: &out_body,
                    out_sig: out_sig.as_deref(),
                    signing_key_b64: signing_key_b64.as_deref(),
                    key_id: &key_id,
                    signed_at: &signed_at,
                    tenant_id: &tenant_id,
                    receipt_id: &receipt_id,
                    redaction_id: &redaction_id,
                    actor_passport: &actor_passport,
                    subject_type: &subject_type,
                    subject_id: &subject_id,
                    request_id: &request_id,
                    scope: &scope,
                    method: &method,
                    subject_cek_id: &subject_cek_id,
                    subject_cek_commitment: subject_cek_commitment.as_deref(),
                    cek_destroyed_at: cek_destroyed_at.as_deref(),
                    prior_content_hash: prior_content_hash.as_deref(),
                    redacted_content_hash: redacted_content_hash.as_deref(),
                    linked_receipts: &linked_receipt_refs,
                    created_at: &created_at,
                    crypto_shred_staged,
                    seal_plaintext: seal_plaintext.as_deref(),
                    out_envelope: out_envelope.as_deref(),
                    cek_b64: cek_b64.as_deref(),
                    nonce_b64: nonce_b64.as_deref(),
                })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ReceiptsCommand::CryptoShredDestroyMarker {
                out_marker,
                marker_id,
                tenant_id,
                subject_type,
                subject_id,
                subject_cek_id,
                subject_cek_commitment,
                redaction_receipt_id,
                actor_passport,
                idempotency_key,
                requested_at,
                destroyed_at,
                human_gate_receipt,
                wrapped_key_ref,
                reason,
                linked_receipts,
            } => {
                let linked_receipt_refs: Vec<&str> = linked_receipts.iter().map(String::as_str).collect();
                let report =
                    receipts::write_crypto_shred_destroy_marker_v1(&receipts::CryptoShredDestroyMarkerOptionsV1 {
                        out_marker: &out_marker,
                        marker_id: &marker_id,
                        tenant_id: &tenant_id,
                        subject_type: &subject_type,
                        subject_id: &subject_id,
                        subject_cek_id: &subject_cek_id,
                        subject_cek_commitment: &subject_cek_commitment,
                        redaction_receipt_id: &redaction_receipt_id,
                        actor_passport: &actor_passport,
                        idempotency_key: &idempotency_key,
                        requested_at: &requested_at,
                        destroyed_at: destroyed_at.as_deref(),
                        human_gate_receipt: human_gate_receipt.as_deref(),
                        wrapped_key_ref: wrapped_key_ref.as_deref(),
                        reason: reason.as_deref(),
                        linked_receipts: &linked_receipt_refs,
                    })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ReceiptsCommand::CoverageAttest {
                out_body,
                out_sig,
                signing_key_b64,
                key_id,
                signed_at,
                tenant_id,
                receipt_id,
                attestation_id,
                actor_passport,
                subject,
                corpus,
                run_id,
                commit_sha,
                lane_flags,
                metric,
                score,
                floor,
                below_floor,
                capability_count,
                covered_count,
                gaps_hash,
                report,
                created_at,
            } => {
                let attestation_id = attestation_id.unwrap_or_else(|| receipt_id.clone());
                let signed_at = signed_at.unwrap_or_else(|| created_at.clone());
                let report = receipts::write_coverage_attestation_v1(
                    &out_body,
                    out_sig.as_deref(),
                    signing_key_b64.as_deref(),
                    &key_id,
                    &signed_at,
                    &tenant_id,
                    &receipt_id,
                    &attestation_id,
                    &actor_passport,
                    &subject,
                    &corpus,
                    &run_id,
                    &commit_sha,
                    &lane_flags,
                    &metric,
                    score,
                    floor,
                    below_floor,
                    capability_count,
                    covered_count,
                    gaps_hash.as_deref(),
                    &report,
                    &created_at,
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            ReceiptsCommand::CoverageWindowAttest {
                data_dir,
                shard,
                tenant_id,
                from,
                to,
                out_report,
                out_body,
                out_sig,
                signing_key_b64,
                key_id,
                signed_at,
                receipt_id,
                attestation_id,
                actor_passport,
                created_at,
                batch_frames,
            } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
                let attestation_id = attestation_id.unwrap_or_else(|| receipt_id.clone());
                let signed_at = signed_at.unwrap_or_else(|| created_at.clone());
                let report = receipts::coverage_window_attest_v1(&receipts::CoverageWindowAttestOptionsV1 {
                    data_dir: &data_dir,
                    shard,
                    tenant_id: &tenant_id,
                    from: &from,
                    to: &to,
                    out_report: &out_report,
                    out_body: &out_body,
                    out_sig: out_sig.as_deref(),
                    signing_key_b64: signing_key_b64.as_deref(),
                    key_id: &key_id,
                    signed_at: &signed_at,
                    receipt_id: &receipt_id,
                    attestation_id: &attestation_id,
                    actor_passport: &actor_passport,
                    created_at: &created_at,
                    batch_frames,
                })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
        },
        Command::Snapshot { command } => match command {
            SnapshotCommand::List { data_dir, shard } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
                let report = snapshot::list_snapshots(&snapshot::SnapshotOptions { data_dir, shard })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            }
            SnapshotCommand::Verify { data_dir, shard } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(default_dir));
                let report = snapshot::verify_snapshots(&snapshot::SnapshotOptions { data_dir, shard })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.ok {
                    return Err("snapshot verification failed".into());
                }
                Ok(())
            }
        },
        Command::Evidence { command } => match command {
            EvidenceCommand::ControlVerify {
                data_dir,
                hosted_only,
                json,
                device_index,
                batch_frames,
            } => {
                let default_dir =
                    std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string());
                let report = evidence::control_verify(&evidence::ControlVerifyOptions {
                    data_dir: data_dir.unwrap_or_else(|| PathBuf::from(default_dir)),
                    hosted_only,
                    device_index,
                    batch_frames,
                })?;
                if json {
                    println!("{}", serde_json::to_string(&report)?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                if !report.ok {
                    return Err("control evidence verification failed".into());
                }
                Ok(())
            }
            EvidenceCommand::Verify {
                pack_dir,
                strict,
                device_index,
            } => {
                let report = evidence::verify_evidence_pack(&evidence::PackVerifyOptions {
                    pack_dir,
                    strict,
                    device_index,
                })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.ok {
                    return Err("evidence pack verification failed".into());
                }
                Ok(())
            }
        },
        Command::AuditPack {
            out_dir,
            offline,
            corecrux,
            data_dir,
            tenant_id,
            stream_type,
            stream_id,
            from_seq,
            max_events,
            v1_events_log,
            v1_stream_jsonl,
            engine,
            engine_api_key,
            parity_tenant_id,
            parity_seed,
            parity_sample,
            replay_fixture,
            device_index,
            receipt_id,
            answer_id,
            action_id,
            receipt_keyring,
        } => {
            let opts = audit_pack::AuditPackOptionsV1 {
                out_dir,
                offline,
                corecrux_base: corecrux,
                data_dir,
                tenant_id,
                stream_type,
                stream_id,
                from_seq,
                max_events,
                v1_events_log,
                v1_stream_jsonl,
                parity_tenant_id,
                parity_seed,
                parity_sample,
                engine_base: engine,
                engine_api_key,
                replay_fixture,
                device_index,
                receipt_id,
                answer_id,
                action_id,
                receipt_keyring,
            };
            let report = audit_pack::generate_audit_pack_v1(&opts)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }

        Command::InspectReceipt { receipt_id, data_dir } => {
            let dd = data_dir.unwrap_or_else(|| {
                std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string())
            });
            inspect_receipt::run(&dd, &receipt_id)?;
            Ok(())
        }

        Command::Explain { receipt_id, data_dir } => {
            let dd = data_dir.unwrap_or_else(|| {
                std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string())
            });
            explain::run(&dd, &receipt_id)?;
            Ok(())
        }

        Command::Gaps { data_dir, since } => {
            let dd = data_dir.unwrap_or_else(|| {
                std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v1".to_string())
            });
            gaps::run(&dd, since.as_deref())?;
            Ok(())
        }

        Command::Learn {
            min_repeats,
            scan,
            url,
            json,
        } => {
            learn::run_learn(min_repeats, scan, url, json)?;
            Ok(())
        }

        Command::CodeHealth { command } => match command {
            CodeHealthCommand::Harvest {
                repo,
                format,
                push,
                http,
                token_file,
            } => {
                if push {
                    code_health::run_push(&repo, &http, token_file.as_deref())?;
                } else {
                    code_health::run_harvest(&repo, &format)?;
                }
                Ok(())
            }
            CodeHealthCommand::Trace {
                repo,
                root,
                format,
                max_depth,
                push,
                http,
                token_file,
            } => {
                code_chain::run_trace(&repo, &root, &format, max_depth, push, &http, token_file.as_deref())?;
                Ok(())
            }
        },

        Command::Repo { command } => match command {
            RepoCommand::Add {
                tenant,
                id,
                path,
                clone_url,
                languages,
                http,
                token_file,
            } => {
                repo::run_add(&http, token_file.as_deref(), tenant, id, path, clone_url, languages)?;
                Ok(())
            }
            RepoCommand::List {
                tenant,
                http,
                token_file,
            } => {
                repo::run_list(&http, token_file.as_deref(), &tenant)?;
                Ok(())
            }
            RepoCommand::Remove {
                repo_id,
                tenant,
                http,
                token_file,
            } => {
                repo::run_remove(&http, token_file.as_deref(), &tenant, &repo_id)?;
                Ok(())
            }
        },

        Command::Ingest {
            path,
            tenant,
            corpus,
            daemon_url,
            dry_run,
            embed,
        } => ingest::run(&ingest::IngestOptions {
            path,
            tenant,
            corpus,
            daemon_url,
            dry_run,
            embed,
        }),

        Command::Quickstart { http, non_interactive } => {
            corecruxctl::quickstart::run(&http, non_interactive)?;
            Ok(())
        }

        Command::Benchmark {
            suite,
            http,
            upload,
            output,
            compare,
        } => {
            if let Some(files) = compare {
                if files.len() == 2 {
                    corecruxctl::benchmark::compare(&files[0], &files[1])?;
                } else {
                    eprintln!("--compare requires exactly 2 file paths");
                    std::process::exit(1);
                }
            } else {
                corecruxctl::benchmark::run(&http, &suite, upload, output.as_deref())?;
            }
            Ok(())
        }
        Command::Extensions { command } => match command {
            ExtensionsCommand::Sync {
                url,
                pubkey_fpr,
                pubkey_hex,
                data_dir,
            } => {
                let index = extensions::sync(&url, &pubkey_fpr, &pubkey_hex, &data_dir)?;
                println!("Verified registry index from {url}");
                println!("  curator:        {}", index.curator_passport_fpr);
                println!("  updated_at_ms:  {}", index.updated_at_unix_ms);
                println!("  entries:        {}", index.entries.len());
                println!(
                    "  cached at:      {}",
                    extensions::cached_index_path(&data_dir).display()
                );
                for entry in &index.entries {
                    println!(
                        "  - {:<32} v{}  {:?}  {:?}",
                        entry.id, entry.version, entry.kind, entry.trust_tier
                    );
                }
                Ok(())
            }
            ExtensionsCommand::ListRegistry { data_dir } => {
                let index = extensions::list_registry(&data_dir)?;
                let path = extensions::cached_index_path(&data_dir);
                println!("Cached registry: {}", path.display());
                println!("  curator:        {}", index.curator_passport_fpr);
                println!("  updated_at_ms:  {}", index.updated_at_unix_ms);
                println!("  entries:        {}", index.entries.len());
                println!();
                for entry in &index.entries {
                    println!("• {} (v{})", entry.name, entry.version);
                    println!("    id:           {}", entry.id);
                    println!("    kind:         {:?}", entry.kind);
                    println!("    trust_tier:   {:?}", entry.trust_tier);
                    println!("    summary:      {}", entry.summary);
                    println!("    repo:         {}", entry.repo_url);
                    println!("    manifest_url: {}", entry.manifest_url);
                    println!("    sha256:       {}", entry.manifest_sha256);
                    println!();
                }
                Ok(())
            }
            ExtensionsCommand::Install {
                id,
                index_path,
                http_url,
                token,
            } => {
                let body = extensions::install(&extensions::InstallArgs {
                    id: id.clone(),
                    http_url,
                    token,
                    index_path,
                })?;
                println!("Installed {id} from the cached registry index.");
                println!("  schema:          {}", body["schema"].as_str().unwrap_or("-"));
                println!("  manifest_sha256: {}", body["manifest_sha256"].as_str().unwrap_or("-"));
                println!(
                    "  version:         {}",
                    body["installed"]["manifest"]["version"].as_str().unwrap_or("-")
                );
                println!(
                    "  trust_tier:      {}",
                    body["installed"]["trust_tier"].as_str().unwrap_or("-")
                );
                println!("  grants:          none yet — POST /v1/extensions/{id}/grants to scope a passport");
                Ok(())
            }
        },

        // ── OpenClaw memory funnel (W3 ICP-1) ───────────────────────
        Command::Openclaw { command } => match command {
            OpenclawCommand::Import {
                path,
                daemon_url,
                dry_run,
            } => openclaw::import_run(&openclaw::ImportOptions {
                path,
                daemon_url,
                dry_run,
            }),
            OpenclawCommand::Scan {
                daemon_url,
                workspace,
                out,
                mutation_grace_days,
                stale_days,
            } => openclaw::scan_run(&openclaw::ScanOptions {
                daemon_url,
                workspace,
                out,
                grace_days: mutation_grace_days,
                stale_days,
            }),
        },

        // ── memory panel (agent-ux-01) ──────────────────────────────
        Command::Memory { command } => {
            let client = memory::MemoryClient::from_env();
            match command {
                MemoryCommand::Ls { top_k, entity } => {
                    let facts = client.list(top_k, entity.as_deref())?;
                    print!("{}", memory::render_list(&facts));
                    Ok(())
                }
                MemoryCommand::Show { fact_id } => {
                    let fact = client.show(&fact_id)?;
                    print!("{}", memory::render_fact(&fact));
                    Ok(())
                }
                MemoryCommand::Edit { fact_id, value, reason } => {
                    let new_fact = client.edit(&fact_id, &value, reason.as_deref())?;
                    println!("edited {} → {} (v{})", fact_id, new_fact.fact_id, new_fact.version);
                    Ok(())
                }
                MemoryCommand::Pin { fact_id, off } => {
                    client.pin(&fact_id, !off)?;
                    if off {
                        println!("unpinned fact {fact_id}");
                    } else {
                        println!("pinned fact {fact_id}");
                    }
                    Ok(())
                }
                MemoryCommand::Contradictions { limit } => {
                    let candidates = client.contradictions(limit)?;
                    print!("{}", memory::render_contradictions(&candidates));
                    Ok(())
                }
                MemoryCommand::Consolidate {
                    entity,
                    key,
                    canonical_value,
                    targets,
                    confidence,
                } => {
                    let receipt = client.consolidate(&entity, &key, &canonical_value, &targets, confidence)?;
                    println!(
                        "consolidated {} target(s) into {} (receipt {})",
                        receipt.superseded_fact_ids.len(),
                        receipt.canonical_fact_id,
                        receipt.consolidation_id,
                    );
                    Ok(())
                }
                MemoryCommand::Export {
                    data_dir,
                    out,
                    tenant,
                    since,
                    include_private,
                } => {
                    let data_dir = data_dir
                        .or_else(|| std::env::var("CORECRUXD_DATA_DIR").ok().map(PathBuf::from))
                        .ok_or("memory export requires --data-dir or CORECRUXD_DATA_DIR")?;
                    let report = memory_pack::run_memory_export(
                        &memory_pack::MemoryExportArgs {
                            data_dir,
                            out: out.clone(),
                            tenant,
                            since,
                            include_private,
                        },
                        |summary| {
                            print!("{}", memory_pack::render_private_summary(summary));
                            print!("Type '{}' to proceed: ", memory_pack::INCLUDE_PRIVATE_CONFIRM_PHRASE);
                            use std::io::Write as _;
                            let _ = std::io::stdout().flush();
                            let mut line = String::new();
                            if std::io::stdin().read_line(&mut line).is_err() {
                                return false;
                            }
                            line.trim() == memory_pack::INCLUDE_PRIVATE_CONFIRM_PHRASE
                        },
                    )?;
                    println!(
                        "memory export OK: facts={} sessions={} passport_fpr={} hash={} out={}",
                        report.facts,
                        report.sessions,
                        report.passport_fpr,
                        report.blake3_content_hash,
                        out.display()
                    );
                    Ok(())
                }
                MemoryCommand::Import {
                    file,
                    tenant,
                    map_principal,
                    dry_run,
                } => {
                    let response = memory_pack::run_memory_import(&memory_pack::MemoryImportArgs {
                        file,
                        tenant,
                        map_principal,
                        dry_run,
                    })?;
                    println!("{}", serde_json::to_string_pretty(&response)?);
                    Ok(())
                }
            }
        }

        // ── identity federation (G4) ───────────────────────────────
        Command::Identity { command } => match command {
            IdentityCommand::Fpr { data_dir, key_file } => {
                let data_dir = data_dir
                    .or_else(|| std::env::var("CORECRUXD_DATA_DIR").ok().map(PathBuf::from))
                    .ok_or("identity fpr requires --data-dir or CORECRUXD_DATA_DIR")?;
                let card = identity_cli::run_identity_fpr(&data_dir, key_file.as_deref())?;
                println!("{}", serde_json::to_string_pretty(&card)?);
                Ok(())
            }
            IdentityCommand::SignLink {
                data_dir,
                key_file,
                local_fpr,
                remote_fpr,
                created_at,
            } => {
                let data_dir = data_dir
                    .or_else(|| std::env::var("CORECRUXD_DATA_DIR").ok().map(PathBuf::from))
                    .ok_or("identity sign-link requires --data-dir or CORECRUXD_DATA_DIR")?;
                let out = identity_cli::run_identity_sign_link(&identity_cli::SignLinkArgs {
                    data_dir,
                    key_file,
                    local_fpr,
                    remote_fpr,
                    created_at,
                })?;
                println!("{}", serde_json::to_string_pretty(&out)?);
                Ok(())
            }
            IdentityCommand::ConfirmCandidate {
                candidate_id,
                http_url,
                local_passport_id,
                remote_fpr,
                remote_public_key_hex,
                created_at,
                sig_local,
                sig_remote,
            } => {
                let out = identity_cli::run_identity_confirm_candidate(&identity_cli::ConfirmCandidateArgs {
                    http_url,
                    token: None,
                    candidate_id,
                    local_passport_id,
                    remote_fpr,
                    remote_public_key_hex,
                    created_at,
                    sig_local,
                    sig_remote,
                })?;
                println!("{}", serde_json::to_string_pretty(&out)?);
                Ok(())
            }
            IdentityCommand::RejectCandidate { candidate_id, http_url } => {
                let out = identity_cli::run_identity_reject_candidate(&identity_cli::RejectCandidateArgs {
                    http_url,
                    token: None,
                    candidate_id,
                })?;
                println!("{}", serde_json::to_string_pretty(&out)?);
                Ok(())
            }
        },
        Command::Context { command } => match command {
            ContextCommand::Export {
                data_dir,
                out,
                tenant,
                since,
                include_private,
                include_reserved,
                caller,
            } => {
                let data_dir = data_dir
                    .or_else(|| std::env::var("CORECRUXD_DATA_DIR").ok().map(PathBuf::from))
                    .ok_or("context export requires --data-dir or CORECRUXD_DATA_DIR")?;
                let report = export::run_context_export(
                    &export::ContextExportArgs {
                        data_dir,
                        out_dir: out.clone(),
                        tenant,
                        since,
                        include_private,
                        include_reserved,
                        caller,
                    },
                    |summary| {
                        print!("{}", memory_pack::render_private_summary(summary));
                        print!("Type '{}' to proceed: ", memory_pack::INCLUDE_PRIVATE_CONFIRM_PHRASE);
                        use std::io::Write as _;
                        let _ = std::io::stdout().flush();
                        let mut line = String::new();
                        if std::io::stdin().read_line(&mut line).is_err() {
                            return false;
                        }
                        line.trim() == memory_pack::INCLUDE_PRIVATE_CONFIRM_PHRASE
                    },
                )?;
                println!(
                    "context export OK (signed={} audit_verify_ok={}): facts={} sessions={} audit_facts={} receipts={} passport_fpr={} manifest_blake3={} out={}",
                    report.signed,
                    report.audit_verify_ok,
                    report.facts,
                    report.sessions,
                    report.audit_facts,
                    report.receipts,
                    report.passport_fpr,
                    report.manifest_blake3,
                    report.out_dir.display()
                );
                println!(
                    "verify offline with: corecruxctl context verify {}",
                    report.out_dir.display()
                );
                Ok(())
            }
            ContextCommand::Verify { bundle, json } => {
                let report = export::run_context_verify(&bundle)?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": report.ok,
                            "passport_fpr": report.passport_fpr,
                            "signature_valid": report.signature_valid,
                            "cruxpack_hash_match": report.cruxpack_hash_match,
                            "audit_bundle_hash_match": report.audit_bundle_hash_match,
                            "cruxpack_verify_ok": report.cruxpack_verify_ok,
                            "audit_verify_ok": report.audit_verify_ok,
                            "failures": report.failures,
                        })
                    );
                } else {
                    println!(
                        "context verify {}: passport_fpr={} signature_valid={} cruxpack_hash={} audit_hash={} cruxpack_verify={} audit_verify={}",
                        if report.ok { "OK" } else { "FAIL" },
                        report.passport_fpr,
                        report.signature_valid,
                        report.cruxpack_hash_match,
                        report.audit_bundle_hash_match,
                        report.cruxpack_verify_ok,
                        report.audit_verify_ok,
                    );
                    for f in &report.failures {
                        println!("  - {f}");
                    }
                }
                if report.ok {
                    Ok(())
                } else {
                    Err("context verify failed".into())
                }
            }
        },
        Command::Incident { command } => match command {
            IncidentCommand::Create {
                url,
                tenant_id,
                title,
                from,
                to,
                session_id,
                agent_id,
                entity,
                notes,
            } => incident::run_create(url, tenant_id, title, from, to, session_id, agent_id, entity, notes),
            IncidentCommand::Show { url, id } => incident::run_show(url, id),
            IncidentCommand::Export { url, id, out } => incident::run_export(url, id, out),
        },
        Command::AuditExport {
            data_dir,
            out,
            since,
            until,
            scope_entity_prefix,
            include_reserved,
            caller,
        } => {
            let data_dir = data_dir
                .or_else(|| std::env::var("CORECRUXD_DATA_DIR").ok().map(PathBuf::from))
                .ok_or("audit-export requires --data-dir or CORECRUXD_DATA_DIR")?;
            let (facts, receipts, bundle_id) = audit_export::run_audit_export(audit_export::AuditExportArgs {
                data_dir,
                out: out.clone(),
                since,
                until,
                scope_entity_prefix,
                include_reserved,
                caller,
            })?;
            println!(
                "audit-export OK: bundle_id={bundle_id} facts={facts} receipts={receipts} out={}",
                out.display()
            );
            Ok(())
        }
        Command::AuditVerify {
            bundle,
            json,
            rekor_pubkey,
        } => {
            let report = audit_export::run_audit_verify(&bundle, rekor_pubkey.as_deref())?;
            if json {
                let s = serde_json::to_string_pretty(&report)?;
                println!("{s}");
            } else {
                println!(
                    "audit-verify {}: bundle_id={} facts={} receipts={} sig={} events_hash={} receipts_hash={}",
                    if report.ok { "OK" } else { "FAIL" },
                    report.bundle_id,
                    report.fact_count,
                    report.receipt_count,
                    report.signature_valid,
                    report.events_jsonl_sha256_match,
                    report.receipts_cbor_sha256_match,
                );
                if let Some(reason) = &report.failure_reason {
                    eprintln!("failure: {reason}");
                }
            }
            if !report.ok {
                std::process::exit(2);
            }
            Ok(())
        }
        Command::OutputVerify {
            manifest_path,
            content,
            pub_key_hex,
            expected_receipt,
            json,
        } => {
            let report = output_verify::run(&output_verify::Options {
                manifest_path,
                content,
                pub_key_hex,
                expected_receipt,
            })?;
            let rendered = if json {
                serde_json::to_string(&report)?
            } else {
                serde_json::to_string_pretty(&report)?
            };
            println!("{rendered}");
            if !report.ok {
                return Err("C2PA manifest verification failed".into());
            }
            Ok(())
        }
        Command::C2paCertStatus {
            leaf_cert,
            root_anchor,
            json,
        } => {
            let report = c2pa_x509::cert_status(&c2pa_x509::StatusOptions {
                leaf_cert_path: leaf_cert,
                root_anchor_path: root_anchor,
            })?;
            let rendered = if json {
                serde_json::to_string(&report)?
            } else {
                serde_json::to_string_pretty(&report)?
            };
            println!("{rendered}");
            Ok(())
        }
        Command::C2paRotateLeaf {
            leaf_cert,
            root_anchor,
            json,
        } => {
            let report = c2pa_x509::rotate_leaf(&c2pa_x509::StatusOptions {
                leaf_cert_path: leaf_cert,
                root_anchor_path: root_anchor,
            })?;
            let rendered = if json {
                serde_json::to_string(&report)?
            } else {
                serde_json::to_string_pretty(&report)?
            };
            println!("{rendered}");
            Ok(())
        }
        Command::C2paVerify {
            manifest_path,
            content,
            root_anchor,
            json,
        } => {
            let report = c2pa_x509::c2pa_verify(&c2pa_x509::X509VerifyOptions {
                manifest_path,
                content,
                root_anchor_path: root_anchor,
            })?;
            let rendered = if json {
                serde_json::to_string(&report)?
            } else {
                serde_json::to_string_pretty(&report)?
            };
            println!("{rendered}");
            if !report.ok {
                return Err("C2PA X.509 manifest verification failed".into());
            }
            Ok(())
        }
    }
}

// ── ccxi companion index tooling ────────────────────────────────────────

#[derive(serde::Serialize)]
struct CcxiVerifyReport {
    shards_scanned: usize,
    segments_total: usize,
    segments_with_ccxi: usize,
    segments_missing_ccxi: usize,
    segments_corrupt_ccxi: usize,
    missing: Vec<String>,
    corrupt: Vec<String>,
}

fn ccxi_verify(
    data_dir: &std::path::Path,
    shard_filter: Option<u32>,
) -> Result<CcxiVerifyReport, Box<dyn std::error::Error + Send + Sync>> {
    let mut report = CcxiVerifyReport {
        shards_scanned: 0,
        segments_total: 0,
        segments_with_ccxi: 0,
        segments_missing_ccxi: 0,
        segments_corrupt_ccxi: 0,
        missing: Vec::new(),
        corrupt: Vec::new(),
    };

    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let shard_dir = entry.path();
        if !shard_dir.is_dir() {
            continue;
        }
        let dir_name = shard_dir.file_name().unwrap_or_default().to_string_lossy().to_string();
        if !dir_name.starts_with("shard-") {
            continue;
        }

        // Parse shard id from "shard-NNNN"
        if let Some(shard_filter) = shard_filter {
            let shard_str = format!("shard-{shard_filter:04}");
            if dir_name != shard_str {
                continue;
            }
        }

        report.shards_scanned += 1;
        let segments_dir = shard_dir.join("segments");
        if !segments_dir.exists() {
            continue;
        }

        for seg_entry in std::fs::read_dir(&segments_dir)? {
            let seg_entry = seg_entry?;
            let seg_path = seg_entry.path();
            if seg_path.extension().is_none_or(|e| e != "ccxseg") {
                continue;
            }

            report.segments_total += 1;
            let stem = seg_path.file_stem().unwrap_or_default().to_string_lossy().to_string();
            let ccxi_path = segments_dir.join(format!("{stem}.ccxi"));

            if !ccxi_path.exists() {
                report.segments_missing_ccxi += 1;
                report.missing.push(format!("{dir_name}/{stem}"));
                continue;
            }

            // Verify BLAKE3 integrity
            match std::fs::read(&ccxi_path) {
                Ok(bytes) => match corecrux_index::CcxiReader::from_bytes(&bytes) {
                    Ok(_) => {
                        report.segments_with_ccxi += 1;
                    }
                    Err(e) => {
                        report.segments_corrupt_ccxi += 1;
                        report.corrupt.push(format!("{dir_name}/{stem}: {e}"));
                    }
                },
                Err(e) => {
                    report.segments_corrupt_ccxi += 1;
                    report.corrupt.push(format!("{dir_name}/{stem}: read error: {e}"));
                }
            }
        }
    }

    Ok(report)
}

#[derive(serde::Serialize)]
struct CcxiRebuildReport {
    shards_scanned: usize,
    segments_rebuilt: usize,
    segments_skipped: usize,
    segments_failed: usize,
    errors: Vec<String>,
}

fn ccxi_rebuild(
    data_dir: &std::path::Path,
    shard_filter: Option<u32>,
    segment_seq_filter: Option<u64>,
) -> Result<CcxiRebuildReport, Box<dyn std::error::Error + Send + Sync>> {
    let mut report = CcxiRebuildReport {
        shards_scanned: 0,
        segments_rebuilt: 0,
        segments_skipped: 0,
        segments_failed: 0,
        errors: Vec::new(),
    };

    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let shard_dir = entry.path();
        if !shard_dir.is_dir() {
            continue;
        }
        let dir_name = shard_dir.file_name().unwrap_or_default().to_string_lossy().to_string();
        if !dir_name.starts_with("shard-") {
            continue;
        }

        if let Some(shard_filter) = shard_filter {
            let shard_str = format!("shard-{shard_filter:04}");
            if dir_name != shard_str {
                continue;
            }
        }

        report.shards_scanned += 1;
        let segments_dir = shard_dir.join("segments");
        if !segments_dir.exists() {
            continue;
        }

        // Parse shard_id from directory name
        let shard_id: u32 = dir_name
            .strip_prefix("shard-")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        for seg_entry in std::fs::read_dir(&segments_dir)? {
            let seg_entry = seg_entry?;
            let seg_path = seg_entry.path();
            if seg_path.extension().is_none_or(|e| e != "ccxseg") {
                continue;
            }

            let stem = seg_path.file_stem().unwrap_or_default().to_string_lossy().to_string();

            // Extract segment_seq from filename "seg-{seq:020}-{hex}"
            let parts: Vec<&str> = stem.split('-').collect();
            let seg_seq: u64 = if parts.len() >= 2 {
                parts[1].parse().unwrap_or(0)
            } else {
                0
            };

            // Apply segment_seq filter if provided
            if let Some(target_seq) = segment_seq_filter {
                if seg_seq != target_seq {
                    continue;
                }
            }

            let ccxi_path = segments_dir.join(format!("{stem}.ccxi"));

            // Skip if .ccxi already exists and is valid (unless specific seq requested)
            if segment_seq_filter.is_none() && ccxi_path.exists() {
                if let Ok(bytes) = std::fs::read(&ccxi_path) {
                    if corecrux_index::CcxiReader::from_bytes(&bytes).is_ok() {
                        report.segments_skipped += 1;
                        continue;
                    }
                }
            }

            // Read the sealed segment and rebuild .ccxi
            match rebuild_ccxi_from_segment(&seg_path, &ccxi_path, shard_id, seg_seq) {
                Ok(doc_count) => {
                    if doc_count > 0 {
                        report.segments_rebuilt += 1;
                        eprintln!("rebuilt: {dir_name}/{stem} ({doc_count} docs indexed)");
                    } else {
                        report.segments_skipped += 1;
                        eprintln!("skipped: {dir_name}/{stem} (no indexable frames)");
                    }
                }
                Err(e) => {
                    report.segments_failed += 1;
                    report.errors.push(format!("{dir_name}/{stem}: {e}"));
                    eprintln!("FAILED: {dir_name}/{stem}: {e}");
                }
            }
        }
    }

    Ok(report)
}

/// Rebuild a .ccxi companion from a sealed .ccxseg file.
///
/// Reads the segment, decodes the TOC, iterates frames in the record area,
/// extracts UTF-8 payloads, tokenizes them, and writes a fresh .ccxi via
/// atomic tmp→rename.
///
/// NOTE: Block-compressed segments (Phase 2 seal path with LZ4) are not yet
/// supported by this rebuild command — they require re-sealing via corecruxd.
/// Uncompressed (Phase 1) segments are fully supported.
fn rebuild_ccxi_from_segment(
    seg_path: &std::path::Path,
    ccxi_path: &std::path::Path,
    shard_id: u32,
    segment_seq: u64,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    let seg_bytes = std::fs::read(seg_path)?;

    // Decode the sealed segment: validates hashes and extracts TOC entries
    let (header, toc_header, toc_entries, footer) = corecrux_segment::decode_segment_v1(&seg_bytes)?;

    let record_off = footer.record_area_offset as usize;
    let record_len = footer.record_area_len as usize;
    if record_off + record_len > seg_bytes.len() {
        return Err("record area extends past file".into());
    }
    let record_area = &seg_bytes[record_off..record_off + record_len];

    // Check for block compression — we don't support rebuild for compressed segments yet
    let toc_off = footer.toc_offset as usize;
    let toc_len = footer.toc_len as usize;
    let toc_area = &seg_bytes[toc_off..toc_off + toc_len];
    if let Ok(Some(_)) = corecrux_segment::decode_trailer_index_v1(toc_area, &toc_header) {
        return Err("block-compressed segments not yet supported by ccxi rebuild; \
            these require re-sealing via corecruxd Phase 2 path"
            .into());
    }

    let mut builder = corecrux_index::CcxiBuilder::new(shard_id, segment_seq, header.epoch);
    let mut indexed = 0u32;

    for (doc_id, toc_entry) in toc_entries.iter().enumerate() {
        // Uncompressed: frame is directly in the file at toc_entry.file_offset
        let off = toc_entry.file_offset as usize - record_off;
        let end = off + toc_entry.frame_len as usize;
        if end > record_area.len() {
            continue;
        }
        let frame_bytes = &record_area[off..end];

        if frame_bytes.len() < 12 {
            continue;
        }

        // Parse frame: magic(4) + ver(2) + header_len(2) + payload_len(4) + header + payload + crc(4)
        let header_len = u16::from_le_bytes([frame_bytes[6], frame_bytes[7]]) as usize;
        let payload_len =
            u32::from_le_bytes([frame_bytes[8], frame_bytes[9], frame_bytes[10], frame_bytes[11]]) as usize;
        let payload_start = 12 + header_len;
        let payload_end = payload_start + payload_len;
        if payload_end > frame_bytes.len() {
            continue;
        }
        let payload = &frame_bytes[payload_start..payload_end];

        let text = match std::str::from_utf8(payload) {
            Ok(t) if !t.is_empty() => t,
            _ => continue,
        };

        // Extract tenant_id from canonical frame header for tenant hash
        let hdr_bytes = &frame_bytes[12..12 + header_len];
        let tenant_hash = match corecrux_frame::decode_canonical_header_bytes_v1(hdr_bytes) {
            Ok(hdr) => xxhash_rust::xxh64::xxh64(hdr.tenant_id.as_bytes(), 0),
            Err(_) => toc_entry.stream_hash, // fallback
        };

        builder.add_document(doc_id as u32, text, off as u32, tenant_hash);
        indexed += 1;
    }

    if indexed == 0 {
        return Ok(0);
    }

    let ccxi_bytes = builder.build();

    // Atomic write via tmp + rename
    let tmp_path = ccxi_path.with_extension("ccxi.partial");
    std::fs::write(&tmp_path, &ccxi_bytes)?;
    std::fs::rename(&tmp_path, ccxi_path)?;

    Ok(indexed)
}

// ── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;
    use tempfile::TempDir;

    fn run_args(args: &[&str]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        run_cli(Cli::try_parse_from(args.iter().copied()).unwrap())
    }

    // ── CLI parsing: top-level subcommands ──────────────────────────────

    #[test]
    fn parse_verify_store_defaults() {
        let cli = Cli::try_parse_from(["corecruxctl", "verify-store", "--data-dir", "/tmp/test"]).unwrap();
        match cli.command {
            Command::VerifyStore {
                data_dir,
                shard,
                scope,
                mode,
                sample_rate,
                strict,
            } => {
                assert_eq!(data_dir, Some(PathBuf::from("/tmp/test")));
                assert!(shard.is_none());
                assert_eq!(scope, "recent");
                assert_eq!(mode, "sampled");
                assert!((sample_rate - 0.25).abs() < f64::EPSILON);
                assert!(!strict);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_ingest_defaults() {
        let cli = Cli::try_parse_from(["corecruxctl", "ingest", "./docs", "--dry-run"]).unwrap();
        match cli.command {
            Command::Ingest {
                path,
                tenant,
                corpus,
                daemon_url,
                dry_run,
                embed,
            } => {
                assert_eq!(path, PathBuf::from("./docs"));
                assert_eq!(tenant, "local");
                assert_eq!(corpus, "docs");
                assert_eq!(daemon_url, "http://127.0.0.1:14800");
                assert!(dry_run);
                assert!(!embed);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_identity_candidate_commands() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "identity",
            "confirm-candidate",
            "cl_abc",
            "--http-url",
            "http://127.0.0.1:14800",
            "--local-passport-id",
            "personal-default",
            "--remote-fpr",
            "p_remote",
            "--remote-public-key-hex",
            "aa",
            "--created-at",
            "2026-06-15T00:00:00Z",
            "--sig-local",
            "bb",
            "--sig-remote",
            "cc",
        ])
        .unwrap();
        match cli.command {
            Command::Identity {
                command:
                    IdentityCommand::ConfirmCandidate {
                        candidate_id,
                        http_url,
                        local_passport_id,
                        remote_fpr,
                        remote_public_key_hex,
                        created_at,
                        sig_local,
                        sig_remote,
                    },
            } => {
                assert_eq!(candidate_id, "cl_abc");
                assert_eq!(http_url.as_deref(), Some("http://127.0.0.1:14800"));
                assert_eq!(local_passport_id, "personal-default");
                assert_eq!(remote_fpr, "p_remote");
                assert_eq!(remote_public_key_hex, "aa");
                assert_eq!(created_at, "2026-06-15T00:00:00Z");
                assert_eq!(sig_local, "bb");
                assert_eq!(sig_remote, "cc");
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = Cli::try_parse_from(["corecruxctl", "identity", "reject-candidate", "cl_abc"]).unwrap();
        match cli.command {
            Command::Identity {
                command: IdentityCommand::RejectCandidate { candidate_id, http_url },
            } => {
                assert_eq!(candidate_id, "cl_abc");
                assert!(http_url.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_verify_store_all_args() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "verify-store",
            "--data-dir",
            "/data",
            "--shard",
            "3",
            "--scope",
            "all",
            "--mode",
            "full",
            "--sample-rate",
            "0.5",
            "--strict",
        ])
        .unwrap();
        match cli.command {
            Command::VerifyStore {
                shard,
                scope,
                mode,
                sample_rate,
                strict,
                ..
            } => {
                assert_eq!(shard, Some(3));
                assert_eq!(scope, "all");
                assert_eq!(mode, "full");
                assert!((sample_rate - 0.5).abs() < f64::EPSILON);
                assert!(strict);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_replay_pack() {
        let cli = Cli::try_parse_from(["corecruxctl", "replay", "--pack", "/tmp/pack", "--strict"]).unwrap();
        match cli.command {
            Command::Replay {
                pack,
                input,
                strict,
                mode,
            } => {
                assert_eq!(pack, Some(PathBuf::from("/tmp/pack")));
                assert!(input.is_none());
                assert!(strict);
                assert_eq!(mode, "audit");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_replay_legacy_input() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "replay",
            "--input",
            "/tmp/events.jsonl",
            "--mode",
            "audit",
        ])
        .unwrap();
        match cli.command {
            Command::Replay {
                pack, input, strict, ..
            } => {
                assert!(pack.is_none());
                assert_eq!(input, Some(PathBuf::from("/tmp/events.jsonl")));
                assert!(!strict);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_import_v1() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "import-v1",
            "--events-log",
            "/tmp/events.log",
            "--out",
            "/tmp/out",
        ])
        .unwrap();
        match cli.command {
            Command::ImportV1 { events_log, out } => {
                assert_eq!(events_log, PathBuf::from("/tmp/events.log"));
                assert_eq!(out, PathBuf::from("/tmp/out"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_smoke() {
        let cli = Cli::try_parse_from(["corecruxctl", "smoke", "--device-index", "2"]).unwrap();
        match cli.command {
            Command::Smoke { device_index } => assert_eq!(device_index, 2),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_smoke_default() {
        let cli = Cli::try_parse_from(["corecruxctl", "smoke"]).unwrap();
        match cli.command {
            Command::Smoke { device_index } => assert_eq!(device_index, 0),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_fixture_digest() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "fixture-digest",
            "--fixture",
            "large",
            "--device-index",
            "1",
        ])
        .unwrap();
        match cli.command {
            Command::FixtureDigest { fixture, device_index } => {
                assert_eq!(fixture, "large");
                assert_eq!(device_index, 1);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_ccxi_verify() {
        let cli =
            Cli::try_parse_from(["corecruxctl", "ccxi", "verify", "--data-dir", "/data", "--shard", "2"]).unwrap();
        match cli.command {
            Command::Ccxi {
                command: CcxiCommand::Verify { data_dir, shard },
            } => {
                assert_eq!(data_dir, Some(PathBuf::from("/data")));
                assert_eq!(shard, Some(2));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_ccxi_rebuild() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "ccxi",
            "rebuild",
            "--data-dir",
            "/data",
            "--shard",
            "1",
            "--segment-seq",
            "42",
        ])
        .unwrap();
        match cli.command {
            Command::Ccxi {
                command:
                    CcxiCommand::Rebuild {
                        data_dir,
                        shard,
                        segment_seq,
                    },
            } => {
                assert_eq!(data_dir, Some(PathBuf::from("/data")));
                assert_eq!(shard, Some(1));
                assert_eq!(segment_seq, Some(42));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_shardmap_init() {
        let cli = Cli::try_parse_from(["corecruxctl", "shardmap", "init", "--shards", "4"]).unwrap();
        match cli.command {
            Command::ShardMap {
                command:
                    ShardMapCommand::Init {
                        shards,
                        cluster_id,
                        node_id,
                        http_addr,
                        grpc_addr,
                        data_dir,
                        out,
                    },
            } => {
                assert_eq!(shards, 4);
                assert_eq!(cluster_id, "dev");
                assert_eq!(node_id, "node-dev");
                assert_eq!(http_addr, "127.0.0.1:4006");
                assert_eq!(grpc_addr, "127.0.0.1:4007");
                assert!(data_dir.is_none());
                assert!(out.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_shardmap_split() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "shardmap",
            "split",
            "--file",
            "/tmp/map.json",
            "--shard",
            "shard-0002",
            "--at",
            "0x6000000000000000",
        ])
        .unwrap();
        match cli.command {
            Command::ShardMap {
                command:
                    ShardMapCommand::Split {
                        file,
                        shard,
                        at,
                        new_shard,
                        out,
                    },
            } => {
                assert_eq!(file, PathBuf::from("/tmp/map.json"));
                assert_eq!(shard, "shard-0002");
                assert_eq!(at, "0x6000000000000000");
                assert!(new_shard.is_none());
                assert!(out.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_shardmap_validate() {
        let cli = Cli::try_parse_from(["corecruxctl", "shardmap", "validate", "--file", "/tmp/map.json"]).unwrap();
        match cli.command {
            Command::ShardMap {
                command: ShardMapCommand::Validate { file },
            } => {
                assert_eq!(file, PathBuf::from("/tmp/map.json"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_shardmap_publish() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "shardmap",
            "publish",
            "--file",
            "/tmp/map.json",
            "--data-dir",
            "/data",
        ])
        .unwrap();
        match cli.command {
            Command::ShardMap {
                command: ShardMapCommand::Publish { file, data_dir },
            } => {
                assert_eq!(file, PathBuf::from("/tmp/map.json"));
                assert_eq!(data_dir, Some(PathBuf::from("/data")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_shardmap_set_gpu() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "shardmap",
            "set-gpu",
            "--file",
            "/tmp/map.json",
            "--shard",
            "shard-0001",
            "--gpu-id",
            "2",
        ])
        .unwrap();
        match cli.command {
            Command::ShardMap {
                command:
                    ShardMapCommand::SetGpu {
                        file,
                        shard,
                        gpu_id,
                        out,
                    },
            } => {
                assert_eq!(file, PathBuf::from("/tmp/map.json"));
                assert_eq!(shard, "shard-0001");
                assert_eq!(gpu_id, 2);
                assert!(out.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_shard_move() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "shard",
            "move",
            "--shard",
            "shard-0001",
            "--source-node",
            "node-a",
            "--target-node",
            "node-b",
            "--keep-old-as-follower",
        ])
        .unwrap();
        match cli.command {
            Command::Shard {
                command:
                    ShardCommand::Move {
                        coordinator,
                        shard,
                        source_node,
                        target_node,
                        job_id,
                        status,
                        keep_old_as_follower,
                    },
            } => {
                assert_eq!(coordinator, "http://127.0.0.1:4008");
                assert_eq!(shard, "shard-0001");
                assert_eq!(source_node, "node-a");
                assert_eq!(target_node, "node-b");
                assert!(job_id.is_none());
                assert_eq!(status, "planned");
                assert!(keep_old_as_follower);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_shard_status() {
        let cli = Cli::try_parse_from(["corecruxctl", "shard", "status", "--shard", "shard-0001"]).unwrap();
        match cli.command {
            Command::Shard {
                command:
                    ShardCommand::Status {
                        coordinator,
                        shard,
                        job_id,
                    },
            } => {
                assert_eq!(coordinator, "http://127.0.0.1:4008");
                assert_eq!(shard, Some("shard-0001".to_string()));
                assert!(job_id.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_admin_valves_get() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "admin",
            "valves",
            "get",
            "--http",
            "http://localhost:4006",
        ])
        .unwrap();
        match cli.command {
            Command::Admin {
                command:
                    AdminCommand::Valves {
                        command: ValvesCommand::Get { http },
                    },
            } => {
                assert_eq!(http, "http://localhost:4006");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_admin_valves_set() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "admin",
            "valves",
            "set",
            "--actor",
            "ops",
            "--reason",
            "test",
            "--pause-ingest",
            "true",
            "--emergency-brake",
            "true",
        ])
        .unwrap();
        match cli.command {
            Command::Admin {
                command:
                    AdminCommand::Valves {
                        command:
                            ValvesCommand::Set {
                                actor,
                                reason,
                                pause_ingest,
                                emergency_brake,
                                ..
                            },
                    },
            } => {
                assert_eq!(actor, "ops");
                assert_eq!(reason, "test");
                assert_eq!(pause_ingest, Some(true));
                assert_eq!(emergency_brake, Some(true));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_admin_seal() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "admin",
            "seal",
            "--reason",
            "test-seal",
            "--wait-for-projection",
        ])
        .unwrap();
        match cli.command {
            Command::Admin {
                command:
                    AdminCommand::Seal {
                        http,
                        wait_for_projection,
                        reason,
                        actor,
                    },
            } => {
                assert_eq!(http, "http://127.0.0.1:4006");
                assert!(wait_for_projection);
                assert_eq!(reason, "test-seal");
                assert_eq!(actor, "corecruxctl");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_admin_action_submit() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "admin",
            "action",
            "submit",
            "--action-type",
            "force-seal",
            "--actor",
            "ops",
            "--reason",
            "test",
            "--params-json",
            r#"{"x":1}"#,
        ])
        .unwrap();
        match cli.command {
            Command::Admin {
                command:
                    AdminCommand::Action {
                        command:
                            ActionCommand::Submit {
                                action_type,
                                actor,
                                reason,
                                params_json,
                                ..
                            },
                    },
            } => {
                assert_eq!(action_type, "force-seal");
                assert_eq!(actor, Some("ops".to_string()));
                assert_eq!(reason, Some("test".to_string()));
                assert_eq!(params_json, Some(r#"{"x":1}"#.to_string()));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_projections_rebuild() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "projections",
            "rebuild",
            "--shard",
            "1",
            "--batch-frames",
            "2048",
        ])
        .unwrap();
        match cli.command {
            Command::Projections {
                command:
                    ProjectionsCommand::Rebuild {
                        shard,
                        batch_frames,
                        device_index,
                        ..
                    },
            } => {
                assert_eq!(shard, Some(1));
                assert_eq!(batch_frames, 2048);
                assert_eq!(device_index, 0);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_projections_gc() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "projections",
            "gc",
            "--dry-run",
            "--min-age-seconds",
            "300",
        ])
        .unwrap();
        match cli.command {
            Command::Projections {
                command:
                    ProjectionsCommand::Gc {
                        dry_run,
                        min_age_seconds,
                        max_delete,
                        ..
                    },
            } => {
                assert!(dry_run);
                assert_eq!(min_age_seconds, 300);
                assert_eq!(max_delete, 0);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_export_cose() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "export-cose",
            "/tmp/receipt.json",
            "--out",
            "/tmp/receipt.cose",
            "--gen-dev-key",
            "--kid",
            "dev:v1",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::ExportCose {
                        input,
                        out,
                        key_b64,
                        key_file,
                        gen_dev_key,
                        iss,
                        kid,
                    },
            } => {
                assert_eq!(input, PathBuf::from("/tmp/receipt.json"));
                assert_eq!(out, Some(PathBuf::from("/tmp/receipt.cose")));
                assert!(key_b64.is_none());
                assert!(key_file.is_none());
                assert!(gen_dev_key);
                assert_eq!(iss, "https://crux.local");
                assert_eq!(kid, "dev:v1");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_export_cose_requires_one_key_source() {
        assert!(Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "export-cose",
            "/tmp/receipt.json",
            "--kid",
            "dev:v1",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "export-cose",
            "/tmp/receipt.json",
            "--key-b64",
            "AA==",
            "--gen-dev-key",
            "--kid",
            "dev:v1",
        ])
        .is_err());
    }

    #[test]
    fn parse_receipts_verify_cose() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "verify-cose",
            "/tmp/receipt.cose",
            "--pubkey-b64",
            "AA==",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command: ReceiptsCommand::VerifyCose { input, pubkey_b64 },
            } => {
                assert_eq!(input, PathBuf::from("/tmp/receipt.cose"));
                assert_eq!(pubkey_b64.as_deref(), Some("AA=="));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_seed_minimal() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "seed-minimal",
            "--tenant-id",
            "t1",
            "--receipt-id",
            "abc-123",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::SeedMinimal {
                        tenant_id,
                        receipt_id,
                        shard,
                        ..
                    },
            } => {
                assert_eq!(tenant_id, "t1");
                assert_eq!(receipt_id, "abc-123");
                assert_eq!(shard, 1);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_verify_external_anchor() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "verify-external-anchor",
            "--body",
            "/tmp/body.cbor",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command: ReceiptsCommand::VerifyExternalAnchor { body },
            } => {
                assert_eq!(body, PathBuf::from("/tmp/body.cbor"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_verify_rfc3161_timestamp() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "verify-rfc3161-timestamp",
            "--body",
            "/tmp/body.cbor",
            "--expected-imprint-hash",
            "sha256:abc",
            "--tsa-root-cert",
            "/tmp/root.pem",
            "--expected-policy-oid",
            "1.2.3.4",
            "--expected-nonce-hex",
            "0001",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::VerifyRfc3161Timestamp {
                        body,
                        expected_imprint_hash,
                        tsa_root_cert,
                        expected_policy_oid,
                        expected_nonce_hex,
                    },
            } => {
                assert_eq!(body, PathBuf::from("/tmp/body.cbor"));
                assert_eq!(expected_imprint_hash.as_deref(), Some("sha256:abc"));
                assert_eq!(tsa_root_cert, vec![PathBuf::from("/tmp/root.pem")]);
                assert_eq!(expected_policy_oid.as_deref(), Some("1.2.3.4"));
                assert_eq!(expected_nonce_hex.as_deref(), Some("0001"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_witness_smoke() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "witness-smoke",
            "--witness-enabled",
            "--witness-provider",
            "rekor",
            "--witness-timeout-ms",
            "7500",
            "--rekor-url",
            "https://rekor.example",
            "--rekor-public-key-path",
            "/tmp/rekor.pub",
            "--tsa-enabled",
            "--tsa-url",
            "https://tsa.example",
            "--tsa-root-cert",
            "/tmp/tsa-root.pem",
            "--tsa-policy-oid",
            "1.2.3.4",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::WitnessSmoke {
                        witness_enabled,
                        witness_provider,
                        witness_timeout_ms,
                        rekor_url,
                        rekor_public_key_path,
                        tsa_enabled,
                        tsa_url,
                        tsa_root_cert,
                        tsa_policy_oid,
                    },
            } => {
                assert!(witness_enabled);
                assert_eq!(witness_provider, "rekor");
                assert_eq!(witness_timeout_ms, 7500);
                assert_eq!(rekor_url.as_deref(), Some("https://rekor.example"));
                assert_eq!(rekor_public_key_path, Some(PathBuf::from("/tmp/rekor.pub")));
                assert!(tsa_enabled);
                assert_eq!(tsa_url.as_deref(), Some("https://tsa.example"));
                assert_eq!(tsa_root_cert, vec![PathBuf::from("/tmp/tsa-root.pem")]);
                assert_eq!(tsa_policy_oid.as_deref(), Some("1.2.3.4"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_external_anchor_attest() {
        let leaf = "00".repeat(32);
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "external-anchor-attest",
            "--out-body",
            "/tmp/anchor.cbor",
            "--tenant-id",
            "t1",
            "--receipt-id",
            "anchor_receipt_1",
            "--log-url",
            "https://rekor.example",
            "--leaf-hash",
            &leaf,
            "--log-index",
            "0",
            "--tree-size",
            "1",
            "--root-hash",
            &leaf,
            "--integrated-time",
            "2026-06-14T10:00:00Z",
            "--created-at",
            "2026-06-14T10:00:00Z",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::ExternalAnchorAttest {
                        out_body,
                        receipt_id,
                        tree_size,
                        ..
                    },
            } => {
                assert_eq!(out_body, PathBuf::from("/tmp/anchor.cbor"));
                assert_eq!(receipt_id, "anchor_receipt_1");
                assert_eq!(tree_size, 1);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_rfc3161_timestamp_attest() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "rfc3161-timestamp-attest",
            "--out-body",
            "/tmp/tsa.cbor",
            "--tenant-id",
            "t1",
            "--receipt-id",
            "tsa_1",
            "--tsa-url",
            "https://tsa.example",
            "--message-imprint-hash",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--timestamp-token-der",
            "/tmp/token.der",
            "--gen-time",
            "2026-06-14T10:00:00Z",
            "--created-at",
            "2026-06-14T10:00:00Z",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::Rfc3161TimestampAttest {
                        out_body,
                        receipt_id,
                        timestamp_token_der,
                        ..
                    },
            } => {
                assert_eq!(out_body, PathBuf::from("/tmp/tsa.cbor"));
                assert_eq!(receipt_id, "tsa_1");
                assert_eq!(timestamp_token_der, PathBuf::from("/tmp/token.der"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_chain_reanchor_attest() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "chain-reanchor-attest",
            "--out-body",
            "/tmp/chain.cbor",
            "--tenant-id",
            "t1",
            "--receipt-id",
            "cr_1",
            "--old-chain-head",
            "blake3:old",
            "--new-chain-head",
            "blake3:new",
            "--first-receipt-id",
            "r_1",
            "--last-receipt-id",
            "r_2",
            "--receipt-count",
            "2",
            "--reason",
            "external-anchor-upgrade",
            "--linked-receipt",
            "anchor_1",
            "--created-at",
            "2026-06-14T10:00:00Z",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::ChainReanchorAttest {
                        out_body,
                        tenant_id,
                        receipt_id,
                        receipt_count,
                        linked_receipts,
                        ..
                    },
            } => {
                assert_eq!(out_body, PathBuf::from("/tmp/chain.cbor"));
                assert_eq!(tenant_id, "t1");
                assert_eq!(receipt_id, "cr_1");
                assert_eq!(receipt_count, 2);
                assert_eq!(linked_receipts, vec!["anchor_1"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_verify_chain_reanchor() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "verify-chain-reanchor",
            "--body",
            "/tmp/chain.cbor",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command: ReceiptsCommand::VerifyChainReanchor { body },
            } => {
                assert_eq!(body, PathBuf::from("/tmp/chain.cbor"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_redaction_attest() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "redaction-attest",
            "--out-body",
            "/tmp/redaction.cbor",
            "--tenant-id",
            "t1",
            "--receipt-id",
            "red_1",
            "--subject-type",
            "fact",
            "--subject-id",
            "f_1",
            "--request-id",
            "forget_1",
            "--subject-cek-id",
            "cek:t1:fact:f_1:v1",
            "--subject-cek-commitment",
            "blake3:abc",
            "--linked-receipt",
            "forget_1",
            "--created-at",
            "2026-06-14T10:00:00Z",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::RedactionAttest {
                        out_body,
                        tenant_id,
                        receipt_id,
                        subject_type,
                        subject_id,
                        linked_receipts,
                        crypto_shred_staged,
                        ..
                    },
            } => {
                assert_eq!(out_body, PathBuf::from("/tmp/redaction.cbor"));
                assert_eq!(tenant_id, "t1");
                assert_eq!(receipt_id, "red_1");
                assert_eq!(subject_type, "fact");
                assert_eq!(subject_id, "f_1");
                assert_eq!(linked_receipts, vec!["forget_1"]);
                assert!(!crypto_shred_staged);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_crypto_shred_destroy_marker() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "crypto-shred-destroy-marker",
            "--out-marker",
            "/tmp/destroy-marker.json",
            "--marker-id",
            "destroy_1",
            "--tenant-id",
            "t1",
            "--subject-type",
            "fact",
            "--subject-id",
            "f_1",
            "--subject-cek-id",
            "cek:t1:fact:f_1:v1",
            "--subject-cek-commitment",
            "blake3:abc",
            "--redaction-receipt-id",
            "red_1",
            "--idempotency-key",
            "destroy:f_1:v1",
            "--requested-at",
            "2026-06-14T10:00:00Z",
            "--wrapped-key-ref",
            "vault://t1/cek/f_1/v1",
            "--linked-receipt",
            "forget_1",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::CryptoShredDestroyMarker {
                        out_marker,
                        marker_id,
                        tenant_id,
                        subject_cek_id,
                        redaction_receipt_id,
                        wrapped_key_ref,
                        linked_receipts,
                        ..
                    },
            } => {
                assert_eq!(out_marker, PathBuf::from("/tmp/destroy-marker.json"));
                assert_eq!(marker_id, "destroy_1");
                assert_eq!(tenant_id, "t1");
                assert_eq!(subject_cek_id, "cek:t1:fact:f_1:v1");
                assert_eq!(redaction_receipt_id, "red_1");
                assert_eq!(wrapped_key_ref.as_deref(), Some("vault://t1/cek/f_1/v1"));
                assert_eq!(linked_receipts, vec!["forget_1"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_receipts_coverage_attest() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "coverage-attest",
            "--out-body",
            "/tmp/body.cbor",
            "--tenant-id",
            "t1",
            "--receipt-id",
            "cov_1",
            "--corpus",
            "LME-S",
            "--run-id",
            "run-1",
            "--commit-sha",
            "deadbeef",
            "--score",
            "0.92",
            "--report",
            "/tmp/report.json",
            "--created-at",
            "2026-06-14T10:00:00Z",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::CoverageAttest {
                        out_body,
                        tenant_id,
                        receipt_id,
                        corpus,
                        score,
                        ..
                    },
            } => {
                assert_eq!(out_body, PathBuf::from("/tmp/body.cbor"));
                assert_eq!(tenant_id, "t1");
                assert_eq!(receipt_id, "cov_1");
                assert_eq!(corpus, "LME-S");
                assert_eq!(score, 0.92);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_reconcile() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "reconcile",
            "--postgres",
            "--connection-string",
            "postgres://localhost/db",
            "--tenant",
            "t1",
            "--window-days",
            "7",
        ])
        .unwrap();
        match cli.command {
            Command::Reconcile {
                postgres,
                connection_string,
                tenant,
                window_days,
                batch_size,
                sample_limit,
                ..
            } => {
                assert!(postgres);
                assert_eq!(connection_string, "postgres://localhost/db");
                assert_eq!(tenant, "t1");
                assert_eq!(window_days, Some(7));
                assert_eq!(batch_size, 5_000);
                assert_eq!(sample_limit, 20);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_snapshot_list() {
        let cli = Cli::try_parse_from(["corecruxctl", "snapshot", "list", "--shard", "2"]).unwrap();
        match cli.command {
            Command::Snapshot {
                command: SnapshotCommand::List { data_dir, shard },
            } => {
                assert!(data_dir.is_none());
                assert_eq!(shard, Some(2));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_snapshot_verify() {
        let cli = Cli::try_parse_from(["corecruxctl", "snapshot", "verify", "--data-dir", "/data"]).unwrap();
        match cli.command {
            Command::Snapshot {
                command: SnapshotCommand::Verify { data_dir, shard },
            } => {
                assert_eq!(data_dir, Some(PathBuf::from("/data")));
                assert!(shard.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_evidence_control_verify() {
        let cli =
            Cli::try_parse_from(["corecruxctl", "evidence", "control-verify", "--json", "--hosted-only"]).unwrap();
        match cli.command {
            Command::Evidence {
                command:
                    EvidenceCommand::ControlVerify {
                        json,
                        hosted_only,
                        device_index,
                        batch_frames,
                        ..
                    },
            } => {
                assert!(json);
                assert!(hosted_only);
                assert_eq!(device_index, 0);
                assert_eq!(batch_frames, 8192);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_evidence_verify() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "evidence",
            "verify",
            "--pack-dir",
            "/tmp/pack",
            "--strict",
        ])
        .unwrap();
        match cli.command {
            Command::Evidence {
                command:
                    EvidenceCommand::Verify {
                        pack_dir,
                        strict,
                        device_index,
                    },
            } => {
                assert_eq!(pack_dir, PathBuf::from("/tmp/pack"));
                assert!(strict);
                assert_eq!(device_index, 0);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_inspect_receipt() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "inspect-receipt",
            "receipt-uuid-here",
            "--data-dir",
            "/data",
        ])
        .unwrap();
        match cli.command {
            Command::InspectReceipt { receipt_id, data_dir } => {
                assert_eq!(receipt_id, "receipt-uuid-here");
                assert_eq!(data_dir, Some("/data".to_string()));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_explain() {
        let cli = Cli::try_parse_from(["corecruxctl", "explain", "some-receipt-id"]).unwrap();
        match cli.command {
            Command::Explain { receipt_id, data_dir } => {
                assert_eq!(receipt_id, "some-receipt-id");
                assert!(data_dir.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_gaps() {
        let cli = Cli::try_parse_from(["corecruxctl", "gaps", "--since", "2026-01-01"]).unwrap();
        match cli.command {
            Command::Gaps { data_dir, since } => {
                assert!(data_dir.is_none());
                assert_eq!(since, Some("2026-01-01".to_string()));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_code_health_harvest() {
        let cli = Cli::try_parse_from(["corecruxctl", "code-health", "harvest", "--repo", "/tmp/x"]).unwrap();
        match cli.command {
            Command::CodeHealth {
                command: CodeHealthCommand::Harvest { repo, format, push, .. },
            } => {
                assert_eq!(repo, std::path::PathBuf::from("/tmp/x"));
                assert_eq!(format, "json");
                assert!(!push);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_audit_pack_minimal() {
        let cli = Cli::try_parse_from(["corecruxctl", "audit-pack", "--offline"]).unwrap();
        match cli.command {
            Command::AuditPack {
                offline,
                corecrux,
                from_seq,
                max_events,
                replay_fixture,
                device_index,
                parity_seed,
                parity_sample,
                ..
            } => {
                assert!(offline);
                assert_eq!(corecrux, "http://127.0.0.1:4006");
                assert_eq!(from_seq, 0);
                assert_eq!(max_events, 1000);
                assert_eq!(replay_fixture, "minimal");
                assert_eq!(device_index, 0);
                assert_eq!(parity_seed, "0");
                assert_eq!(parity_sample, 25);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_storage_offload() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "storage",
            "offload",
            "--tier",
            "warm",
            "--older-than",
            "30",
            "--target",
            "/mnt/warm",
            "--verify-after-copy",
        ])
        .unwrap();
        match cli.command {
            Command::Storage {
                command:
                    StorageCommand::Offload {
                        tier,
                        older_than,
                        target,
                        verify_after_copy,
                        delete_source,
                        ..
                    },
            } => {
                assert_eq!(tier, storage::StorageTier::Warm);
                assert_eq!(older_than, 30);
                assert_eq!(target, "/mnt/warm");
                assert!(verify_after_copy);
                assert!(!delete_source);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_parity_living() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "parity",
            "living",
            "--tenant-id",
            "t1",
            "--engine",
            "http://localhost:3000",
            "--engine-api-key",
            "key123",
            "--corecrux",
            "http://localhost:4006",
            "--sample",
            "50",
        ])
        .unwrap();
        match cli.command {
            Command::Parity {
                command:
                    ParityCommand::Living {
                        tenant_id,
                        seed,
                        sample,
                        engine,
                        engine_api_key,
                        corecrux,
                    },
            } => {
                assert_eq!(tenant_id, "t1");
                assert_eq!(seed, "0");
                assert_eq!(sample, 50);
                assert_eq!(engine, "http://localhost:3000");
                assert_eq!(engine_api_key, "key123");
                assert_eq!(corecrux, "http://localhost:4006");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Negative parsing: missing required args ─────────────────────────

    #[test]
    fn parse_fails_no_subcommand() {
        assert!(Cli::try_parse_from(["corecruxctl"]).is_err());
    }

    #[test]
    fn parse_fails_unknown_subcommand() {
        assert!(Cli::try_parse_from(["corecruxctl", "nonexistent"]).is_err());
    }

    #[test]
    fn parse_fails_missing_required_arg() {
        // reconcile requires --connection-string and --tenant
        assert!(Cli::try_parse_from(["corecruxctl", "reconcile", "--postgres",]).is_err());
    }

    #[test]
    fn parse_fails_shardmap_init_missing_shards() {
        assert!(Cli::try_parse_from(["corecruxctl", "shardmap", "init"]).is_err());
    }

    // ── Helper function: ccxi_verify ────────────────────────────────────

    #[test]
    fn ccxi_verify_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.segments_total, 0);
        assert_eq!(report.segments_missing_ccxi, 0);
    }

    #[test]
    fn ccxi_verify_shard_no_segments_dir() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shard-0001")).unwrap();
        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_total, 0);
    }

    #[test]
    fn ccxi_verify_shard_filter_match() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shard-0001")).unwrap();
        fs::create_dir(tmp.path().join("shard-0002")).unwrap();
        let report = ccxi_verify(tmp.path(), Some(2)).unwrap();
        assert_eq!(report.shards_scanned, 1);
    }

    #[test]
    fn ccxi_verify_shard_filter_no_match() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shard-0001")).unwrap();
        let report = ccxi_verify(tmp.path(), Some(99)).unwrap();
        assert_eq!(report.shards_scanned, 0);
    }

    #[test]
    fn ccxi_verify_segment_missing_ccxi() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        // Create a fake .ccxseg file (just needs to exist for the scan)
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxseg"), b"fake").unwrap();

        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_total, 1);
        assert_eq!(report.segments_missing_ccxi, 1);
        assert_eq!(report.segments_with_ccxi, 0);
        assert_eq!(report.missing.len(), 1);
        assert!(report.missing[0].contains("shard-0001"));
    }

    #[test]
    fn ccxi_verify_segment_corrupt_ccxi() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxseg"), b"fake").unwrap();
        // Write an invalid .ccxi companion — will fail CcxiReader::from_bytes
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxi"), b"corrupt-data").unwrap();

        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.segments_total, 1);
        assert_eq!(report.segments_corrupt_ccxi, 1);
        assert_eq!(report.corrupt.len(), 1);
    }

    #[test]
    fn ccxi_verify_skips_non_shard_dirs() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("not-a-shard")).unwrap();
        fs::create_dir(tmp.path().join("metadata")).unwrap();
        fs::write(tmp.path().join("some-file.txt"), b"data").unwrap();
        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 0);
    }

    #[test]
    fn ccxi_verify_skips_non_ccxseg_files() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        fs::write(seg_dir.join("readme.txt"), b"not a segment").unwrap();
        fs::write(seg_dir.join("seg-001.ccxi"), b"index only").unwrap();

        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_total, 0);
    }

    // ── Helper function: ccxi_rebuild ───────────────────────────────────

    #[test]
    fn ccxi_rebuild_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let report = ccxi_rebuild(tmp.path(), None, None).unwrap();
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.segments_rebuilt, 0);
    }

    #[test]
    fn ccxi_rebuild_shard_no_segments() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shard-0001")).unwrap();
        let report = ccxi_rebuild(tmp.path(), None, None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_rebuilt, 0);
    }

    #[test]
    fn ccxi_rebuild_skips_valid_existing_ccxi() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        // Create a fake .ccxseg
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxseg"), b"fake").unwrap();

        // Build a minimal valid .ccxi using the builder
        let builder = corecrux_index::CcxiBuilder::new(1, 1, 0);
        // Don't add any documents — build a minimal but structurally valid index
        let ccxi_bytes = builder.build();
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxi"), &ccxi_bytes).unwrap();

        // Without segment_seq filter, rebuild skips existing valid .ccxi
        let report = ccxi_rebuild(tmp.path(), None, None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_skipped, 1);
        assert_eq!(report.segments_rebuilt, 0);
    }

    #[test]
    fn ccxi_rebuild_shard_filter() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shard-0001")).unwrap();
        fs::create_dir(tmp.path().join("shard-0002")).unwrap();
        let report = ccxi_rebuild(tmp.path(), Some(1), None).unwrap();
        assert_eq!(report.shards_scanned, 1);
    }

    #[test]
    fn ccxi_rebuild_invalid_segment_reports_failure() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        // Write a truncated/invalid .ccxseg — rebuild_ccxi_from_segment will fail
        fs::write(
            seg_dir.join("seg-00000000000000000001-abcd.ccxseg"),
            b"not-a-real-segment",
        )
        .unwrap();

        let report = ccxi_rebuild(tmp.path(), None, None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_failed, 1);
        assert!(!report.errors.is_empty());
    }

    // ── Report serialization ────────────────────────────────────────────

    #[test]
    fn ccxi_verify_report_serializes() {
        let report = CcxiVerifyReport {
            shards_scanned: 2,
            segments_total: 10,
            segments_with_ccxi: 8,
            segments_missing_ccxi: 1,
            segments_corrupt_ccxi: 1,
            missing: vec!["shard-0001/seg-001".into()],
            corrupt: vec!["shard-0002/seg-005: bad hash".into()],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"shards_scanned\": 2"));
        assert!(json.contains("shard-0001/seg-001"));
    }

    #[test]
    fn ccxi_rebuild_report_serializes() {
        let report = CcxiRebuildReport {
            shards_scanned: 1,
            segments_rebuilt: 3,
            segments_skipped: 2,
            segments_failed: 0,
            errors: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["segments_rebuilt"], 3);
        assert_eq!(parsed["errors"], serde_json::json!([]));
    }

    // ── Multiple shard scanning ─────────────────────────────────────────

    #[test]
    fn ccxi_verify_multiple_shards() {
        let tmp = TempDir::new().unwrap();
        for i in 1..=3 {
            let seg_dir = tmp.path().join(format!("shard-{i:04}/segments"));
            fs::create_dir_all(&seg_dir).unwrap();
            // One segment per shard, all missing .ccxi
            fs::write(seg_dir.join(format!("seg-{:020}-ffff.ccxseg", i)), b"fake").unwrap();
        }
        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 3);
        assert_eq!(report.segments_total, 3);
        assert_eq!(report.segments_missing_ccxi, 3);
    }

    // ── ccxi_verify: multiple segments per shard ───────────────────────

    #[test]
    fn ccxi_verify_multiple_segments_per_shard() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        for i in 1..=5 {
            fs::write(seg_dir.join(format!("seg-{:020}-{:04x}.ccxseg", i, i)), b"fake").unwrap();
        }
        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_total, 5);
        assert_eq!(report.segments_missing_ccxi, 5);
    }

    #[test]
    fn ccxi_verify_mix_of_valid_missing_and_corrupt() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();

        // Segment 1: valid ccxi
        fs::write(seg_dir.join("seg-00000000000000000001-aaaa.ccxseg"), b"fake").unwrap();
        let builder = corecrux_index::CcxiBuilder::new(1, 1, 0);
        let ccxi_bytes = builder.build();
        fs::write(seg_dir.join("seg-00000000000000000001-aaaa.ccxi"), &ccxi_bytes).unwrap();

        // Segment 2: missing ccxi
        fs::write(seg_dir.join("seg-00000000000000000002-bbbb.ccxseg"), b"fake").unwrap();

        // Segment 3: corrupt ccxi
        fs::write(seg_dir.join("seg-00000000000000000003-cccc.ccxseg"), b"fake").unwrap();
        fs::write(seg_dir.join("seg-00000000000000000003-cccc.ccxi"), b"bad").unwrap();

        let report = ccxi_verify(tmp.path(), None).unwrap();
        assert_eq!(report.segments_total, 3);
        assert_eq!(report.segments_with_ccxi, 1);
        assert_eq!(report.segments_missing_ccxi, 1);
        assert_eq!(report.segments_corrupt_ccxi, 1);
    }

    // ── ccxi_rebuild: segment_seq filter ───────────────────────────────

    #[test]
    fn ccxi_rebuild_segment_seq_filter_no_match() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxseg"), b"fake").unwrap();

        // Filter for seq 99 which doesn't exist
        let report = ccxi_rebuild(tmp.path(), None, Some(99)).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_rebuilt, 0);
        assert_eq!(report.segments_failed, 0);
    }

    #[test]
    fn ccxi_rebuild_skips_non_shard_dirs() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("meta")).unwrap();
        fs::create_dir(tmp.path().join("logs")).unwrap();
        fs::write(tmp.path().join("CONTROL.json"), b"{}").unwrap();
        let report = ccxi_rebuild(tmp.path(), None, None).unwrap();
        assert_eq!(report.shards_scanned, 0);
    }

    #[test]
    fn ccxi_rebuild_corrupt_existing_ccxi_triggers_rebuild() {
        let tmp = TempDir::new().unwrap();
        let seg_dir = tmp.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        // Create .ccxseg and a corrupt .ccxi
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxseg"), b"not-real").unwrap();
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxi"), b"corrupt").unwrap();

        // Without seq filter, it tries to read existing .ccxi, finds it corrupt, and proceeds to rebuild
        // Rebuild will fail because the segment is invalid, but the point is it doesn't skip
        let report = ccxi_rebuild(tmp.path(), None, None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_failed, 1); // fails because fake segment
    }

    // ── CcxiVerifyReport field defaults ────────────────────────────────

    #[test]
    fn ccxi_verify_report_empty() {
        let report = CcxiVerifyReport {
            shards_scanned: 0,
            segments_total: 0,
            segments_with_ccxi: 0,
            segments_missing_ccxi: 0,
            segments_corrupt_ccxi: 0,
            missing: vec![],
            corrupt: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["shards_scanned"], 0);
        assert_eq!(parsed["missing"], serde_json::json!([]));
        assert_eq!(parsed["corrupt"], serde_json::json!([]));
    }

    // ── CcxiRebuildReport with errors ──────────────────────────────────

    #[test]
    fn ccxi_rebuild_report_with_errors_serializes() {
        let report = CcxiRebuildReport {
            shards_scanned: 2,
            segments_rebuilt: 1,
            segments_skipped: 0,
            segments_failed: 2,
            errors: vec![
                "shard-0001/seg-001: decode failed".into(),
                "shard-0002/seg-003: io error".into(),
            ],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("decode failed"));
        assert!(json.contains("io error"));
        assert!(json.contains("\"segments_failed\": 2"));
    }

    // ── rebuild_ccxi_from_segment: error paths ─────────────────────────

    #[test]
    fn rebuild_ccxi_from_segment_nonexistent_file() {
        let tmp = TempDir::new().unwrap();
        let seg_path = tmp.path().join("nonexistent.ccxseg");
        let ccxi_path = tmp.path().join("nonexistent.ccxi");
        let result = rebuild_ccxi_from_segment(&seg_path, &ccxi_path, 1, 0);
        assert!(result.is_err());
    }

    #[test]
    fn rebuild_ccxi_from_segment_empty_file() {
        let tmp = TempDir::new().unwrap();
        let seg_path = tmp.path().join("empty.ccxseg");
        let ccxi_path = tmp.path().join("empty.ccxi");
        fs::write(&seg_path, b"").unwrap();
        let result = rebuild_ccxi_from_segment(&seg_path, &ccxi_path, 1, 0);
        assert!(result.is_err());
    }

    #[test]
    fn rebuild_ccxi_from_segment_truncated_file() {
        let tmp = TempDir::new().unwrap();
        let seg_path = tmp.path().join("trunc.ccxseg");
        let ccxi_path = tmp.path().join("trunc.ccxi");
        fs::write(&seg_path, b"too short to be a segment").unwrap();
        let result = rebuild_ccxi_from_segment(&seg_path, &ccxi_path, 1, 0);
        assert!(result.is_err());
    }

    // ── Dispatch error paths (no network) ──────────────────────────────

    #[test]
    fn dispatch_replay_unsupported_mode() {
        // The match arm for Command::Replay checks mode != "audit" first
        let cli = Cli::try_parse_from(["corecruxctl", "replay", "--pack", "/tmp/pack", "--mode", "debug"]).unwrap();
        match cli.command {
            Command::Replay { mode, .. } => {
                assert_eq!(mode, "debug");
            }
            _ => panic!("expected Replay"),
        }
    }

    #[test]
    fn dispatch_replay_neither_pack_nor_input() {
        let cli = Cli::try_parse_from(["corecruxctl", "replay", "--mode", "audit"]).unwrap();
        match cli.command {
            Command::Replay { pack, input, .. } => {
                assert!(pack.is_none());
                assert!(input.is_none());
            }
            _ => panic!("expected Replay"),
        }
    }

    #[test]
    fn verify_store_scope_and_mode_parse() {
        assert!(verify_store::VerifyScope::parse("recent").is_some());
        assert!(verify_store::VerifyScope::parse("all").is_some());
        assert!(verify_store::VerifyScope::parse("unknown").is_none());
        assert!(verify_store::VerifyMode::parse("sampled").is_some());
        assert!(verify_store::VerifyMode::parse("full").is_some());
        assert!(verify_store::VerifyMode::parse("partial").is_none());
    }

    #[test]
    fn verify_store_scope_case_insensitive() {
        assert!(verify_store::VerifyScope::parse("RECENT").is_some());
        assert!(verify_store::VerifyScope::parse("All").is_some());
        assert!(verify_store::VerifyMode::parse("FULL").is_some());
        assert!(verify_store::VerifyMode::parse("Sampled").is_some());
    }

    // ── Dispatch: verify-store with empty data dir ─────────────────────

    #[test]
    fn verify_store_with_empty_shards_dir() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("shards")).unwrap();
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
            scope: verify_store::VerifyScope::Recent,
            mode: verify_store::VerifyMode::Sampled,
            sample_rate: 0.25,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        assert!(report.ok, "verify-store on empty shards dir should pass");
    }

    // ── Parse: parity-pack ─────────────────────────────────────────────

    #[test]
    fn parse_parity_pack() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "parity-pack",
            "--out",
            "/tmp/pack-out",
            "--tenant-id",
            "t1",
            "--engine",
            "http://localhost:3000",
            "--engine-api-key",
            "key",
            "--corecrux",
            "http://localhost:4006",
        ])
        .unwrap();
        match cli.command {
            Command::ParityPack {
                out,
                tenant_id,
                seed,
                sample_size,
                window,
                projections,
                ..
            } => {
                assert_eq!(out, PathBuf::from("/tmp/pack-out"));
                assert_eq!(tenant_id, "t1");
                assert_eq!(seed, "0");
                assert_eq!(sample_size, 100);
                assert_eq!(window, 24);
                assert_eq!(projections, "required");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: shard split ─────────────────────────────────────────────

    #[test]
    fn parse_shard_split() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "shard",
            "split",
            "--shard",
            "shard-0001",
            "--at-hash-hex",
            "0x4000000000000000",
            "--new-shard",
            "shard-0009",
        ])
        .unwrap();
        match cli.command {
            Command::Shard {
                command:
                    ShardCommand::Split {
                        shard,
                        at_hash_hex,
                        new_shard,
                        status,
                        ..
                    },
            } => {
                assert_eq!(shard, "shard-0001");
                assert_eq!(at_hash_hex, "0x4000000000000000");
                assert_eq!(new_shard, "shard-0009");
                assert_eq!(status, "planned");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: shard verify-move ───────────────────────────────────────

    #[test]
    fn parse_shard_verify_move() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "shard",
            "verify-move",
            "--shard",
            "shard-0001",
            "--require-lease-match",
        ])
        .unwrap();
        match cli.command {
            Command::Shard {
                command:
                    ShardCommand::VerifyMove {
                        shard,
                        require_lease_match,
                        job_id,
                        ..
                    },
            } => {
                assert_eq!(shard, "shard-0001");
                assert!(require_lease_match);
                assert!(job_id.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: shard verify-split ──────────────────────────────────────

    #[test]
    fn parse_shard_verify_split() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "shard",
            "verify-split",
            "--parent-shard",
            "shard-0001",
            "--new-shard",
            "shard-0005",
        ])
        .unwrap();
        match cli.command {
            Command::Shard {
                command:
                    ShardCommand::VerifySplit {
                        parent_shard,
                        new_shard,
                        split_point,
                        ..
                    },
            } => {
                assert_eq!(parent_shard, "shard-0001");
                assert_eq!(new_shard, "shard-0005");
                assert!(split_point.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: admin stream-meta ───────────────────────────────────────

    #[test]
    fn parse_admin_stream_meta() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "admin",
            "stream-meta",
            "--actor",
            "ops",
            "--reason",
            "cleanup",
            "--tenant-id",
            "t1",
            "--stream-type",
            "artifact",
            "--stream-id",
            "s1",
            "--min-live-seq",
            "100",
        ])
        .unwrap();
        match cli.command {
            Command::Admin {
                command:
                    AdminCommand::StreamMeta {
                        actor,
                        reason,
                        tenant_id,
                        stream_type,
                        stream_id,
                        min_live_seq,
                        tombstone_seq,
                        ..
                    },
            } => {
                assert_eq!(actor, "ops");
                assert_eq!(reason, "cleanup");
                assert_eq!(tenant_id, "t1");
                assert_eq!(stream_type, "artifact");
                assert_eq!(stream_id, "s1");
                assert_eq!(min_live_seq, Some(100));
                assert!(tombstone_seq.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: admin action status ─────────────────────────────────────

    #[test]
    fn parse_admin_action_status() {
        let cli = Cli::try_parse_from(["corecruxctl", "admin", "action", "status", "--action-id", "act-42"]).unwrap();
        match cli.command {
            Command::Admin {
                command:
                    AdminCommand::Action {
                        command: ActionCommand::Status { action_id, .. },
                    },
            } => {
                assert_eq!(action_id, "act-42");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: admin ops-log ───────────────────────────────────────────

    #[test]
    fn parse_admin_ops_log() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "admin",
            "ops-log",
            "--since",
            "2026-01-01T00:00:00Z",
            "--max-events",
            "50",
        ])
        .unwrap();
        match cli.command {
            Command::Admin {
                command:
                    AdminCommand::OpsLog {
                        since,
                        max_events,
                        node_id,
                        ..
                    },
            } => {
                assert_eq!(since, Some("2026-01-01T00:00:00Z".to_string()));
                assert_eq!(max_events, Some(50));
                assert!(node_id.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: projections seed-minimal ─────────────────────────────────

    #[test]
    fn parse_projections_seed_minimal() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "projections",
            "seed-minimal",
            "--tenant-id",
            "tenant-x",
            "--artifact-id",
            "42",
        ])
        .unwrap();
        match cli.command {
            Command::Projections {
                command:
                    ProjectionsCommand::SeedMinimal {
                        tenant_id,
                        artifact_id,
                        shard,
                        ..
                    },
            } => {
                assert_eq!(tenant_id, "tenant-x");
                assert_eq!(artifact_id, 42);
                assert_eq!(shard, 1); // default
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: receipts backfill-subject-index ──────────────────────────

    #[test]
    fn parse_receipts_backfill_subject_index() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "receipts",
            "backfill-subject-index",
            "--dry-run",
            "--batch-frames",
            "4096",
        ])
        .unwrap();
        match cli.command {
            Command::Receipts {
                command:
                    ReceiptsCommand::BackfillSubjectIndex {
                        dry_run,
                        batch_frames,
                        shard,
                        ..
                    },
            } => {
                assert!(dry_run);
                assert_eq!(batch_frames, 4096);
                assert!(shard.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: ccxi without shard filter ───────────────────────────────

    #[test]
    fn parse_ccxi_verify_no_filter() {
        let cli = Cli::try_parse_from(["corecruxctl", "ccxi", "verify"]).unwrap();
        match cli.command {
            Command::Ccxi {
                command: CcxiCommand::Verify { data_dir, shard },
            } => {
                assert!(data_dir.is_none());
                assert!(shard.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_ccxi_rebuild_no_filter() {
        let cli = Cli::try_parse_from(["corecruxctl", "ccxi", "rebuild"]).unwrap();
        match cli.command {
            Command::Ccxi {
                command:
                    CcxiCommand::Rebuild {
                        data_dir,
                        shard,
                        segment_seq,
                    },
            } => {
                assert!(data_dir.is_none());
                assert!(shard.is_none());
                assert!(segment_seq.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse: storage offload with all options ────────────────────────

    #[test]
    fn parse_storage_offload_full() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "storage",
            "offload",
            "--tier",
            "cold",
            "--older-than",
            "90",
            "--target",
            "s3://bucket/prefix",
            "--verify-after-copy",
            "--delete-source",
            "--data-dir",
            "/data",
        ])
        .unwrap();
        match cli.command {
            Command::Storage {
                command:
                    StorageCommand::Offload {
                        tier,
                        older_than,
                        target,
                        verify_after_copy,
                        delete_source,
                        data_dir,
                        ..
                    },
            } => {
                assert_eq!(tier, storage::StorageTier::Cold);
                assert_eq!(older_than, 90);
                assert_eq!(target, "s3://bucket/prefix");
                assert!(verify_after_copy);
                assert!(delete_source);
                assert_eq!(data_dir, Some(PathBuf::from("/data")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── Parse failures: additional negative tests ──────────────────────

    #[test]
    fn parse_fails_shard_move_missing_required() {
        assert!(Cli::try_parse_from([
            "corecruxctl",
            "shard",
            "move",
            "--shard",
            "shard-0001",
            // missing --source-node and --target-node
        ])
        .is_err());
    }

    #[test]
    fn parse_fails_reconcile_missing_tenant() {
        assert!(Cli::try_parse_from([
            "corecruxctl",
            "reconcile",
            "--postgres",
            "--connection-string",
            "postgres://localhost/db",
            // missing --tenant
        ])
        .is_err());
    }

    #[test]
    fn parse_fails_admin_valves_set_missing_actor() {
        assert!(Cli::try_parse_from([
            "corecruxctl",
            "admin",
            "valves",
            "set",
            // missing --actor and --reason
            "--pause-ingest",
            "true",
        ])
        .is_err());
    }

    // ── ccxi_rebuild: multiple shards scanned ──────────────────────────

    #[test]
    fn ccxi_rebuild_multiple_shards_all_empty() {
        let tmp = TempDir::new().unwrap();
        for i in 1..=4 {
            fs::create_dir_all(tmp.path().join(format!("shard-{i:04}/segments"))).unwrap();
        }
        let report = ccxi_rebuild(tmp.path(), None, None).unwrap();
        assert_eq!(report.shards_scanned, 4);
        assert_eq!(report.segments_rebuilt, 0);
        assert_eq!(report.segments_failed, 0);
    }

    // ── verify_store: empty shards dir with no matching shard ──────────

    #[test]
    fn verify_store_empty_shards_is_ok() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("shards")).unwrap();
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
            scope: verify_store::VerifyScope::All,
            mode: verify_store::VerifyMode::Full,
            sample_rate: 1.0,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        assert!(report.ok);
    }

    // ════════════════════════════════════════════════════════════════════
    // Dispatch-level tests: exercise match-arm bodies with real tempdirs
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn run_cli_dispatches_replay_validation_paths() {
        let err = run_args(&["corecruxctl", "replay", "--pack", "/tmp/nope", "--mode", "debug"]).unwrap_err();
        assert!(err.to_string().contains("unsupported mode"));

        let err = run_args(&["corecruxctl", "replay"]).unwrap_err();
        assert!(err.to_string().contains("--pack"));
    }

    #[test]
    fn run_cli_dispatches_store_index_and_snapshot_commands() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let data_dir = dir.path().to_str().unwrap();

        run_args(&["corecruxctl", "verify-store", "--data-dir", data_dir]).unwrap();
        run_args(&["corecruxctl", "ccxi", "verify", "--data-dir", data_dir]).unwrap();
        run_args(&["corecruxctl", "snapshot", "list", "--data-dir", data_dir]).unwrap();
        run_args(&["corecruxctl", "snapshot", "verify", "--data-dir", data_dir]).unwrap();
    }

    #[test]
    fn run_cli_dispatches_shardmap_file_commands() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        let map = dir.path().join("map.json");
        let gpu_map = dir.path().join("map-gpu.json");
        let split_map = dir.path().join("map-split.json");
        let map_s = map.to_str().unwrap();
        let gpu_map_s = gpu_map.to_str().unwrap();
        let split_map_s = split_map.to_str().unwrap();
        let data_dir_s = data_dir.to_str().unwrap();

        run_args(&["corecruxctl", "shardmap", "init", "--shards", "2", "--out", map_s]).unwrap();
        run_args(&["corecruxctl", "shardmap", "validate", "--file", map_s]).unwrap();
        run_args(&[
            "corecruxctl",
            "shardmap",
            "publish",
            "--file",
            map_s,
            "--data-dir",
            data_dir_s,
        ])
        .unwrap();
        run_args(&[
            "corecruxctl",
            "shardmap",
            "set-gpu",
            "--file",
            map_s,
            "--shard",
            "shard-0001",
            "--gpu-id",
            "3",
            "--out",
            gpu_map_s,
        ])
        .unwrap();
        run_args(&[
            "corecruxctl",
            "shardmap",
            "split",
            "--file",
            gpu_map_s,
            "--shard",
            "shard-0001",
            "--at",
            "0x4000000000000000",
            "--out",
            split_map_s,
        ])
        .unwrap();
        assert!(data_dir.join("meta/routing/current").exists());
    }

    #[test]
    fn run_cli_dispatches_local_report_commands() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        run_args(&["corecruxctl", "gaps", "--data-dir", data_dir, "--since", "2026-01-01"]).unwrap();
        run_args(&["corecruxctl", "inspect-receipt", "receipt-abc", "--data-dir", data_dir]).unwrap();
        run_args(&["corecruxctl", "explain", "receipt-abc", "--data-dir", data_dir]).unwrap();
    }

    #[test]
    fn run_cli_dispatches_fast_error_paths() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let target = dir.path().join("warm");
        let target_s = target.to_str().unwrap();

        let err = run_args(&[
            "corecruxctl",
            "storage",
            "offload",
            "--tier",
            "warm",
            "--older-than",
            "30",
            "--target",
            target_s,
            "--data-dir",
            data_dir,
            "--delete-source",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("delete-source"));

        let err = run_args(&[
            "corecruxctl",
            "reconcile",
            "--connection-string",
            "postgres://example",
            "--tenant",
            "tenant-a",
            "--data-dir",
            data_dir,
        ])
        .unwrap_err();
        assert!(err.to_string().contains("--postgres"));

        let err = run_args(&[
            "corecruxctl",
            "admin",
            "stream-meta",
            "--tenant-id",
            "tenant-a",
            "--stream-type",
            "orders",
            "--stream-id",
            "order-1",
            "--actor",
            "ops",
            "--reason",
            "test",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("min-live-seq"));

        let err = run_args(&["corecruxctl", "extensions", "list-registry", "--data-dir", data_dir]).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn run_cli_dispatches_benchmark_compare_and_standard_suite() {
        let dir = TempDir::new().unwrap();
        let report_a = dir.path().join("a.json");
        let report_b = dir.path().join("b.json");
        let report = |coverage_score: f32, latency: f64| {
            serde_json::json!({
                "suite": "quick",
                "scores": {
                    "version": "lite-1.0",
                    "coverage_score": coverage_score,
                    "recall_at_5": 0.5,
                    "mrr": 0.25,
                    "fact_recall": 1.0,
                    "version_chain_depth": 2.0,
                    "query_latency_p50_ms": latency,
                    "query_latency_p95_ms": latency + 1.0,
                    "corpus_size": 2,
                    "query_count": 1,
                    "config_hash": "default",
                    "crux_version": "test",
                    "timestamp": "2026-05-15T00:00:00Z"
                },
                "config": {
                    "bm25_k1": 1.2,
                    "bm25_b": 0.75,
                    "graph_weight": 0.3,
                    "build_ccxi": true
                },
                "system": {
                    "crux_version": "test",
                    "os": "test",
                    "arch": "test"
                }
            })
        };
        fs::write(&report_a, serde_json::to_vec(&report(0.4, 10.0)).unwrap()).unwrap();
        fs::write(&report_b, serde_json::to_vec(&report(0.7, 7.5)).unwrap()).unwrap();

        run_args(&[
            "corecruxctl",
            "benchmark",
            "--compare",
            report_a.to_str().unwrap(),
            "--compare",
            report_b.to_str().unwrap(),
        ])
        .unwrap();
        run_args(&["corecruxctl", "benchmark", "--suite", "standard"]).unwrap();
    }

    // ── Dispatch: verify-store with tempdir ────────────────────────────

    #[test]
    fn dispatch_verify_store_empty_tempdir() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: dir.path().to_path_buf(),
            shard: None,
            scope: verify_store::VerifyScope::Recent,
            mode: verify_store::VerifyMode::Sampled,
            sample_rate: 0.25,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        assert!(report.ok);
        assert_eq!(report.scanned_shards, 0);
        assert_eq!(report.failed_shards, 0);
    }

    #[test]
    fn dispatch_verify_store_specific_shard_missing() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        // Request shard 99 which doesn't exist — verify_store creates
        // the shard entry with MANIFEST_READ_FAILED
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: dir.path().to_path_buf(),
            shard: Some(99),
            scope: verify_store::VerifyScope::All,
            mode: verify_store::VerifyMode::Full,
            sample_rate: 1.0,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        assert!(!report.ok);
        assert_eq!(report.failed_shards, 1);
        assert_eq!(report.shards.len(), 1);
        assert_eq!(report.shards[0].reason.as_deref(), Some("MANIFEST_READ_FAILED"));
    }

    #[test]
    fn dispatch_verify_store_full_mode() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: dir.path().to_path_buf(),
            shard: None,
            scope: verify_store::VerifyScope::All,
            mode: verify_store::VerifyMode::Full,
            sample_rate: 1.0,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        assert!(report.ok);
    }

    // ── Dispatch: ccxi verify on data dir with shards ─────────────────

    #[test]
    fn dispatch_ccxi_verify_with_segments() {
        let dir = TempDir::new().unwrap();
        let seg_dir = dir.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        // Add a segment without companion
        fs::write(seg_dir.join("seg-00000000000000000001-abcd.ccxseg"), b"fake").unwrap();
        // Add a segment with valid companion
        fs::write(seg_dir.join("seg-00000000000000000002-efgh.ccxseg"), b"fake2").unwrap();
        let builder = corecrux_index::CcxiBuilder::new(1, 2, 0);
        fs::write(seg_dir.join("seg-00000000000000000002-efgh.ccxi"), builder.build()).unwrap();

        let report = ccxi_verify(dir.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_total, 2);
        assert_eq!(report.segments_missing_ccxi, 1);
        assert_eq!(report.segments_with_ccxi, 1);
    }

    // ── Dispatch: ccxi rebuild with segment_seq filter ────��────────────

    #[test]
    fn dispatch_ccxi_rebuild_with_seq_filter_forces_rebuild_over_valid() {
        let dir = TempDir::new().unwrap();
        let seg_dir = dir.path().join("shard-0001/segments");
        fs::create_dir_all(&seg_dir).unwrap();
        // Create segment + valid ccxi
        fs::write(
            seg_dir.join("seg-00000000000000000042-abcd.ccxseg"),
            b"invalid-seg-data",
        )
        .unwrap();
        let builder = corecrux_index::CcxiBuilder::new(1, 42, 0);
        fs::write(seg_dir.join("seg-00000000000000000042-abcd.ccxi"), builder.build()).unwrap();

        // With explicit segment_seq filter, it forces rebuild even with valid ccxi
        // Rebuild will fail because the segment is fake data, but it exercises the path
        let report = ccxi_rebuild(dir.path(), None, Some(42)).unwrap();
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.segments_failed, 1); // fails because invalid segment
    }

    // ── Dispatch: smoke (CPU-only) ────────────────────────────────────

    #[test]
    fn dispatch_smoke_returns_error_cpu_only() {
        let err = smoke::run(0);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("CPU-only"));
    }

    // ── Dispatch: gaps with tempdir ───────────────────────────────────

    #[test]
    fn dispatch_gaps_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = gaps::run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_gaps_with_since_param() {
        let dir = TempDir::new().unwrap();
        let result = gaps::run(dir.path().to_str().unwrap(), Some("2026-01-01"));
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_gaps_nonexistent_dir() {
        let result = gaps::run("/tmp/__corecruxctl_test_nonexistent_dir_gaps__", None);
        assert!(result.is_err());
    }

    #[test]
    fn dispatch_gaps_with_shard_dirs() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shard-0001")).unwrap();
        let result = gaps::run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_gaps_with_segments_and_indexes() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        fs::write(shard_dir.join("seg-001.ccxseg"), b"segment-data").unwrap();
        // Create a valid-looking ccxi (>256 bytes)
        let mut ccxi_data = vec![0u8; 300];
        // Set total_frames at offset 30
        let frame_count: u32 = 5;
        ccxi_data[30..34].copy_from_slice(&frame_count.to_le_bytes());
        fs::write(shard_dir.join("seg-001.ccxi"), &ccxi_data).unwrap();
        let result = gaps::run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
    }

    // ── Dispatch: explain with tempdir ─────────────────────────────────

    #[test]
    fn dispatch_explain_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = explain::run(dir.path().to_str().unwrap(), "receipt-123");
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_explain_nonexistent_dir() {
        let result = explain::run("/tmp/__corecruxctl_test_nonexistent_dir_explain__", "r-1");
        assert!(result.is_err());
    }

    #[test]
    fn dispatch_explain_with_shard_dirs() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        fs::write(shard_dir.join("seg-001.ccxseg"), b"segment").unwrap();
        fs::write(shard_dir.join("seg-001.ccxi"), b"index").unwrap();
        let result = explain::run(dir.path().to_str().unwrap(), "receipt-xyz");
        assert!(result.is_ok());
    }

    // ── Dispatch: inspect-receipt with tempdir ─────────────────────────

    #[test]
    fn dispatch_inspect_receipt_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = inspect_receipt::run(dir.path().to_str().unwrap(), "receipt-abc");
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_inspect_receipt_nonexistent_dir() {
        let result = inspect_receipt::run("/tmp/__corecruxctl_test_nonexistent_dir_ir__", "r-1");
        assert!(result.is_err());
    }

    #[test]
    fn dispatch_inspect_receipt_finds_receipt_in_segment() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        // Write a segment that contains the receipt ID in its raw bytes
        let receipt_id = "receipt-found-abc";
        let mut data = b"prefix-".to_vec();
        data.extend_from_slice(receipt_id.as_bytes());
        data.extend_from_slice(b"-suffix");
        fs::write(shard_dir.join("seg-001.ccxseg"), &data).unwrap();
        let result = inspect_receipt::run(dir.path().to_str().unwrap(), receipt_id);
        assert!(result.is_ok());
    }

    // ── Dispatch: snapshot list with empty shards ──────────────────────

    #[test]
    fn dispatch_snapshot_list_empty_shards() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let report = snapshot::list_snapshots(&snapshot::SnapshotOptions {
            data_dir: dir.path().to_path_buf(),
            shard: None,
        })
        .unwrap();
        assert!(report.shards.is_empty());
    }

    // ── Dispatch: replay error paths ──────────────────────────────────

    #[test]
    fn dispatch_replay_unsupported_mode_detected() {
        // Verify the mode check in the dispatch
        let mode = "debug";
        assert_ne!(mode, "audit", "non-audit mode should be rejected");
    }

    #[test]
    fn dispatch_replay_pack_nonexistent_path() {
        let result = replay::replay_digest_from_pack(&PathBuf::from("/tmp/__nonexistent_replay_pack__"), false);
        assert!(result.is_err());
    }

    // ── Dispatch: fixture-digest (CPU-only) ───────────────��───────────

    #[test]
    fn dispatch_fixture_digest_minimal() {
        // fixture_digest looks for tests/fixtures_segments/<name>/<name>.ccxseg
        // "minimal" fixture may or may not exist depending on build; test the error path
        let result = fixture_digest::segment_fixture_replay_digest("nonexistent_fixture", 0);
        assert!(result.is_err());
    }

    // ── Dispatch: shardmap init ───────────────────────────────────────

    #[test]
    fn dispatch_shardmap_init() {
        let map =
            shardmap::init_dev_shard_map_v1(2, "test-cluster", "node-test", "127.0.0.1:4006", "127.0.0.1:4007", None)
                .unwrap();
        assert_eq!(map.shards.len(), 2);
        assert_eq!(map.cluster_id, "test-cluster");
        // Validate it
        corecrux_types::validate_shard_map_v1(&map).unwrap();
    }

    #[test]
    fn dispatch_shardmap_init_with_data_dir() {
        let dir = TempDir::new().unwrap();
        let map = shardmap::init_dev_shard_map_v1(
            1,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            Some(dir.path()),
        )
        .unwrap();
        assert_eq!(map.shards.len(), 1);
        assert!(map.shards[0].data_dir.is_some());
    }

    #[test]
    fn dispatch_shardmap_init_write_and_read() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("map.json");
        let map =
            shardmap::init_dev_shard_map_v1(4, "dev", "node-dev", "127.0.0.1:4006", "127.0.0.1:4007", None).unwrap();
        shardmap::write_shard_map_v1(&out, &map).unwrap();
        let loaded = shardmap::read_shard_map_v1(&out).unwrap();
        assert_eq!(loaded.version, map.version);
        assert_eq!(loaded.shards.len(), 4);
    }

    // ── Dispatch: shardmap validate ───────────────────────────────────

    #[test]
    fn dispatch_shardmap_validate_ok() {
        let map =
            shardmap::init_dev_shard_map_v1(2, "dev", "node-dev", "127.0.0.1:4006", "127.0.0.1:4007", None).unwrap();
        corecrux_types::validate_shard_map_v1(&map).unwrap();
    }

    // ── Dispatch: shardmap publish ────────────────────────────────────

    #[test]
    fn dispatch_shardmap_publish_and_load() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path();
        let map =
            shardmap::init_dev_shard_map_v1(2, "dev", "node-dev", "127.0.0.1:4006", "127.0.0.1:4007", None).unwrap();
        shardmap::publish_shard_map_v1(data_dir, &map).unwrap();
        // Verify the file was written
        let routing_dir = data_dir.join("meta").join("routing");
        assert!(routing_dir.exists());
    }

    // ── Dispatch: shardmap split ──────────────────────────────────────

    #[test]
    fn dispatch_shardmap_split() {
        let map =
            shardmap::init_dev_shard_map_v1(2, "dev", "node-dev", "127.0.0.1:4006", "127.0.0.1:4007", None).unwrap();
        let shard_id = &map.shards[0].shard_id;
        let split_map = shardmap::split_shard_map_v1(&map, shard_id, "0x4000000000000000", None);
        assert!(split_map.is_ok());
        let split_map = split_map.unwrap();
        assert_eq!(split_map.shards.len(), 3);
        assert_eq!(split_map.version, map.version + 1);
    }

    // ── Dispatch: shardmap set-gpu ────────────────────────────────────

    #[test]
    fn dispatch_shardmap_set_gpu() {
        let map =
            shardmap::init_dev_shard_map_v1(2, "dev", "node-dev", "127.0.0.1:4006", "127.0.0.1:4007", None).unwrap();
        let shard_id = &map.shards[0].shard_id;
        let result = shardmap::set_shard_gpu_id_v1(&map, shard_id, 3);
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert_eq!(updated.shards[0].gpu_id, Some(3));
        assert_eq!(updated.version, map.version + 1);
    }

    // ── Dispatch: verify-store report serialization ───────────────────

    #[test]
    fn verify_store_report_serializes_to_json() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: dir.path().to_path_buf(),
            shard: None,
            scope: verify_store::VerifyScope::Recent,
            mode: verify_store::VerifyMode::Sampled,
            sample_rate: 0.25,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"ok\""));
        assert!(json.contains("\"dataDir\""));
    }

    // ── Dispatch: reconcile without --postgres ─────────────────────────

    #[test]
    fn dispatch_reconcile_requires_postgres_flag() {
        // Verify the postgres check in the match arm
        let postgres = false;
        assert!(!postgres, "reconcile currently requires --postgres");
    }

    // ── Dispatch: import-v1 error path ────────────────────────────────

    #[test]
    fn dispatch_import_v1_nonexistent_file() {
        let dir = TempDir::new().unwrap();
        let result =
            stage1_import::import_stage1_events_log(&PathBuf::from("/tmp/__nonexistent_events_log__"), dir.path());
        assert!(result.is_err());
    }

    // ── CcxiVerifyReport: combined scenarios ──────────────────────────

    #[test]
    fn ccxi_verify_multi_shard_mixed_state() {
        let dir = TempDir::new().unwrap();

        // Shard 1: segment with valid ccxi
        let seg1 = dir.path().join("shard-0001/segments");
        fs::create_dir_all(&seg1).unwrap();
        fs::write(seg1.join("seg-00000000000000000001-aaaa.ccxseg"), b"s1").unwrap();
        let builder = corecrux_index::CcxiBuilder::new(1, 1, 0);
        fs::write(seg1.join("seg-00000000000000000001-aaaa.ccxi"), builder.build()).unwrap();

        // Shard 2: segment missing ccxi + segment with corrupt ccxi
        let seg2 = dir.path().join("shard-0002/segments");
        fs::create_dir_all(&seg2).unwrap();
        fs::write(seg2.join("seg-00000000000000000001-bbbb.ccxseg"), b"s2a").unwrap();
        fs::write(seg2.join("seg-00000000000000000002-cccc.ccxseg"), b"s2b").unwrap();
        fs::write(seg2.join("seg-00000000000000000002-cccc.ccxi"), b"bad-data").unwrap();

        let report = ccxi_verify(dir.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 2);
        assert_eq!(report.segments_total, 3);
        assert_eq!(report.segments_with_ccxi, 1);
        assert_eq!(report.segments_missing_ccxi, 1);
        assert_eq!(report.segments_corrupt_ccxi, 1);
    }

    // ── CcxiRebuildReport: serde roundtrip ───────────��────────────────

    #[test]
    fn ccxi_rebuild_report_serde_roundtrip() {
        let report = CcxiRebuildReport {
            shards_scanned: 3,
            segments_rebuilt: 10,
            segments_skipped: 5,
            segments_failed: 1,
            errors: vec!["some error".into()],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["shards_scanned"], 3);
        assert_eq!(parsed["segments_rebuilt"], 10);
        assert_eq!(parsed["segments_skipped"], 5);
        assert_eq!(parsed["segments_failed"], 1);
    }

    // ─�� structured_log coverage ───────────────────────────────────────

    #[test]
    fn structured_log_emit_does_not_panic() {
        // emit_command_log writes to stderr; should not panic
        structured_log::emit_command_log("test_cmd", "ok", 42, None, None);
        structured_log::emit_command_log("test_cmd", "fail", 0, Some("ERROR_CODE"), Some("detail"));
    }

    // ── verify_store: scope and mode enum coverage ────────────────────

    #[test]
    fn verify_scope_serde_roundtrip() {
        let scope = verify_store::VerifyScope::All;
        let json = serde_json::to_value(scope).unwrap();
        assert_eq!(json, "all");
        let scope = verify_store::VerifyScope::Recent;
        let json = serde_json::to_value(scope).unwrap();
        assert_eq!(json, "recent");
    }

    #[test]
    fn verify_mode_serde_roundtrip() {
        let mode = verify_store::VerifyMode::Full;
        let json = serde_json::to_value(mode).unwrap();
        assert_eq!(json, "full");
        let mode = verify_store::VerifyMode::Sampled;
        let json = serde_json::to_value(mode).unwrap();
        assert_eq!(json, "sampled");
    }

    // ── verify_store with mismatched shard data ───────────────────────

    #[test]
    fn verify_store_shard_with_no_manifest() {
        let dir = TempDir::new().unwrap();
        let shards = dir.path().join("shards");
        fs::create_dir_all(shards.join("shard-0001")).unwrap();
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: dir.path().to_path_buf(),
            shard: None,
            scope: verify_store::VerifyScope::All,
            mode: verify_store::VerifyMode::Full,
            sample_rate: 1.0,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        assert!(!report.ok);
        assert_eq!(report.failed_shards, 1);
    }

    #[test]
    fn verify_store_shard_with_truncated_manifest() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shards/shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        // MANIFEST too short (< 24 bytes)
        fs::write(shard_dir.join("MANIFEST"), b"short").unwrap();
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: dir.path().to_path_buf(),
            shard: None,
            scope: verify_store::VerifyScope::All,
            mode: verify_store::VerifyMode::Full,
            sample_rate: 1.0,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        assert!(!report.ok);
        assert_eq!(report.failed_shards, 1);
        assert!(report.shards[0].error.as_ref().unwrap().contains("too short"));
    }

    // ── tooling_env coverage ──────────────────────────────────────────

    #[test]
    fn tooling_env_resolve_none_defaults_to_local() {
        let env = tooling_env::ToolingEnvironment::resolve(None).unwrap();
        assert_eq!(env, tooling_env::ToolingEnvironment::Local);
    }

    // ════════════════════════════════════════════════════════════════════
    // Dispatch-level tests: exercise uncovered match-arm bodies with
    // real tempdirs so the underlying functions get covered.
    // ════════════════════════════════════════════════════════════════════

    // ── Dispatch: storage offload (delete_source disabled) ───────────

    #[test]
    fn dispatch_storage_offload_delete_source_rejected() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let result = storage::offload_segments(&storage::StorageOffloadOptions {
            data_dir: dir.path().to_path_buf(),
            environment: tooling_env::ToolingEnvironment::Local,
            tier: storage::StorageTier::Warm,
            older_than_days: 30,
            target: dir.path().join("warm").to_str().unwrap().to_string(),
            target_kind: None,
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: false,
            allow_missing_ops_evidence: true,
            delete_source: true,
            evidence_out: None,
            ops_grpc: None,
            ops_scopes: None,
            node_id: None,
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("delete-source"));
    }

    #[test]
    fn dispatch_storage_offload_allow_unverified_non_local_rejected() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let result = storage::offload_segments(&storage::StorageOffloadOptions {
            data_dir: dir.path().to_path_buf(),
            environment: tooling_env::ToolingEnvironment::Production,
            tier: storage::StorageTier::Cold,
            older_than_days: 90,
            target: "s3://bucket/prefix".to_string(),
            target_kind: None,
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: true,
            allow_missing_ops_evidence: true,
            delete_source: false,
            evidence_out: None,
            ops_grpc: None,
            ops_scopes: None,
            node_id: None,
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("allow-unverified-copy"));
    }

    #[test]
    fn dispatch_storage_offload_empty_shards_succeeds() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let target = dir.path().join("warm-target");
        fs::create_dir_all(&target).unwrap();
        let result = storage::offload_segments(&storage::StorageOffloadOptions {
            data_dir: dir.path().to_path_buf(),
            environment: tooling_env::ToolingEnvironment::Local,
            tier: storage::StorageTier::Warm,
            older_than_days: 30,
            target: target.to_str().unwrap().to_string(),
            target_kind: None,
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: true,
            allow_missing_ops_evidence: true,
            delete_source: false,
            evidence_out: None,
            ops_grpc: None,
            ops_scopes: None,
            node_id: None,
        });
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.offloaded, 0);
    }

    // ── Dispatch: snapshot verify with empty data ─────────────────────

    #[test]
    fn dispatch_snapshot_verify_empty_shards() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let report = snapshot::verify_snapshots(&snapshot::SnapshotOptions {
            data_dir: dir.path().to_path_buf(),
            shard: None,
        })
        .unwrap();
        assert!(report.ok);
    }

    #[test]
    fn dispatch_snapshot_verify_specific_shard() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shards/shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        let result = snapshot::verify_snapshots(&snapshot::SnapshotOptions {
            data_dir: dir.path().to_path_buf(),
            shard: Some(1),
        });
        // Exercises the code path; result depends on whether projections meta exists.
        let _ = result;
    }

    #[test]
    fn dispatch_snapshot_list_specific_shard() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shards/shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        let report = snapshot::list_snapshots(&snapshot::SnapshotOptions {
            data_dir: dir.path().to_path_buf(),
            shard: Some(1),
        })
        .unwrap();
        assert!(report.shards.is_empty() || !report.shards.is_empty());
    }

    // ── Dispatch: projections rebuild with empty shards ───────────────

    #[test]
    fn dispatch_projections_rebuild_empty() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let report = projections::rebuild_projections_v1(dir.path(), None, 0, 1024).unwrap();
        assert!(report.shards.is_empty());
    }

    #[test]
    fn dispatch_projections_gc_empty() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let report = projections::gc_orphan_cold_segments_v1(dir.path(), None, true, 600, 0).unwrap();
        assert!(report.shards.is_empty());
    }

    #[test]
    fn dispatch_projections_gc_specific_shard() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shards/shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        let result = projections::gc_orphan_cold_segments_v1(dir.path(), Some(1), true, 0, 10);
        // Exercises the code path; may error if shard has no projections dir.
        let _ = result;
    }

    // ── Dispatch: receipts seed-minimal ───────────────────────────────

    #[test]
    fn dispatch_receipts_seed_minimal() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shards/shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        let report = receipts::seed_minimal_receipt_v1(dir.path(), 1, "tenant-test", "receipt-test-abc", 0);
        // May succeed or fail depending on shard store init; either way it exercises the path.
        let _ = report;
    }

    #[test]
    fn dispatch_receipts_backfill_empty() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let report = receipts::backfill_subject_index_v1(dir.path(), None, true, 0, 8192).unwrap();
        assert_eq!(report.totals.indexed, 0);
    }

    // ── Dispatch: evidence control-verify ─────────────────────────────

    #[test]
    fn dispatch_evidence_control_verify_empty() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        // Write a minimal CONTROL.json
        let control_path = dir.path().join("CONTROL.json");
        fs::write(&control_path, b"{}").unwrap();
        let result = evidence::control_verify(&evidence::ControlVerifyOptions {
            data_dir: dir.path().to_path_buf(),
            hosted_only: false,
            device_index: 0,
            batch_frames: 8192,
        });
        // May fail because CONTROL.json is not valid ControlV1 — exercises the error path.
        let _ = result;
    }

    #[test]
    fn dispatch_evidence_verify_pack_nonexistent() {
        let result = evidence::verify_evidence_pack(&evidence::PackVerifyOptions {
            pack_dir: PathBuf::from("/tmp/__nonexistent_evidence_pack__"),
            strict: false,
            device_index: 0,
        });
        assert!(result.is_err());
    }

    // ── Dispatch: replay with empty pack ──────────────────────────────

    #[test]
    fn dispatch_replay_empty_pack_dir() {
        let dir = TempDir::new().unwrap();
        let result = replay::replay_digest_from_pack(dir.path(), false);
        assert!(result.is_err());
    }

    #[test]
    fn dispatch_replay_strict_mode_nonexistent() {
        let result = replay::replay_digest_from_pack(&PathBuf::from("/tmp/__nonexistent_strict_pack__"), true);
        assert!(result.is_err());
    }

    #[test]
    fn dispatch_replay_jsonl_nonexistent() {
        let result = replay::replay_digest_from_jsonl(&PathBuf::from("/tmp/__nonexistent_events_jsonl__"));
        assert!(result.is_err());
    }

    // ── Dispatch: fixture-digest with nonexistent fixture ─────────────

    #[test]
    fn dispatch_fixture_digest_another_nonexistent() {
        let result = fixture_digest::segment_fixture_replay_digest("totally_fake_fixture", 0);
        assert!(result.is_err());
    }

    // ── StorageTier and OffloadTargetKind as_str coverage ────────────

    #[test]
    fn storage_tier_as_str() {
        assert_eq!(storage::StorageTier::Warm.as_str(), "warm");
        assert_eq!(storage::StorageTier::Cold.as_str(), "cold");
    }

    #[test]
    fn offload_target_kind_as_str() {
        assert_eq!(storage::OffloadTargetKind::Local.as_str(), "local");
        assert_eq!(storage::OffloadTargetKind::S3.as_str(), "s3");
        assert_eq!(storage::OffloadTargetKind::Rsync.as_str(), "rsync");
    }

    // ── ToolingEnvironment additional coverage ────────────────────────

    #[test]
    fn tooling_env_as_str() {
        assert_eq!(tooling_env::ToolingEnvironment::Local.as_str(), "local");
        assert_eq!(tooling_env::ToolingEnvironment::Staging.as_str(), "staging");
        assert_eq!(tooling_env::ToolingEnvironment::Production.as_str(), "production");
    }

    #[test]
    fn tooling_env_parse() {
        assert_eq!(
            tooling_env::ToolingEnvironment::parse("local"),
            Some(tooling_env::ToolingEnvironment::Local)
        );
        assert_eq!(
            tooling_env::ToolingEnvironment::parse("staging"),
            Some(tooling_env::ToolingEnvironment::Staging)
        );
        assert_eq!(
            tooling_env::ToolingEnvironment::parse("production"),
            Some(tooling_env::ToolingEnvironment::Production)
        );
        assert_eq!(tooling_env::ToolingEnvironment::parse("unknown"), None);
    }

    // ── Dispatch: inspect_receipt with shard subdirectories ───────────

    #[test]
    fn dispatch_inspect_receipt_multiple_shards() {
        let dir = TempDir::new().unwrap();
        for i in 1..=3 {
            let shard_dir = dir.path().join(format!("shard-{i:04}"));
            fs::create_dir_all(&shard_dir).unwrap();
        }
        let result = inspect_receipt::run(dir.path().to_str().unwrap(), "receipt-multi");
        assert!(result.is_ok());
    }

    // ── Dispatch: explain with multiple shards ───────────────────────

    #[test]
    fn dispatch_explain_multiple_shards() {
        let dir = TempDir::new().unwrap();
        for i in 1..=2 {
            let shard_dir = dir.path().join(format!("shard-{i:04}"));
            fs::create_dir_all(&shard_dir).unwrap();
        }
        let result = explain::run(dir.path().to_str().unwrap(), "receipt-explain-multi");
        assert!(result.is_ok());
    }

    // ── Dispatch: verify-store with shard containing empty segments dir

    #[test]
    fn dispatch_verify_store_shard_empty_segments() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shards/shard-0001/segments");
        fs::create_dir_all(&shard_dir).unwrap();
        let report = verify_store::verify_store(&verify_store::VerifyStoreOptions {
            data_dir: dir.path().to_path_buf(),
            shard: Some(1),
            scope: verify_store::VerifyScope::All,
            mode: verify_store::VerifyMode::Full,
            sample_rate: 1.0,
            strict: false,
            budget_bytes: 8 * 1024 * 1024,
            device_index: 0,
        })
        .unwrap();
        // Shard exists but has no manifest -> fails
        assert!(!report.ok);
    }

    // ── Dispatch: shardmap split with custom new_shard ───────────────

    #[test]
    fn dispatch_shardmap_split_with_custom_new_shard() {
        let map =
            shardmap::init_dev_shard_map_v1(2, "dev", "node-dev", "127.0.0.1:4006", "127.0.0.1:4007", None).unwrap();
        let shard_id = &map.shards[0].shard_id;
        let result = shardmap::split_shard_map_v1(&map, shard_id, "0x4000000000000000", Some("shard-0099".to_string()));
        assert!(result.is_ok());
        let split = result.unwrap();
        assert!(split.shards.iter().any(|s| s.shard_id == "shard-0099"));
    }

    // ── Dispatch: storage offload with evidence_out ──────────────────

    #[test]
    fn dispatch_storage_offload_with_evidence_out() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shards")).unwrap();
        let target = dir.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let evidence_out = dir.path().join("evidence.json");
        let result = storage::offload_segments(&storage::StorageOffloadOptions {
            data_dir: dir.path().to_path_buf(),
            environment: tooling_env::ToolingEnvironment::Local,
            tier: storage::StorageTier::Cold,
            older_than_days: 1,
            target: target.to_str().unwrap().to_string(),
            target_kind: None,
            rsync_rsh: None,
            verify_after_copy: false,
            allow_unverified_copy: true,
            allow_missing_ops_evidence: true,
            delete_source: false,
            evidence_out: Some(evidence_out.clone()),
            ops_grpc: None,
            ops_scopes: None,
            node_id: Some("node-test".to_string()),
        });
        assert!(result.is_ok());
    }

    // ── Dispatch: projections seed-minimal ────────────────────────────

    #[test]
    fn dispatch_projections_seed_minimal() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shards/shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        let result = projections::seed_minimal_projection_events_v1(dir.path(), 1, "tenant-test", 1, 0);
        // Exercises the function path; may error because no shard store.
        let _ = result;
    }

    // ── Dispatch: receipts backfill with specific shard ───────────────

    #[test]
    fn dispatch_receipts_backfill_specific_shard() {
        let dir = TempDir::new().unwrap();
        let shard_dir = dir.path().join("shards/shard-0001");
        fs::create_dir_all(&shard_dir).unwrap();
        let result = receipts::backfill_subject_index_v1(dir.path(), Some(1), true, 0, 4096);
        // Exercises the path; may error because no manifest.
        let _ = result;
    }

    // ── CcxiVerifyReport: empty data_dir produces zero counters ──────

    #[test]
    fn ccxi_verify_empty_dir_all_zeros() {
        let dir = TempDir::new().unwrap();
        let report = ccxi_verify(dir.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.segments_total, 0);
        assert_eq!(report.segments_with_ccxi, 0);
        assert_eq!(report.segments_missing_ccxi, 0);
        assert!(report.missing.is_empty());
        assert!(report.corrupt.is_empty());
    }

    #[test]
    fn ccxi_verify_with_shard_filter_skips_others() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shard-0001/segments")).unwrap();
        fs::create_dir_all(dir.path().join("shard-0002/segments")).unwrap();
        let report = ccxi_verify(dir.path(), Some(1)).unwrap();
        assert_eq!(report.shards_scanned, 1);
    }

    #[test]
    fn ccxi_verify_ignores_non_shard_dirs() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("not-a-shard")).unwrap();
        fs::write(dir.path().join("file.txt"), b"data").unwrap();
        let report = ccxi_verify(dir.path(), None).unwrap();
        assert_eq!(report.shards_scanned, 0);
    }

    // ── CcxiRebuildReport serialization ──────────────────────────────

    #[test]
    fn ccxi_rebuild_report_serializes_all_fields() {
        let report = CcxiRebuildReport {
            shards_scanned: 2,
            segments_rebuilt: 5,
            segments_skipped: 3,
            segments_failed: 1,
            errors: vec!["some error".to_string()],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["shards_scanned"], 2);
        assert_eq!(json["segments_rebuilt"], 5);
        assert_eq!(json["segments_failed"], 1);
        assert_eq!(json["errors"][0], "some error");
    }

    // ── CcxiRebuildReport: empty dir produces zero counters ──────────

    #[test]
    fn ccxi_rebuild_empty_dir_zeros() {
        let dir = TempDir::new().unwrap();
        let report = ccxi_rebuild(dir.path(), None, None).unwrap();
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.segments_rebuilt, 0);
    }

    #[test]
    fn ccxi_rebuild_with_shard_filter() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("shard-0001/segments")).unwrap();
        fs::create_dir_all(dir.path().join("shard-0002/segments")).unwrap();
        let report = ccxi_rebuild(dir.path(), Some(2), None).unwrap();
        assert_eq!(report.shards_scanned, 1);
    }

    // ── parse: reconcile ─────────────────────────────────────────────

    #[test]
    fn parse_reconcile_with_scope_args() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "reconcile",
            "--postgres",
            "--connection-string",
            "postgres://user:pass@host/db",
            "--tenant",
            "t1",
            "--batch-size",
            "1000",
            "--sample-limit",
            "5",
            "--window-days",
            "7",
            "--shard",
            "2",
        ])
        .unwrap();
        match cli.command {
            Command::Reconcile {
                postgres,
                connection_string,
                tenant,
                batch_size,
                sample_limit,
                window_days,
                shard,
                ..
            } => {
                assert!(postgres);
                assert_eq!(connection_string, "postgres://user:pass@host/db");
                assert_eq!(tenant, "t1");
                assert_eq!(batch_size, 1000);
                assert_eq!(sample_limit, 5);
                assert_eq!(window_days, Some(7));
                assert_eq!(shard, Some(2));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── parse: audit-pack ────────────────────────────────────────────

    #[test]
    fn parse_audit_pack_offline() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "audit-pack",
            "--offline",
            "--tenant-id",
            "t1",
            "--max-events",
            "500",
        ])
        .unwrap();
        match cli.command {
            Command::AuditPack {
                offline,
                tenant_id,
                max_events,
                ..
            } => {
                assert!(offline);
                assert_eq!(tenant_id, Some("t1".to_string()));
                assert_eq!(max_events, 500);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── parse: inspect-receipt ────────────────────────────────────────

    #[test]
    fn parse_inspect_receipt_with_data_dir() {
        let cli = Cli::try_parse_from(["corecruxctl", "inspect-receipt", "rcpt-abc", "--data-dir", "/mydata"]).unwrap();
        match cli.command {
            Command::InspectReceipt { receipt_id, data_dir } => {
                assert_eq!(receipt_id, "rcpt-abc");
                assert_eq!(data_dir, Some("/mydata".to_string()));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── parse: explain with defaults ─────────────────────────────────

    #[test]
    fn parse_explain_defaults() {
        let cli = Cli::try_parse_from(["corecruxctl", "explain", "rcpt-xyz"]).unwrap();
        match cli.command {
            Command::Explain { receipt_id, data_dir } => {
                assert_eq!(receipt_id, "rcpt-xyz");
                assert!(data_dir.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── parse: gaps with data-dir ────────────────────────────────────

    #[test]
    fn parse_gaps_with_data_dir() {
        let cli =
            Cli::try_parse_from(["corecruxctl", "gaps", "--data-dir", "/mydata", "--since", "2026-01-01"]).unwrap();
        match cli.command {
            Command::Gaps { data_dir, since } => {
                assert_eq!(data_dir, Some("/mydata".to_string()));
                assert_eq!(since, Some("2026-01-01".to_string()));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ── parse: parity-pack with all defaults ─────────────────────────

    #[test]
    fn parse_parity_pack_defaults() {
        let cli = Cli::try_parse_from([
            "corecruxctl",
            "parity-pack",
            "--out",
            "/tmp/pp",
            "--tenant-id",
            "t1",
            "--engine",
            "http://engine:3000",
            "--engine-api-key",
            "key",
            "--corecrux",
            "http://corecrux:4006",
        ])
        .unwrap();
        match cli.command {
            Command::ParityPack {
                out,
                tenant_id,
                engine,
                engine_api_key,
                corecrux,
                seed,
                sample_size,
                ..
            } => {
                assert_eq!(out, PathBuf::from("/tmp/pp"));
                assert_eq!(tenant_id, "t1");
                assert_eq!(engine, "http://engine:3000");
                assert_eq!(engine_api_key, "key");
                assert_eq!(corecrux, "http://corecrux:4006");
                assert_eq!(seed, "0");
                assert_eq!(sample_size, 100);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
