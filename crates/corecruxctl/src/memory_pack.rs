// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl memory export|import` — `.cruxpack` memory portability
//! (ExecPlan `identity-memory-portability-2026-06-11`, G5; spec:
//! `PlanCrux docs/master-plan/shared/Memory-Portability-v1.md`).
//!
//! - `export` reads the on-disk stores directly (read-only against
//!   `--data-dir`, safe while the daemon runs — the `audit-export`
//!   precedent) and signs the pack with the daemon passport key
//!   (`data_dir/passport.key`).
//! - `import` talks HTTP to the daemon (`POST /v1/memory/import`) so writes
//!   are authenticated, scoped, and journaled through the normal substrate
//!   path. It refuses to run unless `CRUX_MEMORY_IMPORT=1` (mirroring the
//!   daemon-side gate).
//!
//! There is no unified `crux` binary yet; `crux memory export|import` is the
//! documented future alias for these commands.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use corecrux_memory::cruxpack::{self, CruxPack, ExportOptions, PrivateSummary, CRUXPACK_SCHEMA_V1};
use corecrux_memory::fact_store::FactStore;
use corecrux_memory::session_store::SessionStore;
use crux_session::passport::LocalPassportKey;

/// The exact phrase the operator must type to opt private facts into a pack
/// (Art. 14: explicit per-invocation consent; no flag-only bypass).
pub const INCLUDE_PRIVATE_CONFIRM_PHRASE: &str = "include private";

#[derive(Debug, thiserror::Error)]
pub enum MemoryPackError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("passport key error: {0}")]
    Passport(String),
    #[error("pack error: {0}")]
    Pack(#[from] corecrux_memory::cruxpack::PackVerifyError),
    #[error("aborted: --include-private requires typing '{INCLUDE_PRIVATE_CONFIRM_PHRASE}' at the prompt")]
    ConfirmationDeclined,
    #[error("memory import is disabled — set CRUX_MEMORY_IMPORT=1 on both the daemon and this CLI to enable")]
    ImportDisabled,
    #[error("invalid --map-principal '{0}' (expected src=dst)")]
    BadPrincipalMap(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("daemon returned status {status}: {body}")]
    UpstreamStatus { status: u16, body: String },
}

// ─── export ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct MemoryExportArgs {
    pub data_dir: PathBuf,
    pub out: PathBuf,
    pub tenant: String,
    pub since: Option<String>,
    pub include_private: bool,
}

#[derive(Debug)]
pub struct MemoryExportReport {
    pub facts: usize,
    pub sessions: usize,
    pub passport_fpr: String,
    pub blake3_content_hash: String,
    pub excluded: PrivateSummary,
}

/// Render the pre-confirmation summary for `--include-private`.
pub fn render_private_summary(summary: &PrivateSummary) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str("--include-private will copy the following born-private records into the pack:\n");
    let _ = writeln!(out, "  private-flagged facts: {}", summary.private_flagged);
    for (prefix, count) in &summary.by_reserved_prefix {
        let _ = writeln!(out, "  {prefix:<28} {count}");
    }
    let _ = writeln!(
        out,
        "  (deleted facts: {} — ALWAYS excluded, no flag overrides erasure)",
        summary.deleted_excluded
    );
    out
}

/// Run the export. `confirm_include_private` is invoked (with the scan
/// summary) only when `--include-private` is set; returning `false` aborts
/// before anything is written. The CLI wires this to a typed stdin prompt;
/// tests inject a closure.
pub fn run_memory_export(
    args: &MemoryExportArgs,
    confirm_include_private: impl FnOnce(&PrivateSummary) -> bool,
) -> Result<MemoryExportReport, MemoryPackError> {
    let store = FactStore::with_persistence(&args.data_dir)?;
    let sessions = SessionStore::with_persistence(&args.data_dir)?;

    let scan = cruxpack::private_summary(&store);
    if args.include_private && !confirm_include_private(&scan) {
        return Err(MemoryPackError::ConfirmationDeclined);
    }

    let since = match &args.since {
        Some(raw) => Some(
            chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|e| MemoryPackError::Passport(format!("invalid --since '{raw}': {e}")))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };

    // The daemon-level passport key (read-or-init, exactly what corecruxd
    // does on boot — exporting from a dir the daemon never started in mints
    // the same identity the daemon would).
    let key = LocalPassportKey::from_data_dir(&args.data_dir)
        .map_err(|e| MemoryPackError::Passport(format!("load {}/passport.key: {e:?}", args.data_dir.display())))?;

    let opts = ExportOptions {
        tenant_id: args.tenant.clone(),
        since,
        include_private: args.include_private,
        include_sessions: true,
        tool: format!("corecruxctl {}", env!("CARGO_PKG_VERSION")),
        daemon_install_fpr: read_install_fpr(&args.data_dir),
        chain_head: journal_chain_head(&args.data_dir),
    };

    let (sections, excluded) = cruxpack::build_pack_sections(&store, Some(&sessions), &opts);
    let manifest = cruxpack::build_manifest(&sections, key.passport_fpr(), key.public_key_hex(), &opts);
    let pack = cruxpack::sign_pack(manifest, sections, |hash| key.sign_hash(hash))?;

    let bytes = serde_json::to_vec(&pack)?;
    let mut file = std::fs::File::create(&args.out)?;
    file.write_all(&bytes)?;
    file.sync_all()?;

    Ok(MemoryExportReport {
        facts: pack.manifest.counts.facts,
        sessions: pack.manifest.counts.sessions,
        passport_fpr: pack.manifest.passport_fpr.clone(),
        blake3_content_hash: pack.blake3_content_hash.clone(),
        excluded,
    })
}

/// `blake3(install_uuid)` hex when `data_dir/.install-uuid` exists — never
/// the raw UUID.
fn read_install_fpr(data_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(data_dir.join(".install-uuid")).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(blake3::hash(trimmed.as_bytes()).to_hex().to_string())
}

/// Fact-journal head hash at export time (`blake3:<hex>` over the journal
/// bytes), when the journal exists.
fn journal_chain_head(data_dir: &Path) -> Option<String> {
    let bytes = std::fs::read(data_dir.join("facts.jsonl")).ok()?;
    Some(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

// ─── import ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct MemoryImportArgs {
    pub file: PathBuf,
    pub tenant: String,
    pub map_principal: Vec<String>,
    pub dry_run: bool,
}

/// Wrapper the daemon's `POST /v1/memory/import` accepts.
#[derive(Debug, serde::Serialize)]
struct MemoryImportRequest<'a> {
    tenant_id: &'a str,
    dry_run: bool,
    principal_map: BTreeMap<String, String>,
    pack: &'a CruxPack,
}

pub fn parse_principal_map(raw: &[String]) -> Result<BTreeMap<String, String>, MemoryPackError> {
    let mut map = BTreeMap::new();
    for entry in raw {
        let (src, dst) = entry
            .split_once('=')
            .ok_or_else(|| MemoryPackError::BadPrincipalMap(entry.clone()))?;
        if src.is_empty() || dst.is_empty() {
            return Err(MemoryPackError::BadPrincipalMap(entry.clone()));
        }
        map.insert(src.to_string(), dst.to_string());
    }
    Ok(map)
}

/// Read + locally verify a pack file (fail fast with a typed error before
/// any network call).
pub fn read_and_verify_pack(path: &Path) -> Result<CruxPack, MemoryPackError> {
    let bytes = std::fs::read(path)?;
    let pack: CruxPack = serde_json::from_slice(&bytes)?;
    if pack.schema_version != CRUXPACK_SCHEMA_V1 {
        // verify_pack would also catch this; surface it as the same error.
        return Err(cruxpack::PackVerifyError::UnsupportedSchema(pack.schema_version.clone()).into());
    }
    cruxpack::verify_pack(&pack)?;
    Ok(pack)
}

/// Run the import against the daemon. Gated by `CRUX_MEMORY_IMPORT=1`.
pub fn run_memory_import(args: &MemoryImportArgs) -> Result<serde_json::Value, MemoryPackError> {
    if !std::env::var("CRUX_MEMORY_IMPORT").map(|v| v == "1").unwrap_or(false) {
        return Err(MemoryPackError::ImportDisabled);
    }
    let pack = read_and_verify_pack(&args.file)?;
    let principal_map = parse_principal_map(&args.map_principal)?;

    let base = std::env::var("CORECRUXD_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1:14800".to_string());
    let bearer = std::env::var("CRUX_AGENT_TOKEN").ok().filter(|s| !s.is_empty());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .build()
        .into();

    let url = format!("{}/v1/memory/import", base.trim_end_matches('/'));
    let body = MemoryImportRequest {
        tenant_id: &args.tenant,
        dry_run: args.dry_run,
        principal_map,
        pack: &pack,
    };
    let mut req = agent.post(&url);
    if let Some(token) = &bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req.send_json(&body).map_err(|e| match e {
        ureq::Error::StatusCode(code) => MemoryPackError::UpstreamStatus {
            status: code,
            body: String::new(),
        },
        other => MemoryPackError::Transport(other.to_string()),
    })?;
    let text = resp
        .into_body()
        .read_to_string()
        .map_err(|e| MemoryPackError::Transport(e.to_string()))?;
    Ok(serde_json::from_str(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_memory::fact_store::StoreFact;

    fn seed_store(dir: &Path) {
        let mut store = FactStore::with_persistence(dir).expect("store");
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "project-alpha".into(),
            key: "status".into(),
            value: "public-value".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "secret".into(),
            key: "k".into(),
            value: "private-value-stays-home".into(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
        let erased = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "gone".into(),
            key: "k".into(),
            value: "erased-value".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.delete(&erased.fact_id);
    }

    #[test]
    fn export_writes_verifiable_pack_excluding_private_and_deleted() {
        let dir = tempfile::tempdir().expect("dir");
        seed_store(dir.path());
        let out = dir.path().join("memory.cruxpack");
        let report = run_memory_export(
            &MemoryExportArgs {
                data_dir: dir.path().to_path_buf(),
                out: out.clone(),
                tenant: "local".into(),
                since: None,
                include_private: false,
            },
            |_| panic!("must not prompt without --include-private"),
        )
        .expect("export");

        assert_eq!(report.facts, 1);
        let pack = read_and_verify_pack(&out).expect("verify");
        assert_eq!(pack.manifest.counts.facts, 1);
        assert_eq!(pack.sections.facts[0].entity, "project-alpha");
        let raw = std::fs::read_to_string(&out).expect("read");
        assert!(!raw.contains("private-value-stays-home"));
        assert!(!raw.contains("erased-value"));
        // Signed by the data-dir passport key (self-certifying).
        let key = LocalPassportKey::from_data_dir(dir.path()).expect("key");
        assert_eq!(pack.manifest.passport_fpr, key.passport_fpr());
    }

    #[test]
    fn include_private_requires_confirmation() {
        let dir = tempfile::tempdir().expect("dir");
        seed_store(dir.path());
        let out = dir.path().join("memory.cruxpack");
        let err = run_memory_export(
            &MemoryExportArgs {
                data_dir: dir.path().to_path_buf(),
                out: out.clone(),
                tenant: "local".into(),
                since: None,
                include_private: true,
            },
            |summary| {
                assert_eq!(summary.private_flagged, 1);
                false // operator declined
            },
        )
        .unwrap_err();
        assert!(matches!(err, MemoryPackError::ConfirmationDeclined));
        assert!(!out.exists(), "nothing may be written on declined confirmation");

        // Confirmed: private rides, erased still never does.
        let report = run_memory_export(
            &MemoryExportArgs {
                data_dir: dir.path().to_path_buf(),
                out: out.clone(),
                tenant: "local".into(),
                since: None,
                include_private: true,
            },
            |_| true,
        )
        .expect("export");
        assert_eq!(report.facts, 2);
        let raw = std::fs::read_to_string(&out).expect("read");
        assert!(raw.contains("private-value-stays-home"));
        assert!(!raw.contains("erased-value"));
    }

    #[test]
    fn import_refuses_without_flag() {
        // Serial-safety: this test relies on CRUX_MEMORY_IMPORT being unset
        // in the test environment (we never set it in-process).
        let dir = tempfile::tempdir().expect("dir");
        let err = run_memory_import(&MemoryImportArgs {
            file: dir.path().join("nope.cruxpack"),
            tenant: "local".into(),
            map_principal: vec![],
            dry_run: true,
        })
        .unwrap_err();
        assert!(matches!(err, MemoryPackError::ImportDisabled));
    }

    #[test]
    fn principal_map_parses_and_rejects_malformed() {
        let map = parse_principal_map(&["a=b".into(), "ce:x:y=tenant:t:y".into()]).expect("ok");
        assert_eq!(map.get("a").map(String::as_str), Some("b"));
        assert_eq!(map.len(), 2);
        assert!(parse_principal_map(&["broken".into()]).is_err());
        assert!(parse_principal_map(&["=b".into()]).is_err());
    }

    #[test]
    fn tampered_pack_file_rejected_before_any_network_call() {
        let dir = tempfile::tempdir().expect("dir");
        seed_store(dir.path());
        let out = dir.path().join("memory.cruxpack");
        run_memory_export(
            &MemoryExportArgs {
                data_dir: dir.path().to_path_buf(),
                out: out.clone(),
                tenant: "local".into(),
                since: None,
                include_private: false,
            },
            |_| true,
        )
        .expect("export");
        let raw = std::fs::read_to_string(&out).expect("read");
        let tampered = raw.replace("public-value", "evil-value");
        std::fs::write(&out, tampered).expect("write");
        let err = read_and_verify_pack(&out).unwrap_err();
        assert!(matches!(
            err,
            MemoryPackError::Pack(corecrux_memory::cruxpack::PackVerifyError::HashMismatch { .. })
        ));
    }
}
