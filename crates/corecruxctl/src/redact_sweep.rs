// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! One-time `__ops__::*` fact sweep for secret-shaped values (ExecPlan
//! `crux-log-redaction-2026-06-11`, design item 6).
//!
//! Scans the on-disk fact store for ops-namespace facts whose values hit the
//! redaction value rules (JWT, `sk-`, `ghp_`, `AKIA`, PEM, plus any
//! `CORECRUXD_REDACT_EXTRA_PATTERNS`) or whose key/value form a denylisted
//! `key=value` shape. **Dry-run is the default and only reports** — every
//! preview in the report is scrubbed through the redactor in `on` mode before
//! it is printed, so the report never contains a matched secret in plaintext.
//!
//! The delete pass is intentionally hard to reach:
//!
//! 1. `--delete` must be passed, AND
//! 2. `--confirm delete-matched-ops-facts` must match exactly, AND
//! 3. the daemon must NOT be running against the data dir (we take the same
//!    `LOCK` file exclusively that `corecruxd` holds while up).
//!
//! Deletion goes through [`FactStore::try_delete`] — the normal soft-delete
//! path that appends a durable `Delete` tombstone to the fact journal before
//! flipping the flag. Never the raw filesystem. Recovery after a delete pass
//! is design-review-only: snapshot the data dir first (operator runbook in the
//! ExecPlan's M4 gate package).

use std::path::{Path, PathBuf};

use corecrux_memory::fact_store::FactStore;
use crux_observe::redact::{RedactMode, Redactor};
use fs2::FileExt;
use serde::Serialize;

type DynError = Box<dyn std::error::Error + Send + Sync>;

/// Confirmation string required (verbatim) for the delete pass.
pub const DELETE_CONFIRM_PHRASE: &str = "delete-matched-ops-facts";

/// Entity prefixes scanned by default: both ops namespaces that appear in
/// the reserved-prefix tables (`fact_privacy::DAEMON_OWNED_ENTITY_PREFIXES`).
pub const DEFAULT_ENTITY_PREFIXES: &[&str] = &["__ops__::", "__ops::"];

/// Maximum characters of scrubbed preview carried per finding.
const PREVIEW_MAX_CHARS: usize = 240;

#[derive(Debug, Clone)]
pub struct RedactSweepArgs {
    /// Data directory holding the fact journal (`CORECRUXD_DATA_DIR`).
    pub data_dir: PathBuf,
    /// Entity prefixes to scan. Empty = [`DEFAULT_ENTITY_PREFIXES`].
    pub entity_prefixes: Vec<String>,
    /// Run the delete pass (still requires `confirm` + a stopped daemon).
    pub delete: bool,
    /// Must equal [`DELETE_CONFIRM_PHRASE`] for the delete pass to run.
    pub confirm: Option<String>,
}

/// One matched fact. `preview` is the composed `key=value` line AFTER
/// scrubbing in `on` mode, truncated — never the stored plaintext.
#[derive(Debug, Clone, Serialize)]
pub struct SweepFinding {
    pub fact_id: String,
    pub tenant_hash: String,
    pub entity: String,
    pub key: String,
    pub stored_at: String,
    /// Redaction rule ids that hit (e.g. `jwt`, `sk`, `fld.api_key`).
    pub rules: Vec<String>,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepReport {
    /// `dry-run` or `delete`.
    pub mode: String,
    pub entity_prefixes: Vec<String>,
    /// Non-deleted facts under the scanned prefixes.
    pub scanned: u64,
    pub matched: u64,
    /// Facts soft-deleted via the journal tombstone path (delete pass only).
    pub deleted: u64,
    pub findings: Vec<SweepFinding>,
}

/// Run the sweep. Dry-run unless `args.delete` — and the delete pass refuses
/// to start without the exact confirmation phrase and an exclusive hold on
/// the daemon's `LOCK` file.
pub fn run_redact_sweep(args: RedactSweepArgs) -> Result<SweepReport, DynError> {
    let prefixes: Vec<String> = if args.entity_prefixes.is_empty() {
        DEFAULT_ENTITY_PREFIXES.iter().map(|p| (*p).to_string()).collect()
    } else {
        args.entity_prefixes.clone()
    };

    // Fail fast on a misconfigured delete pass BEFORE touching the store.
    let delete_pass = args.delete;
    if delete_pass {
        match args.confirm.as_deref() {
            Some(c) if c == DELETE_CONFIRM_PHRASE => {}
            _ => {
                return Err(format!(
                    "refusing delete pass: pass --confirm {DELETE_CONFIRM_PHRASE} (exactly). \
                     Dry-run (the default) needs neither flag."
                )
                .into());
            }
        }
    }
    // Hold the daemon's LOCK exclusively for the whole delete pass: refuses
    // to run while corecruxd is up, and blocks a daemon start mid-pass.
    let _daemon_lock = if delete_pass {
        Some(acquire_daemon_lock(&args.data_dir)?)
    } else {
        None
    };

    // Forced `on` mode: matching + scrubbed previews must work regardless of
    // the operator's CORECRUXD_REDACT setting; env extra patterns still apply.
    let redactor = Redactor::with_mode_and_env_extras(RedactMode::On);

    let mut store = FactStore::with_persistence(&args.data_dir)?;

    let mut scanned = 0u64;
    let mut findings: Vec<SweepFinding> = Vec::new();
    for fact in store.all_facts() {
        if fact.deleted {
            continue;
        }
        if !prefixes.iter().any(|p| fact.entity.starts_with(p)) {
            continue;
        }
        scanned += 1;

        let before = counts_map(&redactor);
        let composed = format!("{}={}", fact.key, fact.value);
        let scrubbed = redactor.redact_line(&composed);
        let after = counts_map(&redactor);

        let mut rules: Vec<String> = after
            .into_iter()
            .filter(|(rule, n)| *n > before.get(rule).copied().unwrap_or(0))
            .map(|(rule, _)| rule)
            .collect();
        rules.sort();
        if rules.is_empty() {
            continue;
        }

        let mut preview: String = scrubbed.chars().take(PREVIEW_MAX_CHARS).collect();
        if scrubbed.chars().count() > PREVIEW_MAX_CHARS {
            preview.push_str("…[truncated]");
        }
        findings.push(SweepFinding {
            fact_id: fact.fact_id.clone(),
            tenant_hash: fact.tenant_hash.clone(),
            entity: fact.entity.clone(),
            key: fact.key.clone(),
            stored_at: fact.stored_at.to_rfc3339(),
            rules,
            preview,
        });
    }

    let mut deleted = 0u64;
    if delete_pass {
        for finding in &findings {
            if store.try_delete(&finding.tenant_hash, &finding.fact_id)? {
                deleted += 1;
            }
        }
    }

    Ok(SweepReport {
        mode: if delete_pass { "delete" } else { "dry-run" }.to_string(),
        entity_prefixes: prefixes,
        scanned,
        matched: findings.len() as u64,
        deleted,
        findings,
    })
}

fn counts_map(redactor: &Redactor) -> std::collections::HashMap<String, u64> {
    redactor.counts().into_iter().collect()
}

/// Take the same `LOCK` file `corecruxd` holds while running. Failure means
/// the daemon (or another exclusive tool) is live against this data dir.
fn acquire_daemon_lock(data_dir: &Path) -> Result<std::fs::File, DynError> {
    let lock_path = data_dir.join("LOCK");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    file.try_lock_exclusive().map_err(|err| {
        format!(
            "refusing delete pass: cannot take exclusive lock on {} ({err}). \
             Stop corecruxd (and snapshot the data dir) before a delete pass.",
            lock_path.display()
        )
    })?;
    Ok(file)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use corecrux_memory::fact_store::StoreFact;

    // SYNTHETIC fixtures only — clearly fake, never real credentials.
    const FIX_JWT: &str = "eyJfixtureSYNTHETICheader00.eyJfixturePayload00.fixtureSigSYNTHETIC";
    const FIX_SK: &str = "sk-fixtureSYNTHETIC0000000000";

    fn seed(dir: &Path) -> (String, String, String) {
        let mut store = FactStore::with_persistence(dir).unwrap();
        let fact = |entity: &str, key: &str, value: &str| StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        let hit = store.store(fact(
            "__ops__::error:evt",
            "error:1",
            &format!("{{\"message\": \"call failed with {FIX_JWT}\"}}"),
        ));
        let clean = store.store(fact("__ops__::error:evt", "error:2", "{\"message\": \"disk full\"}"));
        // Secret-shaped but OUTSIDE the ops namespaces — must never be touched.
        let outside = store.store(fact("project-x", "note", &format!("value {FIX_SK} here")));
        (hit.fact_id, clean.fact_id, outside.fact_id)
    }

    fn dry_run(dir: &Path) -> SweepReport {
        run_redact_sweep(RedactSweepArgs {
            data_dir: dir.to_path_buf(),
            entity_prefixes: Vec::new(),
            delete: false,
            confirm: None,
        })
        .unwrap()
    }

    #[test]
    fn dry_run_reports_without_mutation_and_scrubs_previews() {
        let td = tempfile::tempdir().unwrap();
        let (hit_id, _clean_id, outside_id) = seed(td.path());

        let report = dry_run(td.path());
        assert_eq!(report.mode, "dry-run");
        assert_eq!(report.scanned, 2, "only the two ops facts are scanned");
        assert_eq!(report.matched, 1);
        assert_eq!(report.deleted, 0);
        let finding = &report.findings[0];
        assert_eq!(finding.fact_id, hit_id);
        assert!(finding.rules.contains(&"jwt".to_string()), "rules: {:?}", finding.rules);
        assert!(
            finding.preview.contains("[REDACTED:jwt#"),
            "preview scrubbed: {}",
            finding.preview
        );
        assert!(!finding.preview.contains(FIX_JWT), "no plaintext secret in report");
        assert!(
            !report.findings.iter().any(|f| f.fact_id == outside_id),
            "non-ops entities are out of scope"
        );

        // Nothing mutated: both ops facts and the outside fact still live.
        let store = FactStore::with_persistence(td.path()).unwrap();
        assert!(store.get(&hit_id).is_some(), "dry-run must not delete");
        assert!(store.get(&outside_id).is_some());
    }

    #[test]
    fn kv_shape_matches_on_denylisted_key() {
        let td = tempfile::tempdir().unwrap();
        {
            let mut store = FactStore::with_persistence(td.path()).unwrap();
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__ops__::config".to_string(),
                key: "api_key".to_string(),
                value: "fixture-value-SYNTHETIC".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
        let report = dry_run(td.path());
        assert_eq!(report.matched, 1);
        assert!(report.findings[0].rules.contains(&"fld.api_key".to_string()));
        assert!(!report.findings[0].preview.contains("fixture-value-SYNTHETIC"));
    }

    #[test]
    fn delete_pass_refuses_without_exact_confirm() {
        let td = tempfile::tempdir().unwrap();
        let (hit_id, ..) = seed(td.path());
        for confirm in [
            None,
            Some("yes".to_string()),
            Some("DELETE-MATCHED-OPS-FACTS".to_string()),
        ] {
            let err = run_redact_sweep(RedactSweepArgs {
                data_dir: td.path().to_path_buf(),
                entity_prefixes: Vec::new(),
                delete: true,
                confirm,
            })
            .unwrap_err();
            assert!(err.to_string().contains("refusing delete pass"), "{err}");
        }
        let store = FactStore::with_persistence(td.path()).unwrap();
        assert!(store.get(&hit_id).is_some(), "refused pass must not mutate");
    }

    #[test]
    fn delete_pass_deletes_matched_only_via_soft_delete() {
        let td = tempfile::tempdir().unwrap();
        let (hit_id, clean_id, outside_id) = seed(td.path());

        let report = run_redact_sweep(RedactSweepArgs {
            data_dir: td.path().to_path_buf(),
            entity_prefixes: Vec::new(),
            delete: true,
            confirm: Some(DELETE_CONFIRM_PHRASE.to_string()),
        })
        .unwrap();
        assert_eq!(report.mode, "delete");
        assert_eq!(report.matched, 1);
        assert_eq!(report.deleted, 1);

        // Tombstone is durable: a fresh replay of the journal sees the delete.
        let store = FactStore::with_persistence(td.path()).unwrap();
        assert!(store.get(&hit_id).is_none(), "matched fact soft-deleted");
        assert!(store.get(&clean_id).is_some(), "clean ops fact survives");
        assert!(store.get(&outside_id).is_some(), "out-of-scope fact survives");
    }

    #[test]
    fn delete_pass_refuses_while_daemon_lock_held() {
        let td = tempfile::tempdir().unwrap();
        let (hit_id, ..) = seed(td.path());

        // Simulate a live corecruxd: hold the LOCK exclusively.
        let lock_path = td.path().join("LOCK");
        let daemon = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        daemon.try_lock_exclusive().unwrap();

        let err = run_redact_sweep(RedactSweepArgs {
            data_dir: td.path().to_path_buf(),
            entity_prefixes: Vec::new(),
            delete: true,
            confirm: Some(DELETE_CONFIRM_PHRASE.to_string()),
        })
        .unwrap_err();
        assert!(err.to_string().contains("exclusive lock"), "{err}");

        let store = FactStore::with_persistence(td.path()).unwrap();
        assert!(store.get(&hit_id).is_some(), "locked pass must not mutate");

        // Dry-run stays available while the daemon is up (read-only).
        let report = dry_run(td.path());
        assert_eq!(report.matched, 1);
    }

    #[test]
    fn custom_entity_prefix_narrows_scope() {
        let td = tempfile::tempdir().unwrap();
        seed(td.path());
        let report = run_redact_sweep(RedactSweepArgs {
            data_dir: td.path().to_path_buf(),
            entity_prefixes: vec!["__ops__::config".to_string()],
            delete: false,
            confirm: None,
        })
        .unwrap();
        assert_eq!(report.scanned, 0, "error facts live under __ops__::error:*");
        assert_eq!(report.matched, 0);
    }
}
