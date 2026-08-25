// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Conformance hook — the M5 frontier seam of
//! `crux-daemon-buyer-fit-buildout-2026-07-13` that gives a pack's declared
//! operations **a place to be run and observed before the pack is trusted**.
//!
//! ## What a hook is, and what it deliberately is not
//!
//! This module runs a set of declared operations against a *staged* pack
//! (see [`crate::pack_lifecycle`]) and records what each one did, as a
//! [`ConformanceRun`]. It does **not** decide whether the pack passed.
//!
//! That separation is the point. `proof-carrying-adaptive-packs-2026-07-13`
//! M0 defines the declared envelope (`pack.conformance.v1`), M1 compares
//! observed behaviour against it and blocks violations, and M2 signs the
//! verdict into a CROWN receipt. If the daemon also owned the verdict there
//! would be two places deciding what "conformant" means, and the receipt
//! would attest to the daemon's opinion rather than to observed behaviour.
//! So the hook produces **evidence**; the consumer produces **judgement**.
//!
//! ## Determinism
//!
//! The consumer requires a replay to be reproducible bit-for-bit given the
//! same pack and corpus, which is what makes a conformance receipt worth
//! signing. [`ConformanceRun::observed_digest`] is therefore computed over
//! the observed *behaviour* only — case ids, statuses, writes, result
//! hashes, drop counts — and deliberately excludes wall-clock duration and
//! the run timestamp, which differ on every run of even a perfectly
//! deterministic pack. Timings are still reported per observation, because
//! the declared envelope bounds latency; they are simply not part of the
//! identity of the run.
//!
//! ## Corpus identity
//!
//! A run without a named corpus is refused. A behavioural claim whose
//! corpus is unknown cannot be compared to anything later, and a number
//! measured on one corpus reported against another is not recoverable after
//! the fact — so the requirement is a precondition, not a convention.

use crate::extension_registry::PackAttribution;
use crate::pack_lifecycle::{ObservedFactWrite, PackLifecycleState};
use crux_integrations::IntegrationManifest;
use serde::{Deserialize, Serialize};

pub const CONFORMANCE_RUN_SCHEMA: &str = "crux.pack.conformance_run.v1";

/// Upper bound on operations in one run. A conformance replay is a bounded
/// audit of declared behaviour, not a load generator: each case is a real
/// outbound call, so an unbounded list would turn this route into an
/// amplifier pointed at the pack's endpoint.
pub const MAX_CASES_PER_RUN: usize = 64;

/// One declared operation to replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConformanceCase {
    /// Stable identity for this case, so an observation can be matched back
    /// to its declaration across runs and across daemon versions. Ordinal
    /// position would break the moment a corpus gains a case in the middle.
    pub case_id: String,
    pub tool_name: String,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStatus {
    /// The operation ran and returned a well-formed response.
    Ok,
    /// The operation ran (or was refused by the daemon) and failed. A
    /// failure is evidence, not an aborted run — a pack that errors on its
    /// own declared operation is exactly what a replay exists to catch.
    Error,
}

/// What one replayed operation actually did.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConformanceObservation {
    pub case_id: String,
    pub tool_name: String,
    pub status: ConformanceStatus,
    /// Writes the operation would have made. The pack is staged, so none of
    /// them landed. An empty list is a finding, not a gap.
    pub observed_fact_writes: Vec<ObservedFactWrite>,
    /// Writes the grant filter rejected. Counted rather than listed: the
    /// content of an out-of-scope write is the pack's, and echoing it back
    /// would make a refused write a channel.
    pub dropped_fact_writes: usize,
    /// BLAKE3 over the canonical JSON of the operation's result payload.
    /// A fingerprint rather than the payload, so two runs can be compared
    /// for equality without the payload's shape becoming part of the
    /// replay contract.
    pub result_hash: String,
    pub result_bytes: usize,
    /// Wall-clock cost of the operation. Reported because the declared
    /// envelope bounds latency; excluded from [`ConformanceRun::observed_digest`]
    /// because it is not a property of the pack's behaviour.
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConformanceTotals {
    pub cases: usize,
    pub ok: usize,
    pub errors: usize,
    pub observed_fact_writes: usize,
    pub dropped_fact_writes: usize,
    pub result_bytes: usize,
    pub duration_ms: u64,
}

/// The evidence record one replay produces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConformanceRun {
    pub schema: String,
    /// Which pack build was replayed — id, version and install-time
    /// `manifest_hash`, so the evidence names bytes rather than a name.
    pub pack: PackAttribution,
    /// The state the pack was in while it ran. Always
    /// [`PackLifecycleState::Staged`]; carried explicitly so a stored run
    /// is self-describing rather than relying on the reader knowing the
    /// precondition.
    pub lifecycle: PackLifecycleState,
    /// Operator-supplied name of the shadow corpus these cases came from.
    pub corpus_id: String,
    pub started_at_unix_ms: u64,
    pub observations: Vec<ConformanceObservation>,
    pub totals: ConformanceTotals,
    /// BLAKE3 over the observed behaviour, excluding timings and the run
    /// timestamp — the value two replays of the same pack against the same
    /// corpus must agree on.
    pub observed_digest: String,
}

/// Outcome of one staged execution, as the transport layer reports it.
///
/// The runner takes these rather than doing the dispatching itself, so the
/// evidence-shaping logic is testable without ureq or wasmtime and stays
/// identical across both pack kinds.
#[derive(Debug, Clone)]
pub struct StagedOperationOutcome {
    pub result: serde_json::Value,
    pub observed_fact_writes: Vec<ObservedFactWrite>,
    pub dropped_fact_writes: usize,
    pub duration_ms: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConformanceError {
    /// The whole point is to run the pack *before* it is trusted. Replaying
    /// a live pack would prove nothing about what enabling it costs, and
    /// its writes would land.
    #[error(
        "conformance runs against a staged pack; '{0}' is {1} — stage it first via POST /v1/extensions/{0}/lifecycle"
    )]
    NotStaged(String, &'static str),
    #[error("corpus_id is required: a behavioural result whose corpus is unnamed cannot be compared to anything")]
    CorpusRequired,
    #[error("no cases to run: the pack declares no tools and none were supplied")]
    NoCases,
    #[error("{0} cases exceeds the {MAX_CASES_PER_RUN}-case cap for one run")]
    TooManyCases(usize),
    #[error("duplicate case_id '{0}': ids identify observations, so they must be unique within a run")]
    DuplicateCaseId(String),
}

/// Refuse a run that cannot produce comparable evidence, before any of the
/// pack's code executes.
pub fn precheck(
    extension_id: &str,
    lifecycle: PackLifecycleState,
    corpus_id: &str,
    cases: &[ConformanceCase],
) -> Result<(), ConformanceError> {
    if lifecycle != PackLifecycleState::Staged {
        return Err(ConformanceError::NotStaged(
            extension_id.to_string(),
            lifecycle.as_str(),
        ));
    }
    if corpus_id.trim().is_empty() {
        return Err(ConformanceError::CorpusRequired);
    }
    if cases.is_empty() {
        return Err(ConformanceError::NoCases);
    }
    if cases.len() > MAX_CASES_PER_RUN {
        return Err(ConformanceError::TooManyCases(cases.len()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for case in cases {
        if !seen.insert(case.case_id.as_str()) {
            return Err(ConformanceError::DuplicateCaseId(case.case_id.clone()));
        }
    }
    Ok(())
}

/// Default corpus when the caller supplies none: one case per tool the
/// manifest declares, called with empty args.
///
/// This is what makes the hook usable today, before
/// `proof-carrying-adaptive-packs` M0 adds a `pack.conformance.v1` block
/// carrying a real corpus reference. It is a floor, not a substitute: empty
/// args exercise a tool's existence and its write scope, not its behaviour
/// on realistic input. The M0 manifest block plugs in exactly here.
pub fn cases_from_manifest(manifest: &IntegrationManifest) -> Vec<ConformanceCase> {
    manifest
        .tools
        .iter()
        .map(|tool| ConformanceCase {
            case_id: tool.name.clone(),
            tool_name: tool.name.clone(),
            args: serde_json::json!({}),
        })
        .collect()
}

/// BLAKE3 over the canonical JSON of one operation's result payload.
pub fn result_hash(result: &serde_json::Value) -> (String, usize) {
    let bytes = canonical_bytes(result);
    (format!("blake3:{}", blake3::hash(&bytes).to_hex()), bytes.len())
}

/// Serialize with map keys in a fixed order so the hash is a function of
/// the value, not of the order serde happened to emit its fields in.
/// `serde_json::Value` already stores objects in a `BTreeMap` by default,
/// so this is `to_vec` with the intent written down; it stops a later
/// switch to `preserve_order` from silently making digests unstable.
fn canonical_bytes(value: &serde_json::Value) -> Vec<u8> {
    fn canonical(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for key in keys {
                    if let Some(child) = map.get(key) {
                        sorted.insert(key.clone(), canonical(child));
                    }
                }
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(items) => serde_json::Value::Array(items.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&canonical(value)).unwrap_or_default()
}

/// Fold one replayed operation's transport outcome into an observation.
pub fn observe(case: &ConformanceCase, outcome: Result<StagedOperationOutcome, String>) -> ConformanceObservation {
    match outcome {
        Ok(outcome) => {
            let (result_hash, result_bytes) = result_hash(&outcome.result);
            ConformanceObservation {
                case_id: case.case_id.clone(),
                tool_name: case.tool_name.clone(),
                status: ConformanceStatus::Ok,
                observed_fact_writes: outcome.observed_fact_writes,
                dropped_fact_writes: outcome.dropped_fact_writes,
                result_hash,
                result_bytes,
                duration_ms: outcome.duration_ms,
                error: None,
            }
        }
        Err(error) => ConformanceObservation {
            case_id: case.case_id.clone(),
            tool_name: case.tool_name.clone(),
            status: ConformanceStatus::Error,
            observed_fact_writes: Vec::new(),
            dropped_fact_writes: 0,
            // Hashing the empty payload rather than emitting a sentinel
            // keeps the field one type, so a comparator never has to branch
            // on "is this a hash or a placeholder".
            result_hash: result_hash(&serde_json::Value::Null).0,
            result_bytes: 0,
            duration_ms: 0,
            error: Some(error),
        },
    }
}

/// Assemble the evidence record from a completed set of observations.
pub fn build_run(
    pack: PackAttribution,
    lifecycle: PackLifecycleState,
    corpus_id: impl Into<String>,
    started_at_unix_ms: u64,
    observations: Vec<ConformanceObservation>,
) -> ConformanceRun {
    let mut totals = ConformanceTotals {
        cases: observations.len(),
        ..ConformanceTotals::default()
    };
    for observation in &observations {
        match observation.status {
            ConformanceStatus::Ok => totals.ok += 1,
            ConformanceStatus::Error => totals.errors += 1,
        }
        totals.observed_fact_writes += observation.observed_fact_writes.len();
        totals.dropped_fact_writes += observation.dropped_fact_writes;
        totals.result_bytes += observation.result_bytes;
        totals.duration_ms += observation.duration_ms;
    }
    let observed_digest = observed_digest(&observations);
    ConformanceRun {
        schema: CONFORMANCE_RUN_SCHEMA.to_string(),
        pack,
        lifecycle,
        corpus_id: corpus_id.into(),
        started_at_unix_ms,
        observations,
        totals,
        observed_digest,
    }
}

/// BLAKE3 over observed behaviour, timings excluded.
///
/// Built from an explicit projection rather than from the serialized
/// observation, so adding a reporting field later cannot silently change
/// every previously computed digest — a new field has to be added here
/// deliberately, which is a reviewable diff.
pub fn observed_digest(observations: &[ConformanceObservation]) -> String {
    let projection: Vec<serde_json::Value> = observations
        .iter()
        .map(|observation| {
            serde_json::json!({
                "case_id": observation.case_id,
                "tool_name": observation.tool_name,
                "status": observation.status,
                "observed_fact_writes": observation.observed_fact_writes,
                "dropped_fact_writes": observation.dropped_fact_writes,
                "result_hash": observation.result_hash,
                "result_bytes": observation.result_bytes,
                "error": observation.error,
            })
        })
        .collect();
    let bytes = canonical_bytes(&serde_json::Value::Array(projection));
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crux_integrations::{
        DataAccess, EntryKind, ExternalToolDefinition, IntegrationEntry, ManifestHashes, NetworkAccess, SafetyPolicy,
        INTEGRATION_SCHEMA_V1,
    };

    fn tool_def(name: &str) -> ExternalToolDefinition {
        ExternalToolDefinition {
            name: name.to_string(),
            description: String::new(),
            input_schema: serde_json::json!({}),
            consequence_metadata: None,
            auth_shared_secret_id: None,
        }
    }

    fn attribution() -> PackAttribution {
        PackAttribution::new(
            "ext.example.quote",
            "0.1.0",
            "blake3:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
        )
    }

    fn case(id: &str, tool: &str) -> ConformanceCase {
        ConformanceCase {
            case_id: id.to_string(),
            tool_name: tool.to_string(),
            args: serde_json::json!({}),
        }
    }

    fn write(entity: &str) -> ObservedFactWrite {
        ObservedFactWrite {
            entity: entity.to_string(),
            key: "content".to_string(),
            value: "Roses are red".to_string(),
            confidence: 0.9,
            private: false,
            actor: Some(attribution().actor()),
        }
    }

    fn outcome(result: serde_json::Value, duration_ms: u64) -> StagedOperationOutcome {
        StagedOperationOutcome {
            result,
            observed_fact_writes: vec![write("personal::quotes::today")],
            dropped_fact_writes: 1,
            duration_ms,
        }
    }

    /// The precondition that makes the whole hook mean something: you
    /// cannot replay a pack that is already live.
    #[test]
    fn a_live_pack_cannot_be_replayed() {
        let cases = vec![case("quote", "quote.daily")];
        assert_eq!(
            precheck("ext.example.quote", PackLifecycleState::Active, "shadow-v1", &cases),
            Err(ConformanceError::NotStaged("ext.example.quote".to_string(), "active"))
        );
        assert_eq!(
            precheck(
                "ext.example.quote",
                PackLifecycleState::Quarantined,
                "shadow-v1",
                &cases
            ),
            Err(ConformanceError::NotStaged(
                "ext.example.quote".to_string(),
                "quarantined"
            ))
        );
        assert_eq!(
            precheck("ext.example.quote", PackLifecycleState::Staged, "shadow-v1", &cases),
            Ok(())
        );
    }

    #[test]
    fn a_run_without_a_named_corpus_is_refused() {
        let cases = vec![case("quote", "quote.daily")];
        assert_eq!(
            precheck("ext.example.quote", PackLifecycleState::Staged, "   ", &cases),
            Err(ConformanceError::CorpusRequired)
        );
    }

    #[test]
    fn empty_duplicate_and_oversized_case_sets_are_refused() {
        assert_eq!(
            precheck("ext.example.quote", PackLifecycleState::Staged, "shadow-v1", &[]),
            Err(ConformanceError::NoCases)
        );
        assert_eq!(
            precheck(
                "ext.example.quote",
                PackLifecycleState::Staged,
                "shadow-v1",
                &[case("a", "quote.daily"), case("a", "quote.weekly")]
            ),
            Err(ConformanceError::DuplicateCaseId("a".to_string()))
        );
        let too_many: Vec<ConformanceCase> = (0..=MAX_CASES_PER_RUN)
            .map(|i| case(&format!("c{i}"), "quote.daily"))
            .collect();
        assert_eq!(
            precheck("ext.example.quote", PackLifecycleState::Staged, "shadow-v1", &too_many),
            Err(ConformanceError::TooManyCases(MAX_CASES_PER_RUN + 1))
        );
    }

    /// The property a signed conformance receipt rests on: two replays of
    /// the same behaviour agree, even when they took different wall-clock
    /// time and ran at different moments.
    #[test]
    fn the_digest_ignores_timing_but_not_behaviour() {
        let case = case("quote", "quote.daily");
        let fast = observe(&case, Ok(outcome(serde_json::json!({"quote": "a"}), 3)));
        let slow = observe(&case, Ok(outcome(serde_json::json!({"quote": "a"}), 941)));
        assert_ne!(fast.duration_ms, slow.duration_ms, "the runs really did differ");

        let first = build_run(attribution(), PackLifecycleState::Staged, "shadow-v1", 1, vec![fast]);
        let second = build_run(
            attribution(),
            PackLifecycleState::Staged,
            "shadow-v1",
            17_700_000_000_000,
            vec![slow],
        );
        assert_eq!(
            first.observed_digest, second.observed_digest,
            "timing and start time must not be part of the run's identity"
        );

        let different = build_run(
            attribution(),
            PackLifecycleState::Staged,
            "shadow-v1",
            1,
            vec![observe(&case, Ok(outcome(serde_json::json!({"quote": "b"}), 3)))],
        );
        assert_ne!(
            first.observed_digest, different.observed_digest,
            "a different result payload is a different behaviour"
        );
    }

    /// A change in what the pack would *write* has to move the digest even
    /// when the returned payload is identical — the writes are the part the
    /// consumer's envelope is mostly about.
    #[test]
    fn the_digest_covers_observed_writes() {
        let case = case("quote", "quote.daily");
        let baseline = build_run(
            attribution(),
            PackLifecycleState::Staged,
            "shadow-v1",
            1,
            vec![observe(&case, Ok(outcome(serde_json::json!({"quote": "a"}), 3)))],
        );

        let mut drifted = outcome(serde_json::json!({"quote": "a"}), 3);
        drifted.observed_fact_writes.push(write("personal::quotes::extra"));
        let drifted = build_run(
            attribution(),
            PackLifecycleState::Staged,
            "shadow-v1",
            1,
            vec![observe(&case, Ok(drifted))],
        );
        assert_ne!(baseline.observed_digest, drifted.observed_digest);

        let mut dropped = outcome(serde_json::json!({"quote": "a"}), 3);
        dropped.dropped_fact_writes = 7;
        let dropped = build_run(
            attribution(),
            PackLifecycleState::Staged,
            "shadow-v1",
            1,
            vec![observe(&case, Ok(dropped))],
        );
        assert_ne!(
            baseline.observed_digest, dropped.observed_digest,
            "a pack that started attempting out-of-scope writes has changed behaviour"
        );
    }

    /// A failing operation is evidence to be recorded, not a run to be
    /// abandoned — a pack that errors on its own declared operation is
    /// precisely what a pre-enable replay is for.
    #[test]
    fn a_failed_operation_is_recorded_not_fatal() {
        let ok = case("ok", "quote.daily");
        let bad = case("bad", "quote.undeclared");
        let run = build_run(
            attribution(),
            PackLifecycleState::Staged,
            "shadow-v1",
            1,
            vec![
                observe(&ok, Ok(outcome(serde_json::json!({"quote": "a"}), 3))),
                observe(&bad, Err("tool 'quote.undeclared' not declared".to_string())),
            ],
        );

        assert_eq!(run.totals.cases, 2);
        assert_eq!(run.totals.ok, 1);
        assert_eq!(run.totals.errors, 1);
        assert_eq!(run.observations[1].status, ConformanceStatus::Error);
        assert_eq!(
            run.observations[1].error.as_deref(),
            Some("tool 'quote.undeclared' not declared")
        );
        assert!(run.observations[1].observed_fact_writes.is_empty());
        assert_eq!(run.schema, CONFORMANCE_RUN_SCHEMA);
        assert_eq!(run.totals.observed_fact_writes, 1);
        assert_eq!(run.totals.dropped_fact_writes, 1);
    }

    /// Case order is part of the replay: the same cases run in a different
    /// order are a different run, because a pack's writes can depend on
    /// what it already wrote.
    #[test]
    fn case_order_is_part_of_the_digest() {
        let a = case("a", "quote.daily");
        let b = case("b", "quote.weekly");
        let obs_a = observe(&a, Ok(outcome(serde_json::json!({"quote": "a"}), 1)));
        let obs_b = observe(&b, Ok(outcome(serde_json::json!({"quote": "b"}), 1)));
        assert_ne!(
            observed_digest(&[obs_a.clone(), obs_b.clone()]),
            observed_digest(&[obs_b, obs_a])
        );
    }

    #[test]
    fn manifest_tools_are_the_default_corpus() {
        let mut manifest = IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "ext.example.quote".to_string(),
            name: "Quote of the Day".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_alice".to_string(),
            summary: "Returns a quote.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::ExternalTool,
                path: "tools/quote.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
            external_tool_endpoint: Some("https://packs.example.com/quote".to_string()),
            tools: Vec::new(),
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
        };
        assert!(cases_from_manifest(&manifest).is_empty());

        manifest.tools = vec![tool_def("quote.daily"), tool_def("quote.weekly")];
        let cases = cases_from_manifest(&manifest);
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0].case_id, "quote.daily");
        assert_eq!(cases[0].tool_name, "quote.daily");
        assert_eq!(cases[1].case_id, "quote.weekly");
    }

    /// Key order in a result payload must not change the fingerprint — two
    /// endpoints emitting the same object are the same behaviour.
    #[test]
    fn result_hash_is_key_order_independent() {
        let first: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":{"y":2,"x":3}}"#).expect("json");
        let second: serde_json::Value = serde_json::from_str(r#"{"b":{"x":3,"y":2},"a":1}"#).expect("json");
        assert_eq!(result_hash(&first).0, result_hash(&second).0);
        assert_ne!(result_hash(&first).0, result_hash(&serde_json::json!({"a": 2})).0);
    }
}
