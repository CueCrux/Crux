// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Optional embedding client for dense vector retrieval.
//!
//! Connects to any OpenAI-compatible `/api/embed` or `/v1/embeddings` endpoint
//! (Ollama, vLLM, llama.cpp, TEI, LiteLLM, etc.). When configured, facts are
//! embedded at store time and queries use cosine similarity for ranking.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SEMANTIC_PROFILE_SCHEMA_V1: &str = "cuecrux.semantic_profile.v1";
pub const EMBEDDING_FINGERPRINT_SCHEMA_V1: &str = "cuecrux.embedding_fingerprint.v1";

pub const DELEGATION_DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const DELEGATION_DEFAULT_MAX_ATTEMPTS: usize = 3;
pub const DELEGATION_DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(50);
/// Breaker ceiling: three consecutive failed logical calls open the circuit.
/// Retries within one call do not increment this counter independently.
pub const DELEGATION_DEFAULT_BREAKER_FAILURE_THRESHOLD: u32 = 3;
pub const DELEGATION_DEFAULT_BREAKER_OPEN_FOR: Duration = Duration::from_secs(30);
pub const DELEGATION_MAX_TEXTS_PER_REQUEST: usize = 64;
pub const DELEGATION_MAX_TEXT_BYTES: usize = 64 * 1024;
pub const DELEGATION_MAX_TEXT_BYTES_PER_REQUEST: usize = 256 * 1024;

const DELEGATION_MAX_ATTEMPTS_CEILING: usize = 5;
const DELEGATION_MAX_BACKOFF: Duration = Duration::from_secs(1);
const DELEGATION_MAX_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DELEGATION_MAX_BREAKER_OPEN_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// Configuration for the embedding endpoint.
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    /// Base URL of the embedding service (e.g. `http://localhost:11434`).
    pub base_url: String,
    /// Model name to request (e.g. `nomic-embed-text`).
    pub model: String,
    /// Dimensionality of the embedding vectors. Auto-detected on first call if 0.
    pub dimensions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddingFingerprint {
    pub schema: String,
    pub fingerprint_id: String,
    pub model: String,
    pub dimensions: usize,
    pub tokenizer: String,
    pub prompt_template_version: String,
    pub normalisation: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticProfile {
    pub schema: String,
    pub profile_id: String,
    pub model: String,
    pub dimensions: usize,
    pub tokenizer: String,
    pub prompt_template_version: String,
    pub normalisation: String,
    pub embedding_fingerprint: EmbeddingFingerprint,
}

impl SemanticProfile {
    pub fn from_embedding_config(config: &EmbeddingConfig, detected_dimensions: usize) -> Self {
        let dimensions = if detected_dimensions == 0 {
            config.dimensions
        } else {
            detected_dimensions
        };
        let tokenizer = "model_default".to_string();
        let prompt_template_version = "none".to_string();
        let normalisation = "none".to_string();
        let hash_material = format!(
            "{}\n{}\n{}\n{}\n{}",
            config.model, dimensions, tokenizer, prompt_template_version, normalisation
        );
        let hash = blake3::hash(hash_material.as_bytes()).to_hex().to_string();
        let fingerprint_id = format!("efp_{}", &hash[..24]);
        let profile_id = format!("sp_{}", &hash[..24]);

        Self {
            schema: SEMANTIC_PROFILE_SCHEMA_V1.to_string(),
            profile_id,
            model: config.model.clone(),
            dimensions,
            tokenizer: tokenizer.clone(),
            prompt_template_version: prompt_template_version.clone(),
            normalisation: normalisation.clone(),
            embedding_fingerprint: EmbeddingFingerprint {
                schema: EMBEDDING_FINGERPRINT_SCHEMA_V1.to_string(),
                fingerprint_id,
                model: config.model.clone(),
                dimensions,
                tokenizer,
                prompt_template_version,
                normalisation,
                hash,
            },
        }
    }
}

impl SemanticProfile {
    /// Derive a profile directly from model parts (for local embedders that
    /// have no `EmbeddingConfig`/base_url). Fingerprint is stable per
    /// (model, dims, tokenizer, template, normalisation) — identical hashing to
    /// [`SemanticProfile::from_embedding_config`] so the two are comparable.
    pub fn from_parts(
        model: &str,
        dimensions: usize,
        tokenizer: &str,
        prompt_template_version: &str,
        normalisation: &str,
    ) -> Self {
        let hash_material = format!("{model}\n{dimensions}\n{tokenizer}\n{prompt_template_version}\n{normalisation}");
        let hash = blake3::hash(hash_material.as_bytes()).to_hex().to_string();
        let fingerprint_id = format!("efp_{}", &hash[..24]);
        let profile_id = format!("sp_{}", &hash[..24]);
        Self {
            schema: SEMANTIC_PROFILE_SCHEMA_V1.to_string(),
            profile_id,
            model: model.to_string(),
            dimensions,
            tokenizer: tokenizer.to_string(),
            prompt_template_version: prompt_template_version.to_string(),
            normalisation: normalisation.to_string(),
            embedding_fingerprint: EmbeddingFingerprint {
                schema: EMBEDDING_FINGERPRINT_SCHEMA_V1.to_string(),
                fingerprint_id,
                model: model.to_string(),
                dimensions,
                tokenizer: tokenizer.to_string(),
                prompt_template_version: prompt_template_version.to_string(),
                normalisation: normalisation.to_string(),
                hash,
            },
        }
    }
}

/// The provider contract shared by every embedder (buyer-fit M3). A dense lane
/// records the provider's [`SemanticProfile`] so document and query vectors can
/// be checked for compatibility (same model/dimension/fingerprint) and an
/// incompatible vector refused rather than silently scored in the wrong space.
///
/// `Debug` is a supertrait so a `Box<dyn Embedder>` can live inside a
/// `#[derive(Debug)]` struct (e.g. [`crate::fact_store::FactStore`]).
pub trait Embedder: Send + Sync + std::fmt::Debug {
    /// Embed a batch of texts — one vector per input, in order.
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError>;
    /// Embed one text.
    fn embed_one(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let mut vecs = self.embed_batch(&[text])?;
        vecs.pop().ok_or(EmbeddingError::EmptyResponse)
    }
    /// Output dimensionality.
    fn dimensions(&self) -> usize;
    /// Model identifier.
    fn model(&self) -> &str;
    /// This embedder's semantic profile (model/dim/fingerprint).
    fn semantic_profile(&self) -> SemanticProfile;
    /// Whether inference executes inside this daemon process. External and
    /// custom embedders default to remote so capability reporting fails closed.
    fn runs_locally(&self) -> bool {
        false
    }
    /// Runtime state for daemon-to-daemon embedding delegation. Other remote
    /// embedders (for example an Ollama [`EmbeddingClient`]) return `None` so
    /// callers can distinguish the authenticated Crux delegation contract.
    fn delegation_status(&self) -> Option<DelegationStatus> {
        None
    }
    /// Report that persisted vectors use a semantic profile incompatible with
    /// this embedder. Non-delegating embedders need no live capability state.
    fn report_semantic_profile_mismatch(&self) {}
    /// Clear a previously reported persisted-vector mismatch after a strict
    /// compatibility check succeeds or incompatible vectors are removed.
    fn clear_semantic_profile_mismatch(&self) {}
}

impl Embedder for EmbeddingClient {
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        EmbeddingClient::embed_batch(self, texts)
    }
    fn dimensions(&self) -> usize {
        EmbeddingClient::dimensions(self)
    }
    fn model(&self) -> &str {
        EmbeddingClient::model(self)
    }
    fn semantic_profile(&self) -> SemanticProfile {
        EmbeddingClient::semantic_profile(self)
    }
}

/// Configuration for authenticated delegation to another CoreCrux daemon's
/// `POST /v1/compute/embed` endpoint.
///
/// `Debug` deliberately redacts the bearer credential. Keep this type's custom
/// formatter if fields are added: a derived formatter would expose the token.
#[derive(Clone)]
pub struct DelegatingEmbeddingConfig {
    pub base_url: String,
    pub bearer_token: String,
    pub expected_model: String,
    pub expected_dimensions: usize,
    pub request_timeout: Duration,
    /// Total attempts, including the initial request (not retries-after-first).
    pub max_attempts: usize,
    pub initial_backoff: Duration,
    pub breaker_failure_threshold: u32,
    pub breaker_open_for: Duration,
}

impl std::fmt::Debug for DelegatingEmbeddingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatingEmbeddingConfig")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"<redacted>")
            .field("expected_model", &self.expected_model)
            .field("expected_dimensions", &self.expected_dimensions)
            .field("request_timeout", &self.request_timeout)
            .field("max_attempts", &self.max_attempts)
            .field("initial_backoff", &self.initial_backoff)
            .field("breaker_failure_threshold", &self.breaker_failure_threshold)
            .field("breaker_open_for", &self.breaker_open_for)
            .finish()
    }
}

impl DelegatingEmbeddingConfig {
    pub fn new(
        base_url: impl Into<String>,
        bearer_token: impl Into<String>,
        expected_model: impl Into<String>,
        expected_dimensions: usize,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token: bearer_token.into(),
            expected_model: expected_model.into(),
            expected_dimensions,
            request_timeout: DELEGATION_DEFAULT_REQUEST_TIMEOUT,
            max_attempts: DELEGATION_DEFAULT_MAX_ATTEMPTS,
            initial_backoff: DELEGATION_DEFAULT_INITIAL_BACKOFF,
            breaker_failure_threshold: DELEGATION_DEFAULT_BREAKER_FAILURE_THRESHOLD,
            breaker_open_for: DELEGATION_DEFAULT_BREAKER_OPEN_FOR,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelegationAvailability {
    Available,
    Degraded,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelegationCircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Secret-free status suitable for `/v1/version` capability reporting.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DelegationStatus {
    pub availability: DelegationAvailability,
    pub circuit_state: DelegationCircuitState,
    pub reason_code: &'static str,
    pub reason: &'static str,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DelegationFailureClass {
    ProfileMismatch,
    Unavailable,
}

#[derive(Debug)]
enum DelegationCircuit {
    Closed,
    Open {
        retry_at: Instant,
    },
    /// Exactly one caller owns the recovery probe. Concurrent callers fail
    /// fast instead of creating an unbounded recovery stampede.
    HalfOpen,
}

#[derive(Debug)]
struct DelegationRuntime {
    circuit: DelegationCircuit,
    consecutive_failures: u32,
    last_failure: Option<DelegationFailureClass>,
    persisted_profile_mismatch: bool,
    pinned_profile: Option<SemanticProfile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DelegationPermit {
    Closed,
    HalfOpen,
}

#[derive(Serialize)]
struct DelegatingEmbedRequest<'a> {
    texts: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_profile: Option<&'a SemanticProfile>,
}

#[derive(Deserialize)]
struct DelegatingEmbedResponse {
    embeddings: Vec<Vec<f32>>,
    semantic_profile: SemanticProfile,
}

#[derive(Deserialize)]
struct DelegationProblemProfile {
    model: String,
    dimensions: usize,
}

#[derive(Deserialize)]
struct DelegationProblemDetails {
    code: Option<String>,
    expected: Option<DelegationProblemProfile>,
    actual: Option<DelegationProblemProfile>,
}

fn semantic_profile_mismatch_from_problem(problem: DelegationProblemDetails) -> Option<EmbeddingError> {
    if problem.code.as_deref() != Some("SEMANTIC_PROFILE_MISMATCH") {
        return None;
    }
    let expected = problem.expected?;
    let actual = problem.actual?;
    Some(EmbeddingError::SemanticProfileMismatch {
        expected_model: expected.model,
        expected_dimensions: expected.dimensions,
        got_model: actual.model,
        got_dimensions: actual.dimensions,
    })
}

trait DelegationTransport: Send + Sync {
    fn send(
        &self,
        endpoint: &str,
        bearer_token: &str,
        body: serde_json::Value,
    ) -> Result<DelegatingEmbedResponse, EmbeddingError>;
}

struct UreqDelegationTransport {
    agent: ureq::Agent,
}

impl DelegationTransport for UreqDelegationTransport {
    fn send(
        &self,
        endpoint: &str,
        bearer_token: &str,
        body: serde_json::Value,
    ) -> Result<DelegatingEmbedResponse, EmbeddingError> {
        let bearer = format!("Bearer {bearer_token}");
        let mut response = self
            .agent
            .post(endpoint)
            .header("Content-Type", "application/json")
            .header("Authorization", &bearer)
            .send_json(body)
            .map_err(|err| EmbeddingError::Network(err.to_string()))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            if status == 409 {
                let problem = response.body_mut().read_json::<DelegationProblemDetails>();
                if let Ok(problem) = problem {
                    if let Some(err) = semantic_profile_mismatch_from_problem(problem) {
                        return Err(err);
                    }
                }
            }
            return Err(EmbeddingError::UpstreamStatus { status });
        }
        response
            .body_mut()
            .read_json()
            .map_err(|err| EmbeddingError::Deserialize(err.to_string()))
    }
}

/// Authenticated, fail-closed embedding client for another CoreCrux daemon.
///
/// The first successful response must match the configured model and
/// dimensions. Its complete [`SemanticProfile`] is then pinned: any subsequent
/// profile drift is rejected before vectors reach a caller.
pub struct DelegatingEmbedder {
    config: DelegatingEmbeddingConfig,
    expected_profile: SemanticProfile,
    endpoint: String,
    transport: Box<dyn DelegationTransport>,
    runtime: Mutex<DelegationRuntime>,
}

impl std::fmt::Debug for DelegatingEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatingEmbedder")
            .field("model", &self.config.expected_model)
            .field("dimensions", &self.config.expected_dimensions)
            .field("request_timeout", &self.config.request_timeout)
            .field("max_attempts", &self.config.max_attempts)
            .field("breaker_failure_threshold", &self.config.breaker_failure_threshold)
            .field("breaker_open_for", &self.config.breaker_open_for)
            .finish_non_exhaustive()
    }
}

impl DelegatingEmbedder {
    pub fn new(config: DelegatingEmbeddingConfig) -> Result<Self, EmbeddingError> {
        validate_delegating_config(&config)?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(config.request_timeout))
            .build()
            .into();
        Self::new_with_transport(config, Box::new(UreqDelegationTransport { agent }))
    }

    fn new_with_transport(
        config: DelegatingEmbeddingConfig,
        transport: Box<dyn DelegationTransport>,
    ) -> Result<Self, EmbeddingError> {
        validate_delegating_config(&config)?;
        let endpoint = format!("{}/v1/compute/embed", config.base_url.trim_end_matches('/'));
        let expected_profile = SemanticProfile::from_parts(
            &config.expected_model,
            config.expected_dimensions,
            "model_default",
            "none",
            "none",
        );
        Ok(Self {
            config,
            expected_profile,
            endpoint,
            transport,
            runtime: Mutex::new(DelegationRuntime {
                circuit: DelegationCircuit::Closed,
                consecutive_failures: 0,
                last_failure: None,
                persisted_profile_mismatch: false,
                pinned_profile: None,
            }),
        })
    }

    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        // One logical call is deliberately capped to one provider request.
        // With three 5s attempts plus backoff this keeps the synchronous
        // caller below the daemon's 30s request timeout; accepting an
        // unbounded sequence of subrequests would make timeout outcomes
        // ambiguous for already-durable operations.
        if texts.len() > DELEGATION_MAX_TEXTS_PER_REQUEST {
            return Err(EmbeddingError::DelegationBatchTooLarge {
                count: texts.len(),
                max_count: DELEGATION_MAX_TEXTS_PER_REQUEST,
            });
        }

        let mut total_bytes = 0usize;
        for (index, text) in texts.iter().enumerate() {
            if text.len() > DELEGATION_MAX_TEXT_BYTES {
                return Err(EmbeddingError::DelegationTextTooLarge {
                    index,
                    bytes: text.len(),
                    max_bytes: DELEGATION_MAX_TEXT_BYTES,
                });
            }
            total_bytes = total_bytes.saturating_add(text.len());
        }
        if total_bytes > DELEGATION_MAX_TEXT_BYTES_PER_REQUEST {
            return Err(EmbeddingError::DelegationPayloadTooLarge {
                bytes: total_bytes,
                max_bytes: DELEGATION_MAX_TEXT_BYTES_PER_REQUEST,
            });
        }
        let permit = self.acquire_permit()?;
        let result = self
            .send_with_retries(texts)
            .and_then(|response| self.validate_and_pin_response(texts.len(), response));
        match result {
            Ok(embeddings) => {
                self.record_success()?;
                Ok(embeddings)
            }
            Err(err) => {
                self.record_failure(permit, &err)?;
                Err(err)
            }
        }
    }

    pub fn status(&self) -> DelegationStatus {
        let Ok(runtime) = self.runtime.lock() else {
            return DelegationStatus {
                availability: DelegationAvailability::Degraded,
                circuit_state: DelegationCircuitState::Open,
                reason_code: "embedding_delegate_state_unavailable",
                reason: "Embedding delegation state is unavailable; delegation is failing closed.",
                consecutive_failures: self.config.breaker_failure_threshold,
            };
        };

        match runtime.circuit {
            DelegationCircuit::Closed if runtime.consecutive_failures == 0 && !runtime.persisted_profile_mismatch => {
                DelegationStatus {
                    availability: DelegationAvailability::Available,
                    circuit_state: DelegationCircuitState::Closed,
                    reason_code: "available",
                    reason: "Remote embedding delegation is available.",
                    consecutive_failures: 0,
                }
            }
            DelegationCircuit::Closed => {
                let (reason_code, reason) = match (runtime.persisted_profile_mismatch, runtime.last_failure) {
                    (true, _) | (_, Some(DelegationFailureClass::ProfileMismatch)) => (
                        "embedding_semantic_profile_mismatch",
                        "The remote embedding provider is incompatible with the expected or persisted semantic profile.",
                    ),
                    _ => (
                        "embedding_delegate_unavailable",
                        "Remote embedding delegation recently failed and is degraded.",
                    ),
                };
                DelegationStatus {
                    availability: DelegationAvailability::Degraded,
                    circuit_state: DelegationCircuitState::Closed,
                    reason_code,
                    reason,
                    consecutive_failures: runtime.consecutive_failures,
                }
            }
            DelegationCircuit::Open { .. } => DelegationStatus {
                availability: DelegationAvailability::Degraded,
                circuit_state: DelegationCircuitState::Open,
                reason_code: "embedding_delegate_circuit_open",
                reason: "Remote embedding delegation circuit is open after repeated failures.",
                consecutive_failures: runtime.consecutive_failures,
            },
            DelegationCircuit::HalfOpen => DelegationStatus {
                availability: DelegationAvailability::Degraded,
                circuit_state: DelegationCircuitState::HalfOpen,
                reason_code: "embedding_delegate_half_open",
                reason: "Remote embedding delegation is testing one recovery probe.",
                consecutive_failures: runtime.consecutive_failures,
            },
        }
    }

    fn acquire_permit(&self) -> Result<DelegationPermit, EmbeddingError> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| EmbeddingError::DelegationState("delegation state lock poisoned".to_string()))?;
        match runtime.circuit {
            DelegationCircuit::Closed => Ok(DelegationPermit::Closed),
            DelegationCircuit::Open { retry_at } => {
                let now = Instant::now();
                if now < retry_at {
                    let remaining = retry_at.saturating_duration_since(now).as_millis();
                    return Err(EmbeddingError::CircuitOpen {
                        retry_after_ms: remaining.min(u128::from(u64::MAX)) as u64,
                    });
                }
                runtime.circuit = DelegationCircuit::HalfOpen;
                Ok(DelegationPermit::HalfOpen)
            }
            DelegationCircuit::HalfOpen => Err(EmbeddingError::HalfOpenProbeInFlight),
        }
    }

    fn send_with_retries(&self, texts: &[&str]) -> Result<DelegatingEmbedResponse, EmbeddingError> {
        let mut backoff = self.config.initial_backoff;
        for attempt in 0..self.config.max_attempts {
            match self.send_once(texts) {
                Ok(response) => return Ok(response),
                Err(err) => {
                    let attempts_exhausted = attempt + 1 >= self.config.max_attempts;
                    if attempts_exhausted || !err.delegation_retryable() {
                        return Err(err);
                    }
                    std::thread::sleep(backoff);
                    backoff = std::cmp::min(backoff.saturating_mul(2), DELEGATION_MAX_BACKOFF);
                }
            }
        }
        Err(EmbeddingError::Network(
            "embedding delegation retry loop ended without an attempt".to_string(),
        ))
    }

    fn send_once(&self, texts: &[&str]) -> Result<DelegatingEmbedResponse, EmbeddingError> {
        let profile = self.semantic_profile();
        let body = DelegatingEmbedRequest {
            texts,
            semantic_profile: Some(&profile),
        };
        let value = serde_json::to_value(&body).map_err(|err| EmbeddingError::Serialize(err.to_string()))?;
        self.transport.send(&self.endpoint, &self.config.bearer_token, value)
    }

    fn validate_and_pin_response(
        &self,
        expected_count: usize,
        response: DelegatingEmbedResponse,
    ) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let profile = response.semantic_profile;
        if profile.model != self.config.expected_model || profile.dimensions != self.config.expected_dimensions {
            return Err(EmbeddingError::SemanticProfileMismatch {
                expected_model: self.config.expected_model.clone(),
                expected_dimensions: self.config.expected_dimensions,
                got_model: profile.model,
                got_dimensions: profile.dimensions,
            });
        }
        if profile.embedding_fingerprint.model != profile.model
            || profile.embedding_fingerprint.dimensions != profile.dimensions
        {
            return Err(EmbeddingError::InvalidSemanticProfile(
                "embedding fingerprint model/dimensions disagree with semantic profile".to_string(),
            ));
        }
        let canonical_profile = SemanticProfile::from_parts(
            &profile.model,
            profile.dimensions,
            &profile.tokenizer,
            &profile.prompt_template_version,
            &profile.normalisation,
        );
        if profile != canonical_profile {
            return Err(EmbeddingError::InvalidSemanticProfile(
                "semantic profile identifiers or fingerprint hash are internally inconsistent".to_string(),
            ));
        }
        if response.embeddings.len() != expected_count {
            return Err(EmbeddingError::LengthMismatch {
                expected: expected_count,
                got: response.embeddings.len(),
            });
        }
        for (index, vector) in response.embeddings.iter().enumerate() {
            if vector.len() != profile.dimensions {
                return Err(EmbeddingError::VectorDimensionMismatch {
                    index,
                    expected: profile.dimensions,
                    got: vector.len(),
                });
            }
            if vector.iter().any(|value| !value.is_finite()) {
                return Err(EmbeddingError::InvalidVectorValue { index });
            }
        }

        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| EmbeddingError::DelegationState("delegation state lock poisoned".to_string()))?;
        if let Some(pinned) = &runtime.pinned_profile {
            if pinned != &profile {
                return Err(EmbeddingError::SemanticProfileChanged {
                    expected_profile_id: pinned.profile_id.clone(),
                    got_profile_id: profile.profile_id,
                });
            }
        } else {
            runtime.pinned_profile = Some(profile);
        }
        Ok(response.embeddings)
    }

    fn record_success(&self) -> Result<(), EmbeddingError> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| EmbeddingError::DelegationState("delegation state lock poisoned".to_string()))?;
        runtime.circuit = DelegationCircuit::Closed;
        runtime.consecutive_failures = 0;
        runtime.last_failure = None;
        Ok(())
    }

    fn record_failure(&self, permit: DelegationPermit, err: &EmbeddingError) -> Result<(), EmbeddingError> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| EmbeddingError::DelegationState("delegation state lock poisoned".to_string()))?;
        runtime.consecutive_failures = runtime.consecutive_failures.saturating_add(1);
        runtime.last_failure = Some(err.delegation_failure_class());
        if permit == DelegationPermit::HalfOpen || runtime.consecutive_failures >= self.config.breaker_failure_threshold
        {
            let retry_at = Instant::now()
                .checked_add(self.config.breaker_open_for)
                .ok_or_else(|| EmbeddingError::Configuration("breaker cooldown is too large".to_string()))?;
            runtime.circuit = DelegationCircuit::Open { retry_at };
        } else {
            runtime.circuit = DelegationCircuit::Closed;
        }
        Ok(())
    }

    fn semantic_profile(&self) -> SemanticProfile {
        self.runtime
            .lock()
            .ok()
            .and_then(|runtime| runtime.pinned_profile.clone())
            .unwrap_or_else(|| self.expected_profile.clone())
    }

    fn report_semantic_profile_mismatch(&self) {
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.persisted_profile_mismatch = true;
        }
    }

    fn clear_semantic_profile_mismatch(&self) {
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.persisted_profile_mismatch = false;
        }
    }
}

impl Embedder for DelegatingEmbedder {
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        DelegatingEmbedder::embed_batch(self, texts)
    }

    fn dimensions(&self) -> usize {
        self.config.expected_dimensions
    }

    fn model(&self) -> &str {
        &self.config.expected_model
    }

    fn semantic_profile(&self) -> SemanticProfile {
        DelegatingEmbedder::semantic_profile(self)
    }

    fn delegation_status(&self) -> Option<DelegationStatus> {
        Some(self.status())
    }

    fn report_semantic_profile_mismatch(&self) {
        DelegatingEmbedder::report_semantic_profile_mismatch(self);
    }

    fn clear_semantic_profile_mismatch(&self) {
        DelegatingEmbedder::clear_semantic_profile_mismatch(self);
    }
}

fn validate_delegating_config(config: &DelegatingEmbeddingConfig) -> Result<(), EmbeddingError> {
    if config.base_url.trim().is_empty() {
        return Err(EmbeddingError::Configuration(
            "embedding delegate base URL must not be empty".to_string(),
        ));
    }
    if config.bearer_token.is_empty() {
        return Err(EmbeddingError::Configuration(
            "embedding delegate bearer token must not be empty".to_string(),
        ));
    }
    if config.bearer_token.contains(['\r', '\n']) {
        return Err(EmbeddingError::Configuration(
            "embedding delegate bearer token contains invalid header characters".to_string(),
        ));
    }
    if config.expected_model.trim().is_empty() {
        return Err(EmbeddingError::Configuration(
            "embedding delegate expected model must not be empty".to_string(),
        ));
    }
    if config.expected_dimensions == 0 {
        return Err(EmbeddingError::Configuration(
            "embedding delegate expected dimensions must be greater than zero".to_string(),
        ));
    }
    if config.request_timeout.is_zero() || config.request_timeout > DELEGATION_MAX_TIMEOUT {
        return Err(EmbeddingError::Configuration(
            "embedding delegate timeout must be between 1ns and 300s".to_string(),
        ));
    }
    if !(1..=DELEGATION_MAX_ATTEMPTS_CEILING).contains(&config.max_attempts) {
        return Err(EmbeddingError::Configuration(format!(
            "embedding delegate max attempts must be between 1 and {DELEGATION_MAX_ATTEMPTS_CEILING}"
        )));
    }
    if config.initial_backoff > DELEGATION_MAX_BACKOFF {
        return Err(EmbeddingError::Configuration(
            "embedding delegate initial backoff must not exceed 1s".to_string(),
        ));
    }
    if config.breaker_failure_threshold == 0 {
        return Err(EmbeddingError::Configuration(
            "embedding delegate breaker threshold must be greater than zero".to_string(),
        ));
    }
    if config.breaker_open_for.is_zero() || config.breaker_open_for > DELEGATION_MAX_BREAKER_OPEN_FOR {
        return Err(EmbeddingError::Configuration(
            "embedding delegate breaker cooldown must be between 1ns and 24h".to_string(),
        ));
    }
    Ok(())
}

/// Pure-Rust, dependency-free, deterministic CPU embedder (buyer-fit M3
/// default). Feature-hashing ("hashing trick") over lowercased word unigrams +
/// adjacent bigrams into a fixed-dimension L2-normalised vector, so lexically
/// overlapping texts score high cosine. Zero deps, zero download, fully offline
/// — this is what makes local dense "work by default". Better semantic recall
/// is the opt-in real model / metered upsell, never a clip on this.
#[derive(Debug, Clone)]
pub struct LocalHashEmbedder {
    dimensions: usize,
}

pub const LOCAL_HASH_EMBEDDER_MODEL: &str = "crux-local-hash-v1";
const LOCAL_HASH_DEFAULT_DIM: usize = 256;

impl Default for LocalHashEmbedder {
    fn default() -> Self {
        Self {
            dimensions: LOCAL_HASH_DEFAULT_DIM,
        }
    }
}

impl LocalHashEmbedder {
    pub fn new(dimensions: usize) -> Self {
        Self {
            dimensions: dimensions.max(1),
        }
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; self.dimensions];
        let tokens: Vec<String> = text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_lowercase())
            .collect();
        let add = |feature: &str, v: &mut [f32]| {
            let h = blake3::hash(feature.as_bytes());
            let bytes = h.as_bytes();
            let idx = (u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize) % self.dimensions;
            // Sign hashing reduces collision bias.
            let sign = if bytes[4] & 1 == 0 { 1.0 } else { -1.0 };
            v[idx] += sign;
        };
        for (i, tok) in tokens.iter().enumerate() {
            add(tok, &mut v);
            if i + 1 < tokens.len() {
                add(&format!("{tok}_{}", tokens[i + 1]), &mut v);
            }
        }
        // L2 normalise (unit vector ⇒ cosine == dot).
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 1e-12 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }
}

impl Embedder for LocalHashEmbedder {
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        Ok(texts.iter().map(|t| self.embed(t)).collect())
    }
    fn dimensions(&self) -> usize {
        self.dimensions
    }
    fn model(&self) -> &str {
        LOCAL_HASH_EMBEDDER_MODEL
    }
    fn semantic_profile(&self) -> SemanticProfile {
        SemanticProfile::from_parts(
            LOCAL_HASH_EMBEDDER_MODEL,
            self.dimensions,
            "whitespace_ngram_v1",
            "none",
            "l2",
        )
    }
    fn runs_locally(&self) -> bool {
        true
    }
}

/// Optional real CPU embedding model (buyer-fit M3.4), behind the
/// `dense-embed-model` feature. Wraps fastembed (ONNX Runtime) with
/// all-MiniLM-L6-v2, downloaded on first use into the given cache dir. This is
/// the opt-in "better vectors" path over the always-on [`LocalHashEmbedder`];
/// the free offline path never requires it, and the default build never
/// compiles or downloads it.
#[cfg(feature = "dense-embed-model")]
pub struct FastEmbedEmbedder {
    // `TextEmbedding::embed` takes `&mut self`; the `Embedder` trait is `&self`
    // (it lives behind a shared `Box<dyn Embedder>`), so guard it with a Mutex.
    inner: Mutex<fastembed::TextEmbedding>,
    dimensions: usize,
    model_id: String,
}

/// Stable model id used in the [`FastEmbedEmbedder`] semantic profile.
#[cfg(feature = "dense-embed-model")]
pub const FASTEMBED_MODEL_ID: &str = "fastembed-all-minilm-l6-v2";
#[cfg(feature = "dense-embed-model")]
const FASTEMBED_DIMENSIONS: usize = 384;

#[cfg(feature = "dense-embed-model")]
impl std::fmt::Debug for FastEmbedEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FastEmbedEmbedder")
            .field("model", &self.model_id)
            .field("dimensions", &self.dimensions)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "dense-embed-model")]
impl FastEmbedEmbedder {
    /// Initialise the model, downloading it on first use into `cache_dir`.
    pub fn new(cache_dir: &std::path::Path) -> Result<Self, EmbeddingError> {
        use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
        let options = InitOptions::new(EmbeddingModel::AllMiniLML6V2)
            .with_cache_dir(cache_dir.to_path_buf())
            .with_show_download_progress(false);
        let inner = TextEmbedding::try_new(options).map_err(|e| EmbeddingError::Model(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(inner),
            dimensions: FASTEMBED_DIMENSIONS,
            model_id: FASTEMBED_MODEL_ID.to_string(),
        })
    }
}

#[cfg(feature = "dense-embed-model")]
impl Embedder for FastEmbedEmbedder {
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let docs: Vec<&str> = texts.to_vec();
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| EmbeddingError::Model(format!("embedder lock poisoned: {e}")))?;
        inner
            .embed(docs, None)
            .map_err(|e| EmbeddingError::Model(e.to_string()))
    }
    fn dimensions(&self) -> usize {
        self.dimensions
    }
    fn model(&self) -> &str {
        &self.model_id
    }
    fn semantic_profile(&self) -> SemanticProfile {
        SemanticProfile::from_parts(&self.model_id, self.dimensions, "bert_wordpiece", "none", "l2")
    }
    fn runs_locally(&self) -> bool {
        true
    }
}

#[derive(Serialize)]
struct OllamaEmbedRequest<'a> {
    model: &'a str,
    input: &'a [&'a str],
}

#[derive(Deserialize)]
struct OllamaEmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

/// Lightweight embedding client that talks to Ollama's `/api/embed` endpoint.
///
/// Thread-safe via interior mutability for dimension auto-detection.
pub struct EmbeddingClient {
    config: EmbeddingConfig,
    detected_dims: Mutex<usize>,
}

impl std::fmt::Debug for EmbeddingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingClient")
            .field("base_url", &self.config.base_url)
            .field("model", &self.config.model)
            .finish_non_exhaustive()
    }
}

impl EmbeddingClient {
    pub fn new(config: EmbeddingConfig) -> Self {
        let dims = config.dimensions;
        Self {
            config,
            detected_dims: Mutex::new(dims),
        }
    }

    /// Embed a single text string. Returns the embedding vector.
    pub fn embed_one(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let mut vecs = self.embed_batch(&[text])?;
        vecs.pop().ok_or(EmbeddingError::EmptyResponse)
    }

    /// Embed a batch of text strings. Returns one vector per input.
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let url = format!("{}/api/embed", self.config.base_url.trim_end_matches('/'));
        let body = OllamaEmbedRequest {
            model: &self.config.model,
            input: texts,
        };

        let mut resp = ureq::post(&url)
            .header("Content-Type", "application/json")
            .send_json(serde_json::to_value(&body).map_err(|e| EmbeddingError::Serialize(e.to_string()))?)
            .map_err(|e| EmbeddingError::Network(e.to_string()))?;

        let parsed: OllamaEmbedResponse = resp
            .body_mut()
            .read_json()
            .map_err(|e| EmbeddingError::Deserialize(e.to_string()))?;

        if parsed.embeddings.len() != texts.len() {
            return Err(EmbeddingError::LengthMismatch {
                expected: texts.len(),
                got: parsed.embeddings.len(),
            });
        }

        // Auto-detect dimensions from first response.
        if let Some(first) = parsed.embeddings.first() {
            if let Ok(mut dims) = self.detected_dims.lock() {
                if *dims == 0 {
                    *dims = first.len();
                    tracing::info!(
                        model = %self.config.model,
                        dimensions = first.len(),
                        "embedding-dimensions-detected"
                    );
                }
            }
        }

        Ok(parsed.embeddings)
    }

    /// Return the detected or configured dimensionality.
    pub fn dimensions(&self) -> usize {
        self.detected_dims.lock().map(|d| *d).unwrap_or(0)
    }

    pub fn model(&self) -> &str {
        &self.config.model
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    pub fn semantic_profile(&self) -> SemanticProfile {
        SemanticProfile::from_embedding_config(&self.config, self.dimensions())
    }
}

/// Compute cosine similarity between two vectors.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom < 1e-12 {
        0.0
    } else {
        dot / denom
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmbeddingError {
    #[error("embedding network error: {0}")]
    Network(String),
    #[error("embedding serialize error: {0}")]
    Serialize(String),
    #[error("embedding deserialize error: {0}")]
    Deserialize(String),
    #[error("embedding response empty")]
    EmptyResponse,
    #[error("embedding length mismatch: expected {expected}, got {got}")]
    LengthMismatch { expected: usize, got: usize },
    #[error("embedding model error: {0}")]
    Model(String),
    #[error("embedding delegation configuration error: {0}")]
    Configuration(String),
    #[error("embedding delegation upstream returned HTTP {status}")]
    UpstreamStatus { status: u16 },
    #[error(
        "embedding delegation semantic profile mismatch: expected {expected_model}/{expected_dimensions}, got {got_model}/{got_dimensions}"
    )]
    SemanticProfileMismatch {
        expected_model: String,
        expected_dimensions: usize,
        got_model: String,
        got_dimensions: usize,
    },
    #[error("embedding delegation semantic profile changed: expected {expected_profile_id}, got {got_profile_id}")]
    SemanticProfileChanged {
        expected_profile_id: String,
        got_profile_id: String,
    },
    #[error("embedding delegation returned an invalid semantic profile: {0}")]
    InvalidSemanticProfile(String),
    #[error("embedding delegation vector {index} dimension mismatch: expected {expected}, got {got}")]
    VectorDimensionMismatch { index: usize, expected: usize, got: usize },
    #[error("embedding delegation vector {index} contains a non-finite value")]
    InvalidVectorValue { index: usize },
    #[error("embedding delegation circuit is open; retry after {retry_after_ms}ms")]
    CircuitOpen { retry_after_ms: u64 },
    #[error("embedding delegation half-open recovery probe is already in flight")]
    HalfOpenProbeInFlight,
    #[error("embedding delegation state error: {0}")]
    DelegationState(String),
    #[error("embedding delegation text {index} is {bytes} bytes, over the {max_bytes}-byte request cap")]
    DelegationTextTooLarge {
        index: usize,
        bytes: usize,
        max_bytes: usize,
    },
    #[error("embedding delegation batch has {count} texts, over the {max_count}-text logical-call cap")]
    DelegationBatchTooLarge { count: usize, max_count: usize },
    #[error("embedding delegation batch is {bytes} bytes, over the {max_bytes}-byte logical-call cap")]
    DelegationPayloadTooLarge { bytes: usize, max_bytes: usize },
}

impl EmbeddingError {
    fn delegation_retryable(&self) -> bool {
        match self {
            Self::Network(_) => true,
            Self::UpstreamStatus { status } => *status == 408 || *status == 429 || (500..600).contains(status),
            _ => false,
        }
    }

    fn delegation_failure_class(&self) -> DelegationFailureClass {
        match self {
            Self::SemanticProfileMismatch { .. }
            | Self::SemanticProfileChanged { .. }
            | Self::InvalidSemanticProfile(_)
            | Self::VectorDimensionMismatch { .. } => DelegationFailureClass::ProfileMismatch,
            _ => DelegationFailureClass::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockDelegationRequest {
        endpoint: String,
        bearer_token: String,
        body: serde_json::Value,
    }

    enum MockDelegationResponse {
        Success(DelegatingEmbedResponse),
        Failure(EmbeddingError),
    }

    struct MockDelegationProvider {
        responses: Mutex<VecDeque<MockDelegationResponse>>,
        requests: Mutex<Vec<MockDelegationRequest>>,
    }

    impl MockDelegationProvider {
        fn new(responses: Vec<MockDelegationResponse>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Result<Vec<MockDelegationRequest>, EmbeddingError> {
            self.requests
                .lock()
                .map(|requests| requests.clone())
                .map_err(|_| EmbeddingError::DelegationState("mock request lock poisoned".to_string()))
        }
    }

    impl DelegationTransport for Arc<MockDelegationProvider> {
        fn send(
            &self,
            endpoint: &str,
            bearer_token: &str,
            body: serde_json::Value,
        ) -> Result<DelegatingEmbedResponse, EmbeddingError> {
            self.requests
                .lock()
                .map_err(|_| EmbeddingError::DelegationState("mock request lock poisoned".to_string()))?
                .push(MockDelegationRequest {
                    endpoint: endpoint.to_string(),
                    bearer_token: bearer_token.to_string(),
                    body,
                });
            self.responses
                .lock()
                .map_err(|_| EmbeddingError::DelegationState("mock response lock poisoned".to_string()))?
                .pop_front()
                .ok_or_else(|| EmbeddingError::Network("mock provider response queue exhausted".to_string()))
                .and_then(|response| match response {
                    MockDelegationResponse::Success(response) => Ok(response),
                    MockDelegationResponse::Failure(err) => Err(err),
                })
        }
    }

    fn delegation_profile(model: &str, dimensions: usize, tokenizer: &str) -> SemanticProfile {
        SemanticProfile::from_parts(model, dimensions, tokenizer, "none", "l2")
    }

    fn delegation_response(semantic_profile: SemanticProfile, embeddings: Vec<Vec<f32>>) -> MockDelegationResponse {
        MockDelegationResponse::Success(DelegatingEmbedResponse {
            embeddings,
            semantic_profile,
        })
    }

    fn delegation_config(model: &str, dimensions: usize) -> DelegatingEmbeddingConfig {
        DelegatingEmbeddingConfig::new(
            "https://provider.example.test",
            "delegate-secret-token",
            model,
            dimensions,
        )
    }

    fn mock_delegating_embedder(
        config: DelegatingEmbeddingConfig,
        provider: Arc<MockDelegationProvider>,
    ) -> Result<DelegatingEmbedder, EmbeddingError> {
        DelegatingEmbedder::new_with_transport(config, Box::new(provider))
    }

    #[test]
    fn cosine_identical_vectors() {
        let v = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6);
    }

    #[test]
    fn cosine_empty_vectors() {
        let sim = cosine_similarity(&[], &[]);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn semantic_profile_is_stable_for_same_embedding_config() {
        let config = EmbeddingConfig {
            base_url: "http://localhost:11434".to_string(),
            model: "nomic-embed-text".to_string(),
            dimensions: 768,
        };

        let a = SemanticProfile::from_embedding_config(&config, 0);
        let b = SemanticProfile::from_embedding_config(&config, 768);

        assert_eq!(a, b);
        assert_eq!(a.schema, SEMANTIC_PROFILE_SCHEMA_V1);
        assert_eq!(a.embedding_fingerprint.schema, EMBEDDING_FINGERPRINT_SCHEMA_V1);
        assert!(a.profile_id.starts_with("sp_"));
        assert!(a.embedding_fingerprint.fingerprint_id.starts_with("efp_"));
    }

    #[test]
    fn local_hash_embedder_is_deterministic_and_unit_norm() {
        let e = LocalHashEmbedder::default();
        let a = e.embed_one("the quick brown fox").unwrap();
        let b = e.embed_one("the quick brown fox").unwrap();
        assert_eq!(a, b, "same text ⇒ identical vector");
        assert_eq!(a.len(), 256);
        let norm: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "unit-normalised");
    }

    #[test]
    fn local_hash_embedder_lexical_overlap_scores_higher() {
        let e = LocalHashEmbedder::default();
        let base = e.embed_one("the cat sat on the mat").unwrap();
        let near = e.embed_one("a cat sat on a mat").unwrap();
        let far = e.embed_one("quantum chromodynamics lecture notes").unwrap();
        let sim_near = cosine_similarity(&base, &near);
        let sim_far = cosine_similarity(&base, &far);
        assert!(sim_near > sim_far, "overlapping text closer: {sim_near} vs {sim_far}");
        assert!(sim_near > 0.4, "strong overlap ⇒ high cosine: {sim_near}");
    }

    #[test]
    fn local_hash_embedder_profile_is_stable_and_named() {
        let e = LocalHashEmbedder::default();
        assert_eq!(e.model(), LOCAL_HASH_EMBEDDER_MODEL);
        let p = e.semantic_profile();
        assert_eq!(p.model, LOCAL_HASH_EMBEDDER_MODEL);
        assert_eq!(p.dimensions, 256);
        assert_eq!(p, LocalHashEmbedder::default().semantic_profile(), "profile stable");
        // A different-dimension local embedder has a different fingerprint.
        assert_ne!(
            p.embedding_fingerprint.hash,
            LocalHashEmbedder::new(384)
                .semantic_profile()
                .embedding_fingerprint
                .hash
        );
    }

    #[test]
    fn embedder_trait_is_object_safe_and_covers_both_impls() {
        let local: Box<dyn Embedder> = Box::new(LocalHashEmbedder::default());
        assert_eq!(local.dimensions(), 256);
        assert!(!local.embed_one("hello world").unwrap().is_empty());
    }

    #[test]
    fn semantic_profile_changes_when_model_changes() {
        let a = SemanticProfile::from_embedding_config(
            &EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "model-a".to_string(),
                dimensions: 384,
            },
            0,
        );
        let b = SemanticProfile::from_embedding_config(
            &EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "model-b".to_string(),
                dimensions: 384,
            },
            0,
        );

        assert_ne!(a.profile_id, b.profile_id);
        assert_ne!(a.embedding_fingerprint.hash, b.embedding_fingerprint.hash);
    }

    #[test]
    fn delegating_embedder_returns_matching_embeddings() -> Result<(), EmbeddingError> {
        let provider_profile = delegation_profile("provider-a", 2, "tokenizer-a");
        let provider = MockDelegationProvider::new(vec![delegation_response(
            provider_profile.clone(),
            vec![vec![0.25, 0.75], vec![0.5, 0.5]],
        )]);
        let config = delegation_config("provider-a", 2);
        assert!(!format!("{config:?}").contains("delegate-secret-token"));
        let embedder = mock_delegating_embedder(config, provider.clone())?;
        assert!(!format!("{embedder:?}").contains("delegate-secret-token"));

        let embeddings = embedder.embed_batch(&["alpha", "beta"])?;
        assert_eq!(embeddings, vec![vec![0.25, 0.75], vec![0.5, 0.5]]);
        assert_eq!(embedder.semantic_profile(), provider_profile);
        assert_eq!(embedder.status().availability, DelegationAvailability::Available);

        let requests = provider.requests()?;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].endpoint, "https://provider.example.test/v1/compute/embed");
        assert_eq!(requests[0].bearer_token, "delegate-secret-token");
        assert_eq!(requests[0].body["texts"], serde_json::json!(["alpha", "beta"]));
        assert_eq!(requests[0].body["semantic_profile"]["model"], "provider-a");
        assert_eq!(requests[0].body["semantic_profile"]["dimensions"], 2);
        Ok(())
    }

    #[test]
    fn delegating_embedder_rejects_unbounded_initial_backoff() {
        let mut config = delegation_config("provider-a", 2);
        config.initial_backoff = DELEGATION_MAX_BACKOFF + Duration::from_nanos(1);

        assert!(matches!(
            DelegatingEmbedder::new(config),
            Err(EmbeddingError::Configuration(message)) if message.contains("initial backoff")
        ));
    }

    #[test]
    fn delegating_embedder_rejects_semantic_profile_mismatch_without_vectors() -> Result<(), EmbeddingError> {
        let wrong_profile = delegation_profile("wrong-provider", 3, "tokenizer-b");
        let provider = MockDelegationProvider::new(vec![delegation_response(wrong_profile, vec![vec![1.0, 2.0, 3.0]])]);
        let embedder = mock_delegating_embedder(delegation_config("expected-provider", 3), provider)?;

        let result = embedder.embed_batch(&["must not escape"]);
        assert!(matches!(result, Err(EmbeddingError::SemanticProfileMismatch { .. })));
        let status = embedder.status();
        assert_eq!(status.availability, DelegationAvailability::Degraded);
        assert_eq!(status.circuit_state, DelegationCircuitState::Closed);
        assert_eq!(status.reason_code, "embedding_semantic_profile_mismatch");
        Ok(())
    }

    #[test]
    fn delegating_embedder_maps_provider_conflict_to_semantic_profile_mismatch() -> Result<(), EmbeddingError> {
        let problem: DelegationProblemDetails = serde_json::from_value(serde_json::json!({
            "type": "https://errors.cuecrux.com/semantic_profile_mismatch",
            "title": "Semantic Profile Conflict",
            "status": 409,
            "code": "SEMANTIC_PROFILE_MISMATCH",
            "expected": { "model": "expected-model", "dimensions": 384 },
            "actual": { "model": "actual-model", "dimensions": 768 }
        }))
        .map_err(|err| EmbeddingError::Deserialize(err.to_string()))?;
        let error = semantic_profile_mismatch_from_problem(problem)
            .ok_or_else(|| EmbeddingError::Deserialize("mismatch problem did not map".to_string()))?;
        assert!(matches!(
            error,
            EmbeddingError::SemanticProfileMismatch {
                expected_model,
                expected_dimensions: 384,
                got_model,
                got_dimensions: 768,
            } if expected_model == "expected-model" && got_model == "actual-model"
        ));
        Ok(())
    }

    #[test]
    fn delegating_embedder_rejects_internally_inconsistent_profile() -> Result<(), EmbeddingError> {
        let mut forged_profile = delegation_profile("provider-a", 2, "tokenizer-a");
        forged_profile.profile_id = "sp_forged".to_string();
        let provider = MockDelegationProvider::new(vec![delegation_response(forged_profile, vec![vec![0.25, 0.75]])]);
        let embedder = mock_delegating_embedder(delegation_config("provider-a", 2), provider)?;

        let result = embedder.embed_batch(&["must not escape"]);
        assert!(matches!(result, Err(EmbeddingError::InvalidSemanticProfile(_))));
        Ok(())
    }

    #[test]
    fn delegating_embedder_persisted_profile_mismatch_latches_without_breaker() -> Result<(), EmbeddingError> {
        let provider = MockDelegationProvider::new(Vec::new());
        let mut store = crate::FactStore::new();
        store.set_embedder(Box::new(mock_delegating_embedder(
            delegation_config("provider-a", 2),
            provider.clone(),
        )?));

        store.report_semantic_profile_mismatch();
        let degraded = store
            .delegation_status()
            .ok_or_else(|| EmbeddingError::DelegationState("delegation status missing".to_string()))?;
        assert_eq!(degraded.availability, DelegationAvailability::Degraded);
        assert_eq!(degraded.circuit_state, DelegationCircuitState::Closed);
        assert_eq!(degraded.reason_code, "embedding_semantic_profile_mismatch");
        assert_eq!(degraded.consecutive_failures, 0);
        assert!(provider.requests()?.is_empty());

        store.clear_semantic_profile_mismatch();
        let recovered = store
            .delegation_status()
            .ok_or_else(|| EmbeddingError::DelegationState("delegation status missing".to_string()))?;
        assert_eq!(recovered.availability, DelegationAvailability::Available);
        assert_eq!(recovered.circuit_state, DelegationCircuitState::Closed);
        assert_eq!(recovered.consecutive_failures, 0);
        Ok(())
    }

    #[test]
    fn delegating_embedder_pins_full_provider_profile() -> Result<(), EmbeddingError> {
        let first_profile = delegation_profile("provider-a", 2, "tokenizer-a");
        let changed_profile = delegation_profile("provider-a", 2, "tokenizer-b");
        let provider = MockDelegationProvider::new(vec![
            delegation_response(first_profile.clone(), vec![vec![0.1, 0.9]]),
            delegation_response(changed_profile, vec![vec![0.2, 0.8]]),
        ]);
        let embedder = mock_delegating_embedder(delegation_config("provider-a", 2), provider)?;

        assert_eq!(embedder.embed_batch(&["first"])?, vec![vec![0.1, 0.9]]);
        let changed = embedder.embed_batch(&["second"]);
        assert!(matches!(changed, Err(EmbeddingError::SemanticProfileChanged { .. })));
        assert_eq!(embedder.semantic_profile(), first_profile);
        Ok(())
    }

    #[test]
    fn delegating_embedder_retries_timeouts_then_opens_circuit() -> Result<(), EmbeddingError> {
        let timeout = || MockDelegationResponse::Failure(EmbeddingError::Network("request timed out".to_string()));
        let provider = MockDelegationProvider::new(vec![timeout(), timeout(), timeout(), timeout()]);
        let mut config = delegation_config("provider-a", 2);
        config.max_attempts = 2;
        config.initial_backoff = Duration::ZERO;
        config.breaker_failure_threshold = 2;
        config.breaker_open_for = Duration::from_millis(100);
        let mut store = crate::FactStore::new();
        store.set_embedder(Box::new(mock_delegating_embedder(config, provider.clone())?));

        let first = store.try_embed_texts(&["first timeout"]);
        assert!(matches!(first, Err(EmbeddingError::Network(_))));
        let second = store.try_embed_texts(&["second timeout"]);
        assert!(matches!(second, Err(EmbeddingError::Network(_))));
        let status = store
            .delegation_status()
            .ok_or_else(|| EmbeddingError::DelegationState("delegation status missing".to_string()))?;
        assert_eq!(status.availability, DelegationAvailability::Degraded);
        assert_eq!(status.circuit_state, DelegationCircuitState::Open);
        assert_eq!(status.consecutive_failures, 2);

        // Fail closed: neither empty vectors nor the legacy `None` fallback,
        // and the open circuit does not issue another provider request.
        let open = store.try_embed_texts(&["circuit-open"]);
        assert!(matches!(open, Err(EmbeddingError::CircuitOpen { .. })));
        assert_eq!(provider.requests()?.len(), 4);
        Ok(())
    }

    #[test]
    fn delegated_fact_writes_and_queries_stay_lexical_without_remote_io() -> Result<(), EmbeddingError> {
        let mut store = crate::FactStore::new();
        let provider = MockDelegationProvider::new(Vec::new());
        store.set_embedder(Box::new(mock_delegating_embedder(
            delegation_config("provider-a", 2),
            provider.clone(),
        )?));
        let fact = |entity: &str, value: &str| crate::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: "summary".to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        store.store(fact("matching", "alpha target"));
        store.store(fact("unrelated", "beta only"));

        let query = crate::fact_store::FactQuery {
            query: Some("alpha".to_string()),
            top_k: 10,
            ..Default::default()
        };

        let strict = store.try_query(&query)?;
        assert_eq!(strict.facts.len(), 1);
        assert_eq!(strict.facts[0].entity, "matching");
        assert_eq!(store.query(&query).facts.len(), 1);
        assert!(provider.requests()?.is_empty());
        Ok(())
    }

    #[test]
    fn delegating_embedder_half_open_probe_recovers() -> Result<(), EmbeddingError> {
        let provider_profile = delegation_profile("provider-a", 2, "tokenizer-a");
        let provider = MockDelegationProvider::new(vec![
            MockDelegationResponse::Failure(EmbeddingError::Network("request timed out".to_string())),
            delegation_response(provider_profile, vec![vec![0.2, 0.8]]),
        ]);
        let mut config = delegation_config("provider-a", 2);
        config.max_attempts = 1;
        config.breaker_failure_threshold = 1;
        config.breaker_open_for = Duration::from_millis(1);
        let embedder = mock_delegating_embedder(config, provider)?;

        assert!(matches!(
            embedder.embed_batch(&["open"]),
            Err(EmbeddingError::Network(_))
        ));
        assert_eq!(embedder.status().circuit_state, DelegationCircuitState::Open);
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(embedder.embed_batch(&["probe"])?, vec![vec![0.2, 0.8]]);
        assert_eq!(embedder.status().availability, DelegationAvailability::Available);
        assert_eq!(embedder.status().circuit_state, DelegationCircuitState::Closed);
        Ok(())
    }

    #[test]
    fn delegating_embedder_rejects_batch_over_provider_count_cap_without_request() -> Result<(), EmbeddingError> {
        let provider = MockDelegationProvider::new(Vec::new());
        let embedder = mock_delegating_embedder(delegation_config("provider-a", 1), provider.clone())?;
        let owned: Vec<String> = (0..65).map(|index| format!("text-{index}")).collect();
        let texts: Vec<&str> = owned.iter().map(String::as_str).collect();

        assert!(matches!(
            embedder.embed_batch(&texts),
            Err(EmbeddingError::DelegationBatchTooLarge {
                count: 65,
                max_count: DELEGATION_MAX_TEXTS_PER_REQUEST,
            })
        ));
        assert!(provider.requests()?.is_empty());
        assert_eq!(embedder.status().availability, DelegationAvailability::Available);
        Ok(())
    }

    #[test]
    fn delegating_embedder_rejects_batch_over_provider_byte_cap_without_request() -> Result<(), EmbeddingError> {
        let provider = MockDelegationProvider::new(Vec::new());
        let embedder = mock_delegating_embedder(delegation_config("provider-a", 1), provider.clone())?;
        let owned: Vec<String> = (0..5).map(|_| "x".repeat(60 * 1024)).collect();
        let texts: Vec<&str> = owned.iter().map(String::as_str).collect();

        assert!(matches!(
            embedder.embed_batch(&texts),
            Err(EmbeddingError::DelegationPayloadTooLarge {
                max_bytes: DELEGATION_MAX_TEXT_BYTES_PER_REQUEST,
                ..
            })
        ));
        assert!(provider.requests()?.is_empty());
        assert_eq!(embedder.status().availability, DelegationAvailability::Available);
        Ok(())
    }

    #[test]
    fn delegating_embedder_rejects_text_over_provider_item_cap_without_request() -> Result<(), EmbeddingError> {
        let provider = MockDelegationProvider::new(Vec::new());
        let embedder = mock_delegating_embedder(delegation_config("provider-a", 1), provider.clone())?;
        let oversized = "x".repeat(DELEGATION_MAX_TEXT_BYTES + 1);

        let result = embedder.embed_batch(&[&oversized]);
        assert!(matches!(
            result,
            Err(EmbeddingError::DelegationTextTooLarge {
                max_bytes: DELEGATION_MAX_TEXT_BYTES,
                ..
            })
        ));
        assert!(provider.requests()?.is_empty());
        Ok(())
    }
}
