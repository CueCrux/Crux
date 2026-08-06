// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Revocation feed for RCX capability tokens (ExecPlan
//! `crux-hosted-relay-gateway-2026-07-30`, M2).
//!
//! `RcxCapabilityToken.revocation` carries a `crl_url` and a `push_channel`
//! ([`rcx_capability_token::Revocation`]), but nothing has ever consumed them —
//! they were fields only. This crate is the source of truth those fields point
//! at: it fetches the CRL, caches it with an explicit freshness window, and
//! answers "is this principal revoked?" in a form the caller can **fail closed**
//! on.
//!
//! # Why a tri-state, and why the caller decides
//!
//! [`rcx_capability_token::verify_token_attenuated`] takes
//! `is_principal_revoked: Fn(&str) -> bool`. A bare `bool` has no "I don't
//! know" — so if the CRL is unreachable, a closure that answers `false` silently
//! converts an outage into "nobody is revoked", which is the single worst
//! failure this crate could have. **The fail-closed decision cannot live inside
//! the verifier**, so it lives here: [`RevocationSnapshot`] is a tri-state, and
//! a caller must convert it via [`RevocationSnapshot::checker`], which refuses
//! to produce a checker from anything but fresh data.
//!
//! The sync boundary's existing peer revocation is deliberately **fail-open**
//! (an unlinked peer is not revoked — `corecruxd/src/http/sync.rs`), because it
//! reads a *local* identity-links plane where absence genuinely means "no link".
//! This crate is the opposite: absence means "could not ask", and a relay
//! session must not start on an unanswered question.
//!
//! # Credential model
//!
//! The CRL endpoint (`GET /v1/rcx-ct/crl`) is authenticated, and it derives the
//! tenant it serves from the request's auth context rather than from the URL.
//! [`HttpCrlTransport`] therefore presents `x-api-key` + `x-tenant-id`
//! ([`API_KEY_ENV`] / [`TENANT_ID_ENV`], the same `CORECRUXD_ENGINE_*` family
//! the daemon already uses to reach CruxEngine `apps/api`). An unauthenticated
//! fetch gets a `401`, which this crate fails closed on — safe, but no relay
//! session can ever start.
//!
//! Making the route public instead would be the wrong repair: `crl_url` is a
//! single static config value with no tenant scope, so a public CRL leaks
//! per-tenant revocation volume to anyone who can enumerate tenant ids.
//!
//! # Not included
//!
//! The `push_channel` half is a live push for bounded revocation latency. It
//! needs a WebSocket client, which does not exist anywhere in this tree yet —
//! M4 introduces the first one. [`RevocationFeed`] exposes
//! [`RevocationFeed::apply_push`] so that transport can drive the same cache
//! once it lands, without this crate depending on it now.

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Wire format of a CRL document.
///
/// `revoked_fprs` are passport fingerprints — the same strings
/// `verify_token_attenuated` passes to its checker, which it derives from both
/// the token subject and the delegate public key. One list therefore covers
/// account-wide and per-device revocation with no extra plumbing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrlDocument {
    /// Schema marker; unknown versions are refused rather than guessed at.
    pub schema: String,
    /// Issuer-side sequence number. Monotonic; a lower value than the cached
    /// one is a rollback and is refused.
    pub sequence: u64,
    /// Revoked passport fingerprints.
    pub revoked_fprs: Vec<String>,
}

/// The schema string this crate understands.
pub const CRL_SCHEMA_V1: &str = "rcx-crl/1";

/// How long a fetched CRL is considered authoritative.
pub const DEFAULT_FRESHNESS_SECS: u64 = 300;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevocationError {
    #[error("transport failure: {0}")]
    Transport(String),
    /// The CRL endpoint rejected the credential (HTTP 401/403).
    ///
    /// Split from [`RevocationError::Transport`] because the two demand opposite
    /// operator responses and are indistinguishable in a log line otherwise: a
    /// transport failure is "the endpoint is down", this is "this daemon is not
    /// configured to talk to it". Both still fail closed.
    #[error("CRL endpoint rejected the credential (HTTP {status}); check {API_KEY_ENV} and {TENANT_ID_ENV}")]
    Unauthorized { status: u16 },
    #[error("malformed CRL: {0}")]
    Malformed(String),
    #[error("unsupported CRL schema: {0}")]
    UnsupportedSchema(String),
    #[error("CRL sequence went backwards: cached {cached}, received {received}")]
    SequenceRollback { cached: u64, received: u64 },
    #[error("no crl_url on this token's revocation block")]
    NoCrlUrl,
}

/// What the cache can currently say about revocation.
///
/// Deliberately not `Option<HashSet>` — the difference between "fresh and empty"
/// (nobody is revoked) and "we could not ask" (unknown) is exactly the
/// distinction that must not collapse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationSnapshot {
    /// Data fetched within the freshness window. Safe to authorize against.
    Fresh { revoked: HashSet<String>, sequence: u64 },
    /// Data we hold, but older than the freshness window.
    Stale {
        revoked: HashSet<String>,
        sequence: u64,
        age_secs: u64,
    },
    /// Never fetched, or the last fetch failed with nothing cached.
    Unavailable { reason: String },
}

impl RevocationSnapshot {
    /// Build a checker for [`rcx_capability_token::verify_token_attenuated`].
    ///
    /// Returns `None` for anything but [`RevocationSnapshot::Fresh`]. That is
    /// the fail-closed rule in its enforceable form: a caller physically cannot
    /// obtain a checker from stale or missing data, so it must refuse the
    /// session instead of authorizing against a guess.
    #[must_use]
    pub fn checker(&self) -> Option<impl Fn(&str) -> bool + '_> {
        match self {
            Self::Fresh { revoked, .. } => Some(move |fpr: &str| revoked.contains(fpr)),
            Self::Stale { .. } | Self::Unavailable { .. } => None,
        }
    }

    /// Whether a session may be authorized against this snapshot at all.
    #[must_use]
    pub fn is_authorizable(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }

    /// Close reason for a session refused because revocation could not be
    /// established. Maps to relay close code `4503` (contract v1 §11).
    #[must_use]
    pub fn refusal_reason(&self) -> Option<&'static str> {
        match self {
            Self::Fresh { .. } => None,
            Self::Stale { .. } | Self::Unavailable { .. } => Some("revocation_unavailable"),
        }
    }
}

/// Run an authorization step only when revocation is known.
///
/// The fail-closed rule stated as code rather than as a comment. `verify` is the
/// call that needs an `is_principal_revoked` closure — in practice
/// `rcx_capability_token::verify_token_attenuated`. If the snapshot is not
/// fresh, `verify` is **never invoked** and the caller gets the close reason to
/// return instead.
///
/// M5's relay accept path should reach for this rather than calling `checker()`
/// and remembering to branch: forgetting the branch is precisely how an outage
/// turns into "nobody is revoked".
///
/// # Errors
/// Returns the relay close reason (`"revocation_unavailable"`, contract v1 §11)
/// when the snapshot is stale or unavailable.
pub fn authorize_when_known<R>(
    snapshot: &RevocationSnapshot,
    verify: impl FnOnce(&dyn Fn(&str) -> bool) -> R,
) -> Result<R, &'static str> {
    match snapshot {
        RevocationSnapshot::Fresh { revoked, .. } => Ok(verify(&|fpr: &str| revoked.contains(fpr))),
        RevocationSnapshot::Stale { .. } | RevocationSnapshot::Unavailable { .. } => Err("revocation_unavailable"),
    }
}

/// Fetches a CRL document. Abstracted so tests exercise the cache and the
/// fail-closed rule without a network, matching the transport-trait idiom used
/// by the daemon's outbound extension dispatch.
pub trait CrlTransport {
    /// # Errors
    /// Returns [`RevocationError::Transport`] when the document cannot be retrieved.
    fn fetch(&self, url: &str) -> Result<String, RevocationError>;
}

/// Credential for the hosted CRL endpoint.
///
/// `GET /v1/rcx-ct/crl` is authenticated like every other `/v1/rcx-ct/*` route
/// (CruxEngine `apps/api/src/plugins/auth.ts`, `ApiKeyAuth` + `TenantHeader`)
/// and derives the tenant it serves from `request.authContext`, never from the
/// URL. That is deliberate and must not be relaxed: `crl_url` is a single static
/// config value with no tenant scope, so a public CRL would expose per-tenant
/// revocation volume to anyone able to enumerate tenant ids.
///
/// The consequence for this client is that an unauthenticated `GET` gets a
/// `401`, which fails closed as `Unavailable` — safe, but the feature cannot
/// work. Hence this type.
#[derive(Clone, PartialEq, Eq)]
pub struct CrlCredential {
    api_key: String,
    tenant_id: String,
}

/// CruxEngine API key, sent as `x-api-key`.
///
/// Deliberately the **same** env family the daemon already uses to reach
/// CruxEngine `apps/api` (`corecrux_memory::snapshot_sync`, which is the source
/// of truth for these names — they must stay in step). A CRL fetch is one more
/// call to the same API with the same credential; a second credential family
/// would be a second thing to rotate for no gain.
pub const API_KEY_ENV: &str = "CORECRUXD_ENGINE_API_KEY";
/// The daemon's own CruxEngine tenant id, sent as `x-tenant-id`.
pub const TENANT_ID_ENV: &str = "CORECRUXD_ENGINE_TENANT_ID";

/// Grounded from CruxEngine openapi `securitySchemes.ApiKeyAuth.name`.
const API_KEY_HEADER: &str = "x-api-key";
/// Required by CruxEngine's auth middleware for per-tenant routes (`TenantHeader`).
const TENANT_HEADER: &str = "x-tenant-id";

/// The hosted token and the environment name different tenants.
///
/// Deliberately not a variant of a broader error: this is a configuration
/// contradiction the operator must resolve, not a runtime failure to retry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "tenant mismatch: the hosted RCX token is scoped to `{token_tenant}` but \
     {TENANT_ID_ENV} is set to `{env_tenant}`. Unset the env var, or pair the \
     daemon against the tenant it is configured for."
)]
pub struct TenantSourceConflict {
    pub token_tenant: String,
    pub env_tenant: String,
}

impl CrlCredential {
    #[must_use]
    pub fn new(api_key: impl Into<String>, tenant_id: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            tenant_id: tenant_id.into(),
        }
    }

    /// Resolve from the environment. `None` when either half is absent or blank
    /// — a half credential is not a credential, and sending one produces the
    /// same `401` as sending none while looking configured.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let api_key = trimmed_env(API_KEY_ENV)?;
        let tenant_id = trimmed_env(TENANT_ID_ENV)?;
        Some(Self::new(api_key, tenant_id))
    }

    /// Resolve, preferring the tenant carried by a hosted token.
    ///
    /// M5 of ExecPlan `auth-principal-separation-2026-08-05`. A hosted token
    /// already carries `tenant_scope.tenant_id`, and the daemon already reads it
    /// elsewhere, so requiring `CORECRUXD_ENGINE_TENANT_ID` as well is a second
    /// source for one fact. Two sources that can disagree is not redundancy, it
    /// is a bug waiting for a deployment to trigger it.
    ///
    /// **A disagreement is an error, never a silent winner.** Picking either
    /// side quietly would mean a daemon fetching one tenant's revocation list
    /// while believing it is another's — precisely the failure a CRL exists to
    /// prevent. Refusing to start is the honest response, and the message names
    /// both values so the fix is obvious.
    ///
    /// An unpaired daemon (no hosted token) keeps today's behaviour exactly.
    pub fn resolve(token_tenant_id: Option<&str>) -> Result<Option<Self>, TenantSourceConflict> {
        let env_tenant = trimmed_env(TENANT_ID_ENV);
        let Some(token_tenant) = token_tenant_id.map(str::trim).filter(|t| !t.is_empty()) else {
            // No hosted token: unchanged.
            return Ok(Self::from_env());
        };
        if let Some(env_tenant) = env_tenant.as_deref() {
            if env_tenant != token_tenant {
                return Err(TenantSourceConflict {
                    token_tenant: token_tenant.to_string(),
                    env_tenant: env_tenant.to_string(),
                });
            }
        }
        // The env var is not read for the value even when it agrees — the token
        // is the source of truth once one exists.
        let Some(api_key) = trimmed_env(API_KEY_ENV) else {
            return Ok(None);
        };
        Ok(Some(Self::new(api_key, token_tenant.to_string())))
    }

    /// The tenant this credential authenticates as. The API key is deliberately
    /// not exposed — it is a secret, and nothing outside the transport needs it.
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

/// Redacts the key. A CRL fetch failure is exactly the moment someone reaches
/// for a debug log, so the `Debug` impl must not be the thing that leaks it.
impl std::fmt::Debug for CrlCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlCredential")
            .field("api_key", &"<redacted>")
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

fn trimmed_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Real HTTP transport. `ureq` with rustls, matching the workspace posture (no
/// openssl anywhere in the dependency surface).
pub struct HttpCrlTransport {
    timeout: Duration,
    credential: Option<CrlCredential>,
}

impl HttpCrlTransport {
    /// An **unauthenticated** transport.
    ///
    /// Correct only for a CRL whose endpoint authenticates by some other means
    /// (an enterprise deployment behind mTLS or a private network). Against the
    /// hosted CueCrux endpoint this always yields
    /// [`RevocationError::Unauthorized`] — use [`HttpCrlTransport::from_env`] or
    /// [`HttpCrlTransport::with_credential`] there.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            credential: None,
        }
    }

    /// Attach a credential.
    #[must_use]
    pub fn with_credential(mut self, credential: CrlCredential) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Build from the environment, attaching a credential when one is fully
    /// configured. An unconfigured daemon still gets a transport — it will fail
    /// closed at the first fetch with a message naming the missing vars, rather
    /// than failing to construct and losing that context.
    #[must_use]
    pub fn from_env(timeout: Duration) -> Self {
        let mut transport = Self::new(timeout);
        transport.credential = CrlCredential::from_env();
        transport
    }

    /// Whether this transport will present a credential. For a boot-time log —
    /// `false` against the hosted endpoint means every relay session will be
    /// refused, and an operator wants to learn that at boot, not at handshake.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.credential.is_some()
    }
}

impl Default for HttpCrlTransport {
    /// Reads the environment. The unauthenticated form has to be asked for by
    /// name ([`HttpCrlTransport::new`]) because against the hosted endpoint it
    /// cannot work.
    fn default() -> Self {
        Self::from_env(Duration::from_secs(10))
    }
}

/// A CRL is only ever fetched over TLS: it is the input to an authorization
/// decision, so a plaintext fetch would let anyone on the path un-revoke a
/// device by stripping entries.
///
/// The loopback exception exists only inside this crate's own test binary, so
/// the header contract can be asserted against a local stub. `cfg!(test)` is
/// false in every dependent crate, so what ships is https-only.
fn scheme_is_permitted(url: &str) -> bool {
    url.starts_with("https://")
        || (cfg!(test) && (url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:")))
}

impl CrlTransport for HttpCrlTransport {
    fn fetch(&self, url: &str) -> Result<String, RevocationError> {
        if !scheme_is_permitted(url) {
            return Err(RevocationError::Transport(
                "crl_url must be https (a plaintext CRL is attacker-editable)".to_string(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .build()
            .new_agent();
        let mut request = agent.get(url).header("accept", "application/json");
        if let Some(credential) = &self.credential {
            request = request
                .header(API_KEY_HEADER, &credential.api_key)
                .header(TENANT_HEADER, &credential.tenant_id);
        }
        request
            .call()
            .map_err(|err| match err {
                // 401 with no credential is the misconfiguration this exists to
                // fix; 403 is a credential valid for a different tenant. Neither
                // is retryable, and neither is "the endpoint is down".
                ureq::Error::StatusCode(status @ (401 | 403)) => RevocationError::Unauthorized { status },
                other => RevocationError::Transport(other.to_string()),
            })?
            .body_mut()
            .read_to_string()
            .map_err(|err| RevocationError::Transport(err.to_string()))
    }
}

/// Cached revocation state for one CRL endpoint.
///
/// Time is injected on every call rather than read from the clock, so the
/// freshness and rollback rules are deterministically testable.
pub struct RevocationFeed<T: CrlTransport> {
    transport: T,
    crl_url: Option<String>,
    freshness_secs: u64,
    cached: Option<CachedCrl>,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedCrl {
    revoked: HashSet<String>,
    sequence: u64,
    fetched_at: u64,
}

impl<T: CrlTransport> RevocationFeed<T> {
    #[must_use]
    pub fn new(transport: T, crl_url: Option<String>) -> Self {
        Self {
            transport,
            crl_url,
            freshness_secs: DEFAULT_FRESHNESS_SECS,
            cached: None,
            last_error: None,
        }
    }

    #[must_use]
    pub fn with_freshness_secs(mut self, secs: u64) -> Self {
        self.freshness_secs = secs;
        self
    }

    /// Build a feed from a token's revocation block.
    #[must_use]
    pub fn from_revocation(transport: T, revocation: &rcx_capability_token::Revocation) -> Self {
        Self::new(transport, revocation.crl_url.clone())
    }

    /// Fetch and replace the cache.
    ///
    /// # Errors
    /// Returns the fetch or validation failure. The previous cache is retained
    /// on failure so a transient outage degrades `Fresh` → `Stale` rather than
    /// straight to `Unavailable`; the caller still refuses either way, but the
    /// distinction is what an operator needs to tell "the feed is down" from
    /// "this daemon has never reached the feed".
    pub fn refresh(&mut self, now_unix_seconds: u64) -> Result<(), RevocationError> {
        let Some(url) = self.crl_url.clone() else {
            self.last_error = Some("no crl_url".to_string());
            return Err(RevocationError::NoCrlUrl);
        };
        let body = match self.transport.fetch(&url) {
            Ok(body) => body,
            Err(err) => {
                self.last_error = Some(err.to_string());
                return Err(err);
            }
        };
        let doc: CrlDocument = match serde_json::from_str(&body) {
            Ok(doc) => doc,
            Err(err) => {
                let err = RevocationError::Malformed(err.to_string());
                self.last_error = Some(err.to_string());
                return Err(err);
            }
        };
        if doc.schema != CRL_SCHEMA_V1 {
            let err = RevocationError::UnsupportedSchema(doc.schema);
            self.last_error = Some(err.to_string());
            return Err(err);
        }
        // Refuse a rollback. Replaying an older CRL is the cheapest way to
        // un-revoke a device, and it needs no key material — just a cached
        // response. Sequence must never go backwards.
        if let Some(cached) = &self.cached {
            if doc.sequence < cached.sequence {
                let err = RevocationError::SequenceRollback {
                    cached: cached.sequence,
                    received: doc.sequence,
                };
                self.last_error = Some(err.to_string());
                return Err(err);
            }
        }
        self.cached = Some(CachedCrl {
            revoked: doc.revoked_fprs.into_iter().collect(),
            sequence: doc.sequence,
            fetched_at: now_unix_seconds,
        });
        self.last_error = None;
        Ok(())
    }

    /// Current snapshot, without fetching.
    #[must_use]
    pub fn snapshot(&self, now_unix_seconds: u64) -> RevocationSnapshot {
        let Some(cached) = &self.cached else {
            return RevocationSnapshot::Unavailable {
                reason: self
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "revocation feed never fetched".to_string()),
            };
        };
        let age = now_unix_seconds.saturating_sub(cached.fetched_at);
        if age <= self.freshness_secs {
            RevocationSnapshot::Fresh {
                revoked: cached.revoked.clone(),
                sequence: cached.sequence,
            }
        } else {
            RevocationSnapshot::Stale {
                revoked: cached.revoked.clone(),
                sequence: cached.sequence,
                age_secs: age,
            }
        }
    }

    /// Refresh if the cache is not fresh, then return the snapshot.
    ///
    /// A failed refresh is not propagated: the returned snapshot already encodes
    /// it as `Stale` or `Unavailable`, and both are unauthorizable, so there is
    /// no path where a caller proceeds on a failed fetch.
    pub fn snapshot_refreshing(&mut self, now_unix_seconds: u64) -> RevocationSnapshot {
        if !self.snapshot(now_unix_seconds).is_authorizable() {
            let _ = self.refresh(now_unix_seconds);
        }
        self.snapshot(now_unix_seconds)
    }

    /// Apply a push-channel revocation without a full refetch.
    ///
    /// Additive only: a push may *add* revocations, never remove them, and never
    /// advances the sequence. A push that could un-revoke would be a
    /// downgrade channel, and the transport carrying it is not yet
    /// authenticated (it lands with M4's WebSocket client).
    pub fn apply_push(&mut self, revoked_fprs: impl IntoIterator<Item = String>) {
        if let Some(cached) = &mut self.cached {
            cached.revoked.extend(revoked_fprs);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Scripted transport: each `fetch` pops the next queued response.
    struct ScriptedTransport {
        responses: RefCell<Vec<Result<String, RevocationError>>>,
        calls: RefCell<usize>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<Result<String, RevocationError>>) -> Self {
            Self {
                responses: RefCell::new(responses),
                calls: RefCell::new(0),
            }
        }
    }

    impl CrlTransport for ScriptedTransport {
        fn fetch(&self, _url: &str) -> Result<String, RevocationError> {
            *self.calls.borrow_mut() += 1;
            let mut responses = self.responses.borrow_mut();
            if responses.is_empty() {
                return Err(RevocationError::Transport("no scripted response".to_string()));
            }
            responses.remove(0)
        }
    }

    fn crl(sequence: u64, fprs: &[&str]) -> String {
        serde_json::to_string(&CrlDocument {
            schema: CRL_SCHEMA_V1.to_string(),
            sequence,
            revoked_fprs: fprs.iter().map(|s| (*s).to_string()).collect(),
        })
        .unwrap()
    }

    fn feed(responses: Vec<Result<String, RevocationError>>) -> RevocationFeed<ScriptedTransport> {
        RevocationFeed::new(
            ScriptedTransport::new(responses),
            Some("https://crl.example/crl.json".to_string()),
        )
    }

    #[test]
    fn a_fresh_fetch_authorizes_and_reports_revoked_principals() {
        let mut feed = feed(vec![Ok(crl(1, &["p_revoked"]))]);
        feed.refresh(1_000).unwrap();

        let snapshot = feed.snapshot(1_000);
        assert!(snapshot.is_authorizable());
        let checker = snapshot.checker().expect("fresh data must yield a checker");
        assert!(checker("p_revoked"));
        assert!(!checker("p_live"));
    }

    #[test]
    fn an_unreachable_feed_with_no_cache_is_unavailable_and_yields_no_checker() {
        // The core fail-closed property: an outage must not read as "nobody is
        // revoked". There is no way to get a checker, so a caller cannot
        // accidentally authorize against an unanswered question.
        let mut feed = feed(vec![Err(RevocationError::Transport("connection refused".into()))]);
        assert!(feed.refresh(1_000).is_err());

        let snapshot = feed.snapshot(1_000);
        assert!(matches!(snapshot, RevocationSnapshot::Unavailable { .. }));
        assert!(!snapshot.is_authorizable());
        assert!(
            snapshot.checker().is_none(),
            "unavailable data must not produce a checker"
        );
        assert_eq!(snapshot.refusal_reason(), Some("revocation_unavailable"));
    }

    #[test]
    fn data_past_the_freshness_window_goes_stale_and_stops_authorizing() {
        let mut feed = feed(vec![Ok(crl(1, &["p_revoked"]))]).with_freshness_secs(300);
        feed.refresh(1_000).unwrap();

        assert!(feed.snapshot(1_300).is_authorizable(), "still inside the window");

        let stale = feed.snapshot(1_301);
        match &stale {
            RevocationSnapshot::Stale { age_secs, .. } => assert_eq!(*age_secs, 301),
            other => panic!("expected Stale, got {other:?}"),
        }
        assert!(stale.checker().is_none(), "stale data must not authorize");
        assert_eq!(stale.refusal_reason(), Some("revocation_unavailable"));
    }

    #[test]
    fn a_transient_outage_degrades_to_stale_not_unavailable() {
        // Operators need to tell "the feed is down but we have data" from "this
        // daemon has never reached the feed". Both refuse; only one is a
        // configuration problem.
        let mut feed = feed(vec![
            Ok(crl(1, &["p_revoked"])),
            Err(RevocationError::Transport("timeout".into())),
        ])
        .with_freshness_secs(10);
        feed.refresh(1_000).unwrap();

        let snapshot = feed.snapshot_refreshing(2_000);

        match snapshot {
            RevocationSnapshot::Stale { revoked, .. } => {
                assert!(revoked.contains("p_revoked"), "cached revocations must be retained");
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn a_replayed_older_crl_is_refused() {
        // Replaying a cached older CRL is the cheapest un-revoke attack: it
        // needs no key material, just a stale response.
        let mut feed = feed(vec![Ok(crl(7, &["p_revoked"])), Ok(crl(6, &[]))]);
        feed.refresh(1_000).unwrap();

        let err = feed.refresh(1_010).expect_err("a sequence rollback must be refused");

        assert_eq!(err, RevocationError::SequenceRollback { cached: 7, received: 6 });
        let snapshot = feed.snapshot(1_010);
        let checker = snapshot.checker().expect("cache must be retained");
        assert!(checker("p_revoked"), "the rollback must not un-revoke anyone");
    }

    #[test]
    fn a_same_sequence_refetch_is_accepted() {
        // Only a *decrease* is a rollback; re-serving the current sequence is
        // normal and must refresh the timestamp.
        let mut feed = feed(vec![Ok(crl(7, &["p_a"])), Ok(crl(7, &["p_a", "p_b"]))]).with_freshness_secs(10);
        feed.refresh(1_000).unwrap();
        feed.refresh(1_100).unwrap();

        let snapshot = feed.snapshot(1_100);
        let checker = snapshot.checker().expect("refreshed data is fresh");
        assert!(checker("p_b"));
    }

    #[test]
    fn malformed_and_unknown_schema_documents_are_refused() {
        let mut malformed = feed(vec![Ok("{not json".to_string())]);
        assert!(matches!(malformed.refresh(1_000), Err(RevocationError::Malformed(_))));
        assert!(!malformed.snapshot(1_000).is_authorizable());

        let bad_schema = serde_json::json!({"schema": "rcx-crl/99", "sequence": 1, "revoked_fprs": []});
        let mut unknown = feed(vec![Ok(bad_schema.to_string())]);
        assert!(matches!(
            unknown.refresh(1_000),
            Err(RevocationError::UnsupportedSchema(_))
        ));
        assert!(
            !unknown.snapshot(1_000).is_authorizable(),
            "an unreadable CRL must never authorize"
        );
    }

    #[test]
    fn an_absent_crl_url_is_unavailable_rather_than_permissive() {
        let mut feed = RevocationFeed::new(ScriptedTransport::new(vec![]), None);
        assert_eq!(feed.refresh(1_000), Err(RevocationError::NoCrlUrl));
        assert!(
            !feed.snapshot(1_000).is_authorizable(),
            "a token with no crl_url must not authorize a relay session"
        );
    }

    #[test]
    fn a_push_may_add_revocations_but_never_remove_them() {
        let mut feed = feed(vec![Ok(crl(1, &["p_a"]))]);
        feed.refresh(1_000).unwrap();

        feed.apply_push(["p_b".to_string()]);

        let snapshot = feed.snapshot(1_000);
        let checker = snapshot.checker().unwrap();
        assert!(checker("p_a"), "an additive push must not drop existing revocations");
        assert!(checker("p_b"), "the pushed revocation must apply immediately");
    }

    #[test]
    fn plaintext_crl_urls_are_refused_by_the_http_transport() {
        // A plaintext CRL is attacker-editable, and stripping entries un-revokes
        // devices. Enforced in the transport so no caller can opt out.
        let transport = HttpCrlTransport::new(Duration::from_secs(1));
        let err = transport
            .fetch("http://crl.example/crl.json")
            .expect_err("http must be refused");
        assert!(matches!(err, RevocationError::Transport(_)));
        // The in-crate loopback exception must not widen to arbitrary hosts.
        assert!(!scheme_is_permitted("http://evil.example/crl.json"));
        assert!(!scheme_is_permitted("http://127.0.0.1.evil.example/crl.json"));
        assert!(scheme_is_permitted("https://auth.cuecrux.com/v1/rcx-ct/crl"));
    }

    // ── HTTP transport auth ──────────────────────────────────────────────────
    //
    // The route derives the tenant it serves from `authContext`, so these
    // headers are not decoration: without them the daemon gets a 401 and
    // refuses every relay session. Asserted on the wire rather than on the
    // struct, because "the field is set" and "the header was sent" are
    // different claims and only the second one is the bug that shipped.

    /// One-shot HTTP stub mirroring `corecrux_memory::snapshot_sync`'s. Captures
    /// the raw request and returns a canned status + body.
    fn spawn_stub(status_line: &'static str, body: &'static str) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("http://{}/v1/rcx-ct/crl", listener.local_addr().expect("addr"));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut bytes = Vec::new();
            let mut buf = [0u8; 4096];
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => bytes.extend_from_slice(&buf[..n]),
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&bytes).to_string());
            let _ = write!(
                stream,
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        });
        (url, rx)
    }

    const STUB_CRL: &str = r#"{"schema":"rcx-crl/1","sequence":4,"revoked_fprs":["p_revoked"]}"#;

    #[test]
    fn the_http_transport_sends_the_engine_credential_headers() {
        let (url, rx) = spawn_stub("200 OK", STUB_CRL);
        let transport =
            HttpCrlTransport::new(Duration::from_secs(5)).with_credential(CrlCredential::new("sk-test-secret", "acme"));

        let body = transport.fetch(&url).expect("stub must answer");

        assert_eq!(body, STUB_CRL);
        let request = rx.recv().expect("captured request").to_ascii_lowercase();
        assert!(request.starts_with("get /v1/rcx-ct/crl "), "request line: {request}");
        assert!(request.contains("x-api-key: sk-test-secret"), "x-api-key: {request}");
        assert!(request.contains("x-tenant-id: acme"), "x-tenant-id: {request}");
    }

    #[test]
    fn an_authenticated_fetch_reaches_fresh_through_the_feed() {
        // The gate for this change, end to end through the cache: authenticated
        // transport in, `Fresh` and a working checker out.
        let (url, _rx) = spawn_stub("200 OK", STUB_CRL);
        let transport =
            HttpCrlTransport::new(Duration::from_secs(5)).with_credential(CrlCredential::new("sk-test-secret", "acme"));
        let mut feed = RevocationFeed::new(transport, Some(url));

        let snapshot = feed.snapshot_refreshing(1_000);

        assert!(snapshot.is_authorizable(), "an authenticated fetch must reach Fresh");
        let checker = snapshot.checker().expect("fresh data must yield a checker");
        assert!(checker("p_revoked"));
        assert!(!checker("p_live"));
    }

    #[test]
    fn an_unauthenticated_transport_sends_no_credential_headers() {
        let (url, rx) = spawn_stub("200 OK", STUB_CRL);

        let _ = HttpCrlTransport::new(Duration::from_secs(5)).fetch(&url);

        let request = rx.recv().expect("captured request").to_ascii_lowercase();
        assert!(!request.contains("x-api-key"), "no key must be invented: {request}");
        assert!(
            !request.contains("x-tenant-id"),
            "no tenant must be invented: {request}"
        );
    }

    #[test]
    fn a_rejected_credential_is_reported_as_unauthorized_not_as_an_outage() {
        // This is the shipped bug's signature. It must still fail closed, but an
        // operator has to be able to tell it from an unreachable endpoint --
        // one is a config fix, the other is an incident.
        let (url, _rx) = spawn_stub("401 Unauthorized", r#"{"ok":false}"#);
        let transport = HttpCrlTransport::new(Duration::from_secs(5));
        let mut feed = RevocationFeed::new(transport, Some(url));

        let err = feed.refresh(1_000).expect_err("a 401 must not read as success");

        assert_eq!(err, RevocationError::Unauthorized { status: 401 });
        assert!(err.to_string().contains(API_KEY_ENV), "the message must name the fix");
        assert!(
            !feed.snapshot(1_000).is_authorizable(),
            "a rejected credential must still fail closed"
        );
    }

    #[test]
    fn a_credential_for_the_wrong_tenant_is_unauthorized_too() {
        let (url, _rx) = spawn_stub("403 Forbidden", r#"{"ok":false}"#);
        let transport = HttpCrlTransport::new(Duration::from_secs(5))
            .with_credential(CrlCredential::new("sk-test-secret", "someone-else"));

        let err = transport.fetch(&url).expect_err("403 must not read as success");

        assert_eq!(err, RevocationError::Unauthorized { status: 403 });
    }

    #[test]
    fn the_credential_never_appears_in_debug_output() {
        // A CRL fetch failure is exactly when someone reaches for a debug log.
        let credential = CrlCredential::new("sk-live-do-not-log", "acme");

        let rendered = format!("{credential:?}");

        assert!(!rendered.contains("sk-live-do-not-log"), "the key must be redacted");
        assert!(rendered.contains("acme"), "the tenant is not secret and aids diagnosis");
        assert_eq!(credential.tenant_id(), "acme");
    }

    #[test]
    fn authorize_when_known_runs_verification_only_on_fresh_data() {
        // The composition rule M5 depends on: the verify closure must not even
        // be reached when revocation is unknown. Asserted by observing whether
        // it ran, not by inspecting the return value.
        let mut feed = feed(vec![Ok(crl(1, &["p_revoked"]))]).with_freshness_secs(10);
        feed.refresh(1_000).unwrap();

        let mut ran = false;
        let outcome = authorize_when_known(&feed.snapshot(1_000), |is_revoked| {
            ran = true;
            (is_revoked("p_revoked"), is_revoked("p_live"))
        });
        assert!(ran, "fresh data must reach the verifier");
        assert_eq!(outcome, Ok((true, false)));

        // Same feed, now past its freshness window.
        let mut ran_stale = false;
        let refused = authorize_when_known(&feed.snapshot(2_000), |_| {
            ran_stale = true;
        });
        assert!(!ran_stale, "stale revocation must not reach the verifier at all");
        assert_eq!(refused, Err("revocation_unavailable"));
    }

    #[test]
    fn snapshot_refreshing_fetches_only_when_not_fresh() {
        let mut feed = feed(vec![Ok(crl(1, &[])), Ok(crl(2, &[]))]).with_freshness_secs(300);

        feed.snapshot_refreshing(1_000);
        let after_first = *feed.transport.calls.borrow();
        feed.snapshot_refreshing(1_100); // still fresh — must not refetch
        let after_second = *feed.transport.calls.borrow();

        assert_eq!(after_first, 1);
        assert_eq!(after_second, 1, "a fresh cache must not trigger a fetch");
    }
}

#[cfg(test)]
mod m5_tenant_source_tests {
    use super::*;

    /// Env access is process-global, so these run under one lock rather than
    /// racing each other through the same two variables.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<T>(api: Option<&str>, tenant: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match api {
            Some(v) => std::env::set_var(API_KEY_ENV, v),
            None => std::env::remove_var(API_KEY_ENV),
        }
        match tenant {
            Some(v) => std::env::set_var(TENANT_ID_ENV, v),
            None => std::env::remove_var(TENANT_ID_ENV),
        }
        let out = f();
        std::env::remove_var(API_KEY_ENV);
        std::env::remove_var(TENANT_ID_ENV);
        out
    }

    #[test]
    fn an_unpaired_daemon_keeps_todays_behaviour() {
        with_env(Some("k"), Some("tenant-env"), || {
            let resolved = CrlCredential::resolve(None).expect("no token, no conflict");
            assert_eq!(resolved.as_ref().map(CrlCredential::tenant_id), Some("tenant-env"));
        });
    }

    #[test]
    fn a_hosted_token_supplies_the_tenant_and_the_env_var_is_not_needed() {
        with_env(Some("k"), None, || {
            let resolved = CrlCredential::resolve(Some("tenant-token")).expect("no conflict");
            assert_eq!(resolved.as_ref().map(CrlCredential::tenant_id), Some("tenant-token"));
        });
    }

    #[test]
    fn agreement_is_not_a_conflict_and_the_token_still_wins() {
        with_env(Some("k"), Some("tenant-same"), || {
            let resolved = CrlCredential::resolve(Some("tenant-same")).expect("agreement");
            assert_eq!(resolved.as_ref().map(CrlCredential::tenant_id), Some("tenant-same"));
        });
    }

    #[test]
    fn disagreement_is_an_error_not_a_silent_winner() {
        // The whole point of M5. Quietly picking either side means fetching one
        // tenant's revocation list while believing it is another's.
        with_env(Some("k"), Some("tenant-env"), || {
            let err = CrlCredential::resolve(Some("tenant-token")).expect_err("must refuse");
            assert_eq!(err.token_tenant, "tenant-token");
            assert_eq!(err.env_tenant, "tenant-env");
            // The message names both, so the operator does not have to guess.
            let rendered = err.to_string();
            assert!(rendered.contains("tenant-token") && rendered.contains("tenant-env"));
        });
    }

    #[test]
    fn a_blank_token_tenant_is_treated_as_absent() {
        with_env(Some("k"), Some("tenant-env"), || {
            let resolved = CrlCredential::resolve(Some("   ")).expect("blank is absent");
            assert_eq!(resolved.as_ref().map(CrlCredential::tenant_id), Some("tenant-env"));
        });
    }

    #[test]
    fn a_token_without_an_api_key_yields_no_credential() {
        // Half a credential is still not a credential.
        with_env(None, None, || {
            assert!(CrlCredential::resolve(Some("tenant-token"))
                .expect("no conflict")
                .is_none());
        });
    }
}
