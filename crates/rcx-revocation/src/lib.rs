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

/// Real HTTP transport. `ureq` with rustls, matching the workspace posture (no
/// openssl anywhere in the dependency surface).
pub struct HttpCrlTransport {
    timeout: Duration,
}

impl HttpCrlTransport {
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for HttpCrlTransport {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

impl CrlTransport for HttpCrlTransport {
    fn fetch(&self, url: &str) -> Result<String, RevocationError> {
        // A CRL is only ever fetched over TLS: it is the input to an
        // authorization decision, so a plaintext fetch would let anyone on the
        // path un-revoke a device by stripping entries.
        if !url.starts_with("https://") {
            return Err(RevocationError::Transport(
                "crl_url must be https (a plaintext CRL is attacker-editable)".to_string(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .build()
            .new_agent();
        agent
            .get(url)
            .call()
            .map_err(|err| RevocationError::Transport(err.to_string()))?
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
        let transport = HttpCrlTransport::default();
        let err = transport
            .fetch("http://crl.example/crl.json")
            .expect_err("http must be refused");
        assert!(matches!(err, RevocationError::Transport(_)));
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
