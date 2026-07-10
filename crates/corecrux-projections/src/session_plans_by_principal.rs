// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `session_plans_by_principal` projection (M2; master-plan §7.4).
//!
//! Maps `(principal_id, origin_install) -> ordered list of plan entries`.
//! Powers the three queries called out in the master plan:
//!
//! - **Audit:** every session a principal has ever opened.
//! - **Migration (M8):** every local-daemon session plan for install `X` that we need
//!   to import to hosted.
//! - **Continuity:** the last N sessions this agent ran, as a timeline.
//!
//! M2 ships a **pure in-memory projection** that replays the sealed-event
//! stream on demand. The full `.ccxs`-backed, hot/cold, snapshot-durable
//! variant (the pattern used by the four existing projections in
//! `ProjectionStoreV1`) is a follow-up refinement once the dataplane
//! sealer lands. The on-wire event format is already stable, so the
//! snapshot upgrade is purely internal.

use std::collections::BTreeMap;

use crate::events::parse_projection_event;
use crate::{ProjectionError, ProjectionEventV1, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntryV1 {
    pub plan_id: [u8; 16],
    pub session_id: [u8; 16],
    pub minted_at_ms: i64,
    pub expires_at_ms: i64,
    pub plan_receipt_hash: [u8; 32],
    pub capability_graph_hash: [u8; 32],
    pub closed: bool,
    pub close_reason: Option<String>,
    pub revoked: bool,
    pub invocation_count: u32,
}

pub type PrincipalKey = (String, Option<[u8; 32]>);

#[derive(Debug, Default, Clone)]
pub struct SessionPlansByPrincipalV1 {
    by_principal: BTreeMap<PrincipalKey, Vec<PlanEntryV1>>,
    // session_id → index into (principal_key, vec_index) so lifecycle events
    // (close / revoke / invocation) can find their plan in O(log N).
    by_session: BTreeMap<[u8; 16], (PrincipalKey, usize)>,
}

impl SessionPlansByPrincipalV1 {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a parsed projection event. Non-session events are silently
    /// ignored; this projection only watches the four session variants.
    pub fn apply(&mut self, ev: &ProjectionEventV1) {
        match ev {
            ProjectionEventV1::SessionPlanSealed(p) => {
                let key = (p.principal_id.clone(), p.origin_install);
                let entry = PlanEntryV1 {
                    plan_id: p.plan_id,
                    session_id: p.session_id,
                    minted_at_ms: p.minted_at_ms,
                    expires_at_ms: p.expires_at_ms,
                    plan_receipt_hash: p.plan_receipt_hash,
                    capability_graph_hash: p.capability_graph_hash,
                    closed: false,
                    close_reason: None,
                    revoked: false,
                    invocation_count: 0,
                };
                let vec = self.by_principal.entry(key.clone()).or_default();
                let idx = vec.len();
                vec.push(entry);
                self.by_session.insert(p.session_id, (key, idx));
            }
            ProjectionEventV1::SessionClosed(p) => {
                if let Some((key, idx)) = self.by_session.get(&p.session_id).cloned() {
                    if let Some(entry) = self.by_principal.get_mut(&key).and_then(|v| v.get_mut(idx)) {
                        entry.closed = true;
                        entry.close_reason = Some(p.reason.clone());
                    }
                }
            }
            ProjectionEventV1::SessionRevoked(p) => {
                if let Some((key, idx)) = self.by_session.get(&p.session_id).cloned() {
                    if let Some(entry) = self.by_principal.get_mut(&key).and_then(|v| v.get_mut(idx)) {
                        entry.revoked = true;
                        entry.close_reason = Some(p.reason.clone());
                    }
                }
            }
            ProjectionEventV1::InvocationReceipted(p) => {
                if let Some((key, idx)) = self.by_session.get(&p.session_id).cloned() {
                    if let Some(entry) = self.by_principal.get_mut(&key).and_then(|v| v.get_mut(idx)) {
                        entry.invocation_count = entry.invocation_count.saturating_add(1);
                    }
                }
            }
            _ => {}
        }
    }

    /// Apply a raw sealed event payload. Useful when replaying from the
    /// segment log.
    pub fn apply_raw(&mut self, event_type: &str, content_type: &str, payload: &[u8]) -> Result<()> {
        match parse_projection_event(event_type, content_type, payload)? {
            Some(ev) => {
                self.apply(&ev);
                Ok(())
            }
            None => Err(ProjectionError::InvalidEvent {
                msg: format!("unknown session event type: {event_type}"),
            }),
        }
    }

    pub fn plans_for(&self, principal_id: &str, origin_install: Option<[u8; 32]>) -> &[PlanEntryV1] {
        self.by_principal
            .get(&(principal_id.to_string(), origin_install))
            .map_or(&[], Vec::as_slice)
    }

    pub fn lookup_session(&self, session_id: &[u8; 16]) -> Option<&PlanEntryV1> {
        let (key, idx) = self.by_session.get(session_id)?;
        self.by_principal.get(key).and_then(|v| v.get(*idx))
    }

    pub fn total_plans(&self) -> usize {
        self.by_principal.values().map(Vec::len).sum()
    }

    pub fn principals(&self) -> impl Iterator<Item = &PrincipalKey> {
        self.by_principal.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{
        InvocationReceiptedV1, SessionClosedV1, SessionPlanSealedV1, SessionRevokedV1, CONTENT_TYPE_SESSION_BIN_V1,
        EVT_INVOCATION_RECEIPTED_V1, EVT_SESSION_CLOSED_V1, EVT_SESSION_PLAN_SEALED_V1, EVT_SESSION_REVOKED_V1,
    };

    fn ev_sealed(principal: &str, session_id: u8, origin_install: Option<[u8; 32]>) -> ProjectionEventV1 {
        ProjectionEventV1::SessionPlanSealed(SessionPlanSealedV1 {
            event_id: [0u8; 16],
            plan_id: [session_id; 16],
            session_id: [session_id; 16],
            principal_id: principal.to_string(),
            origin: if origin_install.is_some() {
                "ce".into()
            } else {
                "core".into()
            },
            origin_install,
            minted_at_ms: 1_000_000,
            expires_at_ms: 2_000_000,
            plan_receipt_hash: [session_id; 32],
            plan_receipt_signature: None,
            capability_graph_hash: [0xC0u8 + session_id; 32],
            plan_bytes_cbor: vec![],
        })
    }

    #[test]
    fn seals_group_by_principal_and_origin_install() {
        let mut proj = SessionPlansByPrincipalV1::new();
        proj.apply(&ev_sealed("tenant:foo:me", 1, None));
        proj.apply(&ev_sealed("tenant:foo:me", 2, None));
        proj.apply(&ev_sealed("ce:aa:me", 3, Some([0xAA; 32])));

        assert_eq!(proj.plans_for("tenant:foo:me", None).len(), 2);
        assert_eq!(proj.plans_for("ce:aa:me", Some([0xAA; 32])).len(), 1);
        assert_eq!(proj.total_plans(), 3);
    }

    #[test]
    fn close_and_revoke_update_entries() {
        let mut proj = SessionPlansByPrincipalV1::new();
        proj.apply(&ev_sealed("tenant:foo:me", 5, None));
        proj.apply(&ProjectionEventV1::SessionClosed(SessionClosedV1 {
            event_id: [0u8; 16],
            session_id: [5; 16],
            reason: "ttl_expired".into(),
            closed_at_ms: 9_999_999,
        }));
        let plans = proj.plans_for("tenant:foo:me", None);
        assert!(plans[0].closed);
        assert_eq!(plans[0].close_reason.as_deref(), Some("ttl_expired"));

        proj.apply(&ProjectionEventV1::SessionRevoked(SessionRevokedV1 {
            event_id: [0u8; 16],
            session_id: [5; 16],
            reason: "admin_revoked".into(),
            revoked_at_ms: 10_000_000,
            revocation_receipt_hash: [0xFE; 32],
        }));
        let plans = proj.plans_for("tenant:foo:me", None);
        assert!(plans[0].revoked);
        assert_eq!(plans[0].close_reason.as_deref(), Some("admin_revoked"));
    }

    #[test]
    fn invocations_increment_counter() {
        let mut proj = SessionPlansByPrincipalV1::new();
        proj.apply(&ev_sealed("tenant:foo:me", 7, None));
        for _ in 0..3 {
            proj.apply(&ProjectionEventV1::InvocationReceipted(InvocationReceiptedV1 {
                event_id: [0u8; 16],
                session_id: [7; 16],
                capability: "retrieve".into(),
                channel: "bulk".into(),
                invocation_at_ms: 1_500_000,
                invocation_receipt_hash: [0x10; 32],
                parent_plan_receipt_hash: [7; 32],
            }));
        }
        let plans = proj.plans_for("tenant:foo:me", None);
        assert_eq!(plans[0].invocation_count, 3);
    }

    #[test]
    fn apply_raw_replays_sealed_bytes() {
        let sealed = match ev_sealed("ce:aa:me", 11, Some([0xAA; 32])) {
            ProjectionEventV1::SessionPlanSealed(s) => s,
            _ => unreachable!(),
        };
        let bytes = sealed.encode_bin();
        let mut proj = SessionPlansByPrincipalV1::new();
        proj.apply_raw(EVT_SESSION_PLAN_SEALED_V1, CONTENT_TYPE_SESSION_BIN_V1, &bytes)
            .unwrap();
        assert_eq!(proj.total_plans(), 1);
    }

    // Silence the dead-code warnings for the close / revoke / invocation
    // event-type constants: they're part of the public surface and will be
    // used once DataplaneSealer lands.
    #[test]
    fn event_type_constants_exist() {
        assert!(EVT_SESSION_CLOSED_V1.starts_with("corecrux.session."));
        assert!(EVT_SESSION_REVOKED_V1.starts_with("corecrux.session."));
        assert!(EVT_INVOCATION_RECEIPTED_V1.starts_with("corecrux.session."));
    }
}
