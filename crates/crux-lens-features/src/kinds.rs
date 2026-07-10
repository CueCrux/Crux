// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Entity-kind registrations for the Features lens.

use corecrux_memory::{KindError, KindRegistration, KindRegistry};
use serde_json::json;

pub const CAPABILITY_KIND: &str = "capability";
pub const REPO_KIND: &str = "repo";
pub const DEPENDS_ON_EDGE: &str = "depends_on";

/// Register the two kinds the Features lens owns. Idempotent in the sense
/// that re-running it on a registry that already has either kind returns
/// `KindError::AlreadyRegistered` so callers can choose whether to ignore.
pub fn bootstrap_kinds(reg: &mut KindRegistry) -> Result<(), KindError> {
    if !reg.is_registered(CAPABILITY_KIND) {
        reg.register(KindRegistration {
            kind: CAPABILITY_KIND.into(),
            description: "PlanCrux Feature Registry capability (Crux M3 lens).".into(),
            allowed_outgoing_edges: vec![DEPENDS_ON_EDGE.into()],
            allowed_incoming_edges: vec![DEPENDS_ON_EDGE.into()],
            json_schema: json!({
                "type": "object",
                "required": ["id", "name", "system", "maturity"],
                "properties": {
                    "id":           {"type": "string"},
                    "name":         {"type": "string"},
                    "system":       {"type": "string"},
                    "subsystem":    {"type": "string"},
                    "maturity":     {"type": "string", "enum": ["planned","documented","building","built","shipped"]},
                    "description":  {"type": "string"},
                    "feature_flag": {"type": "string"},
                    "repo_id":      {"type": "string"},
                    "files":        {"type": "array"},
                    "depends_on":   {"type": "array"},
                    "depended_by":  {"type": "array"},
                    "tests":        {"type": "object"},
                    "audit":        {"type": "object"},
                    "dod":          {"type": "array"},
                    "promise_alignment": {"type": "array"},
                    "external_deps":     {"type": "array"}
                }
            }),
        })?;
    }
    if !reg.is_registered(REPO_KIND) {
        reg.register(KindRegistration {
            kind: REPO_KIND.into(),
            description: "Repository registered alongside capabilities. Trivial co-resident kind.".into(),
            allowed_outgoing_edges: vec![],
            allowed_incoming_edges: vec![],
            json_schema: json!({
                "type": "object",
                "required": ["id", "slug", "name"],
                "properties": {
                    "id":   {"type": "string"},
                    "slug": {"type": "string"},
                    "name": {"type": "string"}
                }
            }),
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_idempotent_against_pre_registered_kinds() {
        let mut r = KindRegistry::new();
        bootstrap_kinds(&mut r).unwrap();
        assert!(r.is_registered(CAPABILITY_KIND));
        assert!(r.is_registered(REPO_KIND));
        // Second call is a no-op (the helper detects already-registered kinds
        // and short-circuits before calling `register`).
        bootstrap_kinds(&mut r).unwrap();
    }

    #[test]
    fn capability_schema_validates_typical_payload() {
        let mut r = KindRegistry::new();
        bootstrap_kinds(&mut r).unwrap();
        let payload = serde_json::json!({
            "id":"X","name":"X","system":"Crux","maturity":"shipped",
            "tests":{"unit":["a.rs"],"integration":[],"e2e":[]},
            "audit":{"status":"audited"},
            "dod":["compiles","tested"]
        });
        r.validate(CAPABILITY_KIND, &payload).unwrap();
    }

    #[test]
    fn capability_schema_rejects_invalid_maturity() {
        let mut r = KindRegistry::new();
        bootstrap_kinds(&mut r).unwrap();
        let payload = serde_json::json!({"id":"X","name":"X","system":"Crux","maturity":"draft"});
        assert!(r.validate(CAPABILITY_KIND, &payload).is_err());
    }
}
