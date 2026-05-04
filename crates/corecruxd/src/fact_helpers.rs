// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Cross-module helpers for the everything-as-facts modules (passports,
//! projects, work, session bindings, relations).
//!
//! `FactStore::query()` returns all live versions of a fact — including
//! superseded ones. The listing surfaces in our modules want only the latest
//! version per `(entity, key)`. This helper consolidates that dedup.

use corecrux_memory::fact_store::Fact;
use std::collections::BTreeMap;

/// Reduce `facts` to one row per (entity, key) — the row with the highest
/// `version` wins. Preserves Fact ordering otherwise (callers can re-sort).
pub fn dedup_latest(facts: Vec<Fact>) -> Vec<Fact> {
    let mut by_key: BTreeMap<(String, String), Fact> = BTreeMap::new();
    for fact in facts {
        let key = (fact.entity.clone(), fact.key.clone());
        match by_key.get(&key) {
            Some(existing) if existing.version >= fact.version => {}
            _ => {
                by_key.insert(key, fact);
            }
        }
    }
    by_key.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use corecrux_memory::fact_store::Fact;

    fn fact(id: &str, entity: &str, key: &str, version: u32) -> Fact {
        Fact {
            fact_id: id.to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: format!("v{version}"),
            source_receipt: None,
            confidence: 1.0,
            stored_at: Utc::now(),
            tokens: 1,
            deleted: false,
            version,
            supersedes: if version > 1 { Some("prev".to_string()) } else { None },
            private: false,
        }
    }

    #[test]
    fn dedup_keeps_highest_version_per_entity_and_key() {
        let input = vec![
            fact("a1", "e1", "k", 1),
            fact("a2", "e1", "k", 3),
            fact("a3", "e1", "k", 2),
            fact("b1", "e2", "k", 5),
        ];
        let mut out = dedup_latest(input);
        out.sort_by(|a, b| a.entity.cmp(&b.entity));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].value, "v3"); // e1 → highest version 3
        assert_eq!(out[1].value, "v5"); // e2 → highest version 5
    }
}
