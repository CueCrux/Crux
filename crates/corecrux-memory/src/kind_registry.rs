// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Kind registry for the entity + edge substrate.
//!
//! Lens crates (e.g. `crux-lens-features`) register a `KindRegistration` at
//! daemon startup. The registry stores the JSON-Schema for each kind, the set
//! of edge kinds it may be a source or target of, and a free-text description
//! used by `kind_list` for discovery.
//!
//! Validation is shallow: we check `type` at the top level, required-field
//! presence (`required: [..]` in the schema), and enum membership on string
//! fields that declare `enum: [..]`. This is intentionally lighter than full
//! JSON-Schema Draft 2020-12 — it catches the failure modes the lens authors
//! actually hit (typos, missing fields, wrong maturity values) without pulling
//! in a heavyweight validator dep.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KindRegistration {
    pub kind: String,
    /// Lens-supplied JSON Schema fragment. The substrate enforces a shallow
    /// subset (top-level `type`, `required`, and per-field `enum`).
    pub json_schema: Value,
    /// Edge kinds whose `from_kind` may equal this kind.
    #[serde(default)]
    pub allowed_outgoing_edges: Vec<String>,
    /// Edge kinds whose `to_kind` may equal this kind.
    #[serde(default)]
    pub allowed_incoming_edges: Vec<String>,
    /// Free-text description for `kind_list` discovery.
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, thiserror::Error)]
pub enum KindError {
    #[error("kind '{0}' is not registered")]
    UnknownKind(String),
    #[error("kind '{0}' already registered")]
    AlreadyRegistered(String),
    #[error("payload validation failed for kind '{kind}': {reason}")]
    Validation { kind: String, reason: String },
}

#[derive(Debug, Default)]
pub struct KindRegistry {
    kinds: HashMap<String, KindRegistration>,
}

impl KindRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, reg: KindRegistration) -> Result<(), KindError> {
        if self.kinds.contains_key(&reg.kind) {
            return Err(KindError::AlreadyRegistered(reg.kind));
        }
        self.kinds.insert(reg.kind.clone(), reg);
        Ok(())
    }

    pub fn get(&self, kind: &str) -> Option<&KindRegistration> {
        self.kinds.get(kind)
    }

    pub fn list(&self) -> Vec<&KindRegistration> {
        let mut v: Vec<&KindRegistration> = self.kinds.values().collect();
        v.sort_by(|a, b| a.kind.cmp(&b.kind));
        v
    }

    pub fn is_registered(&self, kind: &str) -> bool {
        self.kinds.contains_key(kind)
    }

    /// Shallow validation. See module docs for the subset enforced.
    pub fn validate(&self, kind: &str, payload: &Value) -> Result<(), KindError> {
        let reg = self.get(kind).ok_or_else(|| KindError::UnknownKind(kind.to_string()))?;
        validate_against_schema(kind, payload, &reg.json_schema)
    }

    /// Validate without requiring the kind to be registered. Used by lens code
    /// that bundles its own schema; treated as a no-op if `schema` is null.
    pub fn validate_with(&self, kind: &str, payload: &Value, schema: &Value) -> Result<(), KindError> {
        if schema.is_null() {
            return Ok(());
        }
        validate_against_schema(kind, payload, schema)
    }
}

fn validate_against_schema(kind: &str, payload: &Value, schema: &Value) -> Result<(), KindError> {
    if schema.is_null() || !schema.is_object() {
        return Ok(());
    }
    if let Some(top_type) = schema.get("type").and_then(|v| v.as_str()) {
        let ok = match top_type {
            "object" => payload.is_object(),
            "array" => payload.is_array(),
            "string" => payload.is_string(),
            "number" => payload.is_number(),
            "integer" => payload.is_i64() || payload.is_u64(),
            "boolean" => payload.is_boolean(),
            "null" => payload.is_null(),
            _ => true,
        };
        if !ok {
            return Err(KindError::Validation {
                kind: kind.to_string(),
                reason: format!("payload top-level type must be '{top_type}'"),
            });
        }
    }
    if let Some(required) = schema.get("required").and_then(|v| v.as_array()) {
        let obj = payload.as_object();
        for req in required {
            let key = match req.as_str() {
                Some(s) => s,
                None => continue,
            };
            let present = obj.is_some_and(|m| m.contains_key(key));
            if !present {
                return Err(KindError::Validation {
                    kind: kind.to_string(),
                    reason: format!("missing required field '{key}'"),
                });
            }
        }
    }
    if let (Some(props), Some(obj)) = (
        schema.get("properties").and_then(|v| v.as_object()),
        payload.as_object(),
    ) {
        for (field, field_schema) in props {
            let Some(field_val) = obj.get(field) else { continue };
            if let Some(allowed) = field_schema.get("enum").and_then(|v| v.as_array()) {
                if !allowed.iter().any(|a| a == field_val) {
                    let allowed_str: Vec<String> =
                        allowed.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    return Err(KindError::Validation {
                        kind: kind.to_string(),
                        reason: format!(
                            "field '{field}' = {} not in enum [{}]",
                            field_val,
                            allowed_str.join(", ")
                        ),
                    });
                }
            }
            if let Some(ftype) = field_schema.get("type").and_then(|v| v.as_str()) {
                // Tolerate explicit null for any typed field — shallow
                // validator treats null as "absent". Real JSON-Schema would
                // require `{"type": ["string", "null"]}` for nullables; this
                // is the M4 ergonomics fix for ad-hoc JSON sources.
                if field_val.is_null() {
                    continue;
                }
                let ok = match ftype {
                    "string" => field_val.is_string(),
                    "number" => field_val.is_number(),
                    "integer" => field_val.is_i64() || field_val.is_u64(),
                    "boolean" => field_val.is_boolean(),
                    "array" => field_val.is_array(),
                    "object" => field_val.is_object(),
                    "null" => field_val.is_null(),
                    _ => true,
                };
                if !ok {
                    return Err(KindError::Validation {
                        kind: kind.to_string(),
                        reason: format!("field '{field}' must be of type '{ftype}'"),
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cap_schema() -> Value {
        json!({
            "type": "object",
            "required": ["id", "name", "system", "maturity"],
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "system": {"type": "string"},
                "maturity": {"type": "string", "enum": ["planned","building","built","shipped"]}
            }
        })
    }

    #[test]
    fn register_and_validate_ok() {
        let mut r = KindRegistry::new();
        r.register(KindRegistration {
            kind: "capability".into(),
            json_schema: cap_schema(),
            allowed_outgoing_edges: vec!["depends_on".into()],
            allowed_incoming_edges: vec!["depends_on".into()],
            description: "Feature Registry capability".into(),
        })
        .unwrap();
        let v = json!({"id":"X","name":"x","system":"s","maturity":"shipped"});
        r.validate("capability", &v).unwrap();
    }

    #[test]
    fn missing_required_field() {
        let mut r = KindRegistry::new();
        r.register(KindRegistration {
            kind: "capability".into(),
            json_schema: cap_schema(),
            allowed_outgoing_edges: vec![],
            allowed_incoming_edges: vec![],
            description: String::new(),
        })
        .unwrap();
        let v = json!({"id":"X","name":"x","system":"s"});
        let err = r.validate("capability", &v).unwrap_err();
        assert!(matches!(err, KindError::Validation { .. }));
    }

    #[test]
    fn enum_violation() {
        let mut r = KindRegistry::new();
        r.register(KindRegistration {
            kind: "capability".into(),
            json_schema: cap_schema(),
            allowed_outgoing_edges: vec![],
            allowed_incoming_edges: vec![],
            description: String::new(),
        })
        .unwrap();
        let v = json!({"id":"X","name":"x","system":"s","maturity":"draft"});
        assert!(r.validate("capability", &v).is_err());
    }

    #[test]
    fn double_register_fails() {
        let mut r = KindRegistry::new();
        let make = || KindRegistration {
            kind: "capability".into(),
            json_schema: cap_schema(),
            allowed_outgoing_edges: vec![],
            allowed_incoming_edges: vec![],
            description: String::new(),
        };
        r.register(make()).unwrap();
        assert!(matches!(r.register(make()), Err(KindError::AlreadyRegistered(_))));
    }

    #[test]
    fn unknown_kind() {
        let r = KindRegistry::new();
        let v = json!({});
        assert!(matches!(r.validate("ghost", &v), Err(KindError::UnknownKind(_))));
    }
}
