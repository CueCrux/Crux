// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `SessionPlan` type family.
//!
//! Schema lives in master-plan §3. Field order here matches the plan's
//! textual definition for readability; on-the-wire order is fixed by the
//! canonical encoder (sorted map keys), not by struct layout.

use crate::canonical::CborValue;
use crate::error::SessionError;

pub const SESSION_PLAN_VERSION: u64 = 1;
pub const INVOCATION_RECEIPT_VERSION: u64 = 1;

pub const HASH_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const ULID_LEN: usize = 16;

/// Receipt mode. `"local"` = BLAKE3 only (CE). `"verified"` = BLAKE3 + ed25519
/// (hosted). `"audit"` = reserved for future audit-grade signing policy.
#[derive(Debug, Clone, PartialEq, Eq)]

pub enum ReceiptMode {
    Local,
    Verified,
    Audit,
}

impl ReceiptMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Verified => "verified",
            Self::Audit => "audit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passport {
    pub principal_id: String,
    pub tier: String,
    pub affinities: Vec<String>,
    /// BLAKE3 of the source passport record; hosted only. None on CE.
    pub passport_receipt: Option<[u8; HASH_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channels {
    /// h2:// URL for the Layer 2 bulk channel. May be absent before Layer 2 ships.
    pub bulk: Option<String>,
    /// Always present; fallback MCP URL.
    pub mcp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub tokens_cap: Option<u64>,
    pub crux_cap: Option<u64>,
    pub ttl_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplPath {
    pub ce: Option<String>,
    pub core: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub cap: String,
    /// "bulk" | "mcp"
    pub prefer: String,
    /// Payload shape, e.g. "stream<Chunk>", "Receipt", "Snapshot".
    pub shape: String,
    pub min_tier: Option<String>,
    /// "free" | "metered" | "heavy"
    pub cost_class: String,
    pub impl_path: ImplPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptEnvelope {
    pub mode: ReceiptMode,
    /// 32-byte BLAKE3 of the canonical plan bytes with this field, `signature`,
    /// and `signer_kid` zeroed.
    pub hash: [u8; HASH_LEN],
    pub signature: Option<[u8; SIGNATURE_LEN]>,
    pub signer_kid: Option<String>,
    pub parent_chain: Option<Vec<[u8; HASH_LEN]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPlan {
    pub plan_id: [u8; ULID_LEN],
    pub plan_version: u64,
    pub minted_at: u64,

    /// "ce" | "core"
    pub origin: String,
    /// BLAKE3(install_uuid), required iff `origin == "ce"`.
    pub origin_install: Option<[u8; HASH_LEN]>,

    pub session_id: [u8; ULID_LEN],
    pub session_ttl_s: u64,

    pub passport: Passport,
    pub channels: Channels,

    pub capability_graph: Vec<Capability>,
    pub capability_graph_hash: [u8; HASH_LEN],

    pub budget: Budget,
    pub receipt: ReceiptEnvelope,

    /// Optional intent hint. Observable in the plan receipt via the
    /// capability-graph-hash input (master-plan §4.4).
    pub intent_hint: Option<String>,
}

impl SessionPlan {
    /// Build the canonical-CBOR `CborValue` tree for this plan. The caller
    /// decides whether the receipt is zeroed (for hashing) or populated (for
    /// on-the-wire transport) via `zero_receipt`.
    pub fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        let mut pairs = Vec::with_capacity(16);
        pairs.push(("plan_id".into(), CborValue::Bytes(self.plan_id.to_vec())));
        pairs.push(("plan_version".into(), CborValue::Uint(self.plan_version)));
        pairs.push(("minted_at".into(), CborValue::Uint(self.minted_at)));
        pairs.push(("origin".into(), CborValue::Text(self.origin.clone())));
        pairs.push((
            "origin_install".into(),
            match &self.origin_install {
                Some(b) => CborValue::Bytes(b.to_vec()),
                None => CborValue::Null,
            },
        ));
        pairs.push(("session_id".into(), CborValue::Bytes(self.session_id.to_vec())));
        pairs.push(("session_ttl_s".into(), CborValue::Uint(self.session_ttl_s)));
        pairs.push(("passport".into(), passport_to_cbor(&self.passport)));
        pairs.push(("channels".into(), channels_to_cbor(&self.channels)));
        pairs.push((
            "capability_graph".into(),
            CborValue::Array(self.capability_graph.iter().map(capability_to_cbor).collect()),
        ));
        pairs.push((
            "capability_graph_hash".into(),
            CborValue::Bytes(self.capability_graph_hash.to_vec()),
        ));
        pairs.push(("budget".into(), budget_to_cbor(&self.budget)));
        pairs.push(("receipt".into(), receipt_to_cbor(&self.receipt, zero_receipt)));
        pairs.push((
            "intent_hint".into(),
            match &self.intent_hint {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ));
        CborValue::Map(pairs)
    }

    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(false).encode()
    }

    /// Canonical CBOR with the receipt hash+signature+signer_kid zeroed
    /// (master-plan §3.3). This is the input to the plan-receipt hash.
    pub fn to_zeroed_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(true).encode()
    }

    pub fn to_canonical_json(&self) -> String {
        crate::canonical::to_canonical_json(&self.to_cbor_value(false))
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SessionError> {
        let value = crate::canonical::decode(bytes)?;
        Self::from_cbor_value(&value)
    }

    pub fn from_cbor_value(value: &CborValue) -> Result<Self, SessionError> {
        let map = as_map(value, "SessionPlan")?;

        Ok(Self {
            plan_id: take_bytes_fixed(map, "plan_id")?,
            plan_version: take_uint(map, "plan_version")?,
            minted_at: take_uint(map, "minted_at")?,
            origin: take_text(map, "origin")?,
            origin_install: take_bytes_fixed_opt(map, "origin_install")?,
            session_id: take_bytes_fixed(map, "session_id")?,
            session_ttl_s: take_uint(map, "session_ttl_s")?,
            passport: passport_from_cbor(get(map, "passport")?)?,
            channels: channels_from_cbor(get(map, "channels")?)?,
            capability_graph: capability_graph_from_cbor(get(map, "capability_graph")?)?,
            capability_graph_hash: take_bytes_fixed(map, "capability_graph_hash")?,
            budget: budget_from_cbor(get(map, "budget")?)?,
            receipt: receipt_from_cbor(get(map, "receipt")?)?,
            intent_hint: take_text_opt(map, "intent_hint")?,
        })
    }
}

// ─── encoders ──────────────────────────────────────────────────────────────

fn passport_to_cbor(p: &Passport) -> CborValue {
    CborValue::Map(vec![
        ("principal_id".into(), CborValue::Text(p.principal_id.clone())),
        ("tier".into(), CborValue::Text(p.tier.clone())),
        (
            "affinities".into(),
            CborValue::Array(p.affinities.iter().map(|s| CborValue::Text(s.clone())).collect()),
        ),
        (
            "passport_receipt".into(),
            match &p.passport_receipt {
                Some(b) => CborValue::Bytes(b.to_vec()),
                None => CborValue::Null,
            },
        ),
    ])
}

fn channels_to_cbor(c: &Channels) -> CborValue {
    CborValue::Map(vec![
        (
            "bulk".into(),
            match &c.bulk {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        ("mcp".into(), CborValue::Text(c.mcp.clone())),
    ])
}

fn budget_to_cbor(b: &Budget) -> CborValue {
    CborValue::Map(vec![
        (
            "tokens_cap".into(),
            match b.tokens_cap {
                Some(n) => CborValue::Uint(n),
                None => CborValue::Null,
            },
        ),
        (
            "crux_cap".into(),
            match b.crux_cap {
                Some(n) => CborValue::Uint(n),
                None => CborValue::Null,
            },
        ),
        ("ttl_s".into(), CborValue::Uint(b.ttl_s)),
    ])
}

fn capability_to_cbor(c: &Capability) -> CborValue {
    CborValue::Map(vec![
        ("cap".into(), CborValue::Text(c.cap.clone())),
        ("prefer".into(), CborValue::Text(c.prefer.clone())),
        ("shape".into(), CborValue::Text(c.shape.clone())),
        (
            "min_tier".into(),
            match &c.min_tier {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        ("cost_class".into(), CborValue::Text(c.cost_class.clone())),
        (
            "impl_path".into(),
            CborValue::Map(vec![
                (
                    "ce".into(),
                    match &c.impl_path.ce {
                        Some(s) => CborValue::Text(s.clone()),
                        None => CborValue::Null,
                    },
                ),
                (
                    "core".into(),
                    match &c.impl_path.core {
                        Some(s) => CborValue::Text(s.clone()),
                        None => CborValue::Null,
                    },
                ),
            ]),
        ),
    ])
}

fn receipt_to_cbor(r: &ReceiptEnvelope, zero: bool) -> CborValue {
    let hash = if zero { vec![0u8; HASH_LEN] } else { r.hash.to_vec() };
    let signature = if zero {
        CborValue::Null
    } else {
        match &r.signature {
            Some(s) => CborValue::Bytes(s.to_vec()),
            None => CborValue::Null,
        }
    };
    let signer_kid = if zero {
        CborValue::Null
    } else {
        match &r.signer_kid {
            Some(s) => CborValue::Text(s.clone()),
            None => CborValue::Null,
        }
    };
    let parent_chain = match &r.parent_chain {
        Some(list) => CborValue::Array(list.iter().map(|h| CborValue::Bytes(h.to_vec())).collect()),
        None => CborValue::Null,
    };
    CborValue::Map(vec![
        ("mode".into(), CborValue::Text(r.mode.as_str().to_string())),
        ("hash".into(), CborValue::Bytes(hash)),
        ("signature".into(), signature),
        ("signer_kid".into(), signer_kid),
        ("parent_chain".into(), parent_chain),
    ])
}

// ─── decoders ──────────────────────────────────────────────────────────────

fn passport_from_cbor(v: &CborValue) -> Result<Passport, SessionError> {
    let map = as_map(v, "passport")?;
    Ok(Passport {
        principal_id: take_text(map, "principal_id")?,
        tier: take_text(map, "tier")?,
        affinities: match get(map, "affinities")? {
            CborValue::Array(items) => items
                .iter()
                .map(|it| match it {
                    CborValue::Text(s) => Ok(s.clone()),
                    _ => Err(SessionError::Decode("affinities item not text".to_string())),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(SessionError::Decode("affinities not array".to_string())),
        },
        passport_receipt: take_bytes_fixed_opt(map, "passport_receipt")?,
    })
}

fn channels_from_cbor(v: &CborValue) -> Result<Channels, SessionError> {
    let map = as_map(v, "channels")?;
    Ok(Channels {
        bulk: take_text_opt(map, "bulk")?,
        mcp: take_text(map, "mcp")?,
    })
}

fn budget_from_cbor(v: &CborValue) -> Result<Budget, SessionError> {
    let map = as_map(v, "budget")?;
    Ok(Budget {
        tokens_cap: take_uint_opt(map, "tokens_cap")?,
        crux_cap: take_uint_opt(map, "crux_cap")?,
        ttl_s: take_uint(map, "ttl_s")?,
    })
}

fn capability_graph_from_cbor(v: &CborValue) -> Result<Vec<Capability>, SessionError> {
    let CborValue::Array(items) = v else {
        return Err(SessionError::Decode("capability_graph not array".to_string()));
    };
    items.iter().map(capability_from_cbor).collect()
}

fn capability_from_cbor(v: &CborValue) -> Result<Capability, SessionError> {
    let map = as_map(v, "Capability")?;
    let impl_path_map = as_map(get(map, "impl_path")?, "impl_path")?;
    Ok(Capability {
        cap: take_text(map, "cap")?,
        prefer: take_text(map, "prefer")?,
        shape: take_text(map, "shape")?,
        min_tier: take_text_opt(map, "min_tier")?,
        cost_class: take_text(map, "cost_class")?,
        impl_path: ImplPath {
            ce: take_text_opt(impl_path_map, "ce")?,
            core: take_text_opt(impl_path_map, "core")?,
        },
    })
}

fn receipt_from_cbor(v: &CborValue) -> Result<ReceiptEnvelope, SessionError> {
    let map = as_map(v, "receipt")?;
    let mode_str = take_text(map, "mode")?;
    let mode = match mode_str.as_str() {
        "local" => ReceiptMode::Local,
        "verified" => ReceiptMode::Verified,
        "audit" => ReceiptMode::Audit,
        other => return Err(SessionError::UnsupportedMode(other.to_string())),
    };
    let signature = match get(map, "signature")? {
        CborValue::Null => None,
        CborValue::Bytes(b) => {
            if b.len() != SIGNATURE_LEN {
                return Err(SessionError::SignatureLength(b.len()));
            }
            let mut arr = [0u8; SIGNATURE_LEN];
            arr.copy_from_slice(b);
            Some(arr)
        }
        _ => return Err(SessionError::Decode("signature must be bytes or null".to_string())),
    };
    let parent_chain = match get(map, "parent_chain")? {
        CborValue::Null => None,
        CborValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let CborValue::Bytes(b) = item else {
                    return Err(SessionError::Decode("parent_chain item not bytes".to_string()));
                };
                if b.len() != HASH_LEN {
                    return Err(SessionError::HashLength(b.len()));
                }
                let mut arr = [0u8; HASH_LEN];
                arr.copy_from_slice(b);
                out.push(arr);
            }
            Some(out)
        }
        _ => return Err(SessionError::Decode("parent_chain must be array or null".to_string())),
    };
    Ok(ReceiptEnvelope {
        mode,
        hash: take_bytes_fixed(map, "hash")?,
        signature,
        signer_kid: take_text_opt(map, "signer_kid")?,
        parent_chain,
    })
}

// ─── map-lookup helpers ────────────────────────────────────────────────────

type Pair = (String, CborValue);

fn as_map<'a>(value: &'a CborValue, ctx: &'static str) -> Result<&'a [Pair], SessionError> {
    match value {
        CborValue::Map(pairs) => Ok(pairs),
        _ => Err(SessionError::Decode(format!("{ctx} is not a map"))),
    }
}

fn get<'a>(map: &'a [Pair], key: &'static str) -> Result<&'a CborValue, SessionError> {
    for (k, v) in map {
        if k == key {
            return Ok(v);
        }
    }
    Err(SessionError::Decode(format!("missing field `{key}`")))
}

fn take_uint(map: &[Pair], key: &'static str) -> Result<u64, SessionError> {
    match get(map, key)? {
        CborValue::Uint(n) => Ok(*n),
        _ => Err(SessionError::Decode(format!("{key} not uint"))),
    }
}

fn take_uint_opt(map: &[Pair], key: &'static str) -> Result<Option<u64>, SessionError> {
    match get(map, key)? {
        CborValue::Null => Ok(None),
        CborValue::Uint(n) => Ok(Some(*n)),
        _ => Err(SessionError::Decode(format!("{key} not uint or null"))),
    }
}

fn take_text(map: &[Pair], key: &'static str) -> Result<String, SessionError> {
    match get(map, key)? {
        CborValue::Text(s) => Ok(s.clone()),
        _ => Err(SessionError::Decode(format!("{key} not text"))),
    }
}

fn take_text_opt(map: &[Pair], key: &'static str) -> Result<Option<String>, SessionError> {
    match get(map, key)? {
        CborValue::Null => Ok(None),
        CborValue::Text(s) => Ok(Some(s.clone())),
        _ => Err(SessionError::Decode(format!("{key} not text or null"))),
    }
}

fn take_bytes_fixed<const N: usize>(map: &[Pair], key: &'static str) -> Result<[u8; N], SessionError> {
    match get(map, key)? {
        CborValue::Bytes(b) => {
            if b.len() != N {
                return Err(SessionError::ByteArrayLength {
                    field: key,
                    expected: N,
                    actual: b.len(),
                });
            }
            let mut arr = [0u8; N];
            arr.copy_from_slice(b);
            Ok(arr)
        }
        _ => Err(SessionError::Decode(format!("{key} not bytes"))),
    }
}

fn take_bytes_fixed_opt<const N: usize>(map: &[Pair], key: &'static str) -> Result<Option<[u8; N]>, SessionError> {
    match get(map, key)? {
        CborValue::Null => Ok(None),
        CborValue::Bytes(b) => {
            if b.len() != N {
                return Err(SessionError::ByteArrayLength {
                    field: key,
                    expected: N,
                    actual: b.len(),
                });
            }
            let mut arr = [0u8; N];
            arr.copy_from_slice(b);
            Ok(Some(arr))
        }
        _ => Err(SessionError::Decode(format!("{key} not bytes or null"))),
    }
}
