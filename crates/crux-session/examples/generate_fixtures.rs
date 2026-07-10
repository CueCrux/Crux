// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Golden-fixture generator for the VaultCrux Session Handshake schema.
//!
//! Run manually when the schema or encoder changes:
//!     cargo run -p crux-session --example generate_fixtures
//!
//! The output lands in `CueCrux-Shared/packages/session/fixtures/` and is
//! consumed by both the Rust golden tests (`tests/golden.rs`) and the TS
//! golden tests (`CueCrux-Shared/packages/session/tests/golden.spec.ts`).
//! Fixtures are checked into git; CI asserts they round-trip bit-identically
//! in both languages.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};

use crux_session::plan::{
    Budget, Capability, Channels, ImplPath, Passport, ReceiptEnvelope, ReceiptMode, SessionPlan, HASH_LEN,
    SESSION_PLAN_VERSION, SIGNATURE_LEN, ULID_LEN,
};
use crux_session::receipt::plan_receipt_hash;

fn main() {
    let fixtures_dir = fixtures_dir();
    fs::create_dir_all(&fixtures_dir).expect("create fixtures dir");

    let specs = all_fixtures();
    let mut index_lines = Vec::new();
    for spec in specs {
        let dir = fixtures_dir.join(spec.name);
        fs::create_dir_all(&dir).expect("create fixture dir");
        let plan = spec.build();
        let cbor = plan.to_canonical_cbor();
        let json = plan.to_canonical_json();
        fs::write(dir.join("plan.cbor"), &cbor).expect("write plan.cbor");
        fs::write(dir.join("plan.json"), &json).expect("write plan.json");
        let meta = serde_json::json!({
            "name": spec.name,
            "description": spec.description,
            "receipt_mode": plan.receipt.mode.as_str(),
            "expected_hash_hex": hex::encode(plan.receipt.hash),
            "expected_cbor_len": cbor.len(),
            "expected_json_len": json.len(),
            "signer_public_key_hex": spec.signer_public_key_hex,
        });
        let meta_str = serde_json::to_string_pretty(&meta).expect("meta json");
        fs::write(dir.join("meta.json"), format!("{meta_str}\n")).expect("write meta.json");
        index_lines.push(format!(
            "{} ({}): {} bytes cbor, hash {}",
            spec.name,
            plan.receipt.mode.as_str(),
            cbor.len(),
            &hex::encode(plan.receipt.hash)[..16]
        ));
    }

    fs::write(fixtures_dir.join("INDEX.txt"), format!("{}\n", index_lines.join("\n"))).expect("write INDEX.txt");
    println!("wrote {} fixtures to {}", index_lines.len(), fixtures_dir.display());
}

fn fixtures_dir() -> PathBuf {
    // Crate root is Crux/crates/crux-session; fixtures live at
    // CueCrux-Shared/packages/session/fixtures relative to repo root.
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .ancestors()
        .nth(3)
        .expect("repo root")
        .join("CueCrux-Shared/packages/session/fixtures")
}

struct FixtureSpec {
    name: &'static str,
    description: &'static str,
    signer_public_key_hex: Option<String>,
    builder: fn(&mut Context) -> SessionPlan,
}

struct Context {
    signing_key: SigningKey,
}

impl Context {
    fn new() -> Self {
        // Deterministic test key. Not a real Vault Transit key.
        Self {
            signing_key: SigningKey::from_bytes(&[1u8; 32]),
        }
    }

    fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

impl FixtureSpec {
    fn build(&self) -> SessionPlan {
        let mut ctx = Context::new();
        let public_key_hex = ctx.public_key_hex();
        let mut plan = (self.builder)(&mut ctx);
        // Compute plan hash (and optional signature) AFTER the plan is built.
        let hash = plan_receipt_hash(&plan);
        plan.receipt.hash = hash;
        if plan.receipt.mode == ReceiptMode::Verified {
            let sig = ctx.signing_key.sign(&hash);
            let mut sig_arr = [0u8; SIGNATURE_LEN];
            sig_arr.copy_from_slice(&sig.to_bytes());
            plan.receipt.signature = Some(sig_arr);
            plan.receipt.signer_kid = Some("vault-transit://test-signer-v1".to_string());
        }
        // Stash public key hex into the fixture spec for test consumption.
        let _ = public_key_hex;
        plan
    }
}

fn all_fixtures() -> Vec<FixtureSpec> {
    let ctx = Context::new();
    let pk_hex = ctx.public_key_hex();

    vec![
        FixtureSpec {
            name: "001-ce-minimal",
            description: "Crux Daemon local plan with three capabilities, no intent, no parent chain.",
            signer_public_key_hex: None,
            builder: ce_minimal,
        },
        FixtureSpec {
            name: "002-ce-full",
            description: "Crux Daemon local plan with 12 capabilities, parent chain of 2, intent_hint set.",
            signer_public_key_hex: None,
            builder: ce_full,
        },
        FixtureSpec {
            name: "003-hosted-free",
            description: "Hosted free-tier plan, 2 capabilities, verified mode.",
            signer_public_key_hex: Some(pk_hex.clone()),
            builder: hosted_free,
        },
        FixtureSpec {
            name: "004-hosted-team",
            description: "Hosted team-tier plan, 15 capabilities, verified mode, budget populated.",
            signer_public_key_hex: Some(pk_hex.clone()),
            builder: hosted_team,
        },
        FixtureSpec {
            name: "005-hosted-pro-parent-chain",
            description: "Hosted pro-tier plan with parent_chain of 3 prior plans.",
            signer_public_key_hex: Some(pk_hex.clone()),
            builder: hosted_pro_parent_chain,
        },
        FixtureSpec {
            name: "006-edge-large-uints",
            description: "Hosted plan exercising u32/u64 boundary values in budget + timestamps.",
            signer_public_key_hex: Some(pk_hex.clone()),
            builder: edge_large_uints,
        },
        FixtureSpec {
            name: "007-empty-affinities",
            description: "Hosted plan with an empty affinities list and zero capabilities.",
            signer_public_key_hex: Some(pk_hex.clone()),
            builder: empty_affinities,
        },
        FixtureSpec {
            name: "008-unicode-principal",
            description: "Hosted plan with non-ASCII tenant/user identifiers and capability names.",
            signer_public_key_hex: Some(pk_hex.clone()),
            builder: unicode_principal,
        },
        FixtureSpec {
            name: "009-audit-mode",
            description: "Audit-mode plan (signed, reserved for future audit-grade signing policy).",
            signer_public_key_hex: Some(pk_hex.clone()),
            builder: audit_mode,
        },
        FixtureSpec {
            name: "010-intent-shaped",
            description: "Hosted plan reordered by intent_hint='audit_review'.",
            signer_public_key_hex: Some(pk_hex),
            builder: intent_shaped,
        },
    ]
}

// ─── fixture builders ───────────────────────────────────────────────────────

fn ulid(n: u8) -> [u8; ULID_LEN] {
    let mut out = [0u8; ULID_LEN];
    out[0] = n;
    out[ULID_LEN - 1] = 0xAA;
    out
}

fn hash32(n: u8) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    for (i, b) in out.iter_mut().enumerate() {
        *b = n.wrapping_add(i as u8);
    }
    out
}

fn cap(
    name: &str,
    prefer: &str,
    shape: &str,
    min_tier: Option<&str>,
    cost_class: &str,
    ce_path: Option<&str>,
    core_path: Option<&str>,
) -> Capability {
    Capability::legacy(
        name,
        prefer,
        shape,
        min_tier.map(String::from),
        cost_class,
        ImplPath {
            ce: ce_path.map(String::from),
            core: core_path.map(String::from),
        },
    )
}

fn empty_receipt(mode: ReceiptMode) -> ReceiptEnvelope {
    ReceiptEnvelope {
        mode,
        hash: [0u8; HASH_LEN],
        signature: None,
        signer_kid: None,
        parent_chain: None,
    }
}

fn ce_minimal(_: &mut Context) -> SessionPlan {
    SessionPlan {
        plan_id: ulid(1),
        plan_version: SESSION_PLAN_VERSION,
        minted_at: 1_745_000_000_000,
        origin: "ce".to_string(),
        origin_install: Some(hash32(0xA0)),
        session_id: ulid(2),
        session_ttl_s: 3600,
        passport: Passport {
            principal_id: "ce:a4f3b1c2:user_001".to_string(),
            tier: "local".to_string(),
            affinities: vec!["*".to_string()],
            denied_capabilities: None,
            grant_expansions: None,
            passport_receipt: None,
        },
        model: None,
        channels: Channels {
            bulk: Some("h2://localhost:14801/v2".to_string()),
            mcp: "http://localhost:14801/mcp".to_string(),
        },
        capability_graph: vec![
            cap(
                "retrieve",
                "bulk",
                "stream<Chunk>",
                None,
                "free",
                Some("retrieve_local"),
                Some("/v2/retrieve"),
            ),
            cap(
                "session_context",
                "bulk",
                "Snapshot",
                None,
                "free",
                Some("session_ctx_local"),
                Some("/v2/session/context"),
            ),
            cap(
                "journal_append",
                "mcp",
                "Receipt",
                None,
                "free",
                Some("journal_local"),
                Some("/mcp/vault#journal_append"),
            ),
        ],
        capability_graph_edges: Vec::new(),
        capability_graph_excluded: Some(Vec::new()),
        capability_graph_version: crux_session::plan::CAPABILITY_GRAPH_VERSION,
        capability_graph_valid_until: 1_745_000_000_000 + 3600 * 1000,
        capability_graph_refresh_hint: None,
        capability_graph_hash: hash32(0xC1),
        budget: Budget {
            tokens_cap: None,
            crux_cap: None,
            ttl_s: 3600,
        },
        receipt: empty_receipt(ReceiptMode::Local),
        intent_hint: None,
    }
}

fn ce_full(_: &mut Context) -> SessionPlan {
    let mut plan = ce_minimal(&mut Context::new());
    plan.plan_id = ulid(3);
    plan.session_id = ulid(4);
    plan.capability_graph = (0..12)
        .map(|i| {
            cap(
                &format!("cap_{i}"),
                if i % 3 == 0 { "bulk" } else { "mcp" },
                "Receipt",
                None,
                if i % 5 == 0 { "heavy" } else { "free" },
                Some(&format!("local_fn_{i}")),
                Some(&format!("/v2/cap_{i}")),
            )
        })
        .collect();
    plan.receipt.parent_chain = Some(vec![hash32(0xD0), hash32(0xD1)]);
    plan.intent_hint = Some("document_ingest".to_string());
    plan
}

fn hosted_free(_: &mut Context) -> SessionPlan {
    SessionPlan {
        plan_id: ulid(5),
        plan_version: SESSION_PLAN_VERSION,
        minted_at: 1_745_100_000_000,
        origin: "core".to_string(),
        origin_install: None,
        session_id: ulid(6),
        session_ttl_s: 3600,
        passport: Passport {
            principal_id: "tenant:indie_co:sam".to_string(),
            tier: "free".to_string(),
            affinities: vec!["retrieval".to_string()],
            denied_capabilities: None,
            grant_expansions: None,
            passport_receipt: Some(hash32(0xE0)),
        },
        model: None,
        channels: Channels {
            bulk: Some("h2://vault.cuecrux.com/v2".to_string()),
            mcp: "https://vault.cuecrux.com/mcp/vault".to_string(),
        },
        capability_graph: vec![
            cap(
                "retrieve",
                "bulk",
                "stream<Chunk>",
                Some("free"),
                "metered",
                None,
                Some("/v2/retrieve"),
            ),
            cap(
                "session_context",
                "mcp",
                "Snapshot",
                Some("free"),
                "free",
                None,
                Some("/mcp/vault#session_context"),
            ),
        ],
        capability_graph_edges: Vec::new(),
        capability_graph_excluded: Some(Vec::new()),
        capability_graph_version: crux_session::plan::CAPABILITY_GRAPH_VERSION,
        capability_graph_valid_until: 1_745_100_000_000 + 3600 * 1000,
        capability_graph_refresh_hint: None,
        capability_graph_hash: hash32(0xC2),
        budget: Budget {
            tokens_cap: Some(10_000),
            crux_cap: Some(5),
            ttl_s: 3600,
        },
        receipt: empty_receipt(ReceiptMode::Verified),
        intent_hint: None,
    }
}

fn hosted_team(_: &mut Context) -> SessionPlan {
    let mut plan = hosted_free(&mut Context::new());
    plan.plan_id = ulid(7);
    plan.session_id = ulid(8);
    plan.passport.principal_id = "tenant:cuecrux_ltd:myles".to_string();
    plan.passport.tier = "team".to_string();
    plan.passport.affinities = vec![
        "retrieval".to_string(),
        "proof".to_string(),
        "audit".to_string(),
        "memory".to_string(),
        "economy".to_string(),
    ];
    plan.capability_graph = (0..15)
        .map(|i| {
            cap(
                &format!("cap_{i:02}"),
                if i % 2 == 0 { "bulk" } else { "mcp" },
                "Receipt",
                Some(if i < 5 {
                    "free"
                } else if i < 10 {
                    "starter"
                } else {
                    "team"
                }),
                if i % 4 == 0 { "heavy" } else { "metered" },
                None,
                Some(&format!("/v2/cap_{i:02}")),
            )
        })
        .collect();
    plan.budget = Budget {
        tokens_cap: Some(100_000),
        crux_cap: Some(500),
        ttl_s: 3600,
    };
    plan
}

fn hosted_pro_parent_chain(_: &mut Context) -> SessionPlan {
    let mut plan = hosted_team(&mut Context::new());
    plan.plan_id = ulid(9);
    plan.session_id = ulid(10);
    plan.passport.tier = "pro".to_string();
    plan.receipt.parent_chain = Some(vec![hash32(0xF0), hash32(0xF1), hash32(0xF2)]);
    plan
}

fn edge_large_uints(_: &mut Context) -> SessionPlan {
    let mut plan = hosted_free(&mut Context::new());
    plan.plan_id = ulid(11);
    plan.session_id = ulid(12);
    plan.minted_at = u64::MAX - 1;
    plan.session_ttl_s = 0xFFFF_FFFF;
    plan.budget = Budget {
        tokens_cap: Some(0xFFFF_FFFF_FFFF_FFFF),
        crux_cap: Some(0),
        ttl_s: 23, // boundary: single-byte head
    };
    plan
}

fn empty_affinities(_: &mut Context) -> SessionPlan {
    let mut plan = hosted_free(&mut Context::new());
    plan.plan_id = ulid(13);
    plan.session_id = ulid(14);
    plan.passport.affinities = vec![];
    plan.capability_graph = vec![];
    plan
}

fn unicode_principal(_: &mut Context) -> SessionPlan {
    let mut plan = hosted_team(&mut Context::new());
    plan.plan_id = ulid(15);
    plan.session_id = ulid(16);
    plan.passport.principal_id = "tenant:cuecrux_café_株式会社:ユーザー_001".to_string();
    plan.capability_graph.push(cap(
        "注釈_追加",
        "mcp",
        "Receipt",
        Some("team"),
        "free",
        None,
        Some("/mcp/vault#annotation_add"),
    ));
    plan
}

fn audit_mode(_: &mut Context) -> SessionPlan {
    let mut plan = hosted_team(&mut Context::new());
    plan.plan_id = ulid(17);
    plan.session_id = ulid(18);
    plan.receipt.mode = ReceiptMode::Audit;
    plan
}

fn intent_shaped(_: &mut Context) -> SessionPlan {
    let mut plan = hosted_team(&mut Context::new());
    plan.plan_id = ulid(19);
    plan.session_id = ulid(20);
    plan.intent_hint = Some("audit_review".to_string());
    // Reorder: push audit-related caps to the front.
    plan.capability_graph
        .sort_by_key(|c| i32::from(!c.cap.starts_with("cap_0")));
    plan
}
