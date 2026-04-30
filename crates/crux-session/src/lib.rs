// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! VaultCrux Session Handshake v1 — schema-lock crate.
//!
//! Implements the canonical CBOR encoder, JSON mirror (RFC 8785 JCS), BLAKE3
//! zeroed-receipt hashing, and ed25519 verification for the `SessionPlan`
//! type family defined in
//! `PlanCrux/docs/master-plan/VaultCrux-Session-Handshake-Master-Plan-v1_0.md`.
//!
//! ## Invariants
//!
//! - **CBOR is the source of truth for hashing.** JSON is a transport/display
//!   mirror; verification requires re-encoding to canonical CBOR.
//! - **Zeroed-receipt rule (§3.3).** `receipt.hash` = 32 zero bytes,
//!   `receipt.signature` = null, `receipt.signer_kid` = null, when computing
//!   the plan hash.
//! - **Deterministic map key ordering** per RFC 8949 §4.2.1 (Core Deterministic
//!   Encoding): bytewise lex ordering of each key's CBOR encoding.
//! - **Byte-parity** with the TypeScript mirror at
//!   `CueCrux-Shared/packages/session/`. Any change that alters canonical bytes
//!   requires a `plan_version` bump.

pub mod canonical;
pub mod catalog;
pub mod error;
pub mod export;
pub mod generator;
pub mod handshake;
pub mod intent;
pub mod invocation;
pub mod passport;
pub mod plan;
pub mod receipt;
pub mod registry;
pub mod sealer;
pub mod signer;

pub use catalog::{tier_meets, CatalogEntry, DEFAULT_CATALOG};
pub use error::SessionError;
pub use export::{
    build_bundle, decode_plan_entry, CeExportBundle, ExportedInvocation, ExportedPlan, ExportedReceiptWire,
    BUNDLE_SCHEMA_VERSION,
};
pub use generator::{generate_default, generate_graph, GenerateInput, GeneratedGraph, GraphHints};
pub use handshake::{mint, HandshakeInputs, HandshakeRequest, SealedPlan};
pub use intent::{
    apply_intent_shaping_with_affinity, default_intent_table, hash_capability_graph_with_intent, IntentTable,
};
pub use invocation::{
    invocation_event_key, mint_invocation_receipt, verify_invocation_receipt, InvocationEventKey, InvocationVerdict,
    MintInvocation,
};
pub use passport::{LocalPassportConfig, LocalPassportKey};
pub use plan::{
    Budget, Capability, Channels, ImplPath, Passport, ReceiptEnvelope, ReceiptMode, SessionPlan,
    INVOCATION_RECEIPT_VERSION, SESSION_PLAN_VERSION,
};
pub use receipt::{plan_receipt_hash, verify_plan_signature, InvocationReceipt};
pub use registry::{FileSessionRegistry, InMemoryRegistry, RegistryEntry, RegistryError, SessionRegistry};
pub use sealer::{FailingSealer, FileSealer, InMemorySealer, NoopSealer, PlanSealer, SealedEvent, StoredEvent};
pub use signer::{InProcessEd25519Signer, NullSigner, PlanSigner, Signed};
