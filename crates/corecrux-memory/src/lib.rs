// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecrux-memory` — Fact store and session store for Crux Daemon.
//!
//! Provides receipted key-value entity memory (fact store) and scoped session state.
//! All writes produce CROWN-compatible receipts. Data is stored in-memory with
//! optional persistence.
//!
//! ## Fact Store
//!
//! [`FactStore`] stores entity/key/value triples with confidence scores. Facts
//! are searchable via BM25 and can be scoped as private (visible only to the
//! writing agent). Each write returns a CROWN receipt for auditability.
//!
//! ## Session Store
//!
//! [`SessionStore`] persists structured session state (decisions, open questions,
//! constraints) keyed by session ID. Sessions cost ~87 tokens vs ~15K tokens
//! for replaying a full conversation.
//!
//! ## Entity / Edge Substrate
//!
//! [`EntityStore`] and [`EdgeStore`], paired with a [`KindRegistry`], form the
//! domain substrate exposed under `/v1/entities/*` and `/v1/edges/*`. Lens
//! crates register a `KindRegistration` at startup and store their domain data
//! as `(kind, id, payload)` tuples plus directed labelled edges between them.

pub mod action_enrichment;
pub mod edge_store;
pub mod embeddings;
pub mod entity_store;
pub mod events;
pub mod fact_store;
pub mod kind_registry;
pub mod replay;
pub mod semantic;
pub mod session_store;
pub mod sync;

pub use edge_store::{EdgeError, EdgeQuery, EdgeRecord, EdgeStore};
pub use entity_store::{EntityError, EntityQuery, EntityRecord, EntityStore};
pub use fact_store::{Fact, FactStore, HorizonClass};
pub use kind_registry::{KindError, KindRegistration, KindRegistry};
pub use session_store::{SessionState, SessionStore};
