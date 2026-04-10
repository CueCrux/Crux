// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecrux-memory` — Fact store and session store for CoreCrux Community Edition.
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

pub mod embeddings;
pub mod events;
pub mod fact_store;
pub mod session_store;
pub mod sync;

pub use fact_store::{Fact, FactStore};
pub use session_store::{SessionState, SessionStore};
