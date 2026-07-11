// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
//! ## Case Store (procedural memory)
//!
//! [`CaseStore`] is a Memento-style case bank: `(task, action, outcome)` cases
//! recording what worked for a situation. Agents `retrieve_similar` past cases
//! at the start of a task and reuse the successful ones — learning from
//! experience with no model fine-tuning. Complements the declarative fact
//! store with procedural know-how.
//!
//! ## Entity / Edge Substrate
//!
//! [`EntityStore`] and [`EdgeStore`], paired with a [`KindRegistry`], form the
//! domain substrate exposed under `/v1/entities/*` and `/v1/edges/*`. Lens
//! crates register a `KindRegistration` at startup and store their domain data
//! as `(kind, id, payload)` tuples plus directed labelled edges between them.

pub mod action_enrichment;
pub mod artefact_store;
pub mod candidate_link;
pub mod case_store;
pub mod cruxpack;
pub mod edge_store;
pub mod embeddings;
pub mod entity_store;
pub mod events;
pub mod fact_privacy;
pub mod fact_store;
pub mod identity_link;
pub mod kind_registry;
pub mod replay;
pub mod result_envelope;
pub mod semantic;
pub mod session_store;
pub mod signed_bundle;
pub mod sync;

pub use artefact_store::{ArtefactError, ArtefactMetadata, ArtefactRecord, ArtefactStore, PutArtefact};
pub use case_store::{Case, CaseStore, RecordCase};
pub use cruxpack::{
    build_manifest, build_pack_sections, cruxpack_content_hash, plan_import, private_summary, sign_pack, verify_pack,
    CruxPack, ExportOptions, ImportOptions, ImportPlan, PackCounts, PackManifest, PackSections, PackSignature,
    PackVerifyError, PrivateSummary, CRUXPACK_RESERVED_PREFIXES, CRUXPACK_SCHEMA_V1,
};
pub use edge_store::{EdgeError, EdgeQuery, EdgeRecord, EdgeStore};
pub use entity_store::{EntityError, EntityQuery, EntityRecord, EntityStore};
pub use fact_store::{Fact, FactStore, HorizonClass};
pub use kind_registry::{KindError, KindRegistration, KindRegistry};
pub use result_envelope::{
    result_envelope_content_hash, verify_result_envelope, CompanionArtifact, EnvelopeEdge, EnvelopeEntity,
    EnvelopeFact, EnvelopePayload, EnvelopeVerifyError, PlatformSignature, ResultEnvelope, TrustedPlatformKey,
    RESULT_ENVELOPE_SCHEMA_V1,
};
pub use session_store::{SessionState, SessionStore};
