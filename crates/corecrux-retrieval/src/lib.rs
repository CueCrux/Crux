// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! CoreCrux fused retrieval — BM25 + graph signal fusion.
//!
//! The retrieval engine loads `.ccxi` companion indexes, builds a merged inverted index,
//! and scores queries using BM25 + graph signals from ProjectionState.

pub mod bm25;
pub mod dense;
pub mod fused;
pub mod graph;
pub mod index_manager;

pub use dense::{CosineDenseProvider, DenseProvider};
pub use graph::{apply_graph_boost, EntityMatch, GraphParams, RelationEdge};
pub use index_manager::{IndexManager, IndexTier, TierStats};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RetrievalError {
    #[error("index error: {0}")]
    Index(#[from] corecrux_index::IndexError),
    #[error("no index loaded")]
    NoIndex,
    #[error("internal: {msg}")]
    Internal { msg: String },
}

pub type Result<T> = std::result::Result<T, RetrievalError>;
