// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tenant membership read from a sealed `.ccxseg`, for segments that carry no
//! `.ccxi`.
//!
//! The `.ccxi` doc table caches `xxh64(tenant_id)` per document, and every
//! tenant-scoped surface used to read it from there. That made a `.ccxi`-less
//! segment **un-attributable**: erasure could neither say whose data it held nor
//! remove it selectively. The tenant is not exclusive to `.ccxi` — it is in
//! every frame's canonical header inside the segment, which is exactly where the
//! `.ccxi` builder reads it at seal time (`corecrux-storage`'s
//! `build_ccxi_companion`). `.ccxi` only caches a hash of it.
//!
//! The hash and the `stream_hash` fallback below deliberately mirror that
//! builder line for line: a segment holding both companions must attribute
//! identically whichever source is consulted, or the fallback is not a fallback.

use std::collections::BTreeMap;
use std::path::Path;

/// Which tenants a segment holds documents for, and how many each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SegmentMembership {
    /// Frames in the segment. Every frame is attributed, so this is the sum of
    /// `tenants`' counts.
    pub docs_total: usize,
    /// `xxh64(tenant_id)` → frame count.
    pub tenants: BTreeMap<u64, usize>,
}

impl SegmentMembership {
    /// Frames belonging to `tenant_hash`.
    pub fn docs_for(&self, tenant_hash: u64) -> usize {
        self.tenants.get(&tenant_hash).copied().unwrap_or(0)
    }
}

/// Read a sealed segment's tenant membership from its frame headers.
///
/// The whole file is read and verified; a segment that does not decode is an
/// error rather than an empty membership, because "could not read it" and
/// "holds nothing" must never look the same to an erasure caller.
pub fn read_segment_membership(ccxseg_path: &Path) -> crate::Result<SegmentMembership> {
    let bytes = std::fs::read(ccxseg_path)?;
    membership_from_segment_bytes(&bytes)
}

/// [`read_segment_membership`] over an in-memory segment.
pub fn membership_from_segment_bytes(bytes: &[u8]) -> crate::Result<SegmentMembership> {
    let frames =
        corecrux_segment::decode_segment_frame_headers_v1(bytes).map_err(|e| crate::RetrievalError::Internal {
            msg: format!("segment frame headers unreadable: {e}"),
        })?;

    let mut out = SegmentMembership {
        docs_total: frames.len(),
        tenants: BTreeMap::new(),
    };
    for frame in &frames {
        // Same fallback as `build_ccxi_companion`: a header that will not decode
        // is attributed to its stream_hash, so both sources agree on the segment.
        let tenant_hash = match corecrux_frame::decode_canonical_header_bytes_v1(&frame.header_bytes) {
            Ok(hdr) => xxhash_rust::xxh64::xxh64(hdr.tenant_id.as_bytes(), 0),
            Err(_) => frame.stream_hash,
        };
        *out.tenants.entry(tenant_hash).or_insert(0) += 1;
    }
    Ok(out)
}
