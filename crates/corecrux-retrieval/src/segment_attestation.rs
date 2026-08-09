// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Load-time provenance resolution for a segment's companions.
//!
//! The format and the mode semantics live in [`corecrux_index::ccxatt`]; this is
//! where they meet the scan. For each discovered segment the policy answers one
//! question — who produced these companions — and the scan decides what to do
//! about it.
//!
//! ## Verification runs in every mode, including `off`
//!
//! `off` silences the noise about a *missing* attestation. It does not silence a
//! *broken* one. A missing stamp is a policy question; a failing signature or
//! digest is evidence that the bytes are not what was signed, and there is no
//! mode in which loading those is correct (C8). Resolution is cheap for the case
//! that matters: a segment with no `.ccxatt` costs one failed open, and the
//! signature and digest work only happens when there is something to check.

use std::path::Path;

use corecrux_index::{decode_attestation, verify_parsed, AttestationMode, Provenance, TrustRoots};

/// Mode plus trust roots — everything needed to turn a segment on disk into a
/// [`Provenance`].
pub struct AttestationPolicy {
    mode: AttestationMode,
    roots: TrustRoots,
}

/// A segment's resolved provenance, and why it failed if it did.
#[derive(Debug, Clone)]
pub struct ResolvedProvenance {
    pub provenance: Provenance,
    /// Stable reason code for logs and `/v1/version`, so an operator can tell a
    /// corrupt download from a forged one. `None` unless `provenance` is
    /// [`Provenance::Invalid`].
    pub reason_code: Option<&'static str>,
}

impl AttestationPolicy {
    pub fn new(mode: AttestationMode, roots: TrustRoots) -> Self {
        Self { mode, roots }
    }

    pub fn mode(&self) -> AttestationMode {
        self.mode
    }

    /// Whether a segment in this state may be served.
    ///
    /// Note what this does *not* decide: whether the segment is discovered. A
    /// refused segment must stay visible to attribution and erasure — see
    /// `IndexManager::scan_and_load`.
    pub fn permits(&self, provenance: Provenance) -> bool {
        self.mode.permits(provenance)
    }

    /// Resolve the provenance of the companions sharing `stem` in `segments_dir`.
    pub fn resolve(&self, segments_dir: &Path, stem: &str) -> ResolvedProvenance {
        let att_path = segments_dir.join(format!("{stem}.ccxatt"));
        let Ok(raw) = std::fs::read(&att_path) else {
            // Absent, or unreadable. Both are "no usable stamp"; neither is
            // evidence of tampering, so neither is `Invalid`.
            return ResolvedProvenance {
                provenance: Provenance::None,
                reason_code: None,
            };
        };

        let parsed = match decode_attestation(&raw) {
            Ok(p) => p,
            Err(failure) => {
                return ResolvedProvenance {
                    provenance: Provenance::Invalid,
                    reason_code: Some(failure.reason_code()),
                }
            }
        };

        // The segment id is the stem's trailing hex field, which is what the
        // signed body binds — so an attestation cannot be moved onto another
        // segment's bytes.
        let expected_segment_id = stem.rsplit('-').next().unwrap_or_default();

        match verify_parsed(&parsed, &self.roots, expected_segment_id, |ext, key| {
            let name = match key {
                Some(k) => format!("{stem}.{ext}@{k}"),
                None => format!("{stem}.{ext}"),
            };
            std::fs::read(segments_dir.join(name)).ok()
        }) {
            Ok(provenance) => ResolvedProvenance {
                provenance,
                reason_code: None,
            },
            Err(failure) => ResolvedProvenance {
                provenance: Provenance::Invalid,
                reason_code: Some(failure.reason_code()),
            },
        }
    }
}
