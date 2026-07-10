// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux-contrib` — Contribution manifest builder and envelope signing.
//!
//! Builds self-contained contribution envelopes (corrections, citations,
//! gap reports, skills) with content-addressed references and ed25519 signatures.

pub mod manifest;
