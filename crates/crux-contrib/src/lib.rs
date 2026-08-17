// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `crux-contrib` — Contribution manifest builder and envelope signing.
//!
//! Builds self-contained contribution envelopes (corrections, citations,
//! gap reports, skills) with content-addressed references and ed25519 signatures.

pub mod manifest;
