// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux-observe` — Self-observation layer for Crux Daemon.
//!
//! Captures operational events (errors, warnings, metrics, health) and bootstrap
//! documentation as facts in the CoreCrux memory subsystem. This enables the
//! system to reason about its own state and operational history.

pub mod bootstrap;
pub mod cold_gate;
pub mod config;
pub mod metrics_sampler;
pub mod ops_layer;
pub mod redact;
pub mod redact_writer;
pub mod schema;
pub mod span_layer;
