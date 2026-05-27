// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Subcommand entrypoints. Each takes a stdin reader and returns
//! `anyhow::Result<()>`. The binary always exits 0 — errors are logged to
//! stderr but never block tool execution.

pub mod context_monitor;
pub mod memory_ack_inline;
pub mod pre_compact;
pub mod session_start;
