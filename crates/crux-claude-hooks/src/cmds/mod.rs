// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Subcommand entrypoints. Each takes a stdin reader and returns
//! `anyhow::Result<()>`. The binary always exits 0 — errors are logged to
//! stderr but never block tool execution.

pub mod code_context;
pub mod context_monitor;
pub mod memory_ack_inline;
pub mod observe_post;
pub mod observe_pre;
pub mod pre_compact;
pub mod session_start;
