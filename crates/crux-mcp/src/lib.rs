// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![recursion_limit = "256"]

//! `crux-mcp` — MCP server for agent integration with Crux Daemon.
//!
//! Implements JSON-RPC 2.0 transport, tool dispatch, and an axum HTTP server
//! that exposes CoreCrux capabilities over the MCP Streamable HTTP protocol.
//!
//! ## Tools exposed
//!
//! - `query` — BM25 full-text search with coverage reporting
//! - `store_fact` — write a receipted fact to entity memory
//! - `query_facts` — search the fact store
//! - `save_session` / `load_session` — persist and resume session state
//! - `create_handoff` / `accept_handoff` — multi-agent context transfer
//!
//! ## Authentication
//!
//! Agents authenticate via `CRUX_AGENT_TOKEN` (Bearer token). The token is
//! validated in the [`agent`] module before any tool dispatch.

#![deny(clippy::unwrap_used)]

pub mod agent;
pub mod dispatch;
pub mod handoff;
pub mod protocol;
pub mod scope;
pub mod server;
pub mod tools;
