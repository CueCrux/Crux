// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![deny(clippy::unwrap_used)]
// CLI tool — printing to stdout/stderr is correct behaviour.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! `corecruxctl` — CLI tool for Crux Daemon operations.
//!
//! Subcommands cover admin tasks (segment fingerprints, projection meta,
//! shard map, force-seal), receipt verification + export, audit packs,
//! benchmark drivers, parity smoke tests, and replay tooling. Reads and
//! writes through the same on-disk substrate as `corecruxd`, but never
//! over the network — operators run it locally against a stopped or
//! quiesced daemon.
//!
//! See `corecruxctl --help` for the live subcommand listing.

pub mod admin;
pub mod audit_pack;
pub mod benchmark;
pub mod evidence;
pub mod explain;
pub mod extensions;
pub mod fixture_digest;
pub mod gaps;
pub mod inspect_receipt;
pub mod memory;
pub mod ops;
pub mod parity;
pub mod projections;
pub mod quickstart;
pub mod receipts;
pub mod reconcile;
pub mod replay;
pub mod shard;
pub mod shardmap;
pub mod smoke;
pub mod snapshot;
pub mod stage1_import;
pub mod storage;
pub mod structured_log;
pub mod tooling_env;
pub mod verify_store;
