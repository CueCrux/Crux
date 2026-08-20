// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Phase B (Model 2) WASM extension host — M6.1 foundation.
//!
//! Sister module to [`super::extension_outbound`]. Where Phase A proxies
//! tool calls out to an HTTPS endpoint, Phase B runs the extension code
//! in-process inside a wasmtime sandbox with a small Crux-native host
//! ABI. The dispatcher upstream of these two modules picks one path based
//! on `manifest.entry.kind` (Phase A → `ExternalTool`, Phase B → `Wasm`).
//!
//! This file ships the **foundation only**:
//! - [`WasmEngine`] — process-wide wasmtime [`Engine`] with fuel + epoch
//!   interruption enabled.
//! - [`WasmConfig`] — fuel / memory / wall-clock limits, env-driven.
//! - [`dispatch_wasm_tool`] — load module, instantiate, call entrypoint,
//!   classify trap into one of the typed [`WasmError`] variants.
//! - Minimal host ABI: `log`, `now_unix_ms`, `current_passport_json`.
//!
//! The richer ABI (`read_fact` / `store_fact` / `query_facts` /
//! `get_secret_decrypted` / `emit_receipt`) lands in the M6.2 follow-up,
//! together with the HTTP-dispatcher branch (M6.3) and module download +
//! sha256 verification (M6.4). Keeping the foundation isolated lets the
//! traps + resource limits land with their own focused tests, before the
//! grant-enforcement surface bolts on top.
//!
//! ## Wire contract (matches Phase A's so the dispatcher can return one
//! shared response shape)
//!
//! Module exports a single function:
//!
//! ```text
//! extension_call(req_ptr: i32, req_len: i32,
//!                resp_ptr: i32, resp_cap: i32) -> i32
//! ```
//!
//! - Arguments: caller writes a UTF-8 JSON request (same fields as
//!   `super::extension_outbound::ExternalToolRequest`) into linear memory
//!   at `req_ptr..req_ptr+req_len`, and provides a writable response
//!   buffer at `resp_ptr..resp_ptr+resp_cap`.
//! - Return value: number of bytes the module wrote into the response
//!   buffer, or `-1` if `resp_cap` was too small for the response.
//!   Negative values other than `-1` are reserved for future use.
//!
//! Module also exports `memory` (the standard linear memory) and
//! optionally `_initialize` (called once after instantiation, lets a
//! WASI-style runtime do its setup).

// Foundation module: the public surface is wired into the dispatcher in
// M6.3. Until then, tests exercise everything directly. The module is
// gated by `cfg(feature = "wasm-extensions")` at the `mod` declaration
// in `main.rs`, so we don't repeat the attribute here.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use wasmtime::{
    AsContextMut, Caller, Config, Engine, Linker, Memory, MemoryType, Module, Store, StoreLimits, StoreLimitsBuilder,
    TypedFunc,
};

use super::extension_grants::ExtensionGrant;
use super::extension_registry::PackAttribution;

/// Per-call resource limits. Defaults are safe for trivial tools; a
/// future "Pro" extension type may want to widen them, but defaulting
/// tight means a misbehaving community module can't take the daemon down.
#[derive(Debug, Clone)]
pub struct WasmConfig {
    /// Fuel budget (≈ instructions). 1M ≈ 10ms on modern hardware for
    /// integer-heavy workloads. Default: 1_000_000.
    pub fuel: u64,
    /// Maximum linear memory in bytes. Default: 16 MiB.
    pub memory_bytes: usize,
    /// Wall-clock limit, enforced via wasmtime's epoch interruption.
    /// Default: 1 second.
    pub wall_clock: Duration,
    /// Background tick that increments the engine epoch. The actual trap
    /// resolution is `epoch_tick` (worst case). Default: 10 ms.
    pub epoch_tick: Duration,
}

impl WasmConfig {
    pub fn from_env() -> Self {
        fn env_u64(name: &str, default: u64) -> u64 {
            std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
        }
        Self {
            fuel: env_u64("CORECRUXD_WASM_FUEL_DEFAULT", 1_000_000),
            memory_bytes: env_u64("CORECRUXD_WASM_MEMORY_BYTES_DEFAULT", 16_000_000) as usize,
            wall_clock: Duration::from_millis(env_u64("CORECRUXD_WASM_WALL_MS_DEFAULT", 1_000)),
            epoch_tick: Duration::from_millis(env_u64("CORECRUXD_WASM_EPOCH_TICK_MS", 10)),
        }
    }
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            fuel: 1_000_000,
            memory_bytes: 16_000_000,
            wall_clock: Duration::from_millis(1_000),
            epoch_tick: Duration::from_millis(10),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("compile error: {0}")]
    Compile(String),
    #[error("instantiate error: {0}")]
    Instantiate(String),
    #[error("missing export: {0}")]
    MissingExport(&'static str),
    #[error("EXT_WASM_FUEL_EXHAUSTED")]
    FuelExhausted,
    #[error("EXT_WASM_DEADLINE_EXCEEDED")]
    DeadlineExceeded,
    #[error("EXT_WASM_OOM")]
    OutOfMemory,
    #[error("EXT_WASM_TRAP: {0}")]
    Trap(String),
    #[error("response buffer overflow")]
    ResponseTooLarge,
    #[error("response is not valid utf-8")]
    ResponseInvalidUtf8,
    #[error("response is not valid JSON: {0}")]
    ResponseInvalidJson(serde_json::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Per-store mutable state the host functions read/write. Keeping it on
/// the [`Store`] (rather than thread-local statics) means concurrent
/// dispatches don't see each other's logs or passport context.
pub struct HostState {
    /// Bound passport for this call. Surfaced to the module via
    /// `current_passport_json`.
    pub calling_passport_id: String,
    /// The grant that authorises this call. `None` only in M6.1-style
    /// foundation tests; M6.3+ always sets this. With `None`, every
    /// fact-store host fn returns the "no grant" code (-2).
    pub grant: Option<Arc<ExtensionGrant>>,
    /// Adapter over the daemon's fact store. `None` means "this build
    /// doesn't wire fact ops"; the host fns return -5 (unavailable).
    pub fact_store: Option<Arc<dyn HostFactStore>>,
    /// Extension id, kept on the state so receipts the host emits can
    /// attribute them. Unused in M6.2 itself; consumed by M6.3 when the
    /// dispatcher records receipt lineage.
    pub extension_id: String,
    /// Buffered log lines emitted via the host `log` ABI. Rendered into
    /// CROWN receipts and the audit tail upstream.
    pub log: Vec<HostLogEntry>,
    /// Resource limiter — caps linear-memory growth.
    pub limits: StoreLimits,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostLogEntry {
    pub level: String,
    pub message: String,
    pub at_unix_ms: u64,
}

impl HostState {
    /// Foundation-mode: no grant, no fact store. Used by M6.1 tests that
    /// only exercise traps + minimal ABI (`log`, `now_unix_ms`,
    /// `current_passport_json`).
    pub fn new(calling_passport_id: String, max_memory_bytes: usize) -> Self {
        Self::with_context(calling_passport_id, String::new(), None, None, max_memory_bytes)
    }

    /// Production form (M6.3): all four context items wired.
    pub fn with_context(
        calling_passport_id: String,
        extension_id: String,
        grant: Option<Arc<ExtensionGrant>>,
        fact_store: Option<Arc<dyn HostFactStore>>,
        max_memory_bytes: usize,
    ) -> Self {
        Self {
            calling_passport_id,
            grant,
            fact_store,
            extension_id,
            log: Vec::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(max_memory_bytes)
                .instances(1)
                .memories(1)
                .build(),
        }
    }
}

/// Trait the M6.3 dispatcher implements to expose the daemon's fact store
/// to a wasm module without coupling `wasm_host.rs` to the concrete
/// `corecrux_memory::FactStore` type. Tests pass a mock; production uses
/// an adapter that calls into the real store via
/// `tokio::sync::RwLock::blocking_{read,write}` from inside
/// `tokio::task::spawn_blocking`.
///
/// Methods take `&self` (not `&mut self`) so a single
/// `Arc<dyn HostFactStore>` can be cloned across host-fn calls; impls
/// use interior mutability.
pub trait HostFactStore: Send + Sync {
    fn read_fact(&self, entity: &str, key: &str) -> Option<HostFact>;
    fn store_fact(&self, req: HostStoreFact) -> Result<HostFact, String>;
    fn query_facts(&self, q: HostFactQuery) -> Vec<HostFact>;
}

/// Projection of `corecrux_memory::Fact` for the wasm wire. Only the
/// fields a community module needs to act; supersession + version
/// bookkeeping is the host's concern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostFact {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    pub confidence: f32,
    pub stored_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct HostStoreFact {
    pub entity: String,
    pub key: String,
    pub value: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Default)]
pub struct HostFactQuery {
    pub entity_prefix: Option<String>,
    pub query: Option<String>,
    pub top_k: usize,
}

// ── Host ABI return-code legend ────────────────────────────────────────
//
// Negative i32 codes returned by `read_fact` / `store_fact` /
// `query_facts` / `get_secret_decrypted` / `emit_receipt`. Modules see
// these as plain i32 < 0; idiomatic guest-side wrappers translate them
// into Result<...>.
//
// Stable contract — DO NOT renumber across daemon versions; modules
// may have hard-coded match arms.
const HOST_RC_NOT_FOUND: i32 = -1;
const HOST_RC_NO_GRANT: i32 = -2;
const HOST_RC_SCOPE_VIOLATION: i32 = -3;
const HOST_RC_BUFFER_TOO_SMALL: i32 = -4;
const HOST_RC_FACT_STORE_UNAVAILABLE: i32 = -5;
const HOST_RC_NOT_IMPLEMENTED: i32 = -6;
/// 7-9 reserved for future scoped errors (e.g. rate-limit, secret-decrypt).
const HOST_RC_HOST_INTERNAL: i32 = -10;
const HOST_RC_BAD_INPUT: i32 = -11;
const HOST_RC_SERIALISE_ERR: i32 = -12;

/// Public re-exports of the negative-return-code constants so the M6.3
/// dispatcher can map them to `WasmError` variants without re-defining
/// the magic numbers.
pub mod rc {
    pub const NOT_FOUND: i32 = super::HOST_RC_NOT_FOUND;
    pub const NO_GRANT: i32 = super::HOST_RC_NO_GRANT;
    pub const SCOPE_VIOLATION: i32 = super::HOST_RC_SCOPE_VIOLATION;
    pub const BUFFER_TOO_SMALL: i32 = super::HOST_RC_BUFFER_TOO_SMALL;
    pub const FACT_STORE_UNAVAILABLE: i32 = super::HOST_RC_FACT_STORE_UNAVAILABLE;
    pub const NOT_IMPLEMENTED: i32 = super::HOST_RC_NOT_IMPLEMENTED;
    pub const HOST_INTERNAL: i32 = super::HOST_RC_HOST_INTERNAL;
    pub const BAD_INPUT: i32 = super::HOST_RC_BAD_INPUT;
    pub const SERIALISE_ERR: i32 = super::HOST_RC_SERIALISE_ERR;
}

/// Whether `entity` falls under any of the granted prefixes. Used by
/// `read_fact` and to filter `query_facts` results post-fetch.
pub(crate) fn entity_matches_any_prefix(entity: &str, prefixes: &[String]) -> bool {
    crate::fact_privacy::default_private_entity_prefix(entity).is_none()
        && prefixes.iter().any(|p| !p.is_empty() && entity.starts_with(p.as_str()))
}

/// Whether a `query_facts` prefix is acceptable for the given grant. The
/// rule: the query prefix must be at least as specific as one granted
/// prefix (i.e. `query_prefix.starts_with(granted)`). The empty string
/// never satisfies this — modules can't enumerate everything.
pub(crate) fn query_prefix_within_grant(query_prefix: &str, granted: &[String]) -> bool {
    if query_prefix.is_empty() || crate::fact_privacy::private_scope_intersection(query_prefix).is_some() {
        return false;
    }
    granted
        .iter()
        .any(|p| !p.is_empty() && query_prefix.starts_with(p.as_str()))
}

/// Process-wide wasmtime [`Engine`] + a background thread that ticks the
/// epoch counter. Sharing one engine across all extensions is the
/// recommended wasmtime pattern (compiled-module cache is keyed off the
/// engine, fuel + epoch config are per-engine).
pub struct WasmEngine {
    engine: Engine,
    _epoch_thread: std::thread::JoinHandle<()>,
    epoch_stop: Arc<std::sync::atomic::AtomicBool>,
}

impl WasmEngine {
    pub fn new(epoch_tick: Duration) -> Result<Self, WasmError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|e| WasmError::Compile(e.to_string()))?;

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let engine_clone = engine.clone();
        let _epoch_thread = std::thread::Builder::new()
            .name("corecruxd-wasm-epoch".into())
            .spawn(move || {
                while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(epoch_tick);
                    engine_clone.increment_epoch();
                }
            })
            .map_err(|e| WasmError::Compile(format!("epoch thread spawn: {e}")))?;

        Ok(Self {
            engine,
            _epoch_thread,
            epoch_stop: stop,
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl Drop for WasmEngine {
    fn drop(&mut self) {
        self.epoch_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// What `dispatch_wasm_tool` returns to the upstream dispatcher. Mirrors
/// [`super::extension_outbound::DispatchOutcome`] but with WASM-specific
/// telemetry instead of HTTP status / upstream latency.
#[derive(Debug, Clone, Serialize)]
pub struct WasmDispatchOutcome {
    pub result: serde_json::Value,
    /// Which pack build produced this outcome — `None` only on the
    /// foundation entry point [`dispatch_wasm_tool`], which runs raw module
    /// bytes with no installed record behind them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<PackAttribution>,
    pub elapsed_ms: u64,
    pub fuel_consumed: u64,
    pub log: Vec<HostLogEntry>,
    pub request_id: String,
}

/// Wire request shape the module's `extension_call` entrypoint receives.
/// Identical fields to Phase A's so contributor templates can share the
/// same struct definitions.
#[derive(Debug, Serialize)]
struct WasmCallRequest<'a> {
    tool: &'a str,
    args: &'a serde_json::Value,
    calling_passport_id: &'a str,
    request_id: &'a str,
}

/// Module response shape — same JSON envelope as Phase A.
#[derive(Debug, Deserialize)]
pub struct WasmCallResponse {
    pub result: serde_json::Value,
    #[serde(default)]
    pub fact_writes: Vec<super::extension_outbound::ProposedFactWrite>,
}

/// Bundled per-call context for [`dispatch_wasm_tool_with_context`].
/// Lifetimes parameterised on `'a` mirror the original
/// [`dispatch_wasm_tool`] borrow shape.
pub struct WasmCallContext<'a> {
    pub tool_name: &'a str,
    pub args: &'a serde_json::Value,
    pub calling_passport_id: &'a str,
    pub request_id: &'a str,
    pub extension_id: &'a str,
    /// Pack build behind this call. Owned rather than borrowed because it
    /// ends up on the outcome, which outlives the borrowed context.
    pub attribution: Option<PackAttribution>,
    pub grant: Option<Arc<ExtensionGrant>>,
    pub fact_store: Option<Arc<dyn HostFactStore>>,
}

/// Compile + instantiate + call. Single-shot; instance is dropped at the
/// end of the call. Re-instantiation amortises instance setup but leaks
/// state between calls — for a community-extension MVP, single-shot is
/// the safer default.
///
/// Foundation form (M6.1 compatibility) — no grant, no fact-store. Use
/// [`dispatch_wasm_tool_with_context`] for M6.2+ paths that need either.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_wasm_tool(
    engine: &WasmEngine,
    config: &WasmConfig,
    module_bytes: &[u8],
    tool_name: &str,
    args: &serde_json::Value,
    calling_passport_id: &str,
    request_id: &str,
) -> Result<(WasmDispatchOutcome, WasmCallResponse), WasmError> {
    dispatch_wasm_tool_with_context(
        engine,
        config,
        module_bytes,
        WasmCallContext {
            tool_name,
            args,
            calling_passport_id,
            request_id,
            extension_id: "",
            attribution: None,
            grant: None,
            fact_store: None,
        },
    )
}

/// M6.2+ entry point: compiles, instantiates, calls, classifies trap.
/// Same return shape as [`dispatch_wasm_tool`] but threads grant +
/// fact-store handles into [`HostState`] so the host ABI can read/write
/// facts on the module's behalf.
pub fn dispatch_wasm_tool_with_context(
    engine: &WasmEngine,
    config: &WasmConfig,
    module_bytes: &[u8],
    ctx: WasmCallContext<'_>,
) -> Result<(WasmDispatchOutcome, WasmCallResponse), WasmError> {
    let started = Instant::now();
    let module = Module::from_binary(engine.engine(), module_bytes).map_err(|e| WasmError::Compile(e.to_string()))?;

    let mut store = Store::new(
        engine.engine(),
        HostState::with_context(
            ctx.calling_passport_id.to_string(),
            ctx.extension_id.to_string(),
            ctx.grant,
            ctx.fact_store,
            config.memory_bytes,
        ),
    );
    store
        .set_fuel(config.fuel)
        .map_err(|e| WasmError::Trap(e.to_string()))?;
    store.limiter(|s| &mut s.limits);

    // Epoch deadline: ceil(wall_clock / epoch_tick) ticks from now.
    let ticks = (config.wall_clock.as_millis() / config.epoch_tick.as_millis().max(1)).max(1) as u64;
    store.set_epoch_deadline(ticks);

    let mut linker: Linker<HostState> = Linker::new(engine.engine());
    register_host_abi(&mut linker)?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    let memory: Memory = instance
        .get_memory(&mut store, "memory")
        .ok_or(WasmError::MissingExport("memory"))?;

    // Optional WASI-style init.
    if let Ok(init) = instance.get_typed_func::<(), ()>(&mut store, "_initialize") {
        init.call(&mut store, ())
            .map_err(|e| classify_trap(&store, e, started, config))?;
    }

    let entry: TypedFunc<(i32, i32, i32, i32), i32> = instance
        .get_typed_func(&mut store, "extension_call")
        .map_err(|_| WasmError::MissingExport("extension_call"))?;

    let request = WasmCallRequest {
        tool: ctx.tool_name,
        args: ctx.args,
        calling_passport_id: ctx.calling_passport_id,
        request_id: ctx.request_id,
    };
    let request_bytes = serde_json::to_vec(&request)?;

    // Allocate request + response in linear memory. We grow the memory
    // by one page (64 KiB) and lay them out at offset 0. For a real
    // host we'd ask the module to allocate; the foundation MVP keeps
    // the interface ABI-flat so test fixtures stay tiny.
    let need_pages = ((request_bytes.len() + 65_536) / 65_536) as u64; // request region (resp shares it)
    let cur_pages = memory.size(&store);
    if cur_pages < need_pages {
        memory
            .grow(&mut store, need_pages - cur_pages)
            .map_err(|e| classify_trap(&store, wasmtime::Error::msg(e.to_string()), started, config))?;
    }

    let req_ptr: i32 = 0;
    let resp_ptr: i32 = (request_bytes.len() as i32 + 8 + 7) & !7; // 8-byte align
    let total_pages = memory.size(&store) * 65_536;
    let resp_cap_max: i32 = (total_pages as i64 - resp_ptr as i64).max(0) as i32;
    let resp_cap: i32 = resp_cap_max.min(64 * 1024);

    memory
        .write(&mut store, req_ptr as usize, &request_bytes)
        .map_err(|e| WasmError::Trap(format!("memory.write: {e}")))?;

    let written = entry
        .call(&mut store, (req_ptr, request_bytes.len() as i32, resp_ptr, resp_cap))
        .map_err(|e| classify_trap(&store, e, started, config))?;

    if written == -1 {
        return Err(WasmError::ResponseTooLarge);
    }
    if written < 0 {
        return Err(WasmError::Trap(format!("module returned reserved code {written}")));
    }
    let mut resp_bytes = vec![0u8; written as usize];
    memory
        .read(&store, resp_ptr as usize, &mut resp_bytes)
        .map_err(|e| WasmError::Trap(format!("memory.read: {e}")))?;
    let response_str = std::str::from_utf8(&resp_bytes).map_err(|_| WasmError::ResponseInvalidUtf8)?;
    let response: WasmCallResponse = serde_json::from_str(response_str).map_err(WasmError::ResponseInvalidJson)?;

    let fuel_consumed = config.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
    let elapsed = started.elapsed();
    let log = std::mem::take(&mut store.data_mut().log);

    Ok((
        WasmDispatchOutcome {
            result: response.result.clone(),
            attribution: ctx.attribution,
            elapsed_ms: elapsed.as_millis() as u64,
            fuel_consumed,
            log,
            request_id: ctx.request_id.to_string(),
        },
        response,
    ))
}

/// Classify a wasmtime error into a typed [`WasmError`] so callers can
/// distinguish "module misbehaved within its budget" (recover) from
/// "module hit a limit" (record + return error to operator).
fn classify_trap(store: &Store<HostState>, err: wasmtime::Error, started: Instant, config: &WasmConfig) -> WasmError {
    use wasmtime::Trap;
    if let Some(trap) = err.downcast_ref::<Trap>() {
        match trap {
            Trap::OutOfFuel => return WasmError::FuelExhausted,
            Trap::Interrupt => return WasmError::DeadlineExceeded,
            other => return WasmError::Trap(format!("trap: {other}")),
        }
    }
    // Memory-growth failures land here (anyhow::Error from grow()).
    if format!("{err:?}").contains("memory") || store.get_fuel().unwrap_or(0) == 0 {
        if started.elapsed() >= config.wall_clock {
            return WasmError::DeadlineExceeded;
        }
        if store.get_fuel().unwrap_or(0) == 0 {
            return WasmError::FuelExhausted;
        }
        return WasmError::OutOfMemory;
    }
    WasmError::Trap(err.to_string())
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn read_string(memory: &Memory, store: impl AsContextMut, ptr: i32, len: i32) -> Option<String> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    memory.read(store, ptr as usize, &mut buf).ok()?;
    String::from_utf8(buf).ok()
}

fn write_str_capped(memory: &Memory, store: impl AsContextMut, ptr: i32, cap: i32, s: &str) -> i32 {
    let bytes = s.as_bytes();
    if (bytes.len() as i32) > cap {
        return -1;
    }
    if memory.write(store, ptr as usize, bytes).is_err() {
        return -1;
    }
    bytes.len() as i32
}

/// Register the full host ABI. Foundation surface (M6.1) + fact-store
/// surface (M6.2) + secret + receipt placeholders.
fn register_host_abi(linker: &mut Linker<HostState>) -> Result<(), WasmError> {
    register_foundation_abi(linker)?;
    register_fact_abi(linker)?;
    register_secret_and_receipt_abi(linker)?;
    Ok(())
}

fn register_foundation_abi(linker: &mut Linker<HostState>) -> Result<(), WasmError> {
    linker
        .func_wrap("crux", "now_unix_ms", |_caller: Caller<'_, HostState>| -> u64 {
            now_unix_ms()
        })
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    linker
        .func_wrap(
            "crux",
            "log",
            |mut caller: Caller<'_, HostState>, level_ptr: i32, level_len: i32, msg_ptr: i32, msg_len: i32| {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return,
                };
                let level = read_string(&mem, &mut caller, level_ptr, level_len).unwrap_or_default();
                let message = read_string(&mem, &mut caller, msg_ptr, msg_len).unwrap_or_default();
                let entry = HostLogEntry {
                    level,
                    message,
                    at_unix_ms: now_unix_ms(),
                };
                caller.data_mut().log.push(entry);
            },
        )
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    linker
        .func_wrap(
            "crux",
            "current_passport_json",
            |mut caller: Caller<'_, HostState>, ptr: i32, cap: i32| -> i32 {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return HOST_RC_HOST_INTERNAL,
                };
                let json = format!(
                    "{{\"calling_passport_id\":\"{}\"}}",
                    caller.data().calling_passport_id.replace('"', "\\\"")
                );
                write_str_capped(&mem, &mut caller, ptr, cap, &json)
            },
        )
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    Ok(())
}

/// Wire signatures for the M6.2 fact ABI:
///
/// ```text
/// crux::read_fact(entity_ptr, entity_len, key_ptr, key_len,
///                 resp_ptr, resp_cap) -> i32
/// crux::store_fact(entity_ptr, entity_len, key_ptr, key_len,
///                  value_ptr, value_len, confidence_thousandths,
///                  resp_ptr, resp_cap) -> i32
/// crux::query_facts(prefix_ptr, prefix_len, query_ptr, query_len,
///                   top_k, resp_ptr, resp_cap) -> i32
/// ```
///
/// Confidence is passed as `i32` in thousandths (`0..=1000`) so the
/// host ABI stays float-free; `confidence_thousandths` of 1000 = 1.0.
fn register_fact_abi(linker: &mut Linker<HostState>) -> Result<(), WasmError> {
    linker
        .func_wrap(
            "crux",
            "read_fact",
            |mut caller: Caller<'_, HostState>,
             entity_ptr: i32,
             entity_len: i32,
             key_ptr: i32,
             key_len: i32,
             resp_ptr: i32,
             resp_cap: i32|
             -> i32 {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return HOST_RC_HOST_INTERNAL,
                };
                let entity = match read_string(&mem, &mut caller, entity_ptr, entity_len) {
                    Some(s) => s,
                    None => return HOST_RC_BAD_INPUT,
                };
                let key = match read_string(&mem, &mut caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return HOST_RC_BAD_INPUT,
                };
                let (grant, store) = match grant_and_store(&caller) {
                    Ok(pair) => pair,
                    Err(rc) => return rc,
                };
                if !entity_matches_any_prefix(&entity, &grant.allowed_prefixes_read) {
                    return HOST_RC_SCOPE_VIOLATION;
                }
                let fact = match store.read_fact(&entity, &key) {
                    Some(f) => f,
                    None => return HOST_RC_NOT_FOUND,
                };
                let json = match serde_json::to_string(&fact) {
                    Ok(s) => s,
                    Err(_) => return HOST_RC_SERIALISE_ERR,
                };
                let written = write_str_capped(&mem, &mut caller, resp_ptr, resp_cap, &json);
                if written < 0 {
                    HOST_RC_BUFFER_TOO_SMALL
                } else {
                    written
                }
            },
        )
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    linker
        .func_wrap(
            "crux",
            "store_fact",
            |mut caller: Caller<'_, HostState>,
             entity_ptr: i32,
             entity_len: i32,
             key_ptr: i32,
             key_len: i32,
             value_ptr: i32,
             value_len: i32,
             confidence_thousandths: i32,
             resp_ptr: i32,
             resp_cap: i32|
             -> i32 {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return HOST_RC_HOST_INTERNAL,
                };
                let entity = match read_string(&mem, &mut caller, entity_ptr, entity_len) {
                    Some(s) => s,
                    None => return HOST_RC_BAD_INPUT,
                };
                let key = match read_string(&mem, &mut caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return HOST_RC_BAD_INPUT,
                };
                let value = match read_string(&mem, &mut caller, value_ptr, value_len) {
                    Some(s) => s,
                    None => return HOST_RC_BAD_INPUT,
                };
                let confidence = (confidence_thousandths.clamp(0, 1000) as f32) / 1000.0;
                let (grant, store) = match grant_and_store(&caller) {
                    Ok(pair) => pair,
                    Err(rc) => return rc,
                };
                if !entity_matches_any_prefix(&entity, &grant.allowed_prefixes_write) {
                    return HOST_RC_SCOPE_VIOLATION;
                }
                let fact = match store.store_fact(HostStoreFact {
                    entity,
                    key,
                    value,
                    confidence,
                }) {
                    Ok(f) => f,
                    Err(_) => return HOST_RC_HOST_INTERNAL,
                };
                let json = match serde_json::to_string(&fact) {
                    Ok(s) => s,
                    Err(_) => return HOST_RC_SERIALISE_ERR,
                };
                let written = write_str_capped(&mem, &mut caller, resp_ptr, resp_cap, &json);
                if written < 0 {
                    HOST_RC_BUFFER_TOO_SMALL
                } else {
                    written
                }
            },
        )
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    linker
        .func_wrap(
            "crux",
            "query_facts",
            |mut caller: Caller<'_, HostState>,
             prefix_ptr: i32,
             prefix_len: i32,
             query_ptr: i32,
             query_len: i32,
             top_k: i32,
             resp_ptr: i32,
             resp_cap: i32|
             -> i32 {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return HOST_RC_HOST_INTERNAL,
                };
                let entity_prefix = if prefix_len <= 0 {
                    None
                } else {
                    match read_string(&mem, &mut caller, prefix_ptr, prefix_len) {
                        Some(s) => Some(s),
                        None => return HOST_RC_BAD_INPUT,
                    }
                };
                let query = if query_len <= 0 {
                    None
                } else {
                    match read_string(&mem, &mut caller, query_ptr, query_len) {
                        Some(s) => Some(s),
                        None => return HOST_RC_BAD_INPUT,
                    }
                };
                let (grant, store) = match grant_and_store(&caller) {
                    Ok(pair) => pair,
                    Err(rc) => return rc,
                };
                // Require the prefix arg AND require it to be inside the
                // grant's read-prefix list. Empty prefix would let the
                // module enumerate the store; reject it.
                let prefix = match entity_prefix.as_deref() {
                    Some(p) => p,
                    None => return HOST_RC_SCOPE_VIOLATION,
                };
                if !query_prefix_within_grant(prefix, &grant.allowed_prefixes_read) {
                    return HOST_RC_SCOPE_VIOLATION;
                }
                let top_k = top_k.clamp(1, 256) as usize;
                let mut facts = store.query_facts(HostFactQuery {
                    entity_prefix: entity_prefix.clone(),
                    query,
                    top_k,
                });
                // Defence in depth: drop any result outside the granted
                // read prefixes (the underlying store could return more
                // than the prefix arg if its impl is loose).
                facts.retain(|f| entity_matches_any_prefix(&f.entity, &grant.allowed_prefixes_read));
                let json = match serde_json::to_string(&facts) {
                    Ok(s) => s,
                    Err(_) => return HOST_RC_SERIALISE_ERR,
                };
                let written = write_str_capped(&mem, &mut caller, resp_ptr, resp_cap, &json);
                if written < 0 {
                    HOST_RC_BUFFER_TOO_SMALL
                } else {
                    written
                }
            },
        )
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    Ok(())
}

/// Wire `crux::get_secret_decrypted` and `crux::emit_receipt` as
/// "not yet implemented" stubs so contributor modules that import them
/// link cleanly even on a daemon that hasn't wired the decryption /
/// receipt-signing paths yet. Both return [`HOST_RC_NOT_IMPLEMENTED`]
/// (-6) until M6.3 wires them to `encrypted_secrets` and the receipts
/// crate.
fn register_secret_and_receipt_abi(linker: &mut Linker<HostState>) -> Result<(), WasmError> {
    linker
        .func_wrap(
            "crux",
            "get_secret_decrypted",
            |_caller: Caller<'_, HostState>, _id_ptr: i32, _id_len: i32, _resp_ptr: i32, _resp_cap: i32| -> i32 {
                HOST_RC_NOT_IMPLEMENTED
            },
        )
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    linker
        .func_wrap(
            "crux",
            "emit_receipt",
            |_caller: Caller<'_, HostState>,
             _action_ptr: i32,
             _action_len: i32,
             _payload_ptr: i32,
             _payload_len: i32,
             _resp_ptr: i32,
             _resp_cap: i32|
             -> i32 { HOST_RC_NOT_IMPLEMENTED },
        )
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    Ok(())
}

/// Pull the grant + fact-store handles off the caller's host state, or
/// classify the absence as one of the host-rc codes. Returns clones so
/// the host fn can drop the borrow on `caller.data()` before doing
/// anything mutating.
fn grant_and_store(caller: &Caller<'_, HostState>) -> Result<(Arc<ExtensionGrant>, Arc<dyn HostFactStore>), i32> {
    let state = caller.data();
    let grant = state.grant.as_ref().ok_or(HOST_RC_NO_GRANT)?;
    let store = state.fact_store.as_ref().ok_or(HOST_RC_FACT_STORE_UNAVAILABLE)?;
    Ok((Arc::clone(grant), Arc::clone(store)))
}

/// Convenience: build a [`WasmEngine`] from env-driven config. Test
/// fixtures use this; production callers will hold a long-lived engine
/// in [`crate::http::AppState`] (wired in M6.3).
pub fn build_engine_from_env() -> Result<Arc<WasmEngine>, WasmError> {
    let config = WasmConfig::from_env();
    Ok(Arc::new(WasmEngine::new(config.epoch_tick)?))
}

// Memory type helpers (currently unused in the foundation but referenced
// so wasmtime's API surface stays imported in one place — when M6.2 adds
// a per-extension instance cache the alloc/grow logic lives here too).
#[allow(dead_code)]
fn default_memory_type() -> MemoryType {
    MemoryType::new(1, Some(256))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_for_test() -> WasmEngine {
        WasmEngine::new(Duration::from_millis(5)).unwrap()
    }

    /// Module that copies the literal string `{"result":"pong","fact_writes":[]}`
    /// into the response buffer. Covers the happy-path round trip.
    fn ping_pong_module() -> Vec<u8> {
        // Body is 34 bytes: {"result":"pong","fact_writes":[]}
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const 1024) "{\"result\":\"pong\",\"fact_writes\":[]}")
              (func (export "extension_call")
                (param $req_ptr i32) (param $req_len i32)
                (param $resp_ptr i32) (param $resp_cap i32)
                (result i32)
                (memory.copy
                  (local.get $resp_ptr)
                  (i32.const 1024)
                  (i32.const 34))
                (i32.const 34)
              )
            )
        "#;
        wat::parse_str(wat).unwrap()
    }

    /// Module with an infinite loop. Triggers either fuel-exhaust (if
    /// fuel is the tighter bound) or epoch-deadline (if wall clock is
    /// tighter). The caller picks which by setting the config.
    fn infinite_loop_module() -> Vec<u8> {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "extension_call")
                (param i32) (param i32) (param i32) (param i32)
                (result i32)
                (loop $l (br $l))
                (i32.const 0)
              )
            )
        "#;
        wat::parse_str(wat).unwrap()
    }

    #[test]
    fn happy_path_round_trip() {
        let engine = engine_for_test();
        let config = WasmConfig::default();
        let (outcome, response) = dispatch_wasm_tool(
            &engine,
            &config,
            &ping_pong_module(),
            "ping",
            &serde_json::json!({}),
            "p_test",
            "req-1",
        )
        .expect("happy path");
        assert_eq!(response.result, serde_json::Value::String("pong".into()));
        assert!(response.fact_writes.is_empty());
        assert_eq!(outcome.request_id, "req-1");
        assert!(
            outcome.fuel_consumed < 1_000,
            "ping consumed too much fuel: {}",
            outcome.fuel_consumed
        );
    }

    #[test]
    fn fuel_exhaustion_traps() {
        let engine = engine_for_test();
        let mut config = WasmConfig::default();
        config.fuel = 1_000; // tight fuel; loop will burn it instantly
        config.wall_clock = Duration::from_secs(60); // ensure fuel is the tighter bound
        let err = dispatch_wasm_tool(
            &engine,
            &config,
            &infinite_loop_module(),
            "loop",
            &serde_json::json!({}),
            "p_test",
            "req-2",
        )
        .err()
        .expect("expected trap");
        assert!(matches!(err, WasmError::FuelExhausted), "got {err:?}");
    }

    #[test]
    fn epoch_deadline_traps() {
        let engine = engine_for_test();
        let mut config = WasmConfig::default();
        config.fuel = 100_000_000_000; // huge — ensure deadline is the tighter bound
        config.wall_clock = Duration::from_millis(50);
        config.epoch_tick = Duration::from_millis(5);
        let err = dispatch_wasm_tool(
            &engine,
            &config,
            &infinite_loop_module(),
            "loop",
            &serde_json::json!({}),
            "p_test",
            "req-3",
        )
        .err()
        .expect("expected trap");
        assert!(matches!(err, WasmError::DeadlineExceeded), "got {err:?}");
    }

    #[test]
    fn missing_extension_call_export_is_classified() {
        let wat = r#"(module (memory (export "memory") 1))"#;
        let bytes = wat::parse_str(wat).unwrap();
        let engine = engine_for_test();
        let config = WasmConfig::default();
        let err = dispatch_wasm_tool(
            &engine,
            &config,
            &bytes,
            "ping",
            &serde_json::json!({}),
            "p_test",
            "req-4",
        )
        .err()
        .expect("expected missing export");
        assert!(matches!(err, WasmError::MissingExport("extension_call")), "got {err:?}");
    }

    #[test]
    fn missing_memory_export_is_classified() {
        let wat = r#"
            (module
              (func (export "extension_call")
                (param i32) (param i32) (param i32) (param i32)
                (result i32)
                (i32.const 0)
              )
            )
        "#;
        let bytes = wat::parse_str(wat).unwrap();
        let engine = engine_for_test();
        let config = WasmConfig::default();
        let err = dispatch_wasm_tool(
            &engine,
            &config,
            &bytes,
            "ping",
            &serde_json::json!({}),
            "p_test",
            "req-5",
        )
        .err()
        .expect("expected missing memory export");
        assert!(matches!(err, WasmError::MissingExport("memory")), "got {err:?}");
    }

    #[test]
    fn default_config_is_safe_for_community_extensions() {
        let cfg = WasmConfig::default();
        assert_eq!(cfg.fuel, 1_000_000);
        assert_eq!(cfg.memory_bytes, 16_000_000);
        assert_eq!(cfg.wall_clock, Duration::from_millis(1_000));
        assert_eq!(cfg.epoch_tick, Duration::from_millis(10));
    }

    // ── M6.2: scope-helper unit tests ───────────────────────────────────

    #[test]
    fn entity_matches_any_prefix_basic() {
        let granted = vec!["__test__::".to_string(), "ext::quote::".to_string()];
        assert!(entity_matches_any_prefix("__test__::foo", &granted));
        assert!(entity_matches_any_prefix("ext::quote::today", &granted));
        assert!(!entity_matches_any_prefix("__other__::baz", &granted));
        assert!(!entity_matches_any_prefix("ext::other::x", &granted));
        // Empty grant denies everything.
        assert!(!entity_matches_any_prefix("anything", &[]));
        // Empty prefix in the grant is ignored (defence — we never want
        // an empty string to match-all by accident).
        assert!(!entity_matches_any_prefix("anything", &["".to_string()]));
        assert!(!entity_matches_any_prefix("__passport__::victim", &["__".to_string()]));
        assert!(entity_matches_any_prefix("g", &["g".to_string()]));
        assert!(!entity_matches_any_prefix("github::owner/repo", &["g".to_string()]));
    }

    #[test]
    fn query_prefix_within_grant_basic() {
        let granted = vec!["__test__::".to_string()];
        assert!(query_prefix_within_grant("__test__::", &granted));
        assert!(query_prefix_within_grant("__test__::sub::", &granted));
        // Module can't query above the grant boundary.
        assert!(!query_prefix_within_grant("__", &granted));
        // Empty prefix is always rejected.
        assert!(!query_prefix_within_grant("", &granted));
        // Out-of-grant prefix.
        assert!(!query_prefix_within_grant("__other__::", &granted));
        assert!(!query_prefix_within_grant("__passport__::", &["__".to_string()]));
    }

    // ── M6.2: HostFactStore mock + integration tests ────────────────────

    use std::sync::Mutex;

    /// Tiny in-memory mock used to assert host-fn behaviour without
    /// pulling the real `corecrux_memory::FactStore` into wasm_host
    /// tests. Records call sites so tests can assert on them.
    struct MockFactStore {
        facts: Mutex<Vec<HostFact>>,
        store_calls: Mutex<Vec<HostStoreFact>>,
    }

    impl MockFactStore {
        fn new() -> Self {
            Self {
                facts: Mutex::new(Vec::new()),
                store_calls: Mutex::new(Vec::new()),
            }
        }
        fn seed(&self, fact: HostFact) {
            self.facts.lock().unwrap().push(fact);
        }
    }

    impl HostFactStore for MockFactStore {
        fn read_fact(&self, entity: &str, key: &str) -> Option<HostFact> {
            self.facts
                .lock()
                .unwrap()
                .iter()
                .find(|f| f.entity == entity && f.key == key)
                .cloned()
        }
        fn store_fact(&self, req: HostStoreFact) -> Result<HostFact, String> {
            self.store_calls.lock().unwrap().push(req.clone());
            let f = HostFact {
                fact_id: format!("fact-{}", self.store_calls.lock().unwrap().len()),
                entity: req.entity,
                key: req.key,
                value: req.value,
                confidence: req.confidence,
                stored_at_unix_ms: 1_700_000_000_000,
            };
            self.facts.lock().unwrap().push(f.clone());
            Ok(f)
        }
        fn query_facts(&self, q: HostFactQuery) -> Vec<HostFact> {
            let prefix = q.entity_prefix.unwrap_or_default();
            self.facts
                .lock()
                .unwrap()
                .iter()
                .filter(|f| prefix.is_empty() || f.entity.starts_with(&prefix))
                .take(q.top_k)
                .cloned()
                .collect()
        }
    }

    /// Escape a Rust `&str` for embedding in a WAT data-section literal.
    /// WAT supports `\"` and `\\` escapes; nothing else in our test strings
    /// needs special handling (no NUL, no non-ASCII).
    fn wat_str_lit(s: &str) -> String {
        let mut out = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    }

    /// WAT module that calls `crux::read_fact("__test__::foo", "bar", buf, cap)`,
    /// then writes a JSON response whose `result` field labels which rc
    /// branch ran. Lengths are computed from the actual Rust strings to
    /// avoid hand-counted off-by-ones.
    ///
    /// Memory layout (entity/key kept past the request window so dispatch's
    /// request-bytes write at offset 0 doesn't trash them):
    /// - 4096..  `__test__::foo` (entity)
    /// - 4128..  `bar`           (key)
    /// - 5000..  candidate response strings, 100-byte stride
    /// - 6000..  `read_fact` host-write target (1 KiB cap)
    fn read_fact_module() -> Vec<u8> {
        let entity = "__test__::foo";
        let key = "bar";
        let ok = r#"{"result":"ok","fact_writes":[]}"#;
        let err1 = r#"{"result":"err:-1","fact_writes":[]}"#;
        let err2 = r#"{"result":"err:-2","fact_writes":[]}"#;
        let err3 = r#"{"result":"err:-3","fact_writes":[]}"#;
        let other = r#"{"result":"err:other","fact_writes":[]}"#;

        let wat = format!(
            r#"
            (module
              (import "crux" "read_fact"
                (func $read_fact (param i32 i32 i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 4096) {entity_lit})
              (data (i32.const 4128) {key_lit})
              (data (i32.const 5000) {ok_lit})
              (data (i32.const 5100) {err1_lit})
              (data (i32.const 5200) {err2_lit})
              (data (i32.const 5300) {err3_lit})
              (data (i32.const 5400) {other_lit})

              (func (export "extension_call")
                (param $req_ptr i32) (param $req_len i32)
                (param $resp_ptr i32) (param $resp_cap i32)
                (result i32)
                (local $rc i32)
                (local.set $rc
                  (call $read_fact
                    (i32.const 4096) (i32.const {entity_len})
                    (i32.const 4128) (i32.const {key_len})
                    (i32.const 6000) (i32.const 1024)
                  )
                )

                (if (i32.ge_s (local.get $rc) (i32.const 0))
                  (then
                    (memory.copy (local.get $resp_ptr) (i32.const 5000) (i32.const {ok_len}))
                    (return (i32.const {ok_len}))
                  )
                )
                (if (i32.eq (local.get $rc) (i32.const -1))
                  (then
                    (memory.copy (local.get $resp_ptr) (i32.const 5100) (i32.const {err1_len}))
                    (return (i32.const {err1_len}))
                  )
                )
                (if (i32.eq (local.get $rc) (i32.const -2))
                  (then
                    (memory.copy (local.get $resp_ptr) (i32.const 5200) (i32.const {err2_len}))
                    (return (i32.const {err2_len}))
                  )
                )
                (if (i32.eq (local.get $rc) (i32.const -3))
                  (then
                    (memory.copy (local.get $resp_ptr) (i32.const 5300) (i32.const {err3_len}))
                    (return (i32.const {err3_len}))
                  )
                )
                (memory.copy (local.get $resp_ptr) (i32.const 5400) (i32.const {other_len}))
                (i32.const {other_len})
              )
            )
            "#,
            entity_lit = wat_str_lit(entity),
            key_lit = wat_str_lit(key),
            ok_lit = wat_str_lit(ok),
            err1_lit = wat_str_lit(err1),
            err2_lit = wat_str_lit(err2),
            err3_lit = wat_str_lit(err3),
            other_lit = wat_str_lit(other),
            entity_len = entity.len(),
            key_len = key.len(),
            ok_len = ok.len(),
            err1_len = err1.len(),
            err2_len = err2.len(),
            err3_len = err3.len(),
            other_len = other.len(),
        );
        wat::parse_str(&wat).unwrap()
    }

    fn grant_with(read: &[&str], write: &[&str]) -> Arc<ExtensionGrant> {
        Arc::new(ExtensionGrant {
            extension_id: "ext.test".to_string(),
            passport_fpr: "p_test".to_string(),
            allowed_tool_names: vec!["ext.test.tool".to_string()],
            allowed_prefixes_read: read.iter().map(|s| s.to_string()).collect(),
            allowed_prefixes_write: write.iter().map(|s| s.to_string()).collect(),
            rate_limit_per_min: None,
            granted_at_unix_ms: 1_700_000_000_000,
            granted_by_passport: None,
        })
    }

    fn dispatch_with(
        engine: &WasmEngine,
        module_bytes: &[u8],
        grant: Option<Arc<ExtensionGrant>>,
        store: Option<Arc<dyn HostFactStore>>,
    ) -> Result<(WasmDispatchOutcome, WasmCallResponse), WasmError> {
        let cfg = WasmConfig::default();
        dispatch_wasm_tool_with_context(
            engine,
            &cfg,
            module_bytes,
            WasmCallContext {
                tool_name: "ext.test.tool",
                args: &serde_json::json!({}),
                calling_passport_id: "p_test",
                request_id: "req-1",
                extension_id: "ext.test",
                attribution: None,
                grant,
                fact_store: store,
            },
        )
    }

    #[test]
    fn read_fact_returns_ok_when_in_scope_and_present() {
        let mock = Arc::new(MockFactStore::new());
        mock.seed(HostFact {
            fact_id: "f1".into(),
            entity: "__test__::foo".into(),
            key: "bar".into(),
            value: "baz".into(),
            confidence: 1.0,
            stored_at_unix_ms: 1_700_000_000_000,
        });
        let engine = engine_for_test();
        let (_, resp) = dispatch_with(
            &engine,
            &read_fact_module(),
            Some(grant_with(&["__test__::"], &[])),
            Some(mock as Arc<dyn HostFactStore>),
        )
        .expect("happy path");
        assert_eq!(resp.result, serde_json::Value::String("ok".into()));
    }

    #[test]
    fn read_fact_returns_not_found_for_missing_entity_in_scope() {
        let mock = Arc::new(MockFactStore::new()) as Arc<dyn HostFactStore>;
        let engine = engine_for_test();
        let (_, resp) = dispatch_with(
            &engine,
            &read_fact_module(),
            Some(grant_with(&["__test__::"], &[])),
            Some(mock),
        )
        .expect("dispatch ok even on not-found");
        assert_eq!(resp.result, serde_json::Value::String("err:-1".into()));
    }

    #[test]
    fn read_fact_returns_no_grant_when_grant_absent() {
        let mock = Arc::new(MockFactStore::new()) as Arc<dyn HostFactStore>;
        let engine = engine_for_test();
        let (_, resp) = dispatch_with(&engine, &read_fact_module(), None, Some(mock)).unwrap();
        assert_eq!(resp.result, serde_json::Value::String("err:-2".into()));
    }

    #[test]
    fn read_fact_returns_scope_violation_when_outside_granted_prefix() {
        let mock = Arc::new(MockFactStore::new());
        // Seed the fact under __test__::, but grant only __other__::.
        mock.seed(HostFact {
            fact_id: "f1".into(),
            entity: "__test__::foo".into(),
            key: "bar".into(),
            value: "baz".into(),
            confidence: 1.0,
            stored_at_unix_ms: 1_700_000_000_000,
        });
        let engine = engine_for_test();
        let (_, resp) = dispatch_with(
            &engine,
            &read_fact_module(),
            Some(grant_with(&["__other__::"], &[])),
            Some(mock as Arc<dyn HostFactStore>),
        )
        .unwrap();
        assert_eq!(resp.result, serde_json::Value::String("err:-3".into()));
    }

    #[test]
    fn host_rc_constants_are_stable_negative_codes() {
        // Wire contract — these MUST NOT change across versions.
        assert_eq!(rc::NOT_FOUND, -1);
        assert_eq!(rc::NO_GRANT, -2);
        assert_eq!(rc::SCOPE_VIOLATION, -3);
        assert_eq!(rc::BUFFER_TOO_SMALL, -4);
        assert_eq!(rc::FACT_STORE_UNAVAILABLE, -5);
        assert_eq!(rc::NOT_IMPLEMENTED, -6);
    }
}
