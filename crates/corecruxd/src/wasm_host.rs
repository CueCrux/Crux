// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
    pub fn new(calling_passport_id: String, max_memory_bytes: usize) -> Self {
        Self {
            calling_passport_id,
            log: Vec::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(max_memory_bytes)
                .instances(1)
                .memories(1)
                .build(),
        }
    }
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

/// Compile + instantiate + call. Single-shot; instance is dropped at the
/// end of the call. Re-instantiation amortises instance setup but leaks
/// state between calls — for a community-extension MVP, single-shot is
/// the safer default.
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
    let started = Instant::now();
    let module = Module::from_binary(engine.engine(), module_bytes).map_err(|e| WasmError::Compile(e.to_string()))?;

    let mut store = Store::new(
        engine.engine(),
        HostState::new(calling_passport_id.to_string(), config.memory_bytes),
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
        tool: tool_name,
        args,
        calling_passport_id,
        request_id,
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
            elapsed_ms: elapsed.as_millis() as u64,
            fuel_consumed,
            log,
            request_id: request_id.to_string(),
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

/// Register the foundation host ABI. Richer fact + receipt ABI lands in
/// M6.2 alongside grant enforcement.
fn register_host_abi(linker: &mut Linker<HostState>) -> Result<(), WasmError> {
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
                    None => return -1,
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
}
