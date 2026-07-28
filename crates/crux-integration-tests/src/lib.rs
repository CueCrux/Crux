// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Integration test harness for Crux Daemon.

// Test harness: panics, unwraps, expects, and large error types are acceptable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::result_large_err)]

use std::fs::OpenOptions;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Default per-attempt boot budget. A healthy corecruxd — even a cold boot that
/// builds/loads the `.ccxi` index and clears the `/readyz` gates (routing_loaded,
/// data_dir_capacity, control_evidence, …) — is serve-ready in well under a
/// second, so 10s is already generous. The failures this was once raised to
/// paper over were not slow boots: they were a `/readyz` gate hard-failing (a
/// full `/srv/data` tripping `data_dir_capacity`), which no timeout can wait
/// out — a longer default only makes each of those failing tests take longer to
/// give up. `wait_healthy` now names the failing gate, so a genuine timeout is
/// diagnosable rather than guessed at. Runners that genuinely need more headroom
/// (e.g. heavy `cargo llvm-cov` instrumentation) override without a rebuild via
/// `CORECRUXD_STARTUP_TIMEOUT_SECS`.
const STARTUP_TIMEOUT_SECS_DEFAULT: u64 = 10;
const REQUEST_TIMEOUT: Duration = Duration::from_millis(750);
const START_ATTEMPTS: usize = 3;
/// Cap on the `/readyz` body echoed into a startup-failure message — enough for
/// the failing-check breakdown, short of dumping an unbounded payload into the
/// panic text of every test in the binary.
const READYZ_BODY_LIMIT: usize = 800;

/// The last poll of the startup probes, retained so a `wait_healthy` timeout can
/// report *which* probe was still failing instead of a bare "not healthy in 10s".
///
/// This matters because the interesting failure mode is silent: a daemon that
/// binds all three ports but never passes a `/readyz` gate (`capacity`,
/// `lock_held`, `routing_loaded`, `control_evidence`, …) logs nothing at
/// `warn`, so `failure_message` finds an empty stderr log and the only signal
/// left is the timeout itself. A full CI disk trips the `capacity` gate exactly
/// this way, and without the probe detail it presents as every integration test
/// in the workspace failing identically for no stated reason.
#[derive(Default)]
struct ProbeSnapshot {
    healthz: String,
    mcp: String,
    grpc: String,
    readyz: String,
}

impl ProbeSnapshot {
    fn describe(&self) -> String {
        let unknown = |s: &String| if s.is_empty() { "unknown".to_string() } else { s.clone() };
        format!(
            "healthz={}, mcp={}, grpc={}, readyz={}",
            unknown(&self.healthz),
            unknown(&self.mcp),
            unknown(&self.grpc),
            unknown(&self.readyz)
        )
    }
}

/// Reduce an HTTP probe to (is_200, short description) for the snapshot.
fn describe_probe(result: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> (bool, String) {
    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            (status == 200, status.to_string())
        }
        Err(err) => (false, format!("error({err})")),
    }
}

/// Liveness variant of [`describe_probe`]: any HTTP answer means the transport
/// is up. Used for the MCP port, where an authenticated daemon answers an
/// unauthenticated probe with `401` — a live, correct response.
fn describe_liveness_probe(result: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> (bool, String) {
    match result {
        Ok(resp) => (true, resp.status().as_u16().to_string()),
        // ureq surfaces non-2xx as StatusCode errors; a status at all is proof
        // of life. Only a transport failure means "not up".
        Err(ureq::Error::StatusCode(code)) => (true, code.to_string()),
        Err(err) => (false, format!("error({err})")),
    }
}

/// Truncate on a char boundary so a multi-byte body can never panic the harness.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max).collect();
    format!("{kept}… (truncated)")
}

/// Per-attempt daemon boot timeout, honouring `CORECRUXD_STARTUP_TIMEOUT_SECS`
/// (falling back to [`STARTUP_TIMEOUT_SECS_DEFAULT`] when unset or unparseable).
fn startup_timeout() -> Duration {
    let secs = std::env::var("CORECRUXD_STARTUP_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(STARTUP_TIMEOUT_SECS_DEFAULT);
    Duration::from_secs(secs)
}

fn repo_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    std::path::Path::new(manifest_dir)
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn build_corecruxd_binary(repo_root: &std::path::Path) -> Result<PathBuf, String> {
    // This nested `cargo build` runs *inside* an outer `cargo test --workspace`,
    // concurrently with other test binaries that spawn the corecruxd executable.
    // On loaded CI runners that race surfaces a transient `Text file busy`
    // (ETXTBSY, os error 26) when the linker rewrites the executable while
    // another process holds it open, or a transient `Resource temporarily
    // unavailable` (EAGAIN) when forking under memory pressure. Retry those with
    // backoff rather than giving up — previously a single transient failure was
    // memoised by `default_binary_path`'s OnceLock and failed *every* test in
    // the process.
    const BUILD_ATTEMPTS: usize = 5;
    let mut last_err = String::new();
    for attempt in 1..=BUILD_ATTEMPTS {
        match try_build_corecruxd_binary(repo_root) {
            Ok(path) => return Ok(path),
            Err(err) => {
                let transient = err.contains("Text file busy")
                    || err.contains("os error 26")
                    || err.contains("Resource temporarily unavailable")
                    || err.contains("os error 11");
                last_err = err;
                if !transient || attempt == BUILD_ATTEMPTS {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250 * attempt as u64));
            }
        }
    }
    Err(last_err)
}

fn try_build_corecruxd_binary(repo_root: &std::path::Path) -> Result<PathBuf, String> {
    let output = Command::new("cargo")
        .current_dir(repo_root)
        .args(["build", "--message-format=json", "--bin", "corecruxd"])
        .output()
        .map_err(|err| format!("build corecruxd: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        let detail = stderr.trim();
        return Err(if detail.is_empty() {
            format!("cargo build --bin corecruxd exited with status {}", output.status)
        } else {
            format!(
                "cargo build --bin corecruxd exited with status {}: {detail}",
                output.status
            )
        });
    }

    let mut executable = None;
    for line in stdout.lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["target"]["name"] != "corecruxd" {
            continue;
        }
        if let Some(path) = message["executable"].as_str() {
            executable = Some(PathBuf::from(path));
        }
    }

    executable.ok_or_else(|| {
        if stderr.trim().is_empty() {
            "cargo build did not report a corecruxd executable path".to_string()
        } else {
            format!(
                "cargo build did not report a corecruxd executable path: {}",
                stderr.trim()
            )
        }
    })
}

fn default_binary_path() -> Result<PathBuf, String> {
    // Cache only a *successful* build path. A failed/transient build must never
    // be memoised, otherwise one ETXTBSY poisons every test in the process (the
    // original `OnceLock<Result<..>>` did exactly that). The mutex serialises
    // concurrent first-builds so parallel tests don't fire N racing `cargo
    // build`s at the same target dir.
    static CACHED: OnceLock<PathBuf> = OnceLock::new();
    static BUILD_LOCK: Mutex<()> = Mutex::new(());

    if let Some(path) = CACHED.get() {
        return Ok(path.clone());
    }
    let _guard = BUILD_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(path) = CACHED.get() {
        return Ok(path.clone());
    }
    let path = build_corecruxd_binary(&repo_root())?;
    let _ = CACHED.set(path.clone());
    Ok(path)
}

/// A running corecruxd instance for integration tests.
pub struct TestDaemon {
    pub process: Child,
    pub http_port: u16,
    pub grpc_port: u16,
    pub mcp_port: u16,
    pub data_dir: tempfile::TempDir,
    pub base_url: String,
    pub mcp_base_url: String,
    stderr_log_path: PathBuf,
}

impl TestDaemon {
    /// Start a corecruxd instance on random ports.
    ///
    /// Set `CORECRUXD_BINARY` to override the daemon binary path (useful when
    /// `cargo llvm-cov` or other tools use a non-standard target directory).
    pub fn start() -> Self {
        Self::start_with_retry(None)
    }

    /// Start a corecruxd instance that requires an MCP bearer token.
    pub fn start_with_agent_token(token: &str) -> Self {
        Self::start_with_retry(Some(token))
    }

    fn start_with_retry(agent_token: Option<&str>) -> Self {
        let mut failures = Vec::new();
        for attempt in 1..=START_ATTEMPTS {
            match Self::spawn_once(agent_token) {
                Ok(mut daemon) => match daemon.wait_healthy(startup_timeout()) {
                    Ok(()) => return daemon,
                    Err(err) => {
                        failures.push(format!("attempt {attempt}: {err}"));
                        daemon.stop();
                    }
                },
                Err(err) => failures.push(format!("attempt {attempt}: {err}")),
            }
        }

        panic!(
            "failed to start corecruxd after {START_ATTEMPTS} attempts:\n{}",
            failures.join("\n\n")
        );
    }

    fn spawn_once(agent_token: Option<&str>) -> Result<Self, String> {
        let data_dir = tempfile::tempdir().expect("create tempdir");
        let mut ports = std::collections::BTreeSet::new();
        while ports.len() < 3 {
            ports.insert(portpicker::pick_unused_port().expect("pick unused port"));
        }
        let mut ports = ports.into_iter();
        let http_port = ports.next().expect("pick HTTP port");
        let grpc_port = ports.next().expect("pick gRPC port");
        let mcp_port = ports.next().expect("pick MCP port");

        let binary = if let Ok(path) = std::env::var("CORECRUXD_BINARY") {
            std::path::PathBuf::from(path)
        } else {
            default_binary_path()?
        };
        let stderr_log_path = data_dir.path().join("corecruxd.stderr.log");
        let stderr_log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&stderr_log_path)
            .map_err(|err| format!("open stderr log {}: {err}", stderr_log_path.display()))?;

        let mut command = Command::new(&binary);
        command
            .env("CORECRUXD_DATA_DIR", data_dir.path())
            .env("CORECRUXD_HTTP_PORT", http_port.to_string())
            .env("CORECRUXD_HTTP_HOST", "127.0.0.1")
            .env("CORECRUXD_GRPC_PORT", grpc_port.to_string())
            .env("CORECRUXD_GRPC_HOST", "127.0.0.1")
            .env("CORECRUXD_MCP_PORT", mcp_port.to_string())
            .env("CORECRUXD_MCP_HOST", "127.0.0.1")
            .env("CORECRUXD_AUTH_MODE", "off")
            .env("CORECRUXD_LOG_LEVEL", "warn")
            .env("CORECRUXD_QUERY_TEXT_SEARCH", "1")
            .env("CORECRUXD_QUERY_GRAPH_EXPAND", "1")
            .env("CORECRUXD_QUERY_TIME_RANGE", "1")
            .env("CORECRUXD_BUILD_CCXI", "1")
            .env("CORECRUXD_UPDATE_CHECK_ENABLED", "0")
            .env_remove("CRUX_AGENT_TOKEN")
            .env_remove("CRUX_AGENT_TOKENS")
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log));

        if let Some(token) = agent_token {
            command.env("CRUX_AGENT_TOKEN", token);
        }

        let process = command
            .spawn()
            .map_err(|err| format!("start corecruxd at {}: {err}", binary.display()))?;

        let base_url = format!("http://127.0.0.1:{http_port}");
        let mcp_base_url = format!("http://127.0.0.1:{mcp_port}");
        Ok(Self {
            process,
            http_port,
            grpc_port,
            mcp_port,
            data_dir,
            base_url,
            mcp_base_url,
            stderr_log_path,
        })
    }

    fn wait_healthy(&mut self, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        let mut probes = ProbeSnapshot::default();
        loop {
            if start.elapsed() > timeout {
                return Err(self.failure_message(format!(
                    "not healthy in {timeout:?} (last probe: {})",
                    probes.describe()
                )));
            }
            match self.process.try_wait() {
                Ok(Some(status)) => {
                    return Err(self.failure_message(format!("process exited early with status {status}")));
                }
                Ok(None) => {}
                Err(err) => return Err(format!("failed to poll corecruxd process status: {err}")),
            }
            // Bind + transport health (/healthz 200, MCP 200, gRPC listening)
            // is necessary but not sufficient — `/readyz` adds the readiness
            // gates (lock_held, routing_loaded, capacity, control_evidence,
            // …) that integration tests like the `readyz` test in
            // `tests/daemon.rs` assert against. Under `cargo llvm-cov`
            // instrumentation the daemon's boot path is slower, so tests
            // racing `/readyz` against `start()` flake. Wait here until the
            // daemon is *actually* serve-ready, not just port-bound.
            let (healthz_ok, healthz) = describe_probe(self.get("/healthz"));
            // The MCP probe is a LIVENESS check, not an authorization check: a
            // `401` proves the listener is up, speaking HTTP, and enforcing auth
            // — which is exactly what a token-configured daemon should answer an
            // unauthenticated `GET /mcp`. Treating only `200` as healthy meant a
            // daemon that correctly challenges never looked ready.
            let (mcp_ok, mcp) = describe_liveness_probe(self.mcp_get());
            let grpc_ok = self.grpc_listening();
            probes.healthz = healthz;
            probes.mcp = mcp;
            probes.grpc = if grpc_ok { "listening" } else { "not-listening" }.to_string();

            if healthz_ok && mcp_ok && grpc_ok {
                let (ready, readyz) = self.probe_readyz();
                probes.readyz = readyz;
                if ready {
                    return Ok(());
                }
            } else {
                probes.readyz = "not-probed (transport not up)".to_string();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `/readyz` probe that also captures the response body. A 503 body is the
    /// `{"ok":false,"checks":[…]}` breakdown naming the gate that is failing,
    /// which is the single most useful thing a startup timeout can report.
    ///
    /// Uses its own agent with `http_status_as_error(false)`: the default agent
    /// turns a 503 into `Err`, which would discard the very body we are here to
    /// read and leave only "http status: 503".
    fn probe_readyz(&self) -> (bool, String) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(REQUEST_TIMEOUT))
            .timeout_recv_response(Some(REQUEST_TIMEOUT))
            .timeout_recv_body(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        match agent.get(&format!("{}/readyz", self.base_url)).call() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    return (true, "200".to_string());
                }
                let body = resp.into_body().read_to_string().unwrap_or_default();
                (false, format!("{status} {}", truncate(body.trim(), READYZ_BODY_LIMIT)))
            }
            Err(err) => (false, format!("error({err})")),
        }
    }

    fn stop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }

    fn failure_message(&self, reason: String) -> String {
        let stderr = std::fs::read_to_string(&self.stderr_log_path).unwrap_or_default();
        if stderr.trim().is_empty() {
            reason
        } else {
            format!("{reason}. stderr log {}:\n{stderr}", self.stderr_log_path.display())
        }
    }

    fn grpc_listening(&self) -> bool {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.grpc_port));
        TcpStream::connect_timeout(&addr, REQUEST_TIMEOUT).is_ok()
    }

    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_connect(Some(REQUEST_TIMEOUT))
            .timeout_recv_response(Some(REQUEST_TIMEOUT))
            .timeout_recv_body(Some(REQUEST_TIMEOUT))
            .build()
            .into()
    }

    pub fn get(&self, path: &str) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        Self::agent().get(&format!("{}{path}", self.base_url)).call()
    }

    pub fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        Self::agent().post(&format!("{}{path}", self.base_url)).send_json(body)
    }

    pub fn put_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        Self::agent().put(&format!("{}{path}", self.base_url)).send_json(body)
    }

    pub fn patch_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        Self::agent().patch(&format!("{}{path}", self.base_url)).send_json(body)
    }

    pub fn delete(&self, path: &str) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        Self::agent().delete(&format!("{}{path}", self.base_url)).call()
    }

    pub fn mcp_get(&self) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        Self::agent().get(&format!("{}/mcp", self.mcp_base_url)).call()
    }

    pub fn mcp_post_json(&self, body: serde_json::Value) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        Self::agent()
            .post(&format!("{}/mcp", self.mcp_base_url))
            .send_json(body)
    }

    pub fn mcp_post_json_with_token(
        &self,
        body: serde_json::Value,
        token: &str,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        Self::agent()
            .post(&format!("{}/mcp", self.mcp_base_url))
            .header("Authorization", &format!("Bearer {token}"))
            .send_json(body)
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::{startup_timeout, truncate, ProbeSnapshot, READYZ_BODY_LIMIT, STARTUP_TIMEOUT_SECS_DEFAULT};

    #[test]
    fn startup_timeout_default_is_ten_seconds() {
        // Locks the decision to keep the default tight: a healthy daemon is
        // ready in <1s, and a longer default only delays failure when a
        // `/readyz` gate is hard-failing (e.g. data_dir_capacity on a full
        // disk). Runners that need more headroom set CORECRUXD_STARTUP_TIMEOUT_SECS.
        assert_eq!(STARTUP_TIMEOUT_SECS_DEFAULT, 10);
        // With the override unset the resolved budget is the default. (CI does
        // not set this var; the daemon-boot tests that would are #[ignore]/serial.)
        if std::env::var_os("CORECRUXD_STARTUP_TIMEOUT_SECS").is_none() {
            assert_eq!(startup_timeout(), std::time::Duration::from_secs(10));
        }
    }

    #[test]
    fn probe_snapshot_reports_unfilled_probes_as_unknown() {
        // A timeout before the first poll completes must still produce a
        // readable line rather than empty `foo=, bar=` fields.
        assert_eq!(
            ProbeSnapshot::default().describe(),
            "healthz=unknown, mcp=unknown, grpc=unknown, readyz=unknown"
        );
    }

    #[test]
    fn probe_snapshot_surfaces_the_failing_readyz_gate() {
        // The capacity-gate case: transport is fully up and only `/readyz`
        // fails, so the description must carry the check breakdown — that is
        // the whole point of retaining the body.
        // Verbatim shape of a real 503 from the daemon's readiness handler,
        // captured by forcing CORECRUXD_CAPACITY_EMERGENCY_FREE_RATIO high.
        let snapshot = ProbeSnapshot {
            healthz: "200".to_string(),
            mcp: "200".to_string(),
            grpc: "listening".to_string(),
            readyz: r#"503 {"ok":false,"checks":[{"name":"data_dir_capacity","ok":false,"error":"data dir free ratio below emergency threshold (free_ratio=0.060 threshold=0.100 free_bytes=50000000000 total_bytes=861000000000)"}]}"#
                .to_string(),
        };
        let described = snapshot.describe();
        assert!(described.contains("healthz=200"), "{described}");
        assert!(described.contains("grpc=listening"), "{described}");
        assert!(described.contains("\"name\":\"data_dir_capacity\""), "{described}");
        assert!(described.contains("free_ratio=0.060"), "{described}");
    }

    #[test]
    fn truncate_keeps_short_input_verbatim() {
        assert_eq!(truncate("short body", READYZ_BODY_LIMIT), "short body");
        assert_eq!(truncate("", READYZ_BODY_LIMIT), "");
    }

    #[test]
    fn truncate_caps_long_input_and_marks_it() {
        let long = "x".repeat(READYZ_BODY_LIMIT + 50);
        let out = truncate(&long, READYZ_BODY_LIMIT);
        assert!(out.ends_with("… (truncated)"), "{out}");
        assert_eq!(out.chars().count(), READYZ_BODY_LIMIT + "… (truncated)".chars().count());
    }

    #[test]
    fn truncate_splits_on_a_char_boundary() {
        // Multi-byte input must not panic: a naive byte slice would split the
        // 3-byte '€' and abort the whole test binary.
        let multibyte = "€".repeat(10);
        assert_eq!(truncate(&multibyte, 4), "€€€€… (truncated)");
    }
}
