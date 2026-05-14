// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Integration test harness for Crux Daemon.

// Test harness: panics, unwraps, expects, and large error types are acceptable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::result_large_err)]

use std::fs::OpenOptions;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_millis(750);
const START_ATTEMPTS: usize = 3;

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
    static BUILD_RESULT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BUILD_RESULT
        .get_or_init(|| {
            let repo_root = repo_root();
            build_corecruxd_binary(&repo_root)
        })
        .clone()
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
                Ok(mut daemon) => match daemon.wait_healthy(STARTUP_TIMEOUT) {
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
        loop {
            if start.elapsed() > timeout {
                return Err(self.failure_message(format!("not healthy in {timeout:?}")));
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
            let healthy = self.get("/healthz").is_ok() && self.mcp_get().is_ok() && self.grpc_listening();
            let ready = healthy
                && self
                    .get("/readyz")
                    .map(|resp| resp.status().as_u16() == 200)
                    .unwrap_or(false);
            if ready {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
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
