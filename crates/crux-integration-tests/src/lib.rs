// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Integration test harness for CoreCrux Community Edition.

// Test harness: panics, unwraps, expects, and large error types are acceptable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::result_large_err)]

use std::io::Read as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A running corecruxd instance for integration tests.
pub struct TestDaemon {
    pub process: Child,
    pub http_port: u16,
    pub grpc_port: u16,
    pub data_dir: tempfile::TempDir,
    pub base_url: String,
}

impl TestDaemon {
    /// Start a corecruxd instance on random ports.
    ///
    /// Set `CORECRUXD_BINARY` to override the daemon binary path (useful when
    /// `cargo llvm-cov` or other tools use a non-standard target directory).
    pub fn start() -> Self {
        let data_dir = tempfile::tempdir().expect("create tempdir");
        let http_port = portpicker::pick_unused_port().expect("pick HTTP port");
        let grpc_port = portpicker::pick_unused_port().expect("pick gRPC port");

        let binary = if let Ok(path) = std::env::var("CORECRUXD_BINARY") {
            std::path::PathBuf::from(path)
        } else {
            let manifest_dir = env!("CARGO_MANIFEST_DIR");
            std::path::Path::new(manifest_dir)
                .parent().unwrap()  // crates/
                .parent().unwrap()  // Crux/
                .join("target/debug/corecruxd")
        };

        let process = Command::new(&binary)
            .env("CORECRUXD_DATA_DIR", data_dir.path())
            .env("CORECRUXD_HTTP_PORT", http_port.to_string())
            .env("CORECRUXD_HTTP_HOST", "127.0.0.1")
            .env("CORECRUXD_GRPC_PORT", grpc_port.to_string())
            .env("CORECRUXD_GRPC_HOST", "127.0.0.1")
            .env("CORECRUXD_AUTH_MODE", "off")
            .env("CORECRUXD_LOG_LEVEL", "warn")
            .env("CORECRUXD_QUERY_TEXT_SEARCH", "1")
            .env("CORECRUXD_QUERY_GRAPH_EXPAND", "1")
            .env("CORECRUXD_QUERY_TIME_RANGE", "1")
            .env("CORECRUXD_BUILD_CCXI", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("start corecruxd at {}: {}", binary.display(), e));

        let base_url = format!("http://127.0.0.1:{http_port}");
        let mut daemon = Self {
            process,
            http_port,
            grpc_port,
            data_dir,
            base_url,
        };
        daemon.wait_healthy(Duration::from_secs(10));
        daemon
    }

    fn wait_healthy(&mut self, timeout: Duration) {
        let start = Instant::now();
        loop {
            if start.elapsed() > timeout {
                let mut stderr = String::new();
                if let Some(ref mut err) = self.process.stderr {
                    let _ = err.read_to_string(&mut stderr);
                }
                panic!("corecruxd not healthy in {timeout:?}. stderr:\n{stderr}");
            }
            if ureq::get(&format!("{}/healthz", self.base_url)).call().is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn get(&self, path: &str) -> Result<ureq::Response, ureq::Error> {
        ureq::get(&format!("{}{path}", self.base_url)).call()
    }

    pub fn post_json(&self, path: &str, body: serde_json::Value) -> Result<ureq::Response, ureq::Error> {
        ureq::post(&format!("{}{path}", self.base_url)).send_json(body)
    }

    pub fn put_json(&self, path: &str, body: serde_json::Value) -> Result<ureq::Response, ureq::Error> {
        ureq::put(&format!("{}{path}", self.base_url)).send_json(body)
    }

    pub fn delete(&self, path: &str) -> Result<ureq::Response, ureq::Error> {
        ureq::delete(&format!("{}{path}", self.base_url)).call()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
