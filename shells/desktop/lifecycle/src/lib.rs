// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

#![forbid(unsafe_code)]

//! Sidecar lifecycle supervisor for the Crux desktop shell.
//!
//! The desktop shell (`shells/desktop/app`, a Tauri v2 wrapper) bundles the
//! `corecruxd` binary and runs it as a *sidecar*: a child process that binds
//! `127.0.0.1:<port>` with auth **off**, so the webview loaded over that origin
//! is itself the operator surface. This crate owns the child-process half of
//! that contract — spawning, health-polling, and (critically) guaranteeing no
//! orphaned daemon survives the shell.
//!
//! It is `std`-only on purpose: no `tokio`, no `libc`, no `reqwest`. That keeps
//! it buildable and unit-testable on any host — including a WSL box with no
//! webkit2gtk, where the Tauri app itself cannot compile.
//!
//! ## Auth posture
//!
//! `spawn_sidecar` sets `CORECRUXD_AUTH_MODE=off` and binds loopback only. The
//! shell therefore *is* the trusted operator surface (matching the v2 console
//! posture derivation in ExecPlan `unified-shell-console-2026-07-03`). The
//! daemon is never exposed off-host.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Default filename for the sidecar's combined stdout/stderr log, created inside
/// the per-user data dir.
pub const DEFAULT_LOG_FILENAME: &str = "corecruxd.log";

/// Default health endpoint. `corecruxd` serves an unauthenticated `GET /healthz`
/// that returns `HTTP/1.1 200 OK` once the router is up.
pub const DEFAULT_HEALTH_PATH: &str = "/healthz";

/// Configuration for a sidecar launch.
///
/// Construct with [`SidecarConfig::new`] (per-user data dir) and override fields
/// as needed. All fields are public so the Tauri host can tune timeouts without
/// a builder ceremony.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Per-user application data directory. Created if absent. Receives the
    /// daemon's `CORECRUXD_DATA_DIR` and the sidecar log file.
    pub data_dir: PathBuf,
    /// Value for `CORECRUXD_AUTH_MODE`. Default `"off"` — the shell is the
    /// operator surface and the daemon binds loopback only.
    pub auth_mode: String,
    /// Whether to set `CORECRUXD_CONSOLE_V2=1` (the unified shell console).
    pub console_v2: bool,
    /// Fixed HTTP port, or `None` to pick a free ephemeral port by binding
    /// `:0` and releasing it (see [`pick_free_port`]).
    pub port: Option<u16>,
    /// Extra positional args passed to the binary. Empty for production —
    /// `corecruxd` is configured entirely via env. Used by tests to drive
    /// stand-in binaries (`/bin/sleep 30`).
    pub args: Vec<String>,
    /// Extra environment entries layered on top of the four the supervisor sets.
    pub extra_env: Vec<(String, String)>,
    /// Health path polled to decide readiness. Default [`DEFAULT_HEALTH_PATH`].
    pub health_path: String,
    /// Number of health-poll attempts before giving up.
    pub health_retries: u32,
    /// Delay between health-poll attempts.
    pub health_interval: Duration,
    /// Per-attempt TCP connect / read / write timeout for the health probe.
    pub connect_timeout: Duration,
    /// How long `shutdown` waits for a graceful (SIGTERM) exit before hard-kill.
    pub shutdown_grace: Duration,
    /// Log filename inside `data_dir`. Default [`DEFAULT_LOG_FILENAME`].
    pub log_filename: String,
}

impl SidecarConfig {
    /// A config with production-safe defaults for the given per-user data dir.
    ///
    /// Health budget: 60 attempts × 500ms ≈ 30s of cold-start slack (a real
    /// `corecruxd` may spend seconds hydrating segments before `/healthz` is
    /// answered). Callers wanting the ExecPlan's "~30×500ms" floor can lower
    /// `health_retries`.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            auth_mode: "off".to_string(),
            console_v2: true,
            port: None,
            args: Vec::new(),
            extra_env: Vec::new(),
            health_path: DEFAULT_HEALTH_PATH.to_string(),
            health_retries: 60,
            health_interval: Duration::from_millis(500),
            connect_timeout: Duration::from_secs(1),
            shutdown_grace: Duration::from_secs(5),
            log_filename: DEFAULT_LOG_FILENAME.to_string(),
        }
    }
}

/// A running sidecar. Owns the child process and enforces the no-orphan
/// guarantee: [`SidecarHandle::shutdown`] is idempotent and [`Drop`] calls it,
/// so the daemon dies even on a panic or early return in the host.
#[derive(Debug)]
pub struct SidecarHandle {
    child: Child,
    port: u16,
    log_path: PathBuf,
    health_path: String,
    health_retries: u32,
    health_interval: Duration,
    connect_timeout: Duration,
    shutdown_grace: Duration,
    finished: bool,
}

impl SidecarHandle {
    /// The HTTP port the sidecar was told to bind.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The child process id (useful for logging / external liveness checks).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Base loopback URL for the sidecar, e.g. `http://127.0.0.1:14801`.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The console URL the shell's webview should load.
    pub fn console_url(&self) -> String {
        format!("http://127.0.0.1:{}/console", self.port)
    }

    /// Path to the combined stdout/stderr log — surfaced in the failure dialog.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Block until the sidecar answers a 2xx on its health path, or fail.
    ///
    /// Fails fast (without exhausting retries) if the child exits early, and
    /// includes the log path in the error so the host can point the operator at
    /// it. Uses `std::thread::sleep` between attempts — intended to be called
    /// off the UI thread by the host.
    pub fn wait_for_health(&mut self) -> io::Result<()> {
        for _ in 0..self.health_retries {
            // If the daemon crashed on boot, don't wait out the whole budget.
            if self.child.try_wait()?.is_some() {
                self.finished = true;
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "sidecar exited before becoming healthy; see log {}",
                        self.log_path.display()
                    ),
                ));
            }
            if let Ok(code) = probe_health(self.port, &self.health_path, self.connect_timeout) {
                if (200..300).contains(&code) {
                    return Ok(());
                }
            }
            std::thread::sleep(self.health_interval);
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "sidecar did not pass health check on 127.0.0.1:{} after {} attempts; see log {}",
                self.port,
                self.health_retries,
                self.log_path.display()
            ),
        ))
    }

    /// Stop the sidecar. Idempotent.
    ///
    /// Graceful first: on unix a SIGTERM (via the `kill` command — no `libc`
    /// dependency), then a bounded wait. If the child is still alive after
    /// `shutdown_grace`, it is hard-killed (SIGKILL) and reaped. On non-unix the
    /// graceful step is skipped and the platform terminate is used directly.
    pub fn shutdown(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        // Already dead? Reap and return.
        if self.child.try_wait()?.is_some() {
            self.finished = true;
            return Ok(());
        }

        #[cfg(unix)]
        request_sigterm(self.child.id());

        // Bounded wait for a graceful exit.
        let deadline = Instant::now() + self.shutdown_grace;
        while Instant::now() < deadline {
            if self.child.try_wait()?.is_some() {
                self.finished = true;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Still alive — hard kill and reap so no zombie/orphan lingers.
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.finished = true;
        Ok(())
    }
}

impl Drop for SidecarHandle {
    fn drop(&mut self) {
        // The gate: quitting the shell (or unwinding past the handle) must never
        // leave a daemon behind. Best-effort — never panic in Drop.
        let _ = self.shutdown();
    }
}

/// Spawn `corecruxd` (or any binary) as a sidecar.
///
/// Sets the four env vars the daemon needs (`CORECRUXD_AUTH_MODE`,
/// `CORECRUXD_HTTP_PORT`, `CORECRUXD_DATA_DIR`, `CORECRUXD_CONSOLE_V2`) plus any
/// `extra_env`, redirects stdout+stderr into `<data_dir>/<log_filename>`, and
/// returns a [`SidecarHandle`]. The child is *not* yet known-healthy — call
/// [`SidecarHandle::wait_for_health`] next.
pub fn spawn_sidecar(binary: &Path, config: SidecarConfig) -> io::Result<SidecarHandle> {
    std::fs::create_dir_all(&config.data_dir)?;

    let port = match config.port {
        Some(p) => p,
        None => pick_free_port()?,
    };

    let log_path = config.data_dir.join(&config.log_filename);
    let log = OpenOptions::new().create(true).append(true).open(&log_path)?;
    let log_err = log.try_clone()?;

    let mut cmd = Command::new(binary);
    cmd.args(&config.args)
        .env("CORECRUXD_AUTH_MODE", &config.auth_mode)
        .env("CORECRUXD_HTTP_PORT", port.to_string())
        .env("CORECRUXD_DATA_DIR", &config.data_dir)
        .env(
            "CORECRUXD_CONSOLE_V2",
            if config.console_v2 { "1" } else { "0" },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    for (k, v) in &config.extra_env {
        cmd.env(k, v);
    }

    let child = cmd.spawn()?;

    Ok(SidecarHandle {
        child,
        port,
        log_path,
        health_path: config.health_path,
        health_retries: config.health_retries,
        health_interval: config.health_interval,
        connect_timeout: config.connect_timeout,
        shutdown_grace: config.shutdown_grace,
        finished: false,
    })
}

/// Pick a currently-free ephemeral TCP port on loopback by binding `:0` and
/// releasing it.
///
/// There is an inherent TOCTOU window between release and the daemon's own
/// bind; acceptable here because the port is loopback-only and the shell owns
/// the machine's session. The daemon will surface a bind failure via `/healthz`
/// never coming up, which the host converts into an error dialog.
pub fn pick_free_port() -> io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Raw HTTP/1.1 health probe: connect, write a minimal `GET`, parse the status
/// line, return the numeric status code. Any I/O or parse failure is an `Err`
/// (the caller retries).
fn probe_health(port: u16, path: &str, timeout: Duration) -> io::Result<u16> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    // Read just enough to cover the status line. The server sends
    // `Connection: close`, so a read returning 0 means EOF.
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.contains(&b'\n') || buf.len() > 8192 {
            break;
        }
    }
    parse_status_code(&buf)
}

/// Parse an HTTP status code out of a response's first line
/// (`HTTP/1.1 200 OK` -> `200`).
fn parse_status_code(buf: &[u8]) -> io::Result<u16> {
    let text = String::from_utf8_lossy(buf);
    let first = text.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let _version = parts.next();
    parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unparseable HTTP status line: {first:?}"),
            )
        })
}

/// Send SIGTERM to `pid` without a `libc` dependency, by shelling out to the
/// `kill` command (resolved via PATH). Best-effort: if `kill` is missing or the
/// pid is already gone, `shutdown`'s bounded wait falls through to the hard-kill
/// path.
#[cfg(unix)]
fn request_sigterm(pid: u32) {
    let _ = Command::new("kill")
        .arg("-s")
        .arg("TERM")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    // --- helpers -------------------------------------------------------------

    fn proc_alive(pid: u32) -> bool {
        // Linux/WSL: a live or zombie process has a /proc entry; once the child
        // is reaped by wait(), the entry is gone.
        Path::new(&format!("/proc/{pid}")).exists()
    }

    fn wait_gone(pid: u32, dur: Duration) -> bool {
        let deadline = Instant::now() + dur;
        while Instant::now() < deadline {
            if !proc_alive(pid) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        !proc_alive(pid)
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "crux-lifecycle-test-{tag}-{}-{}",
            std::process::id(),
            nanos
        ));
        p
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    fn sleep_cfg(dir: &Path, secs: &str) -> SidecarConfig {
        let mut cfg = SidecarConfig::new(dir);
        cfg.args = vec![secs.to_string()];
        cfg
    }

    // --- port picking --------------------------------------------------------

    #[test]
    fn pick_free_port_is_bindable() {
        let p = pick_free_port().expect("pick a free port");
        assert!(p > 0, "port must be nonzero");
        // Released by pick_free_port, so it must be immediately re-bindable.
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, p)).expect("re-bind picked port");
        drop(l);
    }

    // --- health probe --------------------------------------------------------

    #[test]
    fn health_poll_succeeds_against_canned_200() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                // Consume the request line/headers, then answer once and close.
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                let _ = sock.flush();
            }
        });

        let code = probe_health(port, "/healthz", Duration::from_secs(2)).expect("probe ok");
        assert_eq!(code, 200);
        server.join().unwrap();
    }

    #[test]
    fn health_poll_fails_on_dead_port() {
        // A just-released port has nothing listening -> connection refused.
        let port = pick_free_port().unwrap();
        let res = probe_health(port, "/healthz", Duration::from_millis(300));
        assert!(res.is_err(), "probe against a dead port must fail");
    }

    #[test]
    fn parse_status_code_reads_the_first_line() {
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n\r\n").unwrap(), 200);
        assert_eq!(
            parse_status_code(b"HTTP/1.1 503 Service Unavailable\r\n").unwrap(),
            503
        );
        assert!(parse_status_code(b"not http at all").is_err());
    }

    #[test]
    fn wait_for_health_times_out_when_nothing_serves() {
        let dir = tmp_dir("health-timeout");
        let mut cfg = sleep_cfg(&dir, "30");
        cfg.health_retries = 3;
        cfg.health_interval = Duration::from_millis(20);
        cfg.connect_timeout = Duration::from_millis(200);
        let mut h = spawn_sidecar(Path::new("/bin/sleep"), cfg).expect("spawn sleep");

        // /bin/sleep never answers /healthz, so this must fail (not hang).
        let res = h.wait_for_health();
        assert!(res.is_err(), "must time out when the child serves no health");

        h.shutdown().expect("shutdown");
        cleanup(&dir);
    }

    // --- process lifecycle: the no-orphan gate -------------------------------

    #[test]
    fn spawn_writes_log_and_leaves_no_process_after_shutdown() {
        let dir = tmp_dir("shutdown");
        let mut h = spawn_sidecar(Path::new("/bin/sleep"), sleep_cfg(&dir, "30")).expect("spawn");
        let pid = h.pid();

        assert!(proc_alive(pid), "child alive right after spawn");
        assert!(h.log_path().exists(), "log file created in data dir");

        h.shutdown().expect("graceful shutdown");
        assert!(
            wait_gone(pid, Duration::from_secs(3)),
            "SIGTERM shutdown must leave no orphan process"
        );
        cleanup(&dir);
    }

    #[test]
    fn drop_kills_the_child() {
        let dir = tmp_dir("drop");
        let pid = {
            let h = spawn_sidecar(Path::new("/bin/sleep"), sleep_cfg(&dir, "30")).expect("spawn");
            let p = h.pid();
            assert!(proc_alive(p), "alive before drop");
            p
            // `h` dropped here -> Drop -> shutdown -> reaped.
        };
        assert!(
            wait_gone(pid, Duration::from_secs(3)),
            "Drop must enforce the no-orphan gate"
        );
        cleanup(&dir);
    }

    #[test]
    fn shutdown_hard_kills_a_sigterm_ignorer() {
        // `sh -c "trap '' TERM; sleep 5"` traps and ignores SIGTERM, forcing the
        // graceful window to elapse and the SIGKILL fallback to fire.
        let dir = tmp_dir("hardkill");
        let mut cfg = SidecarConfig::new(&dir);
        cfg.args = vec!["-c".to_string(), "trap '' TERM; sleep 5".to_string()];
        cfg.shutdown_grace = Duration::from_millis(300);
        let mut h = spawn_sidecar(Path::new("/bin/sh"), cfg).expect("spawn sh");
        let pid = h.pid();
        assert!(proc_alive(pid), "alive after spawn");

        let t0 = Instant::now();
        h.shutdown().expect("shutdown");
        assert!(
            t0.elapsed() >= Duration::from_millis(300),
            "graceful window must elapse before hard kill"
        );
        assert!(
            wait_gone(pid, Duration::from_secs(3)),
            "hard kill must remove a TERM-ignoring child"
        );
        cleanup(&dir);
    }
}
