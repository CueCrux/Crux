// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux self update [--check]` — the explicit, foreground update command.
//!
//! Fetches the signed release update-manifest.json, compares its version
//! against the running binary, prints the result, and (without `--check`)
//! downloads the matching platform asset, verifies its sha256 against the
//! manifest, and atomically replaces the running executable.
//!
//! Posture (`docs/update-channel.md`): this is NEVER automatic and NEVER a
//! background default. It runs only when an operator types the command, makes
//! its outbound GETs only then, and re-verifies the artifact before swapping it
//! in — consistent with "the upgrade is always an explicit operator command
//! that re-verifies signatures".
//!
//! Trust model: the artifact's sha256 is checked against the HTTPS-fetched
//! manifest. Full cosign keyless / SLSA verification remains the `install.sh`
//! path (which this command points the operator at when it cannot proceed).
//!
//! ponytail: sha256-vs-HTTPS-manifest is the ceiling here, not in-process
//! cosign verification; upgrade path is to verify the manifest signature with
//! the sigstore crate if the manifest host is ever considered untrusted.

// CLI output path (like `mcp_stdio`): stdout/stderr are the contract, so the
// workspace print lints are intentionally relaxed for this module only.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::cmp::Ordering;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Stable "always the newest release" manifest URL (see docs/update-channel.md).
const MANIFEST_URL: &str = "https://github.com/CueCrux/Crux/releases/latest/download/update-manifest.json";
/// Version of the running binary, stamped at compile time.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `crux.update_manifest.v1` — only the fields this command consumes; serde
/// ignores the rest (schema, published_at, verify_doc).
#[derive(serde::Deserialize)]
struct Manifest {
    version: String,
    tag: String,
    #[serde(default)]
    notes_url: Option<String>,
    artifacts: Vec<Artifact>,
}

#[derive(serde::Deserialize)]
struct Artifact {
    name: String,
    sha256: String,
}

/// Entry point for the `self` CLI action. `args` is the full argv (after
/// argv\[0\]); `args[0]` is guaranteed to be `"self"` by `parse_cli_arg`.
/// Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let check_only = match parse_self_args(args) {
        Ok(check_only) => check_only,
        Err(usage) => {
            eprintln!("{usage}");
            return 2;
        }
    };
    match run_inner(check_only) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("crux self update: {message}");
            1
        }
    }
}

/// Parse `self update` / `self update --check`. Returns `check_only`, or a
/// usage string on anything else (trailing junk included).
fn parse_self_args(args: &[String]) -> Result<bool, String> {
    match (
        args.get(1).map(String::as_str),
        args.get(2).map(String::as_str),
        args.len(),
    ) {
        (Some("update"), None, 2) => Ok(false),
        (Some("update"), Some("--check"), 3) => Ok(true),
        _ => Err(self_usage()),
    }
}

fn self_usage() -> String {
    "usage: crux self update [--check]\n\
     \n\
     \x20 self update          download, verify (sha256) and install the latest release\n\
     \x20 self update --check  report whether a newer release exists; make no changes"
        .to_string()
}

fn run_inner(check_only: bool) -> Result<(), String> {
    println!("crux {CURRENT_VERSION} — checking {MANIFEST_URL}");
    let manifest = fetch_manifest()?;

    match compare_versions(&manifest.version, CURRENT_VERSION) {
        Ordering::Greater => println!(
            "update available: {CURRENT_VERSION} -> {} ({})",
            manifest.version, manifest.tag
        ),
        Ordering::Equal => {
            println!("up to date: crux {CURRENT_VERSION} is the latest release");
        }
        Ordering::Less => println!(
            "running {CURRENT_VERSION}, newer than the latest release {} (development build)",
            manifest.version
        ),
    }
    if let Some(notes) = &manifest.notes_url {
        println!("release notes: {notes}");
    }

    if check_only {
        return Ok(());
    }
    if compare_versions(&manifest.version, CURRENT_VERSION) != Ordering::Greater {
        println!("nothing to install. To change to a specific version, reinstall via install.sh --version vX.Y.Z.");
        return Ok(());
    }

    let suffix = platform_suffix().ok_or_else(|| {
        format!(
            "no published binary for this platform ({}/{}); build from source or use install.sh",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let name = format!("crux-{suffix}");
    let artifact = manifest
        .artifacts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| format!("release {} carries no artifact named {name}", manifest.tag))?;

    let exe = download_and_replace(artifact, &manifest.tag)?;
    println!("replaced {} with crux {}", exe.display(), manifest.version);
    println!("restart the daemon (or your service manager) to run the new version.");
    Ok(())
}

/// Map the compile target to the release artifact suffix used in the manifest
/// (`crux-<suffix>`). Mirrors packaging/install.sh's platform table and
/// scripts/generate-update-manifest.sh's SUFFIXES. `None` for platforms with no
/// published binary yet (e.g. linux-arm64 today) — the caller prints a clear
/// "build from source / use install.sh" message.
fn platform_suffix() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-amd64"),
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-amd64"),
        _ => None,
    }
}

fn fetch_manifest() -> Result<Manifest, String> {
    let mut resp = ureq::get(MANIFEST_URL)
        .call()
        .map_err(|e| format!("fetching update manifest failed: {e}"))?;
    resp.body_mut()
        .read_json::<Manifest>()
        .map_err(|e| format!("parsing update manifest failed: {e}"))
}

/// Download `crux-<suffix>` for `tag`, verify its sha256 against the manifest,
/// and atomically replace the running executable. Returns the replaced path.
fn download_and_replace(artifact: &Artifact, tag: &str) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate the running executable: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "the running executable has no parent directory".to_string())?;

    let url = format!(
        "https://github.com/CueCrux/Crux/releases/download/{tag}/{}",
        artifact.name
    );
    println!("downloading {} ...", artifact.name);
    let mut resp = ureq::get(&url).call().map_err(|e| format!("download failed: {e}"))?;
    // as_reader() (not read_to_vec) so the multi-MB binary is not truncated by a
    // convenience-method size limit — mirrors the audit-pack export download.
    let mut bytes = Vec::new();
    resp.body_mut()
        .as_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading the download failed: {e}"))?;

    let got = sha256_hex(&bytes);
    if !got.eq_ignore_ascii_case(artifact.sha256.trim()) {
        return Err(format!(
            "sha256 mismatch for {} — manifest {}, downloaded {got}; refusing to install",
            artifact.name, artifact.sha256
        ));
    }
    println!("verified sha256 {got}");

    // Stage next to the current binary (same filesystem => the rename below is
    // atomic) under a unique temp name. Creating this temp is also the
    // writability probe: we must NOT open the running binary for write, which is
    // ETXTBSY on linux.
    let tmp = dir.join(format!(".crux-self-update.{}.tmp", std::process::id()));
    write_executable(&tmp, &bytes).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => format!(
            "{} is not writable — re-run with sufficient privileges, or reinstall via install.sh",
            dir.display()
        ),
        _ => format!("failed to stage the new binary in {}: {e}", dir.display()),
    })?;

    // The running-binary rename dance: linux refuses to truncate-write a running
    // executable (ETXTBSY) but happily renames over its path — the live process
    // keeps executing the old, now-unlinked inode while new invocations pick up
    // the replacement. rename(2) is atomic, so `exe` is never a torn binary.
    if let Err(e) = std::fs::rename(&tmp, &exe) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("failed to replace {}: {e}", exe.display()));
    }
    Ok(exe)
}

fn write_executable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Compare two dotted versions numerically (0.5.9 < 0.5.10), tolerating a
/// leading `v` and ignoring any pre-release / build metadata after `-`/`+`.
fn compare_versions(a: &str, b: &str) -> Ordering {
    parse_version(a).cmp(&parse_version(b))
}

fn parse_version(v: &str) -> (u64, u64, u64) {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next().unwrap_or(core);
    let mut parts = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare_is_numeric_and_tolerant() {
        assert_eq!(compare_versions("0.5.44", "0.5.44"), Ordering::Equal);
        assert_eq!(compare_versions("0.5.45", "0.5.44"), Ordering::Greater);
        assert_eq!(compare_versions("0.6.0", "0.5.99"), Ordering::Greater);
        // numeric, not lexical: 9 < 10
        assert_eq!(compare_versions("0.5.9", "0.5.10"), Ordering::Less);
        // leading v tolerated
        assert_eq!(compare_versions("v1.0.0", "0.9.9"), Ordering::Greater);
        // pre-release metadata ignored → same core compares equal
        assert_eq!(compare_versions("0.5.44-rc1", "0.5.44"), Ordering::Equal);
    }

    #[test]
    fn sha256_hex_matches_known_vectors() {
        // sha256("") and sha256("abc")
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parse_self_args_accepts_only_update_and_check() {
        let v = |s: &str| s.to_string();
        assert_eq!(parse_self_args(&[v("self"), v("update")]), Ok(false));
        assert_eq!(parse_self_args(&[v("self"), v("update"), v("--check")]), Ok(true));
        assert!(parse_self_args(&[v("self")]).is_err());
        assert!(parse_self_args(&[v("self"), v("bogus")]).is_err());
        assert!(parse_self_args(&[v("self"), v("update"), v("--force")]).is_err());
        assert!(parse_self_args(&[v("self"), v("update"), v("--check"), v("extra")]).is_err());
    }

    #[test]
    fn manifest_deserializes_and_platform_artifact_is_selectable() {
        let json = r#"{
          "schema":"crux.update_manifest.v1","tag":"v0.5.45","version":"0.5.45",
          "published_at":"2026-07-17T00:00:00Z",
          "notes_url":"https://example.invalid/notes","verify_doc":"https://example.invalid/verify",
          "artifacts":[
            {"name":"crux-linux-amd64","sha256":"aa"},
            {"name":"crux-darwin-arm64","sha256":"bb"}
          ]
        }"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.version, "0.5.45");
        assert_eq!(m.tag, "v0.5.45");
        assert_eq!(m.notes_url.as_deref(), Some("https://example.invalid/notes"));
        let selected = m.artifacts.iter().find(|a| a.name == "crux-linux-amd64").unwrap();
        assert_eq!(selected.sha256, "aa");
    }

    #[test]
    fn platform_suffix_maps_known_targets() {
        // At least the host running the test suite must map to a real suffix on
        // supported CI platforms; assert the mapping shape rather than a
        // specific host so this holds across the matrix.
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => assert_eq!(platform_suffix(), Some("linux-amd64")),
            ("macos", "aarch64") => assert_eq!(platform_suffix(), Some("darwin-arm64")),
            ("macos", "x86_64") => assert_eq!(platform_suffix(), Some("darwin-amd64")),
            _ => assert!(platform_suffix().is_none()),
        }
    }
}
