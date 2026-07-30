// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `crux self update [--check]` — the explicit, foreground update command.
//!
//! Resolves the newest immutable release tag, fetches that release's
//! update-manifest and Sigstore bundle, authenticates the raw manifest bytes
//! with `cosign`, and only then parses its fields. Without `--check`, the
//! command downloads the matching platform asset, verifies its sha256 against
//! the authenticated manifest, and atomically replaces the running executable.
//! Packaged installs that also carry `crux-hook` or `corecruxctl` fail closed
//! and route to the complete installer/package-manager upgrade so companion
//! versions cannot silently skew.
//!
//! Posture (`docs/update-channel.md`): this is NEVER automatic and NEVER a
//! background default. It runs only when an operator types the command, makes
//! its outbound GETs only then, and re-verifies the artifact before swapping it
//! in — consistent with "the upgrade is always an explicit operator command
//! that re-verifies artifact integrity".
//!
//! Trust model: `cosign verify-blob` must authenticate a complete Sigstore
//! bundle against the exact CueCrux release workflow identity and GitHub
//! Actions OIDC issuer. Missing `cosign`, missing proof, malformed proof,
//! identity/issuer mismatch, and tampering all fail closed before JSON parsing.
//! The signed manifest then authenticates the downloaded binary's sha256.

// CLI output path (like `mcp_stdio`): stdout/stderr are the contract, so the
// workspace print lints are intentionally relaxed for this module only.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::cmp::Ordering;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ureq::ResponseExt;

/// Stable redirect used only to resolve a canonical immutable release tag.
const LATEST_RELEASE_URL: &str = "https://github.com/CueCrux/Crux/releases/latest";
const RELEASE_BASE_URL: &str = "https://github.com/CueCrux/Crux/releases/download";
const MANIFEST_NAME: &str = "update-manifest.json";
const MANIFEST_BUNDLE_NAME: &str = "update-manifest.json.sigstore.json";
const RELEASE_WORKFLOW_IDENTITY_PREFIX: &str =
    "https://github.com/CueCrux/Crux/.github/workflows/release.yml@refs/tags/";
const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_RELEASE_BINARY_BYTES: u64 = 512 * 1024 * 1024;
/// Cosign intentionally supports custom trust roots for private Sigstore
/// deployments. A self-updater must not inherit those ambient overrides or an
/// attacker-controlled environment could replace Fulcio/Rekor/TUF trust while
/// retaining the expected SAN and issuer strings.
const COSIGN_TRUST_OVERRIDE_ENV: [&str; 6] = [
    "SIGSTORE_ROOT_FILE",
    "SIGSTORE_REKOR_PUBLIC_KEY",
    "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE",
    "SIGSTORE_TSA_CERTIFICATE_FILE",
    "TUF_MIRROR",
    "TUF_ROOT_JSON",
];
const COSIGN_TUF_ROOT_ENV: &str = "TUF_ROOT";
/// Version of the running binary, stamped at compile time.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The authenticated `crux.update_manifest.v2` schema. Unknown fields fail
/// closed so a future schema cannot silently acquire security-sensitive
/// semantics that an old updater ignores.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    version: String,
    tag: String,
    published_at: String,
    notes_url: Option<String>,
    verify_doc: String,
    artifacts: Vec<Artifact>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    name: String,
    asset_name: String,
    sha256: String,
}

impl Artifact {
    fn release_asset_name(&self) -> &str {
        &self.asset_name
    }
}

struct SignerPolicy {
    tag: String,
    identity: String,
}

impl SignerPolicy {
    fn for_tag(tag: &str) -> Result<Self, String> {
        if !is_canonical_release_tag(tag) {
            return Err(format!("latest release resolved to non-canonical tag {tag:?}"));
        }
        Ok(Self {
            tag: tag.to_string(),
            identity: format!("{RELEASE_WORKFLOW_IDENTITY_PREFIX}{tag}"),
        })
    }
}

trait ManifestVerifier {
    fn verify(&self, manifest: &[u8], bundle: &[u8], policy: &SignerPolicy) -> Result<(), String>;
}

struct CosignManifestVerifier;

impl ManifestVerifier for CosignManifestVerifier {
    fn verify(&self, manifest: &[u8], bundle: &[u8], policy: &SignerPolicy) -> Result<(), String> {
        ensure_patched_cosign()?;
        let temp = tempfile::Builder::new()
            .prefix("crux-self-update.")
            .tempdir()
            .map_err(|e| format!("creating private verification workspace failed: {e}"))?;
        let manifest_path = temp.path().join(MANIFEST_NAME);
        let bundle_path = temp.path().join(MANIFEST_BUNDLE_NAME);
        let tuf_root = temp.path().join("tuf");
        std::fs::create_dir(&tuf_root).map_err(|e| format!("creating private Sigstore trust cache failed: {e}"))?;
        std::fs::write(&manifest_path, manifest)
            .map_err(|e| format!("staging update manifest for verification failed: {e}"))?;
        std::fs::write(&bundle_path, bundle)
            .map_err(|e| format!("staging Sigstore bundle for verification failed: {e}"))?;

        let mut command = hardened_cosign_command(&tuf_root);
        command.args(cosign_verify_args(&manifest_path, &bundle_path, &policy.identity));
        let output = command.output().map_err(|e| {
            format!(
                "cannot run cosign for mandatory manifest verification: {e}. \
                     Install cosign 2.6.2, 3.0.4, or a later patched release, or use the complete signed installer"
            )
        })?;
        if !output.status.success() {
            return Err(format!(
                "Sigstore verification failed for {} (cosign status {}); refusing to trust the update manifest",
                policy.tag, output.status
            ));
        }
        Ok(())
    }
}

fn hardened_cosign_command(tuf_root: &Path) -> Command {
    let mut command = Command::new("cosign");
    for name in COSIGN_TRUST_OVERRIDE_ENV {
        command.env_remove(name);
    }
    // Never inherit $HOME/.sigstore/root: it may contain a custom mirror/root
    // established by `cosign initialize`. A fresh private directory forces
    // Cosign to bootstrap from its compiled production TUF mirror and root.
    command.env(COSIGN_TUF_ROOT_ENV, tuf_root);
    command
}

fn ensure_patched_cosign() -> Result<(), String> {
    let output = Command::new("cosign")
        .args(["version", "--json"])
        .output()
        .map_err(|e| {
            format!(
                "cannot run cosign for mandatory manifest verification: {e}. \
                 Install cosign 2.6.2, 3.0.4, or a later patched release, or use the complete signed installer"
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "cosign version check failed with status {}; refusing to verify an update",
            output.status
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "cosign returned an unrecognised version response".to_string())?;
    let version = value
        .get("gitVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "cosign version response omitted gitVersion".to_string())?;
    let parsed =
        parse_strict_semver(version).ok_or_else(|| format!("cosign reported non-release version {version:?}"))?;
    if !cosign_version_is_patched(parsed) {
        return Err(format!(
            "cosign {version} is vulnerable or unsupported; install 2.6.2+, 3.0.4+, or a later release"
        ));
    }
    Ok(())
}

fn cosign_version_is_patched(version: (u64, u64, u64)) -> bool {
    match version.0 {
        0 | 1 => false,
        2 => version >= (2, 6, 2),
        3 => version >= (3, 0, 4),
        _ => true,
    }
}

fn parse_strict_semver(version: &str) -> Option<(u64, u64, u64)> {
    let version = version.trim().strip_prefix('v').unwrap_or(version.trim());
    if version.contains(['-', '+']) {
        return None;
    }
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let parse_part = |part: &str| {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) || (part != "0" && part.starts_with('0'))
        {
            return None;
        }
        part.parse::<u64>().ok()
    };
    Some((parse_part(parts[0])?, parse_part(parts[1])?, parse_part(parts[2])?))
}

fn cosign_verify_args(manifest_path: &Path, bundle_path: &Path, identity: &str) -> Vec<OsString> {
    [
        OsString::from("verify-blob"),
        OsString::from("--new-bundle-format=true"),
        OsString::from("--bundle"),
        bundle_path.as_os_str().to_owned(),
        OsString::from("--certificate-identity"),
        OsString::from(identity),
        OsString::from("--certificate-oidc-issuer"),
        OsString::from(GITHUB_ACTIONS_OIDC_ISSUER),
        manifest_path.as_os_str().to_owned(),
    ]
    .into_iter()
    .collect()
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
     \x20 self update          update a standalone daemon binary; packaged installs use their installer\n\
     \x20 self update --check  report whether a newer release exists; make no changes"
        .to_string()
}

fn run_inner(check_only: bool) -> Result<(), String> {
    println!("crux {CURRENT_VERSION} — checking {LATEST_RELEASE_URL}");
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
    let artifact = select_standalone_artifact(&manifest, suffix).ok_or_else(|| {
        format!(
            "release {} carries no standalone daemon artifact for {suffix}; use the complete signed installer",
            manifest.tag
        )
    })?;

    let exe = download_and_replace(artifact, &manifest.tag)?;
    println!("replaced {} with crux {}", exe.display(), manifest.version);
    println!("restart the daemon (or your service manager) to run the new version.");
    Ok(())
}

fn select_standalone_artifact<'a>(manifest: &'a Manifest, suffix: &str) -> Option<&'a Artifact> {
    let fenced_name = format!("standalone-crux-{suffix}");
    manifest.artifacts.iter().find(|artifact| artifact.name == fenced_name)
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
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(5)
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let latest = agent
        .get(LATEST_RELEASE_URL)
        .call()
        .map_err(|e| format!("resolving latest release failed: {e}"))?;
    let tag = release_tag_from_uri(latest.get_uri())?;
    let policy = SignerPolicy::for_tag(&tag)?;
    let base_url = format!("{RELEASE_BASE_URL}/{tag}");
    let manifest = fetch_bounded(
        &agent,
        &format!("{base_url}/{MANIFEST_NAME}"),
        "update manifest",
        MAX_MANIFEST_BYTES,
    )?;
    let bundle = fetch_bounded(
        &agent,
        &format!("{base_url}/{MANIFEST_BUNDLE_NAME}"),
        "Sigstore bundle",
        MAX_BUNDLE_BYTES,
    )?;
    verify_then_parse_manifest(&manifest, &bundle, &policy, &CosignManifestVerifier)
}

fn release_tag_from_uri(uri: &ureq::http::Uri) -> Result<String, String> {
    if uri.scheme_str() != Some("https")
        || uri.authority().map(|authority| authority.as_str()) != Some("github.com")
        || uri.query().is_some()
    {
        return Err(format!("latest release redirected to an unexpected origin: {uri}"));
    }
    let tag = uri
        .path()
        .strip_prefix("/CueCrux/Crux/releases/tag/")
        .filter(|tag| !tag.is_empty() && !tag.contains('/'))
        .ok_or_else(|| format!("latest release redirected to an unexpected path: {uri}"))?;
    if !is_canonical_release_tag(tag) {
        return Err(format!("latest release redirected to a non-canonical tag: {tag:?}"));
    }
    Ok(tag.to_string())
}

fn fetch_bounded(agent: &ureq::Agent, url: &str, label: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| format!("fetching {label} failed: {e}"))?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit((max_bytes + 1) as u64)
        .read_to_vec()
        .map_err(|e| format!("reading {label} failed: {e}"))?;
    if bytes.len() > max_bytes {
        return Err(format!("{label} exceeds the {max_bytes}-byte verification limit"));
    }
    if bytes.is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(bytes)
}

fn verify_then_parse_manifest(
    manifest_bytes: &[u8],
    bundle: &[u8],
    policy: &SignerPolicy,
    verifier: &impl ManifestVerifier,
) -> Result<Manifest, String> {
    if manifest_bytes.is_empty() {
        return Err("update manifest is empty".to_string());
    }
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "update manifest exceeds the {MAX_MANIFEST_BYTES}-byte verification limit"
        ));
    }
    if bundle.is_empty() {
        return Err("mandatory Sigstore bundle is missing or empty".to_string());
    }
    if bundle.len() > MAX_BUNDLE_BYTES {
        return Err(format!(
            "Sigstore bundle exceeds the {MAX_BUNDLE_BYTES}-byte verification limit"
        ));
    }

    // Authentication deliberately precedes deserialization: no tag, URL,
    // version, artifact name, or hash from the manifest is trusted earlier.
    verifier.verify(manifest_bytes, bundle, policy)?;
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| format!("parsing authenticated update manifest failed: {e}"))?;
    validate_manifest(&manifest, policy)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &Manifest, policy: &SignerPolicy) -> Result<(), String> {
    if manifest.schema != "crux.update_manifest.v2" {
        return Err(format!(
            "unsupported authenticated update-manifest schema {:?}",
            manifest.schema
        ));
    }
    if manifest.tag != policy.tag {
        return Err(format!(
            "authenticated manifest tag {:?} does not match resolved release tag {:?}",
            manifest.tag, policy.tag
        ));
    }
    if manifest.version != policy.tag.trim_start_matches('v') {
        return Err(format!(
            "authenticated manifest version {:?} does not match tag {:?}",
            manifest.version, policy.tag
        ));
    }
    if manifest.published_at.trim().is_empty() {
        return Err("authenticated manifest has an empty published_at".to_string());
    }
    let expected_notes = format!("https://github.com/CueCrux/Crux/releases/tag/{}", policy.tag);
    if manifest.notes_url.as_deref() != Some(expected_notes.as_str()) {
        return Err("authenticated manifest has a non-canonical notes_url".to_string());
    }
    let expected_verify = format!(
        "https://github.com/CueCrux/Crux/blob/{}/docs/verify-release.md",
        policy.tag
    );
    if manifest.verify_doc != expected_verify {
        return Err("authenticated manifest has a non-canonical verify_doc".to_string());
    }

    const EXPECTED: [(&str, &str); 3] = [
        ("standalone-crux-linux-amd64", "crux-linux-amd64"),
        ("standalone-crux-darwin-arm64", "crux-darwin-arm64"),
        ("standalone-crux-darwin-amd64", "crux-darwin-amd64"),
    ];
    if manifest.artifacts.len() != EXPECTED.len() {
        return Err(format!(
            "authenticated manifest must contain exactly {} standalone artifacts",
            EXPECTED.len()
        ));
    }
    for (name, asset_name) in EXPECTED {
        let matches = manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.name == name)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "authenticated manifest must contain exactly one {name:?} artifact"
            ));
        }
        let artifact = matches[0];
        if artifact.asset_name != asset_name {
            return Err(format!(
                "authenticated manifest maps {name:?} to unexpected asset {:?}",
                artifact.asset_name
            ));
        }
        if artifact.sha256.len() != 64 || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("authenticated manifest has an invalid sha256 for {name:?}"));
        }
    }
    Ok(())
}

fn is_canonical_release_tag(tag: &str) -> bool {
    let Some(version) = tag.strip_prefix('v') else {
        return false;
    };
    let parts = version.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == &"0" || !part.starts_with('0'))
                && part.parse::<u64>().is_ok()
        })
}

/// Download the selected release asset for `tag`, verify its sha256 against the
/// manifest, and atomically replace the running executable. Returns the
/// replaced path.
fn download_and_replace(artifact: &Artifact, tag: &str) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate the running executable: {e}"))?;
    guard_packaged_companions(&exe, tag)?;
    let dir = exe
        .parent()
        .ok_or_else(|| "the running executable has no parent directory".to_string())?;

    let asset_name = artifact.release_asset_name();
    let url = format!("https://github.com/CueCrux/Crux/releases/download/{tag}/{asset_name}");
    println!("downloading {asset_name} ...");
    let mut resp = ureq::get(&url).call().map_err(|e| format!("download failed: {e}"))?;
    // as_reader() (not read_to_vec) so the multi-MB binary is not truncated by a
    // convenience-method size limit — mirrors the audit-pack export download.
    let mut bytes = Vec::new();
    resp.body_mut()
        .as_reader()
        .take(MAX_RELEASE_BINARY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading the download failed: {e}"))?;
    if bytes.len() as u64 > MAX_RELEASE_BINARY_BYTES {
        return Err(format!(
            "{asset_name} exceeds the {} MiB standalone-update limit; use the complete signed installer",
            MAX_RELEASE_BINARY_BYTES / (1024 * 1024)
        ));
    }

    let got = sha256_hex(&bytes);
    if !got.eq_ignore_ascii_case(artifact.sha256.trim()) {
        return Err(format!(
            "sha256 mismatch for {} — manifest {}, downloaded {got}; refusing to install",
            asset_name, artifact.sha256
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

/// Refuse a daemon-only replacement when this is visibly a managed bundle.
///
/// The signed installer, Debian package, and Homebrew formula place both
/// companions beside the daemon. Updating only `crux` would strand an older
/// hook/CLI while reporting the daemon as current. A multi-file replacement is
/// not atomic, so the safe boundary is to use the existing complete-bundle
/// upgrade path.
fn guard_packaged_companions(exe: &Path, tag: &str) -> Result<(), String> {
    let Some(dir) = exe.parent() else {
        return Ok(());
    };
    let companion = ["crux-hook", "corecruxctl"]
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.exists());
    let Some(companion) = companion else {
        return Ok(());
    };

    Err(format!(
        "refusing a daemon-only update because {} is installed beside {}; replacing only crux would leave companion versions stale. Upgrade the complete signed bundle with install.sh --version {tag}, brew upgrade crux, or a new .deb",
        companion.display(),
        exe.display()
    ))
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
    use std::cell::Cell;

    const TEST_TAG: &str = "v0.5.45";

    fn valid_manifest_json() -> Vec<u8> {
        let digest_a = "a".repeat(64);
        let digest_b = "b".repeat(64);
        let digest_c = "c".repeat(64);
        format!(
            r#"{{
              "schema":"crux.update_manifest.v2",
              "tag":"{TEST_TAG}",
              "version":"0.5.45",
              "published_at":"2026-07-17T00:00:00Z",
              "notes_url":"https://github.com/CueCrux/Crux/releases/tag/{TEST_TAG}",
              "verify_doc":"https://github.com/CueCrux/Crux/blob/{TEST_TAG}/docs/verify-release.md",
              "artifacts":[
                {{"name":"standalone-crux-linux-amd64","asset_name":"crux-linux-amd64","sha256":"{digest_a}"}},
                {{"name":"standalone-crux-darwin-arm64","asset_name":"crux-darwin-arm64","sha256":"{digest_b}"}},
                {{"name":"standalone-crux-darwin-amd64","asset_name":"crux-darwin-amd64","sha256":"{digest_c}"}}
              ]
            }}"#
        )
        .into_bytes()
    }

    fn policy() -> SignerPolicy {
        SignerPolicy::for_tag(TEST_TAG).expect("canonical fixture tag")
    }

    /// Deterministic test double for the parse-order and identity-policy
    /// boundary. Production cryptography is delegated to the pinned, official
    /// cosign invocation and exercised by the release workflow itself.
    struct FixtureVerifier;

    impl ManifestVerifier for FixtureVerifier {
        fn verify(&self, manifest: &[u8], bundle: &[u8], policy: &SignerPolicy) -> Result<(), String> {
            let expected = format!(
                "{}\n{}\n{}",
                sha256_hex(manifest),
                policy.identity,
                GITHUB_ACTIONS_OIDC_ISSUER
            );
            if bundle == expected.as_bytes() {
                Ok(())
            } else {
                Err("fixture signature, identity, or issuer mismatch".to_string())
            }
        }
    }

    fn fixture_bundle(manifest: &[u8], identity: &str, issuer: &str) -> Vec<u8> {
        format!("{}\n{identity}\n{issuer}", sha256_hex(manifest)).into_bytes()
    }

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
        let bytes = valid_manifest_json();
        let fixture_policy = policy();
        let bundle = fixture_bundle(&bytes, &fixture_policy.identity, GITHUB_ACTIONS_OIDC_ISSUER);
        let m = verify_then_parse_manifest(&bytes, &bundle, &fixture_policy, &FixtureVerifier).unwrap();
        assert_eq!(m.version, "0.5.45");
        assert_eq!(m.tag, TEST_TAG);
        let selected = select_standalone_artifact(&m, "linux-amd64").unwrap();
        assert_eq!(selected.sha256, "a".repeat(64));
        assert_eq!(selected.release_asset_name(), "crux-linux-amd64");
    }

    #[test]
    fn unsigned_wrong_identity_wrong_issuer_and_tamper_all_fail_closed() {
        let bytes = valid_manifest_json();
        let fixture_policy = policy();
        let valid = fixture_bundle(&bytes, &fixture_policy.identity, GITHUB_ACTIONS_OIDC_ISSUER);
        assert!(verify_then_parse_manifest(&bytes, &valid, &fixture_policy, &FixtureVerifier).is_ok());

        let unsigned = verify_then_parse_manifest(&bytes, b"", &fixture_policy, &FixtureVerifier).unwrap_err();
        assert!(unsigned.contains("bundle"));

        let wrong_identity = fixture_bundle(
            &bytes,
            "https://github.com/attacker/Crux/.github/workflows/release.yml@refs/tags/v0.5.45",
            GITHUB_ACTIONS_OIDC_ISSUER,
        );
        assert!(
            verify_then_parse_manifest(&bytes, &wrong_identity, &fixture_policy, &FixtureVerifier)
                .unwrap_err()
                .contains("identity")
        );

        let wrong_issuer = fixture_bundle(&bytes, &fixture_policy.identity, "https://issuer.example.invalid");
        assert!(
            verify_then_parse_manifest(&bytes, &wrong_issuer, &fixture_policy, &FixtureVerifier)
                .unwrap_err()
                .contains("issuer")
        );

        // Invalid JSON with the valid proof for the original bytes must fail
        // authentication, proving deserialization did not run first.
        let tampered = b"{ definitely not valid signed JSON";
        let error = verify_then_parse_manifest(tampered, &valid, &fixture_policy, &FixtureVerifier).unwrap_err();
        assert!(error.contains("fixture signature"));
        assert!(!error.contains("parsing"));
    }

    #[test]
    fn signature_verification_precedes_schema_and_semantic_validation() {
        struct AcceptingVerifier;
        impl ManifestVerifier for AcceptingVerifier {
            fn verify(&self, _manifest: &[u8], _bundle: &[u8], _policy: &SignerPolicy) -> Result<(), String> {
                Ok(())
            }
        }

        let fixture_policy = policy();
        let error = verify_then_parse_manifest(
            b"{ signed but invalid JSON",
            b"fixture-proof",
            &fixture_policy,
            &AcceptingVerifier,
        )
        .unwrap_err();
        assert!(error.contains("parsing authenticated"));

        let mut value: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).expect("fixture JSON");
        value["tag"] = serde_json::json!("v0.5.46");
        let mismatch = serde_json::to_vec(&value).expect("serialize fixture");
        let error =
            verify_then_parse_manifest(&mismatch, b"fixture-proof", &fixture_policy, &AcceptingVerifier).unwrap_err();
        assert!(error.contains("does not match resolved release tag"));
    }

    #[test]
    fn authenticated_manifest_schema_and_artifact_constraints_fail_closed() {
        struct AcceptingVerifier;
        impl ManifestVerifier for AcceptingVerifier {
            fn verify(&self, _manifest: &[u8], _bundle: &[u8], _policy: &SignerPolicy) -> Result<(), String> {
                Ok(())
            }
        }

        let fixture_policy = policy();
        let base: serde_json::Value = serde_json::from_slice(&valid_manifest_json()).expect("fixture JSON");
        let mut cases = Vec::new();

        let mut wrong_schema = base.clone();
        wrong_schema["schema"] = serde_json::json!("crux.update_manifest.v3");
        cases.push((wrong_schema, "schema"));

        let mut wrong_version = base.clone();
        wrong_version["version"] = serde_json::json!("0.5.46");
        cases.push((wrong_version, "version"));

        let mut short_hash = base.clone();
        short_hash["artifacts"][0]["sha256"] = serde_json::json!("aa");
        cases.push((short_hash, "sha256"));

        let mut wrong_asset = base.clone();
        wrong_asset["artifacts"][0]["asset_name"] = serde_json::json!("../crux");
        cases.push((wrong_asset, "unexpected asset"));

        let mut duplicate = base.clone();
        duplicate["artifacts"][1]["name"] = serde_json::json!("standalone-crux-linux-amd64");
        cases.push((duplicate, "exactly one"));

        let mut unexpected_field = base;
        unexpected_field["trusted_hash_override"] = serde_json::json!("yes");
        cases.push((unexpected_field, "unknown field"));

        for (value, expected_error) in cases {
            let bytes = serde_json::to_vec(&value).expect("serialize fixture");
            let error =
                verify_then_parse_manifest(&bytes, b"fixture-proof", &fixture_policy, &AcceptingVerifier).unwrap_err();
            assert!(
                error.contains(expected_error),
                "expected {expected_error:?} in {error:?}"
            );
        }
    }

    #[test]
    fn oversized_inputs_are_rejected_before_verifier_execution() {
        struct RecordingVerifier(Cell<bool>);
        impl ManifestVerifier for RecordingVerifier {
            fn verify(&self, _manifest: &[u8], _bundle: &[u8], _policy: &SignerPolicy) -> Result<(), String> {
                self.0.set(true);
                Ok(())
            }
        }

        let fixture_policy = policy();
        let verifier = RecordingVerifier(Cell::new(false));
        let too_large_manifest = vec![b'x'; MAX_MANIFEST_BYTES + 1];
        assert!(
            verify_then_parse_manifest(&too_large_manifest, b"proof", &fixture_policy, &verifier)
                .unwrap_err()
                .contains("exceeds")
        );
        assert!(!verifier.0.get());

        let too_large_bundle = vec![b'x'; MAX_BUNDLE_BYTES + 1];
        assert!(
            verify_then_parse_manifest(&valid_manifest_json(), &too_large_bundle, &fixture_policy, &verifier)
                .unwrap_err()
                .contains("exceeds")
        );
        assert!(!verifier.0.get());
    }

    #[test]
    fn release_tag_resolution_and_signer_policy_are_exact() {
        let valid: ureq::http::Uri = "https://github.com/CueCrux/Crux/releases/tag/v1.2.3".parse().unwrap();
        assert_eq!(release_tag_from_uri(&valid).unwrap(), "v1.2.3");

        for invalid in [
            "http://github.com/CueCrux/Crux/releases/tag/v1.2.3",
            "https://evil.example/CueCrux/Crux/releases/tag/v1.2.3",
            "https://github.com/CueCrux/Crux/releases/tag/v01.2.3",
            "https://github.com/CueCrux/Crux/releases/tag/main",
            "https://github.com/CueCrux/Crux/releases/tag/v1.2.3/extra",
            "https://github.com/CueCrux/Crux/releases/tag/v1.2.3?download=1",
        ] {
            let uri: ureq::http::Uri = invalid.parse().unwrap();
            assert!(release_tag_from_uri(&uri).is_err(), "{invalid}");
        }

        let fixture_policy = SignerPolicy::for_tag("v1.2.3").unwrap();
        assert_eq!(
            fixture_policy.identity,
            "https://github.com/CueCrux/Crux/.github/workflows/release.yml@refs/tags/v1.2.3"
        );
        for invalid in ["1.2.3", "v1.2", "v1.2.3-rc1", "v01.2.3", "v1.2.3/main"] {
            assert!(SignerPolicy::for_tag(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn cosign_command_pins_bundle_identity_and_issuer_without_bypass_flags() {
        let args = cosign_verify_args(
            Path::new("/private/update-manifest.json"),
            Path::new("/private/update-manifest.json.sigstore.json"),
            "expected-identity",
        );
        let args = args.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "verify-blob",
                "--new-bundle-format=true",
                "--bundle",
                "/private/update-manifest.json.sigstore.json",
                "--certificate-identity",
                "expected-identity",
                "--certificate-oidc-issuer",
                GITHUB_ACTIONS_OIDC_ISSUER,
                "/private/update-manifest.json",
            ]
        );
        assert!(!args.iter().any(|arg| arg.contains("insecure")));
        assert_eq!(
            COSIGN_TRUST_OVERRIDE_ENV,
            [
                "SIGSTORE_ROOT_FILE",
                "SIGSTORE_REKOR_PUBLIC_KEY",
                "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE",
                "SIGSTORE_TSA_CERTIFICATE_FILE",
                "TUF_MIRROR",
                "TUF_ROOT_JSON",
            ]
        );

        let command = hardened_cosign_command(Path::new("/private/tuf"));
        let env = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(env.get(COSIGN_TUF_ROOT_ENV), Some(&Some("/private/tuf".to_string())));
        for name in COSIGN_TRUST_OVERRIDE_ENV {
            assert_eq!(env.get(name), Some(&None), "{name} must be removed");
        }
    }

    #[test]
    fn cosign_version_parser_accepts_only_canonical_release_versions() {
        assert_eq!(parse_strict_semver("v2.6.2"), Some((2, 6, 2)));
        assert_eq!(parse_strict_semver("3.0.4"), Some((3, 0, 4)));
        for invalid in ["v2.6", "v02.6.2", "v2.6.2-rc.1", "v2.6.2+local", "main"] {
            assert_eq!(parse_strict_semver(invalid), None, "{invalid}");
        }
        for vulnerable in [(1, 13, 6), (2, 4, 3), (2, 6, 1), (3, 0, 3)] {
            assert!(!cosign_version_is_patched(vulnerable));
        }
        for patched in [(2, 6, 2), (2, 9, 0), (3, 0, 4), (4, 0, 0)] {
            assert!(cosign_version_is_patched(patched));
        }
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

    #[test]
    fn packaged_companions_refuse_daemon_only_update() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let standalone = temp.path().join("standalone");
        std::fs::create_dir(&standalone)?;
        let standalone_exe = standalone.join("crux");
        assert_eq!(guard_packaged_companions(&standalone_exe, "v0.5.45"), Ok(()));

        for companion_name in ["crux-hook", "corecruxctl"] {
            let case_dir = temp.path().join(companion_name);
            std::fs::create_dir(&case_dir)?;
            let exe = case_dir.join("crux");
            std::fs::write(case_dir.join(companion_name), b"fixture")?;
            let message = guard_packaged_companions(&exe, "v0.5.45")
                .err()
                .ok_or_else(|| std::io::Error::other("packaged update was not refused"))?;
            assert!(message.contains(companion_name));
            assert!(message.contains("install.sh --version v0.5.45"));
            assert!(message.contains("companion versions stale"));
        }
        Ok(())
    }
}
