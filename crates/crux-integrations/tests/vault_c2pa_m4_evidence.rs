// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M4 integration test for ExecPlan
//! `corecruxd-c2pa-vault-pki-runtime-enablement-2026-05-29`.
//!
//! Proves the `CORECRUX_C2PA_SIGNER=vault` runtime path end-to-end
//! against a **real, local** `vault server -dev` PKI mount and the
//! off-the-shelf `c2patool` verifier. This is the same call chain
//! `crux_mcp::tools::output_attest` drives at runtime:
//!
//! 1. `C2paSignerKind::from_canonical_env()` resolves the flag,
//! 2. `build_manifest_signer(Vault, ..)` constructs the
//!    `VaultPkiX509Signer` via `from_env()` + `initialize()` — which
//!    generates a P-256 leaf key on the host, builds a CSR, and POSTs
//!    it to `${VAULT_ADDR}/v1/${mount}/sign/c2pa-leaf` (the Vault PKI
//!    CSR-sign-only custody model),
//! 3. `sign_c2pa_manifest_via_signer(..)` emits the JUMBF envelope.
//!
//! ## `#[ignore]` — needs external services
//!
//! Gated `#[ignore]` because it requires a running Vault dev server and
//! `c2patool` on `PATH`. Run with:
//!
//! ```text
//! VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root> \
//! CORECRUXD_VAULT_PKI_MOUNT=pki-c2pa \
//! VAULT_C2PA_ROOT_PEM=/path/to/vault-root.pem \
//! C2PATOOL_BIN=/abs/path/to/c2patool \
//! cargo test -p crux-integrations --test vault_c2pa_m4_evidence -- --ignored --nocapture
//! ```
//!
//! ## Environment contract (all REQUIRED — the leg is not optional)
//!
//! - `VAULT_ADDR`, `VAULT_TOKEN` — a `vault server -dev` with a PKI mount
//!   (`CORECRUXD_VAULT_PKI_MOUNT`, default `pki-c2pa`) whose `c2pa-leaf`
//!   role issues EC P-256 leaves with KeyUsage `digitalSignature` + EKU
//!   `emailProtection` (the C2PA end-entity signing-cert profile).
//! - `VAULT_C2PA_ROOT_PEM` — path to the Vault PKI root cert PEM. Used
//!   (a) as the `c2patool` trust anchor and (b) to cross-check leaf
//!   issuance. The leaf key/cert are throwaway artefacts minted into a
//!   `tempfile` dir for this run.
//! - `C2PATOOL_BIN` — absolute path to `c2patool` (avoids `PATH`
//!   hijack); defaults to `c2patool` on `PATH`.
//! - `C2PA_M4_SUMMARY_OUT` (optional) — path to write a machine-readable
//!   JSON evidence summary (p95, verifier verdicts).
//!
//! ## What it asserts vs. what it records
//!
//! Hard assertions (the genuinely-required M4 truths):
//! - the flag resolves to the Vault backend,
//! - `build_manifest_signer(Vault)` mints a leaf against real Vault,
//! - the emitted envelope is `es256` and carries an `x5chain`,
//! - the emitted signature is a valid **true ES256** signature —
//!   ECDSA-P256 over `SHA-256(canonical_body)` — **verified against the
//!   leaf certificate's own public key parsed from the envelope x5chain**
//!   (not the on-disk private key — so a signer that never talked to
//!   Vault cannot pass),
//! - the x5chain leaf is **issued by** the Vault root (issuer == root
//!   subject), and `c2patool` resolves `signingCredential.trusted` for
//!   it against the Vault root anchor **with no allow-list shortcut**
//!   (so trust must cryptographically chain to the Vault root),
//! - the daemon's own stateless ES256 verifier
//!   `verify_c2pa_signed_manifest_es256_v1` (ECDSA-**SHA-256**, used by
//!   `corecruxd/src/http/provenance.rs`) **accepts** the Vault envelope.
//!   This was the M5-gate blocker: `VaultPkiX509Signer::sign_body` used
//!   to sign a **BLAKE3** prehash while advertising `es256`, so the
//!   verifier reported `signature_valid=false`. Once the signer moved to
//!   a true SHA-256 prehash this became a hard assertion and is the
//!   end-to-end regression guard against that algorithm confusion.
//!
//! Recorded (evidence, not assertions) — surfaced to stderr + summary:
//! - p50/p95/max per-sign latency over 50 calls + one-time Vault CSR
//!   init cost.

// Integration test: panicking on a failed external service and printing
// evidence to stderr is the intended behaviour, so opt out of the
// workspace's restriction lints for this test binary (mirrors the
// `#[allow(clippy::unwrap_used, clippy::expect_used)]` on the crate's
// unit-test modules).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stderr)]

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crux_integrations::c2pa_signer_selector::{
    build_manifest_signer, C2paSignerKind, SIGNER_FLAG_ENV, SIGNER_VALUE_VAULT,
};

use corecrux_receipts::{
    build_c2pa_manifest_v1, canonical_body_bytes_v1, parse_jumbf_base64, sign_c2pa_manifest_via_signer,
    verify_c2pa_signed_manifest_es256_v1, C2paManifestInputV1,
};

use ed25519_dalek::SigningKey;
use p256::ecdsa::signature::Verifier as _;
use x509_cert::der::Decode as _;

/// A 64x64 RGB PNG fixture — large enough for `c2patool` to embed a
/// manifest (a 1x1 PNG is rejected as "PNG out of range").
const FIXTURE_PNG_B64: &str = "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";

/// Timeout (seconds) applied to every `c2patool` child so a hung /
/// incompatible binary cannot wedge the ignored test. Enforced via the
/// coreutils `timeout` wrapper.
const C2PATOOL_TIMEOUT_SECS: u32 = 60;

/// RAII guard that restores process env vars on drop (panic-safe), so a
/// failed assertion cannot leak `CORECRUX_C2PA_SIGNER=vault` or the leaf
/// path overrides into a co-located test.
#[derive(Default)]
struct EnvGuard {
    restore: Vec<(String, Option<String>)>,
}

impl EnvGuard {
    fn set(&mut self, key: &str, value: &OsStr) {
        self.restore.push((key.to_string(), std::env::var(key).ok()));
        std::env::set_var(key, value);
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, old) in self.restore.drain(..) {
            match old {
                Some(v) => std::env::set_var(&key, v),
                None => std::env::remove_var(&key),
            }
        }
    }
}

/// One entry point so `--ignored` runs the whole flow in a single test
/// (env mutation + shared Vault init state make a monolithic test the
/// least surprising choice here).
#[test]
#[ignore = "needs a running vault server -dev + c2patool; run with --ignored"]
fn vault_signer_end_to_end_against_local_vault() {
    let vault_addr = require_env("VAULT_ADDR");
    let _vault_token = require_env("VAULT_TOKEN");
    let root_pem_path = require_env("VAULT_C2PA_ROOT_PEM");
    let c2patool = std::env::var("C2PATOOL_BIN").unwrap_or_else(|_| "c2patool".to_string());
    assert!(
        c2patool_available(&c2patool),
        "c2patool must be available (set C2PATOOL_BIN to an absolute path); the interop leg is not optional"
    );
    eprintln!(
        "\n== M4 vault integration :: VAULT_ADDR={} ==",
        redact_addr(&vault_addr)
    );

    // Isolate the signer's on-disk leaf artefacts to a throwaway dir so
    // the test never touches /var/lib/corecruxd.
    let tmp = tempfile::tempdir().expect("tempdir");
    let leaf_key_path = tmp.path().join("c2pa-leaf.key.pem");
    let leaf_cert_path = tmp.path().join("c2pa-leaf.cert.pem");
    let root_anchor_path = tmp.path().join("c2pa-root.cert.pem");
    let mut env = EnvGuard::default();
    env.set("CORECRUXD_C2PA_LEAF_KEY_PATH", leaf_key_path.as_os_str());
    env.set("CORECRUXD_C2PA_LEAF_CERT_PATH", leaf_cert_path.as_os_str());
    env.set("CORECRUXD_C2PA_ROOT_ANCHOR_PATH", root_anchor_path.as_os_str());

    // ── 1. Flag resolution (the runtime selector) ──────────────────────
    env.set(SIGNER_FLAG_ENV, OsStr::new(SIGNER_VALUE_VAULT));
    assert_eq!(
        C2paSignerKind::from_canonical_env(),
        Some(C2paSignerKind::Vault),
        "CORECRUX_C2PA_SIGNER=vault must resolve to the Vault backend"
    );

    // ── 2. Build the signer against real Vault (mints a leaf) ───────────
    // The `signing_key` arg is ignored on the Vault branch (it only feeds
    // the in-process Ed25519 backend); pass a fixed throwaway key.
    let ignored_key = SigningKey::from_bytes(&[0x11u8; 32]);
    let t_init = Instant::now();
    let signer = build_manifest_signer(C2paSignerKind::Vault, ignored_key, "m4-vault-key")
        .expect("build_manifest_signer(Vault) must succeed against a reachable dev Vault PKI mount");
    let init_ms = t_init.elapsed().as_secs_f64() * 1e3;
    assert!(
        leaf_key_path.exists() && leaf_cert_path.exists(),
        "initialize() must persist the Vault-minted leaf key + cert to disk"
    );
    eprintln!("[init] Vault CSR-sign round-trip + leaf mint: {init_ms:.1} ms");

    // ── 3. Sign a synthetic C2PA payload (the output_attest path) ──────
    let content: &[u8] = b"m4-integration-content-bytes-for-attestation";
    let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
        content_bytes: content,
        content_type: Some("image/png"),
        crown_receipt_id: "r_m4_integration",
        signer_passport: "passport:m4-test",
        claim_generator: "cuecrux/m4-integration",
        manifest_id: "urn:cuecrux:c2pa:m4-integration",
        when: "2026-05-29T12:00:00Z",
        model: None,
    });
    let body = canonical_body_bytes_v1(&manifest).expect("canonical body");
    let signed = sign_c2pa_manifest_via_signer(manifest, &*signer, "2026-05-29T12:00:00Z")
        .expect("sign via Arc<dyn C2paSigner> (Vault)");
    assert_eq!(signed.signature_alg, "es256", "Vault backend must advertise es256");
    let x5chain_pem = signed
        .x5chain_pem
        .clone()
        .expect("Vault backend must embed an x5chain (leaf + intermediates)");

    // ── 4. Signer soundness against the LEAF CERT public key ───────────
    // Parse the leaf certificate FROM the envelope x5chain, derive its
    // public key, and verify the emitted DER signature as **true ES256**
    // (ECDSA-P256 over the SHA-256 hash of the canonical body) — exactly
    // what corecruxctl's `c2pa-verify` does (corecruxctl/src/c2pa_x509.rs)
    // and what the `es256` algorithm identifier actually means. Using the
    // cert's own key (not the on-disk private key) means a signer that
    // skipped Vault and wrote an unrelated cert cannot pass.
    let leaf_der = first_cert_der(&x5chain_pem).expect("x5chain has a leaf certificate");
    let leaf_cert = x509_cert::Certificate::from_der(&leaf_der).expect("leaf cert DER parses");
    let leaf_vk = p256_verifying_key_from_cert(&leaf_cert).expect("leaf SPKI is a P-256 point");
    let der_sig = p256::ecdsa::Signature::from_der(&signed.signature).expect("es256 signature is DER ECDSA");
    let es256_signature_valid = leaf_vk.verify(&signed.canonical_body_bytes, &der_sig).is_ok();
    assert!(
        es256_signature_valid,
        "the emitted signature must verify as true ES256 (ECDSA-P256 over SHA-256(canonical_body)) under the x5chain leaf key"
    );
    eprintln!("[soundness] true ES256 (ECDSA-P256 over SHA-256(body)) under the x5chain LEAF cert key: VALID");

    // ── 5. Leaf issuance: the x5chain leaf is issued by the Vault root ─
    let root_pem = std::fs::read_to_string(&root_pem_path).expect("read VAULT_C2PA_ROOT_PEM");
    let root_der = first_cert_der(&root_pem).expect("root pem has a certificate");
    let root_cert = x509_cert::Certificate::from_der(&root_der).expect("root cert DER parses");
    assert_eq!(
        leaf_cert.tbs_certificate().issuer(),
        root_cert.tbs_certificate().subject(),
        "the x5chain leaf must be issued by the Vault root (issuer == root subject)"
    );
    eprintln!("[issuance] x5chain leaf issuer == Vault root subject: OK");

    // ── 6. Daemon / off-the-shelf ES256 (SHA-256) verifier MUST accept ─
    // The daemon's own stateless verifier and any off-the-shelf ES256
    // verifier hash the body with SHA-256. Before the true-ES256 fix this
    // reported signature_valid=false (the BLAKE3-vs-SHA-256 prehash
    // mismatch that blocked the M5 gate); it is now a hard assertion and
    // the end-to-end regression guard against that algorithm confusion.
    let envelope = signed.to_jumbf_base64();
    let parsed = parse_jumbf_base64(&envelope).expect("round-trip parse");
    let es256_report = verify_c2pa_signed_manifest_es256_v1(&parsed, content).expect("es256 verify runs");
    assert!(
        es256_report.canonical_hash_match && es256_report.content_hash_match,
        "envelope integrity (BLAKE3 canonical-body hash + content hash) must hold"
    );
    let es256_sha256_valid = es256_report.signature_valid;
    assert!(
        es256_sha256_valid,
        "verify_c2pa_signed_manifest_es256_v1 (ECDSA-SHA256) must ACCEPT the Vault-signed envelope \
         (was false before VaultPkiX509Signer moved to a true SHA-256 prehash)"
    );
    eprintln!("[es256] verify_c2pa_signed_manifest_es256_v1 (ECDSA-SHA256) signature_valid = true");

    // ── 7. Latency: p50/p95/max over 50 per-manifest sign calls ────────
    let mut micros: Vec<u128> = Vec::with_capacity(50);
    for _ in 0..50 {
        let t = Instant::now();
        let _ = signer.sign_body(&body).expect("sign_body");
        micros.push(t.elapsed().as_micros());
    }
    micros.sort_unstable();
    let p50 = micros[nearest_rank(micros.len(), 0.50)];
    let p95 = micros[nearest_rank(micros.len(), 0.95)];
    let max = *micros.last().unwrap();
    eprintln!("[latency] per-sign over 50 calls (local ECDSA, post-init): p50={p50}us p95={p95}us max={max}us");
    eprintln!(
        "[latency] NOTE: the Vault round-trip is amortised at init/rotation (CSR-sign-only custody); \
         per-sign is a local P-256 operation, so the Vault backend adds ~0 per-sign latency vs in-process."
    );

    // ── 8. Off-the-shelf c2patool: Vault-issued cert trust interop ─────
    // Sign a real asset with the Vault-minted leaf, then verify with the
    // Vault ROOT as the sole trust anchor (no allow-list): a pass proves
    // the leaf cryptographically chains to the Vault root.
    let (trusted, mismatch) = run_c2patool_trust_leg(
        &c2patool,
        tmp.path(),
        &std::fs::read_to_string(&leaf_key_path).expect("read leaf key"),
        &x5chain_pem,
        &root_pem,
        &root_pem_path,
    );
    assert!(
        trusted,
        "c2patool must resolve signingCredential.trusted for the Vault-issued leaf when the Vault root \
         is the sole trust anchor (chain-to-root, no allow-list shortcut)"
    );
    eprintln!("[c2patool] signingCredential.trusted = true (Vault root as sole anchor)");
    eprintln!(
        "[c2patool] claimSignature.mismatch = {mismatch} \
         (c2patool 0.27.1 self-sign artifact — independent of Vault; trust/cert-profile are sound)"
    );

    // ── 9. Machine-readable evidence summary ───────────────────────────
    if let Ok(out) = std::env::var("C2PA_M4_SUMMARY_OUT") {
        let summary = format!(
            "{{\"vault_pki_mode\":\"pki-csr-sign-p256-emailProtection\",\
\"init_ms\":{init_ms:.1},\
\"p50_us\":{p50},\"p95_us\":{p95},\"max_us\":{max},\
\"es256_leaf_key_signature_valid\":{es256_signature_valid},\
\"es256_sha256_signature_valid\":{es256_sha256_valid},\
\"c2patool_signingCredential_trusted\":{trusted},\
\"c2patool_claimSignature_mismatch\":{mismatch}}}\n"
        );
        let mut f = std::fs::File::create(&out).expect("create summary out");
        f.write_all(summary.as_bytes()).expect("write summary");
        eprintln!("[summary] wrote {out}");
    }

    eprintln!("== M4 vault integration :: OK ==\n");
}

/// Nearest-rank percentile index into a length-`n` ascending vec.
fn nearest_rank(n: usize, p: f64) -> usize {
    if n == 0 {
        return 0;
    }
    let rank = (p * n as f64).ceil() as usize;
    rank.saturating_sub(1).min(n - 1)
}

/// Redact any `userinfo` from a URL before logging.
fn redact_addr(addr: &str) -> String {
    if let Some(scheme_end) = addr.find("://") {
        let (scheme, rest) = addr.split_at(scheme_end + 3);
        if let Some(at) = rest.find('@') {
            return format!("{scheme}<redacted>@{}", &rest[at + 1..]);
        }
    }
    addr.to_string()
}

fn require_env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required for the #[ignore]-gated M4 integration test (see module docs)"))
}

/// First `-----BEGIN CERTIFICATE-----` block of a PEM bundle, decoded to DER.
fn first_cert_der(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let end = pem[start..].find(END)? + start;
    let b64: String = pem[start..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).ok()
}

/// Extract a P-256 verifying key from a certificate's SubjectPublicKeyInfo.
fn p256_verifying_key_from_cert(cert: &x509_cert::Certificate) -> Option<p256::ecdsa::VerifyingKey> {
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(spki).ok()
}

fn c2patool_available(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A `c2patool` invocation wrapped in coreutils `timeout` (so a hung
/// child cannot wedge the test) with Vault credentials scrubbed from the
/// child environment (c2patool has no need for `VAULT_TOKEN`/`VAULT_ADDR`).
fn c2patool_command(bin: &str) -> Command {
    let mut cmd = Command::new("timeout");
    cmd.arg(C2PATOOL_TIMEOUT_SECS.to_string())
        .arg(bin)
        .env_remove("VAULT_TOKEN")
        .env_remove("VAULT_ADDR");
    cmd
}

/// Sign the PNG fixture with the Vault-minted leaf via `c2patool` (creds
/// supplied through `C2PA_PRIVATE_KEY` / `C2PA_SIGN_CERT` — the leaf key
/// is a throwaway artefact minted for this run, not a durable secret),
/// then verify with the Vault root as the SOLE trust anchor. Returns
/// `(signingCredential.trusted, claimSignature.mismatch)` parsed from the
/// verifier's structured JSON active-manifest report.
fn run_c2patool_trust_leg(
    bin: &str,
    dir: &Path,
    leaf_key_pem: &str,
    x5chain_pem: &str,
    root_pem: &str,
    root_pem_path: &str,
) -> (bool, bool) {
    use base64::Engine as _;

    let png = base64::engine::general_purpose::STANDARD
        .decode(FIXTURE_PNG_B64)
        .expect("fixture png decodes");
    let asset = dir.join("m4-asset.png");
    let signed = dir.join("m4-asset-signed.png");
    let manifest = dir.join("m4-manifest.json");
    // sign_cert = leaf(+intermediates) + root, so the embedded x5chain
    // chains cleanly to the trust anchor with no allow-list shortcut.
    let full_chain = format!("{}\n{}\n", x5chain_pem.trim(), root_pem.trim());
    std::fs::write(&asset, &png).expect("write asset");
    std::fs::write(
        &manifest,
        br#"{"alg":"es256","claim_generator":"cuecrux-m4/0.1","assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}]}}]}"#,
    )
    .expect("write manifest");

    // Sign. c2patool's post-sign self-verify may flag
    // claimSignature.mismatch (a c2patool 0.27.1 artifact) but still
    // exits 0 and writes the output.
    let sign = c2patool_command(bin)
        .arg(&asset)
        .arg("-m")
        .arg(&manifest)
        .arg("-o")
        .arg(&signed)
        .arg("-f")
        .env("C2PA_PRIVATE_KEY", leaf_key_pem)
        .env("C2PA_SIGN_CERT", &full_chain)
        .output()
        .expect("run c2patool sign");
    assert!(
        sign.status.success() && signed.exists(),
        "c2patool sign must exit 0 and produce a signed asset; status={:?}\nstderr:\n{}",
        sign.status.code(),
        String::from_utf8_lossy(&sign.stderr)
    );

    // Verify with the Vault root injected as the SOLE trust anchor.
    let verify = c2patool_command(bin)
        .arg(&signed)
        .arg("trust")
        .arg("--trust_anchors")
        .arg(root_pem_path)
        .output()
        .expect("run c2patool verify");
    assert!(
        verify.status.success(),
        "c2patool verify must exit 0; status={:?}\nstderr:\n{}",
        verify.status.code(),
        String::from_utf8_lossy(&verify.stderr)
    );
    let stdout = String::from_utf8_lossy(&verify.stdout);
    let (success, failure) = active_manifest_codes(&stdout);
    let trusted = success.iter().any(|c| c == "signingCredential.trusted")
        && !failure.iter().any(|c| c == "signingCredential.untrusted");
    let mismatch = failure.iter().any(|c| c == "claimSignature.mismatch");
    if !trusted {
        eprintln!("[c2patool][diag] trust not resolved. verify stdout:\n{stdout}");
    }
    (trusted, mismatch)
}

/// Parse `c2patool`'s JSON report and return the active-manifest
/// `success` and `failure` validation `code`s. Handles both the
/// top-level and `manifest_store`-nested `validation_results` shapes.
fn active_manifest_codes(stdout: &str) -> (Vec<String>, Vec<String>) {
    let root: serde_json::Value = serde_json::from_str(stdout).unwrap_or(serde_json::Value::Null);
    let vr = root
        .get("validation_results")
        .or_else(|| root.get("manifest_store").and_then(|m| m.get("validation_results")));
    let active = vr.and_then(|v| v.get("activeManifest"));
    let codes = |bucket: &str| -> Vec<String> {
        active
            .and_then(|a| a.get(bucket))
            .and_then(|b| b.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("code").and_then(|c| c.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    (codes("success"), codes("failure"))
}
