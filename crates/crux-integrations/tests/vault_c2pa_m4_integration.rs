// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M4 integration: Vault-PKI-signed C2PA manifest must verify under the
//! daemon's off-the-shelf ES256 verifier (`verify_c2pa_signed_manifest_es256_v1`).
//!
//! This is the end-to-end regression guard for the algorithm-confusion bug:
//! `VaultPkiX509Signer::sign_body` previously signed a **BLAKE3** prehash while
//! labelling the COSE envelope `es256`, so the daemon provenance verifier
//! (ECDSA-over-SHA-256) reported `signature_valid=false`. After the fix the
//! signer performs true ES256 (SHA-256 prehash) and the SAME verifier ACCEPTS.
//!
//! `#[ignore]` because it needs a live `hashicorp/vault` dev server with a
//! `pki-c2pa` mount and a `c2pa-leaf` role. Provision it, then run:
//!
//! ```sh
//! docker run -d --name vault-dev --cap-add=IPC_LOCK \
//!   -e VAULT_DEV_ROOT_TOKEN_ID=root-test-token -p 18201:8200 \
//!   hashicorp/vault:latest server -dev -dev-listen-address=0.0.0.0:8200
//! # enable pki-c2pa, generate an EC P-256 root, create the c2pa-leaf role
//! # (allow_any_name, use_csr_common_name, key_type=ec key_bits=256) ...
//! VAULT_ADDR=http://127.0.0.1:18201 VAULT_TOKEN=root-test-token \
//!   cargo test -p crux-integrations --test vault_c2pa_m4_integration -- --ignored --nocapture
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use corecrux_receipts::vault_pki_x509_signer::{Config, VaultPkiX509Signer};
use corecrux_receipts::{
    build_c2pa_manifest_v1, parse_jumbf_base64, sign_c2pa_manifest_via_signer, verify_c2pa_signed_manifest_es256_v1,
    C2paManifestInputV1,
};

/// The daemon provenance path calls `verify_c2pa_signed_manifest_es256_v1`
/// on every `es256` envelope. A Vault-signed manifest must clear it.
#[test]
#[ignore = "requires a live hashicorp/vault dev server with a pki-c2pa mount + c2pa-leaf role"]
fn vault_signed_manifest_verifies_under_daemon_es256_verifier() {
    let Some((vault_addr, vault_token)) = vault_env() else {
        eprintln!("SKIP: VAULT_ADDR / VAULT_TOKEN not set — provision vault dev first");
        return;
    };
    let pki_mount = std::env::var("CORECRUXD_VAULT_PKI_MOUNT").unwrap_or_else(|_| "pki-c2pa".to_string());

    let tmp = tempfile::tempdir().unwrap();
    let config = Config {
        vault_addr,
        vault_token,
        vault_cacert_path: None,
        pki_mount,
        leaf_key_path: tmp.path().join("c2pa-leaf.key.pem"),
        leaf_cert_path: tmp.path().join("c2pa-leaf.cert.pem"),
        root_anchor_path: tmp.path().join("c2pa-root.cert.pem"),
        leaf_ttl_hours: 720,
        leaf_common_name: "cuecrux daemon C2PA signer".to_string(),
    };

    // Real HTTP path: `new` wires the default `ureq_post_csr` hook, so this
    // mints a genuine leaf from the running Vault PKI (no mocks).
    let signer = VaultPkiX509Signer::new(config);
    signer
        .regenerate_leaf()
        .expect("Vault PKI must issue a c2pa-leaf certificate");

    let content = b"vault-pki-m4-true-es256-content";
    let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
        content_bytes: content,
        content_type: Some("image/png"),
        crown_receipt_id: "r_m4_vault",
        signer_passport: "passport:m4-vault",
        claim_generator: "cuecrux/m4-integration",
        manifest_id: "urn:cuecrux:c2pa:m4-vault",
        when: "2026-05-29T00:00:00Z",
        model: None,
    });

    let signed = sign_c2pa_manifest_via_signer(manifest, &signer, "2026-05-29T00:00:00Z")
        .expect("signing the manifest through the Vault signer must succeed");
    assert_eq!(signed.signature_alg, "es256", "envelope must advertise es256");
    assert!(signed.key_id.starts_with("x509-sha256:"), "X.509 key id convention");

    // Round-trip through the wire encoding, exactly as the daemon receives it.
    let parsed = parse_jumbf_base64(&signed.to_jumbf_base64()).expect("envelope must parse");

    // THE assertion: the daemon-path ES256 verifier accepts a Vault-signed
    // manifest. Before the fix this was `signature_valid == false`.
    let report = verify_c2pa_signed_manifest_es256_v1(&parsed, content).expect("es256 verification must not error");
    assert!(
        report.signature_valid,
        "daemon ES256 verifier must ACCEPT the Vault-signed manifest (was false before the SHA-256 fix)"
    );
    assert!(report.canonical_hash_match, "envelope integrity (BLAKE3) must hold");
    assert!(report.content_hash_match, "content binding must hold");
    assert!(report.ok, "overall verification must pass");

    // Opt-in artefact dump for an INDEPENDENT off-the-shelf ES256 check, e.g.
    //   openssl x509 -in leaf.pem -pubkey -noout > pub.pem
    //   openssl dgst -sha256 -verify pub.pem -signature signature.der canonical_body.bin
    // "Verified OK" proves the signature is genuine ECDSA-P256-SHA256 (true ES256)
    // per a third-party verifier, not just our own code.
    if let Ok(dir) = std::env::var("CRUX_C2PA_DUMP_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("leaf.pem"), parsed.x5chain_pem.as_deref().unwrap_or("")).unwrap();
        std::fs::write(dir.join("canonical_body.bin"), &parsed.canonical_body_bytes).unwrap();
        std::fs::write(dir.join("signature.der"), &parsed.signature).unwrap();
        eprintln!(
            "DUMP: wrote leaf.pem / canonical_body.bin / signature.der to {}",
            dir.display()
        );
    }

    eprintln!("OK: Vault-signed es256 manifest verified — signature_valid=true, ok=true");
}

fn vault_env() -> Option<(String, String)> {
    let addr = std::env::var("VAULT_ADDR").ok().filter(|v| !v.trim().is_empty())?;
    let token = std::env::var("VAULT_TOKEN").ok().filter(|v| !v.trim().is_empty())?;
    Some((addr, token))
}
