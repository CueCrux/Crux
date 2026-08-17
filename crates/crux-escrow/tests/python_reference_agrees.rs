// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! The published verification story rests on two independent implementations
//! agreeing: `crux_escrow::verify` (and the `corecruxctl verify-escrow` that
//! wraps it) and `scripts/verify-escrow.py`, which a sceptic reads instead of
//! trusting our binary.
//!
//! Two implementations that silently drift apart are worse than one, so this
//! runs the Python script on the same record the Rust checks ran on and requires
//! the verdicts to match — including on a record deliberately made bad.
//!
//! A contributor without `pynacl` is not blocked: the cross-check skips with a
//! printed reason. CI sets `CRUX_REQUIRE_PYTHON_REFERENCE=1`, which turns that
//! skip into a failure — otherwise a runner that quietly lost the dependency
//! would leave the published claim unenforced while CI stayed green.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use crux_escrow::verify::{all_checks, all_passed, server_holdings_cannot_open, Check};
use crux_escrow::{VaultSetup, WrappedDek};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn script() -> PathBuf {
    repo_root().join("scripts/verify-escrow.py")
}

/// `None` when the script cannot run here (no python3, or missing deps).
fn python_deps_available() -> bool {
    Command::new("python3")
        .args([
            "-c",
            "import blake3; from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt",
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The same list the CLI reports, from the same record bytes the script sees.
fn rust_checks(record: &WrappedDek) -> Vec<Check> {
    all_checks(&serde_json::to_value(record).unwrap()).unwrap()
}

/// Run the reference script over a record on disk; returns (exit_ok, stdout).
fn run_python(record: &WrappedDek) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("crux-escrow-xcheck-{}", uuid_like()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("record.json");
    std::fs::write(&path, serde_json::to_vec(record).unwrap()).unwrap();

    let output = Command::new("python3")
        .arg(script())
        .arg("--record-file")
        .arg(&path)
        .output()
        .expect("run the reference script");
    let _ = std::fs::remove_dir_all(&dir);
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// The crate deliberately has no `rand`-based test id helper; this is enough to
/// keep concurrent test runs off each other's files.
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    format!("{nanos}-{:?}", std::thread::current().id())
}

#[test]
fn the_python_reference_agrees_with_the_rust_checks() {
    if !python_deps_available() {
        assert!(
            std::env::var("CRUX_REQUIRE_PYTHON_REFERENCE").as_deref() != Ok("1"),
            "CRUX_REQUIRE_PYTHON_REFERENCE=1 but the reference script cannot run here: \
             install its dependencies (`pip install pynacl blake3`) or the cross-check is \
             not actually being enforced"
        );
        eprintln!("SKIP: scripts/verify-escrow.py needs `pip install pynacl blake3`");
        return;
    }

    // A good record: both implementations must pass it.
    let setup = VaultSetup::new(&[9u8; 32], "vault-crosscheck").unwrap();
    let good = setup.acknowledge();
    let rust_good = all_passed(&rust_checks(&good));
    let (python_good, stdout) = run_python(&good);
    assert!(rust_good, "the Rust checks failed on a good record");
    assert_eq!(
        rust_good, python_good,
        "the two implementations disagree on a good record.\n{stdout}"
    );
    assert!(
        stdout.contains("All checks passed"),
        "unexpected reference output:\n{stdout}"
    );
    // Both must be checking the same number of things, or one is doing less
    // work while reporting the same verdict.
    assert_eq!(
        stdout.matches("PASS").count(),
        rust_checks(&good).len(),
        "the implementations ran a different number of checks:\n{stdout}"
    );

    // A record the server has quietly grown: both must fail it, or the check is
    // decorative.
    let setup = VaultSetup::new(&[9u8; 32], "vault-crosscheck").unwrap();
    let mut grown = setup.acknowledge();
    grown.ciphertext.push(0);
    let rust_grown = all_passed(&rust_checks(&grown));
    let (python_grown, stdout) = run_python(&grown);
    assert!(!rust_grown, "the Rust checks passed a record with an extra byte");
    assert_eq!(
        rust_grown, python_grown,
        "the two implementations disagree on a grown record.\n{stdout}"
    );
}

/// The two implementations share four constants by copy. A change to any of
/// them in Rust without the matching edit to the script would make the reference
/// silently wrong, and the cross-check above would still pass on a good record
/// if only the *labels* drifted.
#[test]
fn the_reference_script_pins_the_same_constants() {
    let source = std::fs::read_to_string(script()).expect("read the reference script");
    for needle in [
        "cuecrux crux-escrow 2026-08-01 recovery-code wrapping key v1",
        "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
        "EXPECTED_CIPHERTEXT_LEN = 32 + 16",
    ] {
        assert!(
            source.contains(needle),
            "scripts/verify-escrow.py no longer pins `{needle}` — the reference has drifted from the crate"
        );
    }
    // Every check name the Rust side emits must appear in the script, so the two
    // outputs stay comparable line for line.
    let setup = VaultSetup::new(&[1u8; 32], "vault-names").unwrap();
    for check in server_holdings_cannot_open(&setup.acknowledge()) {
        assert!(
            source.contains(check.name),
            "the reference script does not implement the `{}` check",
            check.name
        );
    }
}
