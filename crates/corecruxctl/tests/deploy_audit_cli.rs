// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_corecruxctl"));
    for key in [
        "CORECRUXD_AUTH_MODE",
        "CORECRUXD_HTTP_HOST",
        "CORECRUXD_GRPC_HOST",
        "CORECRUXD_CONFIG_PATH",
        "CORECRUXD_ENTERPRISE_ENABLED",
        "CORECRUXD_OPERATING_MODE",
        "CRUX_OPERATING_MODE",
        "XDG_CONFIG_HOME",
    ] {
        command.env_remove(key);
    }
    command
        .arg("deploy-audit")
        .args(args)
        .output()
        .expect("run corecruxctl deploy-audit")
}

#[test]
fn loopback_dev_scopes_passes() {
    let output = run(&[
        "--auth-mode",
        "dev_scopes",
        "--http-bind",
        "127.0.0.1",
        "--grpc-bind",
        "::1",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS: deploy auth audit"));
    assert!(stdout.contains("exposure: local_only"));
}

#[test]
fn networked_dev_scopes_and_unset_auth_fail() {
    for auth_args in [vec!["--auth-mode", "dev_scopes"], Vec::new()] {
        let mut args = auth_args;
        args.extend(["--http-bind", "0.0.0.0", "--grpc-bind", "::1"]);
        let output = run(&args);
        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("FAIL: deploy auth audit"));
        assert!(stdout.contains("must use jwt_hs256 or jwt_jwks"));
    }
}

#[test]
fn both_jwt_modes_pass_on_network() {
    for auth_mode in ["jwt_hs256", "jwt_jwks"] {
        let output = run(&[
            "--auth-mode",
            auth_mode,
            "--http-bind",
            "0.0.0.0",
            "--grpc-bind",
            "::",
            "--json",
        ]);
        assert!(output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON report");
        assert_eq!(report["verdict"], "pass");
        assert_eq!(report["exposure"], "network_exposed");
        assert_eq!(report["auth_mode"]["value"], auth_mode);
    }
}

#[test]
fn explicit_proxy_exposure_rejects_loopback_dev_scopes() {
    let output = run(&[
        "--auth-mode",
        "dev_scopes",
        "--http-bind",
        "127.0.0.1",
        "--grpc-bind",
        "::1",
        "--network-exposed",
    ]);
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("exposure reason: --network-exposed"));
}
