// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl verify-escrow` — prove, against a live daemon, that what the
//! server stores for a vault cannot open that vault.
//!
//! The published counterpart is `docs/verify-key-escrow.md` and the readable
//! reference implementation is `scripts/verify-escrow.py`. All three run the
//! same named checks (`crux_escrow::verify`) so their output can be compared
//! line for line — the point of a verification tool a customer does not have to
//! trust is that an independent implementation agrees with it.

use std::time::Duration;

use crux_escrow::verify::{all_checks, all_passed, opens_with_recovery_code, Check};
use crux_escrow::{RecoveryCode, WrappedDek};

pub struct VerifyEscrowOptions {
    /// Base URL of the daemon that holds the vault, e.g. `http://127.0.0.1:14800`.
    pub daemon: String,
    /// Vault to verify.
    pub vault_id: String,
    /// Bearer token with `admin:read`.
    pub token: Option<String>,
    /// Read a recovery code from stdin and additionally prove the blob opens
    /// for its owner. Off by default — the negative needs no secret at all.
    pub with_recovery_code: bool,
    /// Emit JSON instead of prose.
    pub json: bool,
}

#[derive(serde::Serialize)]
pub struct VerifyEscrowReport {
    pub daemon: String,
    pub vault_id: String,
    pub passed: bool,
    pub checks: Vec<ReportedCheck>,
}

#[derive(serde::Serialize)]
pub struct ReportedCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl From<Check> for ReportedCheck {
    fn from(check: Check) -> Self {
        Self {
            name: check.name.to_string(),
            passed: check.passed,
            detail: check.detail,
        }
    }
}

type Failure = Box<dyn std::error::Error + Send + Sync>;

/// Fetch the stored record exactly as the server returns it, so the field-set
/// check sees the wire bytes rather than something a typed parse has already
/// normalised away.
fn fetch_raw(options: &VerifyEscrowOptions) -> Result<serde_json::Value, Failure> {
    let url = format!(
        "{}/v1/escrow/vaults/{}",
        options.daemon.trim_end_matches('/'),
        urlencoding::encode(&options.vault_id)
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut req = agent.get(&url);
    if let Some(token) = &options.token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req.call()?;
    let status = resp.status().as_u16();
    let body = resp.into_body().read_to_string()?;
    if status >= 400 {
        return Err(format!("daemon returned {status} for {url}: {body}").into());
    }
    Ok(serde_json::from_str(&body)?)
}

/// Read a recovery code from stdin.
///
/// Deliberately never a command-line argument: argv is visible to every process
/// on the machine through `ps`, and shells record it in history. It is not sent
/// anywhere — the check that uses it runs entirely in this process.
fn read_recovery_code() -> Result<RecoveryCode, Failure> {
    eprintln!("Paste your recovery code, then press enter.");
    eprintln!("It is used only in this process, on this machine, and is never sent anywhere.");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    RecoveryCode::parse(line.trim()).map_err(|err| format!("that is not a valid recovery code: {err}").into())
}

/// Run every check against a live daemon.
///
/// # Errors
/// If the daemon cannot be reached, returns a non-2xx, or returns a record that
/// is not a wrapped key at all.
pub fn verify_escrow(options: &VerifyEscrowOptions) -> Result<VerifyEscrowReport, Failure> {
    let raw = fetch_raw(options)?;
    let mut checks = all_checks(&raw).map_err(|err| format!("the daemon's record is not a wrapped key: {err}"))?;

    if options.with_recovery_code {
        let blob: WrappedDek = serde_json::from_value(raw)?;
        checks.push(opens_with_recovery_code(&blob, &read_recovery_code()?));
    }

    let passed = all_passed(&checks);
    Ok(VerifyEscrowReport {
        daemon: options.daemon.clone(),
        vault_id: options.vault_id.clone(),
        passed,
        checks: checks.into_iter().map(ReportedCheck::from).collect(),
    })
}

/// Print a report for a human. Returns the process exit code: non-zero if any
/// check failed, so this is usable as a CI or cron gate without parsing.
#[must_use]
pub fn render(report: &VerifyEscrowReport, json: bool) -> i32 {
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(text) => println!("{text}"),
            Err(err) => eprintln!("could not render report: {err}"),
        }
    } else {
        println!("vault {} on {}", report.vault_id, report.daemon);
        for check in &report.checks {
            println!("  {} {}", if check.passed { "PASS" } else { "FAIL" }, check.detail);
        }
        println!();
        if report.passed {
            println!("All checks passed: the server holds ciphertext and nothing that opens it.");
        } else {
            println!("At least one check FAILED. Do not trust this vault until it is explained.");
        }
    }
    i32::from(!report.passed)
}
