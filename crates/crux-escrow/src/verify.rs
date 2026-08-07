// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Proving the negative: that what the server holds cannot open a customer's vault.
//!
//! This is the machine-checkable half of the published verification story
//! (ExecPlan `crux-key-escrow-and-recovery-2026-07-31`, M5). `corecruxctl
//! verify-escrow` runs it against a live daemon, `scripts/verify-escrow.py`
//! mirrors it in a form a sceptic can read in a minute, and the crate's own
//! tests run it in CI so the claim cannot rot.
//!
//! The interesting check is not "a random key fails" — of course it does. It is
//! [`server_holdings_cannot_open`]: derive a wrapping key from **every field the
//! server actually stores**, and show that none of them opens the blob. That is
//! the published claim, tested rather than asserted.

use crate::{unwrap_dek_with_key, RecoveryCode, WrappedDek, WrappingKey, KDF_CONTEXT};

/// One named check and how it came out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable identifier — the same string appears in the CLI, the Python
    /// script and the published document, so results can be compared.
    pub name: &'static str,
    /// Whether the property held.
    pub passed: bool,
    /// What was actually tried, in the customer's terms.
    pub detail: String,
}

impl Check {
    fn new(name: &'static str, passed: bool, detail: impl Into<String>) -> Self {
        Self {
            name,
            passed,
            detail: detail.into(),
        }
    }
}

/// Every candidate wrapping key derivable from the server's own holdings.
///
/// The KDF is public (`blake3::derive_key` under a published context string), so
/// anyone can reproduce this list. If the server held any input to the real key,
/// one of these — or an obvious variation a reader can add — would open the blob.
fn server_derived_candidates(blob: &WrappedDek) -> Vec<(&'static str, WrappingKey)> {
    let mut out = Vec::new();
    let mut push = |label: &'static str, material: &[u8]| {
        out.push((label, WrappingKey(blake3::derive_key(KDF_CONTEXT, material))));
    };
    push("the vault id", blob.vault_id.as_bytes());
    push("the stored nonce", &blob.nonce);
    push("the stored ciphertext", &blob.ciphertext);
    push("the whole stored record", &{
        let mut all = blob.vault_id.as_bytes().to_vec();
        all.extend_from_slice(&blob.nonce);
        all.extend_from_slice(&blob.ciphertext);
        all
    });
    // A server that stored nothing at all still has the empty string and the
    // context constant; include them so "we tried the trivial keys" is on record.
    push("an empty secret", b"");
    push("the published KDF context itself", KDF_CONTEXT.as_bytes());
    out
}

/// Try to open `blob` with everything the server holds. Every attempt must fail.
///
/// Requires no secret from the customer, so it can be run by anyone, on any
/// stored blob, without typing a recovery code anywhere.
#[must_use]
pub fn server_holdings_cannot_open(blob: &WrappedDek) -> Vec<Check> {
    // Ordered to match `scripts/verify-escrow.py` exactly: the two outputs are
    // meant to be compared line for line, and a reader who has to reconcile two
    // orderings is a reader who stops checking.
    let mut checks = vec![Check::new(
        "stored_record_is_ciphertext_only",
        blob.ciphertext.len() == EXPECTED_CIPHERTEXT_LEN,
        format!(
            "the stored ciphertext is {} bytes: a 32-byte key under a 16-byte tag, \
             with no room for anything else",
            blob.ciphertext.len()
        ),
    )];
    checks.extend(server_derived_candidates(blob).into_iter().map(|(label, key)| {
        let opened = unwrap_dek_with_key(blob, &key).is_ok();
        Check::new(
            "server_holdings_cannot_open",
            !opened,
            format!("a key derived from {label} did not open the vault"),
        )
    }));
    // These negatives could pass vacuously on a blob nothing can open, including
    // its owner. The positive control is `opens_with_recovery_code`, which the
    // customer runs with their code.
    checks
}

/// A wrapped 32-byte DEK plus its Poly1305 tag. A longer blob would mean the
/// server is storing something beyond the sealed key.
const EXPECTED_CIPHERTEXT_LEN: usize = 32 + 16;

/// Every field the server is allowed to be holding.
pub const ALLOWED_FIELDS: [&str; 3] = ["ciphertext", "nonce", "vault_id"];

/// The one check the typed API cannot make for itself: that the server is not
/// storing a *fourth* field.
///
/// Takes the record as raw JSON on purpose. Deserialising into [`WrappedDek`]
/// silently drops unknown fields, so a typed parse would report a clean record
/// no matter what else the server had decided to keep alongside it.
#[must_use]
pub fn stored_record_has_no_extra_fields(raw: &serde_json::Value) -> Check {
    const NAME: &str = "stored_record_has_no_extra_fields";
    let Some(object) = raw.as_object() else {
        return Check::new(NAME, false, "the record is not a JSON object");
    };
    let mut fields: Vec<&str> = object.keys().map(String::as_str).collect();
    fields.sort_unstable();
    let unexpected: Vec<&str> = fields
        .iter()
        .copied()
        .filter(|field| !ALLOWED_FIELDS.contains(field))
        .collect();
    if unexpected.is_empty() {
        Check::new(
            NAME,
            true,
            format!("the server stores exactly {}, and nothing else", fields.join(", ")),
        )
    } else {
        Check::new(
            NAME,
            false,
            format!(
                "the server is storing {} beyond the wrapped key — re-read the threat model before trusting this vault",
                unexpected.join(", ")
            ),
        )
    }
}

/// The positive control: the customer's own code *does* open it.
///
/// Without this, "nothing opens the vault" is also true of a server that stored
/// garbage. Running it requires the recovery code, so it is opt-in — and the
/// code never leaves the machine the check runs on.
#[must_use]
pub fn opens_with_recovery_code(blob: &WrappedDek, code: &RecoveryCode) -> Check {
    Check::new(
        "opens_with_your_recovery_code",
        crate::unwrap_dek(blob, code).is_ok(),
        "your recovery code opened the vault, so the stored blob is the real one and not a decoy",
    )
}

/// The full no-secret check list, in the order every implementation reports it.
///
/// One definition, so the CLI, the Python reference and the published document
/// cannot each grow their own idea of what "verified" means.
///
/// # Errors
/// [`serde_json::Error`] if `raw` is not a wrapped-key record at all.
pub fn all_checks(raw: &serde_json::Value) -> Result<Vec<Check>, serde_json::Error> {
    let mut checks = vec![stored_record_has_no_extra_fields(raw)];
    let blob: WrappedDek = serde_json::from_value(raw.clone())?;
    checks.extend(server_holdings_cannot_open(&blob));
    Ok(checks)
}

/// Whether a set of checks is clean.
#[must_use]
pub fn all_passed(checks: &[Check]) -> bool {
    checks.iter().all(|check| check.passed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::VaultSetup;

    const DEK: [u8; 32] = [3u8; 32];
    const VAULT: &str = "vault-verify";

    #[test]
    fn the_server_cannot_open_what_it_stores() {
        let setup = VaultSetup::new(&DEK, VAULT).unwrap();
        let blob = setup.acknowledge();
        let checks = server_holdings_cannot_open(&blob);
        assert!(all_passed(&checks), "{checks:#?}");
        assert!(checks.len() >= 6, "the candidate list got shorter: {checks:#?}");
    }

    #[test]
    fn but_the_customer_can() {
        let setup = VaultSetup::new(&DEK, VAULT).unwrap();
        let code = setup.code().clone();
        let blob = setup.acknowledge();
        assert!(opens_with_recovery_code(&blob, &code).passed);
    }

    /// The negative checks must not pass vacuously. A blob nothing can open,
    /// including its owner, would satisfy `server_holdings_cannot_open` while
    /// being useless — which is why the positive control exists and why this
    /// test pins that the two disagree on a corrupt blob.
    #[test]
    fn a_corrupt_blob_fails_the_positive_control() {
        let setup = VaultSetup::new(&DEK, VAULT).unwrap();
        let code = setup.code().clone();
        let mut blob = setup.acknowledge();
        blob.ciphertext[0] ^= 0x01;

        assert!(all_passed(&server_holdings_cannot_open(&blob)));
        assert!(
            !opens_with_recovery_code(&blob, &code).passed,
            "a corrupt blob must fail the positive control"
        );
    }

    /// If the stored record ever grows past a sealed 32-byte key, the shape
    /// check fails — which is the signal that the server started keeping
    /// something the threat model says it does not.
    #[test]
    fn a_longer_stored_record_is_reported() {
        let setup = VaultSetup::new(&DEK, VAULT).unwrap();
        let mut blob = setup.acknowledge();
        blob.ciphertext.push(0);
        let checks = server_holdings_cannot_open(&blob);
        assert!(!all_passed(&checks));
        assert!(checks
            .iter()
            .any(|c| c.name == "stored_record_is_ciphertext_only" && !c.passed));
    }
}
