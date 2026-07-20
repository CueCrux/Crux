// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::fmt;

/// Native-only bearer material.
///
/// Construction mirrors `corecruxd`'s static agent-token policy. Memory owned
/// by this value is overwritten on drop; the type deliberately is not `Clone`.
pub struct SecretToken(Vec<u8>);

impl SecretToken {
    /// Validate and take ownership of static agent-token bytes.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, String> {
        if !(32..=256).contains(&bytes.len()) {
            return reject_and_zero(&mut bytes, "agent token must contain 32 to 256 bytes");
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
        {
            return reject_and_zero(
                &mut bytes,
                "agent token contains a character outside the daemon token alphabet",
            );
        }
        Ok(Self(bytes))
    }

    /// Expose bytes to native broker code. Never serialize or log this slice.
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn reject_and_zero(bytes: &mut [u8], message: &'static str) -> Result<SecretToken, String> {
    bytes.fill(0);
    Err(message.to_string())
}

impl Drop for SecretToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretToken([REDACTED])")
    }
}

impl fmt::Display for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::{reject_and_zero, SecretToken};

    #[test]
    fn enforces_daemon_alphabet_and_redacts_formatting() {
        let token = SecretToken::from_bytes(b"aA09._~-aA09._~-aA09._~-aA09._~-".to_vec()).unwrap();
        assert_eq!(format!("{token}"), "[REDACTED]");
        assert_eq!(format!("{token:?}"), "SecretToken([REDACTED])");
        assert!(SecretToken::from_bytes(vec![b'a'; 31]).is_err());
        assert!(SecretToken::from_bytes(vec![b'a'; 257]).is_err());
        assert!(SecretToken::from_bytes(vec![b'!'; 32]).is_err());
    }

    #[test]
    fn validation_failure_zeroes_owned_material() {
        let mut invalid = vec![b'!'; 32];
        assert!(reject_and_zero(&mut invalid, "invalid token").is_err());
        assert!(invalid.iter().all(|byte| *byte == 0));
    }
}
