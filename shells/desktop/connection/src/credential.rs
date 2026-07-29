// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Native OS credential-store adapter.
//!
//! Fixed platform clients are invoked without a shell. No environment or
//! plaintext-file fallback exists, stderr is discarded, and all public errors
//! are static and sanitized.

use std::fmt;
use std::io::{Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::SecretToken;

#[cfg(target_os = "linux")]
const CREDENTIAL_SERVICE: &str = "com.cuecrux.crux";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
// Daemon tokens are at most 256 bytes; permit only a platform client's CRLF
// terminator beyond that limit while reading its bounded output.
const MAX_CAPTURE_BYTES: usize = 258;

/// Loads attach-profile bearer material from the platform credential store.
#[derive(Debug, Clone, Copy)]
pub struct NativeCredentialBroker {
    timeout: Duration,
}

struct CredentialInvocation {
    command: Command,
    stdin: Option<Vec<u8>>,
}

impl NativeCredentialBroker {
    /// Construct a broker with a bounded subprocess deadline.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout: timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT),
        }
    }

    /// Retrieve `token_ref` from the OS credential store.
    pub fn load(&self, token_ref: &str) -> Result<SecretToken, NativeCredentialError> {
        validate_token_ref(token_ref)?;
        let mut invocation = credential_command(token_ref)?;
        invocation
            .command
            .stdin(if invocation.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = invocation
            .command
            .spawn()
            .map_err(|_| NativeCredentialError::sanitized("the native credential client is unavailable"))?;
        if let Some(mut input) = invocation.stdin {
            input.push(b'\n');
            let written = child
                .stdin
                .take()
                .is_some_and(|mut stdin| stdin.write_all(&input).is_ok());
            input.fill(0);
            if !written {
                terminate(&mut child);
                return Err(NativeCredentialError::sanitized(
                    "the native credential client could not receive the lookup reference",
                ));
            }
        }
        let status = wait_bounded(&mut child, self.timeout)?;
        if !status.success() {
            return Err(NativeCredentialError::sanitized(
                "the credential is missing, locked, or unavailable",
            ));
        }

        let Some(stdout) = child.stdout.take() else {
            return Err(NativeCredentialError::sanitized(
                "the native credential client returned no secret",
            ));
        };
        let mut bytes = Vec::new();
        if stdout
            .take((MAX_CAPTURE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .is_err()
        {
            bytes.fill(0);
            return Err(NativeCredentialError::sanitized(
                "the native credential client returned an unreadable secret",
            ));
        }
        secret_from_output(bytes)
    }
}

impl Default for NativeCredentialBroker {
    fn default() -> Self {
        Self::new(DEFAULT_TIMEOUT)
    }
}

/// Credential failure safe to render in native UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCredentialError {
    message: &'static str,
}

impl NativeCredentialError {
    const fn sanitized(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn reason(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for NativeCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for NativeCredentialError {}

fn validate_token_ref(token_ref: &str) -> Result<(), NativeCredentialError> {
    if token_ref.is_empty()
        || token_ref.len() > 256
        || !token_ref
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-' | b':'))
    {
        return Err(NativeCredentialError::sanitized("the credential reference is invalid"));
    }
    Ok(())
}

fn secret_from_output(mut bytes: Vec<u8>) -> Result<SecretToken, NativeCredentialError> {
    if bytes.len() > MAX_CAPTURE_BYTES {
        bytes.fill(0);
        return Err(NativeCredentialError::sanitized(
            "the native credential client returned an invalid secret",
        ));
    }
    while bytes.last().is_some_and(|byte| matches!(*byte, b'\r' | b'\n')) {
        let _ = bytes.pop();
    }
    if bytes.len() > 256 {
        bytes.fill(0);
        return Err(NativeCredentialError::sanitized(
            "the native credential client returned an invalid secret",
        ));
    }
    SecretToken::from_bytes(bytes)
        .map_err(|_| NativeCredentialError::sanitized("the native credential client returned an invalid secret"))
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<ExitStatus, NativeCredentialError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                terminate(child);
                return Err(NativeCredentialError::sanitized(
                    "the native credential store timed out",
                ));
            }
            Err(_) => {
                terminate(child);
                return Err(NativeCredentialError::sanitized(
                    "the native credential store is unavailable",
                ));
            }
        }
    }
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn credential_command(token_ref: &str) -> Result<CredentialInvocation, NativeCredentialError> {
    let mut command = Command::new("/usr/bin/secret-tool");
    command
        .arg("lookup")
        .arg("--")
        .arg("service")
        .arg(CREDENTIAL_SERVICE)
        .arg("token-ref")
        .arg(token_ref);
    Ok(CredentialInvocation { command, stdin: None })
}

#[cfg(target_os = "windows")]
fn credential_command(token_ref: &str) -> Result<CredentialInvocation, NativeCredentialError> {
    const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    const LOOKUP_SCRIPT: &str = concat!(
        "$ErrorActionPreference='Stop';",
        "$null=[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];",
        "$ref=[Console]::In.ReadLine();",
        "if([string]::IsNullOrEmpty($ref)){throw 'missing credential reference'};",
        "$vault=New-Object Windows.Security.Credentials.PasswordVault;",
        "$credential=$vault.Retrieve('com.cuecrux.crux',$ref);",
        "$credential.RetrievePassword();",
        "$bytes=[System.Text.Encoding]::UTF8.GetBytes($credential.Password);",
        "$stdout=[Console]::OpenStandardOutput();",
        "$stdout.Write($bytes,0,$bytes.Length);",
        "$stdout.Flush();"
    );

    let mut command = Command::new(POWERSHELL);
    command
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(LOOKUP_SCRIPT);
    // The validated lookup reference is not a credential. Supplying it over a
    // dedicated pipe keeps the fixed script independent of PowerShell's
    // `-Command` argument reconstruction and never creates a token fallback.
    Ok(CredentialInvocation {
        command,
        stdin: Some(token_ref.as_bytes().to_vec()),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn credential_command(_token_ref: &str) -> Result<CredentialInvocation, NativeCredentialError> {
    Err(NativeCredentialError::sanitized(
        "the operating system credential store is unsupported",
    ))
}

#[cfg(test)]
mod tests {
    use super::{secret_from_output, validate_token_ref, NativeCredentialBroker};

    #[test]
    fn invalid_reference_fails_before_native_lookup() {
        let broker = NativeCredentialBroker::default();
        for reference in ["", "bad\nreference", "bad reference", "bad;reference"] {
            let error = broker.load(reference).unwrap_err();
            assert_eq!(error.reason(), "the credential reference is invalid");
        }
        assert!(validate_token_ref(&"x".repeat(257)).is_err());
    }

    #[test]
    fn captured_secret_is_strictly_bounded_and_trims_only_crlf() {
        let valid = [b"0123456789abcdef0123456789abcdef".as_slice(), b"\r\n"].concat();
        assert!(secret_from_output(valid).is_ok());
        assert!(secret_from_output(vec![b'a'; 259]).is_err());
        assert!(secret_from_output(vec![b' '; 32]).is_err());
    }
}
