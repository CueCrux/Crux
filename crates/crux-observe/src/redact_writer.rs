// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sink-boundary redaction for formatted log output.
//!
//! [`RedactMakeWriter`] wraps any `tracing_subscriber` `MakeWriter` (stdout,
//! stderr, test buffers) and scrubs each formatted event through
//! [`Redactor::redact_line`] before it reaches the underlying sink. Because
//! the scrub happens on the final formatted bytes, one implementation covers
//! both the human-readable fmt layer and the JSON layer.
//!
//! Note on architecture (plan deviation, recorded in the ExecPlan decision
//! log): `tracing` events are immutable — a `Layer` cannot rewrite the field
//! values that sibling layers (fmt/JSON/OTLP) will see. Sink-boundary
//! scrubbing here + visitor-level redaction inside `OpsObserveLayer` (M3)
//! provide the same guarantee the planned "RedactLayer" was after, asserted
//! per-sink by the leak-canary tests.

use std::io;
use std::sync::Arc;

use tracing_subscriber::fmt::MakeWriter;

use crate::redact::{RedactMode, Redactor};

/// `MakeWriter` adapter that redacts each write through a shared [`Redactor`].
#[derive(Clone, Debug)]
pub struct RedactMakeWriter<M> {
    inner: M,
    redactor: Arc<Redactor>,
}

impl<M> RedactMakeWriter<M> {
    /// Wrap `inner` so every produced writer scrubs through `redactor`.
    pub fn new(inner: M, redactor: Arc<Redactor>) -> Self {
        Self { inner, redactor }
    }
}

impl<'a, M> MakeWriter<'a> for RedactMakeWriter<M>
where
    M: MakeWriter<'a>,
{
    type Writer = RedactWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactWriter {
            inner: self.inner.make_writer(),
            redactor: Arc::clone(&self.redactor),
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        RedactWriter {
            inner: self.inner.make_writer_for(meta),
            redactor: Arc::clone(&self.redactor),
        }
    }
}

/// Writer that applies line redaction to every buffer before forwarding.
#[derive(Debug)]
pub struct RedactWriter<W: io::Write> {
    inner: W,
    redactor: Arc<Redactor>,
}

impl<W: io::Write> io::Write for RedactWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.redactor.mode() == RedactMode::Off {
            return self.inner.write(buf);
        }
        // fmt layers format the whole event then issue a single write_all, so
        // `buf` is a complete formatted event (or line) in practice. Non-UTF8
        // buffers pass through untouched.
        let Ok(text) = std::str::from_utf8(buf) else {
            return self.inner.write(buf);
        };
        match self.redactor.redact_line(text) {
            std::borrow::Cow::Borrowed(_) => self.inner.write(buf),
            std::borrow::Cow::Owned(scrubbed) => {
                self.inner.write_all(scrubbed.as_bytes())?;
                // Report the caller's length as consumed — the logical event
                // was fully written even though byte counts differ.
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::RedactMode;
    use std::io::Write as _;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Buf {
        fn contents(&self) -> String {
            // SAFETY: test-only; poisoning implies a prior panic.
            #[allow(clippy::unwrap_used)]
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl io::Write for Buf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // SAFETY: test-only; poisoning implies a prior panic.
            #[allow(clippy::unwrap_used)]
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_scrubs_secret_line_in_on_mode() {
        let buf = Buf::default();
        let redactor = Arc::new(Redactor::with_mode(RedactMode::On));
        let mut w = RedactWriter {
            inner: buf.clone(),
            redactor,
        };
        let line: &[u8] = b"WARN upstream auth failed api_key=sk-fixtureSYNTHETIC0000000000 attempt=3\n";
        // SAFETY: test-only.
        #[allow(clippy::unwrap_used)]
        let n = w.write(line).unwrap();
        assert_eq!(n, line.len(), "must report caller's byte count as consumed");
        let out = buf.contents();
        assert!(!out.contains("sk-fixtureSYNTHETIC"), "got: {out}");
        assert!(out.contains("[REDACTED:fld.api_key#"), "got: {out}");
        assert!(out.contains("attempt=3"), "got: {out}");
    }

    #[test]
    fn writer_passthrough_in_audit_and_off_modes() {
        for mode in [RedactMode::Audit, RedactMode::Off] {
            let buf = Buf::default();
            let redactor = Arc::new(Redactor::with_mode(mode));
            let mut w = RedactWriter {
                inner: buf.clone(),
                redactor: Arc::clone(&redactor),
            };
            let line = b"WARN password=fixture-pw-SYNTHETIC\n";
            w.write_all(line).unwrap();
            assert_eq!(buf.contents().as_bytes(), line, "mode {mode:?} must not alter output");
            if mode == RedactMode::Audit {
                assert!(
                    redactor.counts().iter().any(|(k, _)| k == "fld.password"),
                    "audit mode must still count"
                );
            }
        }
    }

    #[test]
    fn writer_clean_line_unchanged() {
        let buf = Buf::default();
        let redactor = Arc::new(Redactor::with_mode(RedactMode::On));
        let mut w = RedactWriter {
            inner: buf.clone(),
            redactor,
        };
        let line = "INFO seal complete frames=4096 token_budget=500 tenant=lme-s\n";
        w.write_all(line.as_bytes()).unwrap();
        assert_eq!(buf.contents(), line);
    }

    #[test]
    fn writer_non_utf8_passthrough() {
        let buf = Buf::default();
        let redactor = Arc::new(Redactor::with_mode(RedactMode::On));
        let mut w = RedactWriter {
            inner: buf.clone(),
            redactor,
        };
        let bytes = [0xff, 0xfe, 0x00, 0x01];
        w.write_all(&bytes).unwrap();
        // SAFETY: test-only.
        #[allow(clippy::unwrap_used)]
        let stored = w.inner.0.lock().unwrap().clone();
        assert_eq!(stored, bytes);
    }
}
