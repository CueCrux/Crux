// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Test-only helpers for this crate.
//!
//! `EnvVarGuard` is a copy of the daemon's helper of the same name rather than a
//! shared dependency: it is ~30 lines, and a cross-crate test-utility dep to pull
//! it in would outweigh the duplication.
//!
//! It restores the previous value on drop, so a test cannot leak an override into
//! its neighbours. That is *not* a race guard — `set_var`/`remove_var` mutate the
//! process-wide environment, which is shared with every other test thread in this
//! binary. Prefer a parameter over an env override in new tests; when a test must
//! set one, keep the guard's lifetime as short as possible.

use std::ffi::OsString;

pub(crate) struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    pub(crate) fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }

    pub(crate) fn unset(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = self.previous.take() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}
