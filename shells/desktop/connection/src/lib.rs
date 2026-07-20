// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

//! Connection primitives for the Crux desktop shell.
//!
//! Secrets enter through [`SecretToken`] and are only exposed to the native
//! upstream adapter. The loopback proxy overwrites browser credentials with
//! that bearer, removes cookie and redirect channels, and never exposes a
//! reflected bearer in response bytes.

mod backoff;
mod credential;
mod health;
mod json;
mod local_file;
mod local_plan;
mod navigation;
mod profile;
mod proxy;
mod secret;
mod transport;

pub use backoff::Backoff;
pub use credential::{NativeCredentialBroker, NativeCredentialError};
pub use health::{probe_health, HealthReport, HealthState, RuntimeCapabilitiesSummary};
pub use local_file::authorize_local_plan_path;
pub use local_plan::{compute_local_plan_hashes, local_plan_hashes_initialization_script};
pub use navigation::{
    generation_is_current, is_public_http_link, next_generation, origin_is_allowed, OriginKey, OriginPolicy,
};
pub use profile::{Profile, ProfileMode, ProfileSet, ProfileStore, PROFILE_SCHEMA_VERSION};
pub use proxy::{
    render_status_html, ForwardRequest, ProxyControl, ProxyHandle, ProxyServer, StatusPage, Upstream, UpstreamError,
    UpstreamResponse,
};
pub use secret::SecretToken;
pub use transport::{validate_attach_url, ValidatedAttachUrl};

use std::fmt;

/// A redacted, operator-safe connection configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionError {
    message: String,
}

impl ConnectionError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Stable rendered reason suitable for a native status page.
    pub fn reason(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConnectionError {}
