// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tenant categorisation model.
//!
//! Every entity_id in the Crux store classifies into one of four categories used
//! by the console UI and by passport-scoped write enforcement:
//!
//! - `Personal` — explicit `personal::` / `personal-` / exact `personal` prefix.
//! - `Work`     — explicit `work::` / `work-` / exact `work` prefix, OR (per
//!   ExecPlan crux-tenant-category-model-2026-05-22) the default for any
//!   non-system, non-prefixed tenant.
//! - `Public`   — explicit `public::` / `public-` / exact `public` prefix.
//! - `System`   — daemon-internal entities matching `__\w+__` standalone or as a
//!   namespace prefix (`__bootstrap__::*`, `__passport__::*`,
//!   `__session_binding__::*`, etc.). Exempt from passport-category write
//!   enforcement so the daemon can write its own bookkeeping with any active
//!   passport.
//!
//! Precedence in `classify_tenant`:
//!   1. system-prefix detector — wins regardless of override
//!   2. explicit override      — typically from `__tenant_metadata__::` store
//!   3. prefix-derived         — work / public / personal
//!   4. default                — Work

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantCategory {
    Personal,
    Work,
    Public,
    System,
}

impl TenantCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Work => "work",
            Self::Public => "public",
            Self::System => "system",
        }
    }

    /// Parse a user-supplied category string. Rejects `system` — it is a
    /// runtime-derived classification only, not user-settable.
    ///
    /// Wired in by M2 (PATCH `/v1/console/tenants/:tenant/category`); the
    /// `#[allow(dead_code)]` lifts when that endpoint lands.
    #[allow(dead_code)]
    pub fn parse_user_input(s: &str) -> Result<Self, ParseError> {
        match s.to_ascii_lowercase().as_str() {
            "personal" => Ok(Self::Personal),
            "work" => Ok(Self::Work),
            "public" => Ok(Self::Public),
            "system" => Err(ParseError::SystemNotUserSettable),
            other => Err(ParseError::Invalid(other.to_string())),
        }
    }
}

impl fmt::Display for TenantCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors from [`TenantCategory::parse_user_input`]. Wired in by M2.
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid category '{0}': must be one of personal, work, public")]
    Invalid(String),
    #[error("category 'system' is not user-settable; it is derived from the entity prefix")]
    SystemNotUserSettable,
}

/// Returns true iff `tenant_id` matches the daemon-internal system prefix
/// pattern `__\w+__` — either standalone (`__bootstrap__`) or as a namespace
/// prefix (`__bootstrap__::foo`).
pub fn is_system_prefix(tenant_id: &str) -> bool {
    let bytes = tenant_id.as_bytes();
    if !bytes.starts_with(b"__") || bytes.len() < 5 {
        return false;
    }
    let rest = &bytes[2..];
    let mut i = 0;
    while i + 1 < rest.len() {
        if rest[i] == b'_' && rest[i + 1] == b'_' {
            if i == 0 {
                // four underscores in a row — empty identifier, invalid
                return false;
            }
            let after = &rest[i + 2..];
            return after.is_empty() || after.starts_with(b"::");
        }
        let c = rest[i];
        if !(c.is_ascii_alphanumeric() || c == b'_') {
            return false;
        }
        i += 1;
    }
    false
}

fn derive_from_prefix(tenant_id: &str) -> Option<TenantCategory> {
    let lower = tenant_id.to_ascii_lowercase();
    if lower.starts_with("work::") || lower.starts_with("work-") || lower == "work" {
        return Some(TenantCategory::Work);
    }
    if lower.starts_with("public::") || lower.starts_with("public-") || lower == "public" {
        return Some(TenantCategory::Public);
    }
    if lower.starts_with("personal::") || lower.starts_with("personal-") || lower == "personal" {
        return Some(TenantCategory::Personal);
    }
    None
}

/// The composing classifier. Precedence: system → override → prefix → default.
///
/// The default (last fallback) is **Work**, flipped from the legacy `Personal`
/// default by ExecPlan crux-tenant-category-model-2026-05-22 to match operator
/// expectation that CueCrux activity is work by default.
pub fn classify_tenant(tenant_id: &str, override_: Option<TenantCategory>) -> TenantCategory {
    if is_system_prefix(tenant_id) {
        return TenantCategory::System;
    }
    if let Some(o) = override_ {
        return o;
    }
    if let Some(c) = derive_from_prefix(tenant_id) {
        return c;
    }
    TenantCategory::Work
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_is_stable() {
        assert_eq!(TenantCategory::Personal.as_str(), "personal");
        assert_eq!(TenantCategory::Work.as_str(), "work");
        assert_eq!(TenantCategory::Public.as_str(), "public");
        assert_eq!(TenantCategory::System.as_str(), "system");
    }

    #[test]
    fn parse_user_input_accepts_three() {
        assert_eq!(
            TenantCategory::parse_user_input("personal").unwrap(),
            TenantCategory::Personal
        );
        assert_eq!(TenantCategory::parse_user_input("work").unwrap(), TenantCategory::Work);
        assert_eq!(
            TenantCategory::parse_user_input("public").unwrap(),
            TenantCategory::Public
        );
        // case-insensitive
        assert_eq!(
            TenantCategory::parse_user_input("PERSONAL").unwrap(),
            TenantCategory::Personal
        );
    }

    #[test]
    fn parse_user_input_rejects_system() {
        assert!(matches!(
            TenantCategory::parse_user_input("system"),
            Err(ParseError::SystemNotUserSettable)
        ));
    }

    #[test]
    fn parse_user_input_rejects_garbage() {
        assert!(matches!(
            TenantCategory::parse_user_input("rubbish"),
            Err(ParseError::Invalid(_))
        ));
        assert!(matches!(
            TenantCategory::parse_user_input(""),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn system_prefix_detects_known_internal_entities() {
        for id in [
            "__bootstrap__",
            "__bootstrap__::foo",
            "__decisions__",
            "__decisions__::abc-123",
            "__dossier__",
            "__passport__::personal-default",
            "__project__::p-foo",
            "__project_layer__::p-foo",
            "__session_binding__::sess-1",
            "__storybook__",
            "__tenant_metadata__::execplan",
            "__agent__",
            "__ops__::a",
            "__synthetic__::test",
        ] {
            assert!(is_system_prefix(id), "expected system prefix for {id}");
        }
    }

    #[test]
    fn system_prefix_rejects_non_system() {
        for id in [
            "",
            "_",
            "__",
            "___",
            "__foo",  // missing trailing __
            "__foo_", // missing trailing __
            "foo",
            "work::foo",
            "personal::__bootstrap__", // doesn't start with __
            "__::foo",                 // empty identifier between __ and __
            "__bootstrap__bar",        // text after __ without ::
        ] {
            assert!(!is_system_prefix(id), "should NOT be system prefix: {id:?}");
        }
    }

    #[test]
    fn classify_system_wins_over_override_and_prefix() {
        // override would normally win, but system always wins
        assert_eq!(
            classify_tenant("__bootstrap__::foo", Some(TenantCategory::Personal)),
            TenantCategory::System
        );
        assert_eq!(classify_tenant("__bootstrap__", None), TenantCategory::System);
    }

    #[test]
    fn classify_override_wins_over_prefix_and_default() {
        assert_eq!(
            classify_tenant("execplan", Some(TenantCategory::Personal)),
            TenantCategory::Personal
        );
        // even an explicit prefix yields to override
        assert_eq!(
            classify_tenant("work::foo", Some(TenantCategory::Personal)),
            TenantCategory::Personal
        );
    }

    #[test]
    fn classify_prefix_recognised_when_no_override() {
        assert_eq!(classify_tenant("work::foo", None), TenantCategory::Work);
        assert_eq!(classify_tenant("work-foo", None), TenantCategory::Work);
        assert_eq!(classify_tenant("work", None), TenantCategory::Work);
        assert_eq!(classify_tenant("public::foo", None), TenantCategory::Public);
        assert_eq!(classify_tenant("public-foo", None), TenantCategory::Public);
        assert_eq!(classify_tenant("public", None), TenantCategory::Public);
        assert_eq!(classify_tenant("personal::foo", None), TenantCategory::Personal);
        assert_eq!(classify_tenant("personal-foo", None), TenantCategory::Personal);
        assert_eq!(classify_tenant("personal", None), TenantCategory::Personal);
        // case-insensitive
        assert_eq!(classify_tenant("WORK::foo", None), TenantCategory::Work);
    }

    #[test]
    fn classify_default_is_work_post_flip() {
        // The behaviour change introduced by ExecPlan
        // crux-tenant-category-model-2026-05-22: untagged tenants default to Work.
        for id in [
            "execplan",
            "decision",
            "github",
            "local",
            "session",
            "random-thing",
            "worklog",     // not "work-" prefix exactly; falls through to default
            "publication", // not "public-" prefix; falls through
        ] {
            assert_eq!(
                classify_tenant(id, None),
                TenantCategory::Work,
                "untagged {id} should default to Work"
            );
        }
    }

    #[test]
    fn classify_empty_string_defaults_to_work() {
        assert_eq!(classify_tenant("", None), TenantCategory::Work);
    }
}
