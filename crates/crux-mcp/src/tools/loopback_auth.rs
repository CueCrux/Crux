// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Shared loopback-auth helpers for MCP tools that call the daemon over HTTP.
//!
//! Background. MCP tools used to send only `X-Corecrux-Scopes: admin:read,…`
//! on loopback requests. That header is consumed by [`AuthMode::DevScopes`]
//! and ignored by [`AuthMode::Off`], but `AuthMode::JwtHs256` /
//! `AuthMode::JwtJwks` ignore it and demand `Authorization: Bearer <token>` —
//! producing a 401 on every coordination, github, storyline, and extension
//! tool when the daemon is in production JWT mode.
//!
//! Fix. Tools must additionally attach a bearer token when one is available
//! in the process environment. `CRUX_AGENT_TOKEN` is the operator-canonical
//! variable (the same one `AgentRegistry::from_env` reads for inbound auth);
//! `CORECRUX_LOOPBACK_TOKEN` is an optional explicit override.

/// Env var names checked, in order, for a bearer token to attach to loopback
/// requests. First non-empty match wins.
pub const LOOPBACK_TOKEN_ENV_VARS: &[&str] = &["CORECRUX_LOOPBACK_TOKEN", "CRUX_AGENT_TOKEN"];

/// Resolve the loopback bearer token from the environment.
///
/// Returns `None` when no variable is set or all candidates are blank. Callers
/// MUST treat `None` as "daemon is in `AuthMode::Off` or `DevScopes`" and rely
/// on the `X-Corecrux-Scopes` header alone.
pub fn loopback_bearer_token() -> Option<String> {
    resolve_bearer_token(|name| std::env::var(name).ok())
}

/// Pure variant used by tests: scans the same env-var list but reads from the
/// supplied closure instead of the real environment. Production callers go
/// through [`loopback_bearer_token`].
pub(crate) fn resolve_bearer_token<F>(getter: F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    for var in LOOPBACK_TOKEN_ENV_VARS {
        if let Some(raw) = getter(var) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn returns_none_when_all_unset() {
        let getter = fake_env(&[]);
        assert!(resolve_bearer_token(getter).is_none());
    }

    #[test]
    fn returns_value_from_crux_agent_token() {
        let getter = fake_env(&[("CRUX_AGENT_TOKEN", "crux_at_abc")]);
        assert_eq!(resolve_bearer_token(getter).as_deref(), Some("crux_at_abc"));
    }

    #[test]
    fn override_takes_precedence() {
        let getter = fake_env(&[
            ("CRUX_AGENT_TOKEN", "fallback"),
            ("CORECRUX_LOOPBACK_TOKEN", "override"),
        ]);
        assert_eq!(resolve_bearer_token(getter).as_deref(), Some("override"));
    }

    #[test]
    fn whitespace_only_treated_as_unset() {
        let getter = fake_env(&[("CRUX_AGENT_TOKEN", "   ")]);
        assert!(resolve_bearer_token(getter).is_none());
    }

    #[test]
    fn falls_through_to_second_var_when_first_blank() {
        let getter = fake_env(&[("CORECRUX_LOOPBACK_TOKEN", ""), ("CRUX_AGENT_TOKEN", "real")]);
        assert_eq!(resolve_bearer_token(getter).as_deref(), Some("real"));
    }
}
