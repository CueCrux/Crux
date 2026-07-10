// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Server→client push channel for MCP Streamable HTTP (dynamic-tool-surface M3.5).
//!
//! The base MCP transport is request/response over `POST /mcp`. This module adds
//! the optional server-initiated side: a client opens an SSE stream on
//! `GET /mcp` (`Accept: text/event-stream`) carrying its `Mcp-Session-Id`, and
//! the server can push JSON-RPC notifications on it — currently just
//! `notifications/tools/list_changed`, fired when the `dynamic` tool surface is
//! reshaped (e.g. after `cuecrux_session(intent=…)` changes the declared intent).
//!
//! Inert unless a client opts in: with no registered SSE stream for a session,
//! [`notify_list_changed`] is a no-op. Process-global, mirroring `crate::traces`
//! / `crate::tools::surface` — no `McpContext` field churn.

use std::collections::HashMap;
use std::env;
use std::sync::{Mutex, OnceLock};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// The exact JSON-RPC notification an MCP client expects when the advertised
/// tool list changes (it should then re-request `tools/list`).
pub const TOOLS_LIST_CHANGED: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;

const DEFAULT_MAX_SESSIONS: usize = 1024;
const DEFAULT_MAX_SESSIONS_PER_OWNER: usize = 64;

#[derive(Debug)]
struct SessionEntry {
    tx: UnboundedSender<String>,
    owner_key: String,
    generation: u64,
}

#[derive(Debug, Default)]
struct RegistryState {
    sessions: HashMap<String, SessionEntry>,
    next_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseLimits {
    pub max_sessions: usize,
    pub max_sessions_per_owner: usize,
}

impl SseLimits {
    pub fn from_env() -> Self {
        Self {
            max_sessions: env_cap("CRUX_MCP_SSE_MAX_SESSIONS", DEFAULT_MAX_SESSIONS),
            max_sessions_per_owner: env_cap("CRUX_MCP_SSE_MAX_SESSIONS_PER_OWNER", DEFAULT_MAX_SESSIONS_PER_OWNER),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterError {
    GlobalLimit {
        max: usize,
    },
    OwnerLimit {
        max: usize,
    },
    /// A live session with this id is owned by a different caller. Replacement
    /// is only permitted by the original owner — a cross-owner takeover (e.g. a
    /// guessed/copied session id) is rejected rather than silently replacing the
    /// stream.
    OwnerMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    session_id: String,
    generation: u64,
}

impl Registration {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

pub struct RegisteredSse {
    registration: Registration,
    rx: UnboundedReceiver<String>,
}

impl RegisteredSse {
    pub fn registration(&self) -> Registration {
        self.registration.clone()
    }

    pub fn into_receiver(self) -> UnboundedReceiver<String> {
        self.rx
    }
}

fn registry() -> &'static Mutex<RegistryState> {
    static REG: OnceLock<Mutex<RegistryState>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(RegistryState::default()))
}

/// Register an SSE stream for `session_id`, returning the receiver the stream
/// drains. A prior stream for the same id is replaced only by its original
/// owner; a different owner is rejected with [`RegisterError::OwnerMismatch`].
pub fn register(session_id: &str, owner_key: &str) -> Result<RegisteredSse, RegisterError> {
    let limits = SseLimits::from_env();
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    register_locked(&mut reg, session_id, owner_key, limits)
}

fn register_locked(
    reg: &mut RegistryState,
    session_id: &str,
    owner_key: &str,
    limits: SseLimits,
) -> Result<RegisteredSse, RegisterError> {
    prune_closed(reg);

    // Owner-bound replacement: a live session may only be replaced by its own
    // owner. A different owner attempting to reuse the id is rejected (no
    // cross-owner takeover of an open stream).
    let replaces_existing = match reg.sessions.get(session_id) {
        Some(existing) => {
            if existing.owner_key != owner_key {
                return Err(RegisterError::OwnerMismatch);
            }
            true
        }
        None => false,
    };
    if !replaces_existing && reg.sessions.len() >= limits.max_sessions {
        return Err(RegisterError::GlobalLimit {
            max: limits.max_sessions,
        });
    }

    let owner_count = reg
        .sessions
        .iter()
        .filter(|(existing_session, entry)| existing_session.as_str() != session_id && entry.owner_key == owner_key)
        .count();
    if owner_count >= limits.max_sessions_per_owner {
        return Err(RegisterError::OwnerLimit {
            max: limits.max_sessions_per_owner,
        });
    }

    let (tx, rx) = unbounded_channel();
    reg.next_generation = reg.next_generation.saturating_add(1);
    let generation = reg.next_generation;
    reg.sessions.insert(
        session_id.to_string(),
        SessionEntry {
            tx,
            owner_key: owner_key.to_string(),
            generation,
        },
    );
    Ok(RegisteredSse {
        registration: Registration {
            session_id: session_id.to_string(),
            generation,
        },
        rx,
    })
}

/// Drop the sender for `session_id` (called when its SSE stream ends).
pub fn unregister(session_id: &str) {
    registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .sessions
        .remove(session_id);
}

/// Drop the sender only if it still refers to this specific registration.
pub fn unregister_registration(registration: &Registration) {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    if reg
        .sessions
        .get(registration.session_id())
        .is_some_and(|entry| entry.generation == registration.generation)
    {
        reg.sessions.remove(registration.session_id());
    }
}

pub fn active_count() -> usize {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    prune_closed(&mut reg);
    reg.sessions.len()
}

pub fn is_registered(session_id: &str) -> bool {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    prune_closed(&mut reg);
    reg.sessions.contains_key(session_id)
}

/// Push `notifications/tools/list_changed` to `session_id`'s open SSE stream, if
/// one is registered. Returns `true` when delivered. A closed receiver (client
/// disconnected) is pruned lazily and returns `false`.
pub fn notify_list_changed(session_id: &str) -> bool {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    let Some(entry) = reg.sessions.get(session_id) else {
        return false;
    };
    if entry.tx.send(TOOLS_LIST_CHANGED.to_string()).is_ok() {
        true
    } else {
        reg.sessions.remove(session_id); // receiver gone — prune
        false
    }
}

fn prune_closed(reg: &mut RegistryState) {
    reg.sessions.retain(|_, entry| !entry.tx.is_closed());
}

fn env_cap(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map_or(default, |value| if value == 0 { usize::MAX } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_then_notify_delivers() {
        let mut rx = register("sess-A", "owner-A").expect("registered").into_receiver();
        assert!(notify_list_changed("sess-A"), "delivered to a registered session");
        let msg = rx.recv().await.expect("a pushed message");
        assert!(msg.contains("notifications/tools/list_changed"));
        unregister("sess-A");
    }

    #[test]
    fn notify_unknown_session_is_noop() {
        assert!(!notify_list_changed("no-such-session-xyz"));
    }

    #[tokio::test]
    async fn unregister_stops_delivery() {
        let _rx = register("sess-B", "owner-B").expect("registered");
        unregister("sess-B");
        assert!(!notify_list_changed("sess-B"), "no delivery after unregister");
    }

    #[tokio::test]
    async fn dropped_receiver_is_pruned() {
        let rx = register("sess-C", "owner-C").expect("registered").into_receiver();
        drop(rx);
        assert!(!notify_list_changed("sess-C"), "closed receiver ⇒ false + pruned");
        assert!(!notify_list_changed("sess-C"), "stays pruned on the next call");
    }

    #[test]
    fn register_enforces_owner_cap() {
        let mut reg = RegistryState::default();
        let limits = SseLimits {
            max_sessions: 10,
            max_sessions_per_owner: 1,
        };
        let _first = register_locked(&mut reg, "sess-cap-1", "owner-cap", limits).expect("first registered");
        let second = register_locked(&mut reg, "sess-cap-2", "owner-cap", limits);
        assert_eq!(second.err(), Some(RegisterError::OwnerLimit { max: 1 }));
    }

    #[test]
    fn register_enforces_global_cap() {
        let mut reg = RegistryState::default();
        let limits = SseLimits {
            max_sessions: 1,
            max_sessions_per_owner: 10,
        };
        let _first = register_locked(&mut reg, "sess-global-1", "owner-1", limits).expect("first registered");
        let second = register_locked(&mut reg, "sess-global-2", "owner-2", limits);
        assert_eq!(second.err(), Some(RegisterError::GlobalLimit { max: 1 }));
    }

    #[test]
    fn sse_same_owner_can_replace_session() {
        let mut reg = RegistryState::default();
        let limits = SseLimits {
            max_sessions: 10,
            max_sessions_per_owner: 10,
        };
        let first = register_locked(&mut reg, "sess-own", "owner-1", limits)
            .expect("first registered")
            .registration();
        let second = register_locked(&mut reg, "sess-own", "owner-1", limits)
            .expect("same owner replaces")
            .registration();
        assert_ne!(first.generation, second.generation);
        assert_eq!(reg.sessions.len(), 1);
    }

    #[test]
    fn sse_different_owner_cannot_replace_session() {
        let mut reg = RegistryState::default();
        let limits = SseLimits {
            max_sessions: 10,
            max_sessions_per_owner: 10,
        };
        let _first = register_locked(&mut reg, "sess-own", "owner-1", limits).expect("first registered");
        let intruder = register_locked(&mut reg, "sess-own", "owner-2", limits);
        assert_eq!(intruder.err(), Some(RegisterError::OwnerMismatch));
        // Original owner's stream is untouched and still replaceable by them.
        assert!(reg.sessions.contains_key("sess-own"));
        assert!(register_locked(&mut reg, "sess-own", "owner-1", limits).is_ok());
    }

    #[test]
    fn stale_registration_does_not_remove_replacement() {
        let mut reg = RegistryState::default();
        let limits = SseLimits {
            max_sessions: 10,
            max_sessions_per_owner: 10,
        };
        let first = register_locked(&mut reg, "sess-replace", "owner-1", limits)
            .expect("first registered")
            .registration();
        let second = register_locked(&mut reg, "sess-replace", "owner-1", limits)
            .expect("second registered")
            .registration();
        assert_ne!(first, second);
        assert!(reg.sessions.contains_key("sess-replace"));
        if reg
            .sessions
            .get(first.session_id())
            .is_some_and(|entry| entry.generation == first.generation)
        {
            reg.sessions.remove(first.session_id());
        }
        assert!(reg.sessions.contains_key("sess-replace"));
    }
}
