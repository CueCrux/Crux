// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Real-time event bus for memory-store mutations.
//!
//! [`EventBus`] wraps a `tokio::sync::broadcast` channel. Stores call
//! [`EventBus::emit`] after each write/delete; SSE or WebSocket handlers
//! call [`EventBus::subscribe`] to receive a live stream.

use serde::Serialize;
use tokio::sync::broadcast;

/// A mutation event emitted by the fact store or session store.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum CruxEvent {
    #[serde(rename = "fact.stored")]
    FactStored {
        fact_id: String,
        entity: String,
        key: String,
    },
    #[serde(rename = "fact.deleted")]
    FactDeleted { fact_id: String },
    #[serde(rename = "session.stored")]
    SessionStored { session_id: String },
    #[serde(rename = "session.deleted")]
    SessionDeleted { session_id: String },
    /// Agent-graph: a new audit step was appended to a session's trace chain.
    #[serde(rename = "observe.audit_step")]
    AuditStep {
        node_id: String,
        session_id: String,
        seq: u64,
    },
    /// Agent-graph: an orchestrator was created or its state/members changed.
    #[serde(rename = "orchestrator.changed")]
    OrchestratorChanged { id: String },
    /// Agent-graph: a punchcard lease transitioned status.
    #[serde(rename = "punchcard.changed")]
    PunchcardChanged { id: String, status: String },
}

/// Broadcast-based event bus for store mutations.
///
/// Cloning an `EventBus` shares the same underlying channel — all clones
/// emit to and subscribe from the same broadcast.
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<CruxEvent>,
}

impl EventBus {
    /// Create a new event bus with the given channel capacity.
    ///
    /// When the channel is full, the oldest event is dropped and lagged
    /// subscribers receive a `RecvError::Lagged` on their next recv.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Emit an event to all current subscribers.
    ///
    /// If there are no subscribers the event is silently discarded.
    pub fn emit(&self, event: CruxEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to future events. Returns a receiver that yields every
    /// event emitted after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<CruxEvent> {
        self.tx.subscribe()
    }
}
