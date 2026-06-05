// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Tracing subscriber layer that captures WARN/ERROR events as facts.

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::Utc;
use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::FactStore;
use tokio::sync::RwLock;
use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use crate::schema::{ops_entity, OpsErrorEvent, OpsWarningEvent, EVT_OPS_ERROR_V1, EVT_OPS_WARNING_V1};

/// A `tracing_subscriber::Layer` that captures WARN and ERROR span events and
/// writes them as facts to a [`FactStore`].
///
/// The layer maintains a ring buffer of fact IDs so it can evict the oldest
/// entries when the maximum is exceeded.
pub struct OpsObserveLayer {
    fact_store: Arc<RwLock<FactStore>>,
    fact_ids: Arc<std::sync::Mutex<VecDeque<String>>>,
    node_id: String,
    max_facts: usize,
    enabled: bool,
}

impl OpsObserveLayer {
    /// Create a new layer.
    pub fn new(fact_store: Arc<RwLock<FactStore>>, node_id: String, max_facts: usize, enabled: bool) -> Self {
        Self {
            fact_store,
            fact_ids: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            node_id,
            max_facts,
            enabled,
        }
    }

    /// Returns the current number of tracked fact IDs.
    #[cfg(test)]
    fn tracked_count(&self) -> usize {
        self.fact_ids.lock().unwrap().len()
    }
}

/// Visitor that extracts `message` and collects other fields.
#[derive(Debug, Default)]
pub struct FieldVisitor {
    pub message: Option<String>,
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let val = format!("{:?}", value);
        if field.name() == "message" {
            self.message = Some(val);
        } else {
            self.fields
                .insert(field.name().to_string(), serde_json::Value::String(val));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), serde_json::Value::String(value.to_string()));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }
}

impl<S> Layer<S> for OpsObserveLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if !self.enabled {
            return;
        }

        let level = *event.metadata().level();
        let is_error = level == tracing::Level::ERROR;
        let is_warn = level == tracing::Level::WARN;
        if !is_error && !is_warn {
            return;
        }

        // Extract fields from the event.
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let message = visitor.message.unwrap_or_default();
        let target = event.metadata().target().to_string();
        let timestamp = Utc::now();
        let id = uuid::Uuid::new_v4().to_string();

        let (kind, event_type, value) = if is_error {
            let evt = OpsErrorEvent {
                event_type: EVT_OPS_ERROR_V1.to_string(),
                node_id: self.node_id.clone(),
                message: message.clone(),
                target: Some(target),
                timestamp,
                fields: serde_json::Value::Object(visitor.fields),
            };
            (
                "error",
                EVT_OPS_ERROR_V1,
                serde_json::to_string(&evt).unwrap_or_default(),
            )
        } else {
            let evt = OpsWarningEvent {
                event_type: EVT_OPS_WARNING_V1.to_string(),
                node_id: self.node_id.clone(),
                message: message.clone(),
                target: Some(target),
                timestamp,
                fields: serde_json::Value::Object(visitor.fields),
            };
            (
                "warning",
                EVT_OPS_WARNING_V1,
                serde_json::to_string(&evt).unwrap_or_default(),
            )
        };

        let entity = ops_entity(kind, &id);
        let fact_store = Arc::clone(&self.fact_store);
        let fact_ids = Arc::clone(&self.fact_ids);
        let max_facts = self.max_facts;

        // Spawn a task so we never hold the fact_store lock synchronously.
        tokio::task::spawn(async move {
            let mut store = fact_store.write().await;

            let fact = store.store(StoreFact {
                entity,
                key: event_type.to_string(),
                value,
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });

            // Ring buffer eviction.
            // SAFETY: Mutex poisoning indicates a prior panic — propagating is correct here.
            #[allow(clippy::unwrap_used)]
            let mut ids = fact_ids.lock().unwrap();
            ids.push_back(fact.fact_id.clone());
            while ids.len() > max_facts {
                if let Some(old_id) = ids.pop_front() {
                    store.delete(&old_id);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_disabled_does_not_track() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let layer = OpsObserveLayer::new(store, "test-node".to_string(), 100, false);
        assert!(!layer.enabled);
        assert_eq!(layer.tracked_count(), 0);
    }

    #[test]
    fn field_visitor_extracts_message_via_debug() {
        let mut v = FieldVisitor::default();

        // Use the tracing macros to exercise FieldVisitor indirectly.
        // We test the visitor struct directly via its Visit trait methods
        // by using the static metadata approach.
        static TEST_META: tracing::Metadata<'static> = tracing::Metadata::new(
            "test",
            "test_target",
            tracing::Level::INFO,
            None,
            None,
            None,
            tracing::field::FieldSet::new(&["message", "extra"], tracing::callsite::Identifier(&DUMMY_CALLSITE)),
            tracing::metadata::Kind::EVENT,
        );

        let fields = TEST_META.fields();
        if let Some(msg_field) = fields.field("message") {
            v.record_str(&msg_field, "hello world");
        }
        if let Some(extra_field) = fields.field("extra") {
            v.record_str(&extra_field, "bonus");
        }

        assert_eq!(v.message.as_deref(), Some("hello world"));
        assert_eq!(
            v.fields.get("extra"),
            Some(&serde_json::Value::String("bonus".to_string()))
        );
    }

    #[test]
    fn field_visitor_record_types() {
        static TEST_META2: tracing::Metadata<'static> = tracing::Metadata::new(
            "test2",
            "test_target",
            tracing::Level::INFO,
            None,
            None,
            None,
            tracing::field::FieldSet::new(
                &["count", "flag", "message"],
                tracing::callsite::Identifier(&DUMMY_CALLSITE),
            ),
            tracing::metadata::Kind::EVENT,
        );

        let mut v = FieldVisitor::default();
        let fields = TEST_META2.fields();

        if let Some(f) = fields.field("count") {
            v.record_i64(&f, 42);
        }
        if let Some(f) = fields.field("flag") {
            v.record_bool(&f, true);
        }
        if let Some(f) = fields.field("message") {
            v.record_debug(&f, &"debug msg");
        }

        assert_eq!(v.fields.get("count"), Some(&serde_json::json!(42)));
        assert_eq!(v.fields.get("flag"), Some(&serde_json::json!(true)));
        // message via record_debug gets Debug formatting (with quotes)
        assert!(v.message.is_some());
    }

    // Dummy callsite for tests.
    static DUMMY_CALLSITE: DummyCallsite = DummyCallsite;
    struct DummyCallsite;
    impl tracing::callsite::Callsite for DummyCallsite {
        fn set_interest(&self, _interest: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            unimplemented!("not called in this test path")
        }
    }

    #[tokio::test]
    async fn ring_buffer_eviction() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let fact_ids = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        let max_facts = 3;

        // Simulate adding 5 facts with eviction.
        let mut all_ids = Vec::new();
        for i in 0..5 {
            let mut s = store.write().await;
            let fact = s.store(StoreFact {
                entity: format!("__ops__::error:test-{i}"),
                key: "ops.error.v1".to_string(),
                value: format!("error {i}"),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            all_ids.push(fact.fact_id.clone());

            let mut ids = fact_ids.lock().unwrap();
            ids.push_back(fact.fact_id);
            while ids.len() > max_facts {
                if let Some(old_id) = ids.pop_front() {
                    s.delete(&old_id);
                }
            }
        }

        // The first two should be deleted (soft-delete).
        let s = store.read().await;
        assert!(s.get(&all_ids[0]).is_none());
        assert!(s.get(&all_ids[1]).is_none());
        // The last three should still be alive.
        assert!(s.get(&all_ids[2]).is_some());
        assert!(s.get(&all_ids[3]).is_some());
        assert!(s.get(&all_ids[4]).is_some());

        let ids = fact_ids.lock().unwrap();
        assert_eq!(ids.len(), max_facts);
    }
}
