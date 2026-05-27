// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Deterministic action enrichment and tool consequence metadata.
//!
//! This module is intentionally CPU/local-only. It turns a raw tool call into a
//! structured action proposal that basic constraint checks, Pro preflight
//! surfaces, and future replay capsules can reference without involving an LLM.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::fact_store::{FactQuery, FactStore};

pub const ACTION_ENRICHMENT_SCHEMA: &str = "crux.action.enriched_action_proposal.v1";
pub const ACTION_ENRICHMENT_RECEIPT_SCHEMA: &str = "crux.action.enrichment_receipt.v1";
pub const ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX: &str = "__action_enrichment_receipt__";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    Reversible,
    ReversibleWithCompensation,
    Irreversible,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Materiality {
    TouchesMoney,
    TouchesCustomerData,
    TouchesProduction,
    CreatesExternalObligation,
    TouchesPii,
    LocalPrivateMemory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyClass {
    Safe,
    RequiresKey,
    MustNotRetry,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    SelfOnly,
    Tenant,
    CrossTenant,
    External,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionDomain {
    Code,
    File,
    EmailCalendar,
    CrmCustomer,
    Memory,
    Sync,
    Extension,
    General,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolConsequenceMetadata {
    pub schema: &'static str,
    pub domain: ActionDomain,
    pub reversibility: Reversibility,
    pub materiality: Vec<Materiality>,
    pub idempotency_class: IdempotencyClass,
    pub blast_radius: BlastRadius,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensating_tool: Option<String>,
    pub pro_enricher_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionEnrichmentInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub tool_name: String,
    #[serde(default)]
    pub tool_parameters: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_description: Option<String>,
    #[serde(default)]
    pub include_first_party_enrichers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCallEnvelope {
    pub name: String,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AffectedPrincipal {
    pub id: String,
    pub role: String,
    pub relation_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AffectedResource {
    pub id: String,
    pub resource_type: String,
    pub domain: ActionDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateDiff {
    pub fields_changed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionConsequence {
    pub consequence_type: String,
    pub target: String,
    pub detail: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelationshipHit {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    pub match_strength: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrichmentReceipt {
    pub schema: &'static str,
    pub receipt_id: String,
    pub event_type: &'static str,
    pub tenant_id: String,
    pub tool_call_hash: String,
    pub proposal_hash: String,
    pub enrichment_mode: String,
    pub enricher_versions: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrichedActionProposal {
    pub schema: &'static str,
    pub tenant_id: String,
    pub enrichment_mode: String,
    pub tool_call: ToolCallEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_description: Option<String>,
    pub narrative: String,
    pub affected_principals: Vec<AffectedPrincipal>,
    pub affected_resources: Vec<AffectedResource>,
    pub state_diff: StateDiff,
    pub consequences: Vec<ActionConsequence>,
    pub relationship_hits: Vec<RelationshipHit>,
    pub consequence_metadata: ToolConsequenceMetadata,
    pub enricher_versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment_receipt: Option<EnrichmentReceipt>,
}

pub fn metadata_for_tool_name(tool_name: &str) -> ToolConsequenceMetadata {
    consequence_metadata_for_tool(tool_name, None, None)
}

pub fn metadata_for_tool_value(tool_name: &str) -> Value {
    serde_json::to_value(metadata_for_tool_name(tool_name)).unwrap_or_else(|_| json!({}))
}

pub fn consequence_metadata_for_tool(
    tool_name: &str,
    parameters: Option<&Value>,
    action_description: Option<&str>,
) -> ToolConsequenceMetadata {
    let haystack = haystack(tool_name, parameters, action_description);
    let domain = classify_domain(&haystack);
    let materiality = classify_materiality(&haystack, domain);
    let blast_radius = classify_blast_radius(&haystack, domain, &materiality);
    let reversibility = classify_reversibility(&haystack, &materiality);
    let idempotency_class = classify_idempotency(&haystack, reversibility);
    let compensating_tool = compensating_tool(tool_name, &haystack);

    ToolConsequenceMetadata {
        schema: "crux.tool_consequence_metadata.v1",
        domain,
        reversibility,
        materiality,
        idempotency_class,
        blast_radius,
        compensating_tool,
        pro_enricher_available: matches!(
            domain,
            ActionDomain::Code | ActionDomain::File | ActionDomain::EmailCalendar | ActionDomain::CrmCustomer
        ),
    }
}

pub fn enrich_action(store: Option<&FactStore>, input: ActionEnrichmentInput) -> EnrichedActionProposal {
    let tenant_id = input
        .tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local")
        .to_string();
    let metadata = consequence_metadata_for_tool(
        &input.tool_name,
        Some(&input.tool_parameters),
        input.action_description.as_deref(),
    );
    let mut principals = extract_principals(&input.tool_parameters);
    let mut resources = extract_resources(&input.tool_parameters, metadata.domain);
    let mut consequences = consequences_from_metadata(&metadata);
    let mut relationship_hits = Vec::new();
    let mut enricher_versions = vec!["deterministic-basic-v1".to_string()];

    if input.include_first_party_enrichers {
        if let Some(store) = store {
            let first_party = first_party_context(store, &tenant_id, &input, metadata.domain);
            enricher_versions.push(first_party.enricher_version);
            relationship_hits.extend(first_party.relationship_hits);
            consequences.extend(first_party.consequences);
            principals.extend(first_party.principals);
            resources.extend(first_party.resources);
        } else {
            enricher_versions.extend(first_party_versions(metadata.domain));
            consequences.push(ActionConsequence {
                consequence_type: "first_party_context_unavailable".to_string(),
                target: input.tool_name.clone(),
                detail: "first-party enricher requested but no local fact store was supplied".to_string(),
                evidence: "dispatcher".to_string(),
            });
        }
    }

    dedup_principals(&mut principals);
    dedup_resources(&mut resources);
    dedup_consequences(&mut consequences);
    relationship_hits.sort_by(|a, b| a.fact_id.cmp(&b.fact_id));
    relationship_hits.dedup_by(|a, b| a.fact_id == b.fact_id);

    let state_diff = state_diff(&input.tool_parameters);
    let mut proposal = EnrichedActionProposal {
        schema: ACTION_ENRICHMENT_SCHEMA,
        tenant_id,
        enrichment_mode: if input.include_first_party_enrichers {
            "first_party".to_string()
        } else {
            "basic".to_string()
        },
        tool_call: ToolCallEnvelope {
            name: input.tool_name.clone(),
            parameters: input.tool_parameters.clone(),
        },
        action_description: input.action_description.clone(),
        narrative: String::new(),
        affected_principals: principals,
        affected_resources: resources,
        state_diff,
        consequences,
        relationship_hits,
        consequence_metadata: metadata,
        enricher_versions,
        enrichment_receipt: None,
    };
    proposal.narrative = build_narrative(&proposal);
    proposal.enrichment_receipt = Some(build_receipt(&proposal));
    proposal
}

fn haystack(tool_name: &str, parameters: Option<&Value>, action_description: Option<&str>) -> String {
    let mut parts = vec![tool_name.to_ascii_lowercase()];
    if let Some(desc) = action_description {
        parts.push(desc.to_ascii_lowercase());
    }
    if let Some(params) = parameters {
        collect_strings(params, &mut parts);
    }
    parts.join(" ")
}

fn classify_domain(haystack: &str) -> ActionDomain {
    if contains_any(
        haystack,
        &[
            "calendar",
            "meeting",
            "invite",
            "attendee",
            "email",
            "mail",
            "recipient",
            "schedule",
        ],
    ) {
        ActionDomain::EmailCalendar
    } else if contains_any(
        haystack,
        &[
            "crm",
            "customer",
            "account",
            "opportunity",
            "deal",
            "invoice",
            "refund",
            "payment",
            "billing",
        ],
    ) {
        ActionDomain::CrmCustomer
    } else if contains_any(
        haystack,
        &[
            "github",
            "git",
            "commit",
            "branch",
            "pull_request",
            "pull request",
            "deploy",
            "test",
            "route",
            "api",
        ],
    ) {
        ActionDomain::Code
    } else if contains_any(
        haystack,
        &[
            "file",
            "path",
            "document",
            "drive",
            "sharepoint",
            "s3",
            "bucket",
            "folder",
        ],
    ) {
        ActionDomain::File
    } else if contains_any(haystack, &["sync", "mirror", "promote", "tenant"]) {
        ActionDomain::Sync
    } else if contains_any(haystack, &["fact", "session", "memory", "constraint", "receipt"]) {
        ActionDomain::Memory
    } else if contains_any(haystack, &["extension", "manifest", "tool invoke", "wasm"]) {
        ActionDomain::Extension
    } else {
        ActionDomain::General
    }
}

fn classify_materiality(haystack: &str, domain: ActionDomain) -> Vec<Materiality> {
    let mut out = Vec::new();
    if contains_any(
        haystack,
        &["money", "invoice", "refund", "payment", "billing", "charge", "credit"],
    ) {
        out.push(Materiality::TouchesMoney);
    }
    if matches!(domain, ActionDomain::CrmCustomer)
        || contains_any(haystack, &["customer", "crm", "account", "opportunity"])
    {
        out.push(Materiality::TouchesCustomerData);
    }
    if contains_any(haystack, &["production", "prod", "deploy", "release", "live"]) {
        out.push(Materiality::TouchesProduction);
    }
    if matches!(domain, ActionDomain::EmailCalendar)
        || contains_any(haystack, &["send", "publish", "invite", "external", "customer-facing"])
    {
        out.push(Materiality::CreatesExternalObligation);
    }
    if contains_any(
        haystack,
        &["email", "user", "attendee", "recipient", "customer", "pii", "personal"],
    ) {
        out.push(Materiality::TouchesPii);
    }
    if matches!(domain, ActionDomain::Memory) || contains_any(haystack, &["private", "session", "passport"]) {
        out.push(Materiality::LocalPrivateMemory);
    }
    out.sort_by_key(|m| format!("{m:?}"));
    out.dedup();
    out
}

fn classify_blast_radius(haystack: &str, domain: ActionDomain, materiality: &[Materiality]) -> BlastRadius {
    if contains_any(haystack, &["cross_tenant", "all tenants", "global"]) {
        BlastRadius::CrossTenant
    } else if materiality.contains(&Materiality::CreatesExternalObligation)
        || matches!(domain, ActionDomain::EmailCalendar | ActionDomain::CrmCustomer)
    {
        BlastRadius::External
    } else if contains_any(haystack, &["tenant", "team", "workspace", "project", "sync", "promote"]) {
        BlastRadius::Tenant
    } else {
        BlastRadius::SelfOnly
    }
}

fn classify_reversibility(haystack: &str, materiality: &[Materiality]) -> Reversibility {
    if contains_any(
        haystack,
        &["delete", "destroy", "drop", "purge", "wipe", "charge", "refund", "send"],
    ) {
        Reversibility::Irreversible
    } else if contains_any(
        haystack,
        &["create", "update", "move", "rename", "deploy", "publish", "promote"],
    ) || !materiality.is_empty()
    {
        Reversibility::ReversibleWithCompensation
    } else if contains_any(haystack, &["read", "get", "list", "query", "scan", "preview", "status"]) {
        Reversibility::Reversible
    } else {
        Reversibility::Unknown
    }
}

fn classify_idempotency(haystack: &str, reversibility: Reversibility) -> IdempotencyClass {
    if contains_any(haystack, &["read", "get", "list", "query", "scan", "status", "preview"]) {
        IdempotencyClass::Safe
    } else if contains_any(haystack, &["send", "charge", "refund", "delete", "deploy", "publish"]) {
        IdempotencyClass::MustNotRetry
    } else if matches!(
        reversibility,
        Reversibility::ReversibleWithCompensation | Reversibility::Irreversible
    ) {
        IdempotencyClass::RequiresKey
    } else {
        IdempotencyClass::Unknown
    }
}

fn compensating_tool(tool_name: &str, haystack: &str) -> Option<String> {
    if contains_any(haystack, &["create", "add"]) {
        Some(format!("{}.delete_or_archive", tool_name.trim()))
    } else if contains_any(haystack, &["update", "move", "rename"]) {
        Some(format!("{}.restore_previous_state", tool_name.trim()))
    } else if contains_any(haystack, &["deploy", "publish", "promote"]) {
        Some(format!("{}.rollback", tool_name.trim()))
    } else {
        None
    }
}

fn extract_principals(parameters: &Value) -> Vec<AffectedPrincipal> {
    let mut out = Vec::new();
    extract_principals_inner(parameters, None, &mut out);
    out
}

fn extract_principals_inner(value: &Value, key: Option<&str>, out: &mut Vec<AffectedPrincipal>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                extract_principals_inner(v, Some(k), out);
            }
        }
        Value::Array(values) => {
            for v in values {
                extract_principals_inner(v, key, out);
            }
        }
        Value::String(s) => {
            let key = key.unwrap_or_default().to_ascii_lowercase();
            let role = if contains_any(&key, &["attendee", "recipient", "to", "cc"]) {
                Some("recipient")
            } else if contains_any(&key, &["organizer", "owner", "author", "from"]) {
                Some("owner")
            } else if contains_any(&key, &["assignee", "passport", "user", "customer", "contact"]) {
                Some("participant")
            } else {
                None
            };
            if let Some(role) = role {
                out.push(AffectedPrincipal {
                    id: s.clone(),
                    role: role.to_string(),
                    relation_type: if s.contains('@') || key.contains("customer") {
                        "external_or_contact".to_string()
                    } else {
                        "local_or_internal".to_string()
                    },
                });
            }
        }
        _ => {}
    }
}

fn extract_resources(parameters: &Value, domain: ActionDomain) -> Vec<AffectedResource> {
    let mut out = Vec::new();
    extract_resources_inner(parameters, None, domain, &mut out);
    out
}

fn extract_resources_inner(value: &Value, key: Option<&str>, domain: ActionDomain, out: &mut Vec<AffectedResource>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                extract_resources_inner(v, Some(k), domain, out);
            }
        }
        Value::Array(values) => {
            for v in values {
                extract_resources_inner(v, key, domain, out);
            }
        }
        Value::String(s) => {
            let key = key.unwrap_or_default().to_ascii_lowercase();
            let resource_type = if key.ends_with("_id") || key == "id" {
                Some(key.trim_end_matches("_id").to_string())
            } else if contains_any(
                &key,
                &[
                    "path", "file", "document", "repo", "branch", "event", "meeting", "tenant",
                ],
            ) {
                Some(key)
            } else {
                None
            };
            if let Some(resource_type) = resource_type {
                out.push(AffectedResource {
                    id: s.clone(),
                    resource_type,
                    domain,
                });
            }
        }
        _ => {}
    }
}

fn state_diff(parameters: &Value) -> StateDiff {
    let fields_changed = parameters
        .as_object()
        .map(|map| {
            let mut fields = map
                .keys()
                .filter(|key| {
                    let key = key.to_ascii_lowercase();
                    contains_any(&key, &["new", "target", "after", "updated", "state", "status", "time"])
                })
                .cloned()
                .collect::<Vec<_>>();
            fields.sort();
            fields
        })
        .unwrap_or_default();

    StateDiff {
        fields_changed,
        before: parameters
            .get("before")
            .cloned()
            .or_else(|| parameters.get("old").cloned()),
        after: parameters
            .get("after")
            .cloned()
            .or_else(|| parameters.get("new").cloned())
            .or_else(|| parameters.get("target").cloned()),
    }
}

fn consequences_from_metadata(metadata: &ToolConsequenceMetadata) -> Vec<ActionConsequence> {
    let mut out = Vec::new();
    for materiality in &metadata.materiality {
        let (consequence_type, detail) = match materiality {
            Materiality::TouchesMoney => (
                "financial_side_effect",
                "action touches money, billing, payments, or credits",
            ),
            Materiality::TouchesCustomerData => {
                ("customer_data_touch", "action touches CRM, account, or customer data")
            }
            Materiality::TouchesProduction => ("production_change", "action may affect a production/live surface"),
            Materiality::CreatesExternalObligation => (
                "external_obligation",
                "action may create or change an external commitment",
            ),
            Materiality::TouchesPii => ("pii_touch", "action may expose or modify personal data"),
            Materiality::LocalPrivateMemory => (
                "local_private_memory_touch",
                "action touches private local memory/session state",
            ),
        };
        out.push(ActionConsequence {
            consequence_type: consequence_type.to_string(),
            target: format!("{:?}", metadata.domain).to_ascii_lowercase(),
            detail: detail.to_string(),
            evidence: "tool_consequence_metadata".to_string(),
        });
    }
    if matches!(
        metadata.reversibility,
        Reversibility::Irreversible | Reversibility::ReversibleWithCompensation
    ) {
        out.push(ActionConsequence {
            consequence_type: "reversibility_risk".to_string(),
            target: format!("{:?}", metadata.reversibility).to_ascii_lowercase(),
            detail: "action is not known to be cleanly reversible".to_string(),
            evidence: "tool_consequence_metadata".to_string(),
        });
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DomainContribution {
    pub enricher_version: String,
    pub relationship_hits: Vec<RelationshipHit>,
    pub consequences: Vec<ActionConsequence>,
    pub principals: Vec<AffectedPrincipal>,
    pub resources: Vec<AffectedResource>,
}

pub trait ActionDomainEnricher {
    fn domain(&self) -> ActionDomain;
    fn version(&self) -> &'static str;
    fn enrich(&self, store: &FactStore, tenant_id: &str, input: &ActionEnrichmentInput) -> DomainContribution;
}

fn first_party_context(
    store: &FactStore,
    tenant_id: &str,
    input: &ActionEnrichmentInput,
    domain: ActionDomain,
) -> DomainContribution {
    match domain {
        ActionDomain::Code => CodeDomainEnricher.enrich(store, tenant_id, input),
        ActionDomain::File => FileDomainEnricher.enrich(store, tenant_id, input),
        ActionDomain::EmailCalendar => EmailCalendarDomainEnricher.enrich(store, tenant_id, input),
        ActionDomain::CrmCustomer => CrmCustomerDomainEnricher.enrich(store, tenant_id, input),
        _ => TenantMemoryDomainEnricher.enrich(store, tenant_id, input),
    }
}

struct CodeDomainEnricher;
struct FileDomainEnricher;
struct EmailCalendarDomainEnricher;
struct CrmCustomerDomainEnricher;
struct TenantMemoryDomainEnricher;

impl ActionDomainEnricher for CodeDomainEnricher {
    fn domain(&self) -> ActionDomain {
        ActionDomain::Code
    }

    fn version(&self) -> &'static str {
        "code-domain-enricher-v1.local"
    }

    fn enrich(&self, store: &FactStore, tenant_id: &str, input: &ActionEnrichmentInput) -> DomainContribution {
        let mut out = fact_context_for_domain(
            store,
            tenant_id,
            input,
            self.domain(),
            self.version(),
            &["repo", "route", "api", "test", "deploy", "branch", "pull request"],
        );
        let text = haystack(
            &input.tool_name,
            Some(&input.tool_parameters),
            input.action_description.as_deref(),
        );
        if contains_any(&text, &["route", "api"]) {
            out.consequences.push(ActionConsequence {
                consequence_type: "route_or_api_surface_touch".to_string(),
                target: input.tool_name.clone(),
                detail: "code enricher detected an API or route surface change".to_string(),
                evidence: self.version().to_string(),
            });
        }
        if contains_any(&text, &["deploy", "production", "prod", "release"]) {
            out.consequences.push(ActionConsequence {
                consequence_type: "deployment_surface_touch".to_string(),
                target: input.tool_name.clone(),
                detail: "code enricher detected deployment or release context".to_string(),
                evidence: self.version().to_string(),
            });
        }
        out
    }
}

impl ActionDomainEnricher for FileDomainEnricher {
    fn domain(&self) -> ActionDomain {
        ActionDomain::File
    }

    fn version(&self) -> &'static str {
        "file-domain-enricher-v1.local"
    }

    fn enrich(&self, store: &FactStore, tenant_id: &str, input: &ActionEnrichmentInput) -> DomainContribution {
        let mut out = fact_context_for_domain(
            store,
            tenant_id,
            input,
            self.domain(),
            self.version(),
            &["file", "document", "path", "drive", "sharepoint", "folder"],
        );
        collect_parameter_resources(&input.tool_parameters, self.domain(), &mut out.resources);
        if !out.resources.is_empty() {
            out.consequences.push(ActionConsequence {
                consequence_type: "file_or_document_touch".to_string(),
                target: input.tool_name.clone(),
                detail: "file enricher detected document or path resources touched by this action".to_string(),
                evidence: self.version().to_string(),
            });
        }
        out
    }
}

impl ActionDomainEnricher for EmailCalendarDomainEnricher {
    fn domain(&self) -> ActionDomain {
        ActionDomain::EmailCalendar
    }

    fn version(&self) -> &'static str {
        "email-calendar-domain-enricher-v1.local"
    }

    fn enrich(&self, store: &FactStore, tenant_id: &str, input: &ActionEnrichmentInput) -> DomainContribution {
        let mut out = fact_context_for_domain(
            store,
            tenant_id,
            input,
            self.domain(),
            self.version(),
            &[
                "calendar",
                "meeting",
                "email",
                "attendee",
                "recipient",
                "conflict",
                "availability",
            ],
        );
        let text = haystack(
            &input.tool_name,
            Some(&input.tool_parameters),
            input.action_description.as_deref(),
        );
        if contains_any(&text, &["new_time", "start", "end", "move", "reschedule", "invite"]) {
            out.consequences.push(ActionConsequence {
                consequence_type: "schedule_or_message_change".to_string(),
                target: input.tool_name.clone(),
                detail: "email/calendar enricher detected a time, attendee, invitation, or message change".to_string(),
                evidence: self.version().to_string(),
            });
        }
        if contains_any(&text, &["customer", "external", "client", "account"]) {
            out.consequences.push(ActionConsequence {
                consequence_type: "customer_facing_commitment".to_string(),
                target: input.tool_name.clone(),
                detail: "email/calendar enricher detected customer-facing or external-party context".to_string(),
                evidence: self.version().to_string(),
            });
        }
        out
    }
}

impl ActionDomainEnricher for CrmCustomerDomainEnricher {
    fn domain(&self) -> ActionDomain {
        ActionDomain::CrmCustomer
    }

    fn version(&self) -> &'static str {
        "crm-customer-domain-enricher-v1.local"
    }

    fn enrich(&self, store: &FactStore, tenant_id: &str, input: &ActionEnrichmentInput) -> DomainContribution {
        let mut out = fact_context_for_domain(
            store,
            tenant_id,
            input,
            self.domain(),
            self.version(),
            &[
                "customer",
                "crm",
                "account",
                "opportunity",
                "deal",
                "contract",
                "invoice",
            ],
        );
        let text = haystack(
            &input.tool_name,
            Some(&input.tool_parameters),
            input.action_description.as_deref(),
        );
        if contains_any(
            &text,
            &["opportunity", "deal", "contract", "invoice", "payment", "refund"],
        ) {
            out.consequences.push(ActionConsequence {
                consequence_type: "customer_commercial_record_touch".to_string(),
                target: input.tool_name.clone(),
                detail: "CRM enricher detected customer, revenue, contract, or billing context".to_string(),
                evidence: self.version().to_string(),
            });
        }
        out
    }
}

impl ActionDomainEnricher for TenantMemoryDomainEnricher {
    fn domain(&self) -> ActionDomain {
        ActionDomain::Memory
    }

    fn version(&self) -> &'static str {
        "tenant-memory-domain-enricher-v1.local"
    }

    fn enrich(&self, store: &FactStore, tenant_id: &str, input: &ActionEnrichmentInput) -> DomainContribution {
        fact_context_for_domain(
            store,
            tenant_id,
            input,
            ActionDomain::Memory,
            self.version(),
            &["constraint", "policy", "decision", "memory", "receipt"],
        )
    }
}

fn fact_context_for_domain(
    store: &FactStore,
    tenant_id: &str,
    input: &ActionEnrichmentInput,
    domain: ActionDomain,
    enricher_version: &str,
    domain_terms: &[&str],
) -> DomainContribution {
    let query = first_party_query(tenant_id, input, domain, domain_terms);
    let result = store.query(&FactQuery {
        query: Some(query),
        entity: None,
        entity_prefix: None,
        top_k: 24,
        token_budget: None,
    });

    let mut relationship_hits = Vec::new();
    let mut consequences = Vec::new();
    let mut principals = Vec::new();
    let mut resources = Vec::new();

    for fact in result.facts.into_iter().filter(|fact| !fact.deleted) {
        if fact.private && !fact.entity.starts_with("__constraints__::") {
            continue;
        }
        let content_hash = format!("blake3:{}", blake3::hash(fact.value.as_bytes()).to_hex());
        relationship_hits.push(RelationshipHit {
            fact_id: fact.fact_id.clone(),
            entity: fact.entity.clone(),
            key: fact.key.clone(),
            match_strength: format!("{enricher_version}:fact_store_match"),
            content_hash,
        });
        consequences.push(ActionConsequence {
            consequence_type: consequence_type_for_fact(&fact.entity, &fact.key, &fact.value),
            target: format!("{}::{}", fact.entity, fact.key),
            detail: format!(
                "{} found related local tenant context for this action",
                enricher_version
            ),
            evidence: fact.fact_id.clone(),
        });
        if fact.entity.contains("customer") || fact.entity.contains("contact") {
            principals.push(AffectedPrincipal {
                id: fact.entity.clone(),
                role: "related_contact".to_string(),
                relation_type: "tenant_memory".to_string(),
            });
        }
        resources.push(AffectedResource {
            id: fact.entity.clone(),
            resource_type: fact.key.clone(),
            domain,
        });
    }

    DomainContribution {
        enricher_version: enricher_version.to_string(),
        relationship_hits,
        consequences,
        principals,
        resources,
    }
}

fn collect_parameter_resources(value: &Value, domain: ActionDomain, out: &mut Vec<AffectedResource>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let key_lower = key.to_ascii_lowercase();
                if contains_any(&key_lower, &["path", "file", "document", "folder", "repo", "branch"]) {
                    if let Some(resource) = value.as_str() {
                        out.push(AffectedResource {
                            id: resource.to_string(),
                            resource_type: key_lower,
                            domain,
                        });
                    }
                }
                collect_parameter_resources(value, domain, out);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_parameter_resources(value, domain, out);
            }
        }
        _ => {}
    }
}

fn first_party_query(
    tenant_id: &str,
    input: &ActionEnrichmentInput,
    _domain: ActionDomain,
    domain_terms: &[&str],
) -> String {
    let mut terms = vec![tenant_id.to_string(), input.tool_name.clone()];
    if let Some(desc) = &input.action_description {
        terms.push(desc.clone());
    }
    collect_strings(&input.tool_parameters, &mut terms);
    terms.extend(domain_terms.iter().map(|term| (*term).to_string()));
    terms.join(" ")
}

fn consequence_type_for_fact(entity: &str, key: &str, value: &str) -> String {
    let text = format!("{entity} {key} {value}").to_ascii_lowercase();
    if contains_any(&text, &["constraint", "policy", "must", "forbid", "never"]) {
        "policy_context".to_string()
    } else if contains_any(&text, &["customer", "account", "opportunity"]) {
        "customer_context".to_string()
    } else if contains_any(&text, &["calendar", "meeting", "conflict", "attendee"]) {
        "schedule_context".to_string()
    } else if contains_any(&text, &["production", "deploy", "release"]) {
        "production_context".to_string()
    } else {
        "tenant_memory_context".to_string()
    }
}

fn first_party_versions(domain: ActionDomain) -> Vec<String> {
    match domain {
        ActionDomain::Code => vec!["code-domain-enricher-v1.local".to_string()],
        ActionDomain::File => vec!["file-domain-enricher-v1.local".to_string()],
        ActionDomain::EmailCalendar => vec!["email-calendar-domain-enricher-v1.local".to_string()],
        ActionDomain::CrmCustomer => vec!["crm-customer-domain-enricher-v1.local".to_string()],
        _ => vec!["tenant-memory-domain-enricher-v1.local".to_string()],
    }
}

fn build_narrative(proposal: &EnrichedActionProposal) -> String {
    let mut parts = Vec::new();
    if let Some(desc) = &proposal.action_description {
        parts.push(desc.clone());
    } else {
        parts.push(format!("Call tool `{}`", proposal.tool_call.name));
    }
    parts.push(format!(
        "domain={:?}; reversibility={:?}; idempotency={:?}; blast_radius={:?}",
        proposal.consequence_metadata.domain,
        proposal.consequence_metadata.reversibility,
        proposal.consequence_metadata.idempotency_class,
        proposal.consequence_metadata.blast_radius
    ));
    if !proposal.consequence_metadata.materiality.is_empty() {
        parts.push(format!("materiality={:?}", proposal.consequence_metadata.materiality));
    }
    if !proposal.affected_principals.is_empty() {
        parts.push(format!(
            "affected_principals={}",
            proposal
                .affected_principals
                .iter()
                .map(|p| format!("{}:{}", p.role, p.id))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if !proposal.affected_resources.is_empty() {
        parts.push(format!(
            "affected_resources={}",
            proposal
                .affected_resources
                .iter()
                .map(|r| format!("{}:{}", r.resource_type, r.id))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if !proposal.consequences.is_empty() {
        parts.push(format!(
            "consequences={}",
            proposal
                .consequences
                .iter()
                .map(|c| c.consequence_type.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if !proposal.relationship_hits.is_empty() {
        parts.push(format!("first_party_hits={}", proposal.relationship_hits.len()));
    }
    parts.join("; ")
}

fn build_receipt(proposal: &EnrichedActionProposal) -> EnrichmentReceipt {
    let tool_call_hash = hash_json(&json!({
        "name": proposal.tool_call.name,
        "parameters": proposal.tool_call.parameters,
    }));
    let proposal_hash = hash_json(&json!({
        "schema": proposal.schema,
        "tenant_id": proposal.tenant_id,
        "enrichment_mode": proposal.enrichment_mode,
        "tool_call": proposal.tool_call,
        "action_description": proposal.action_description,
        "narrative": proposal.narrative,
        "affected_principals": proposal.affected_principals,
        "affected_resources": proposal.affected_resources,
        "state_diff": proposal.state_diff,
        "consequences": proposal.consequences,
        "relationship_hits": proposal.relationship_hits,
        "consequence_metadata": proposal.consequence_metadata,
        "enricher_versions": proposal.enricher_versions,
    }));
    let suffix = proposal_hash
        .trim_start_matches("blake3:")
        .chars()
        .take(16)
        .collect::<String>();
    EnrichmentReceipt {
        schema: ACTION_ENRICHMENT_RECEIPT_SCHEMA,
        receipt_id: format!("action_enrichment:{suffix}"),
        event_type: "action_enrichment_capsule",
        tenant_id: proposal.tenant_id.clone(),
        tool_call_hash,
        proposal_hash,
        enrichment_mode: proposal.enrichment_mode.clone(),
        enricher_versions: proposal.enricher_versions.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

pub fn hash_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(n.to_string()),
        Value::Bool(b) => out.push(b.to_string()),
        Value::Array(values) => values.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(map) => {
            for (key, value) in map {
                out.push(key.clone());
                collect_strings(value, out);
            }
        }
        Value::Null => {}
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn dedup_principals(principals: &mut Vec<AffectedPrincipal>) {
    principals.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.role.cmp(&b.role)));
    principals.dedup_by(|a, b| a.id == b.id && a.role == b.role);
}

fn dedup_resources(resources: &mut Vec<AffectedResource>) {
    resources.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.resource_type.cmp(&b.resource_type)));
    resources.dedup_by(|a, b| a.id == b.id && a.resource_type == b.resource_type);
}

fn dedup_consequences(consequences: &mut Vec<ActionConsequence>) {
    consequences.sort_by(|a, b| {
        a.consequence_type
            .cmp(&b.consequence_type)
            .then_with(|| a.target.cmp(&b.target))
    });
    consequences.dedup_by(|a, b| a.consequence_type == b.consequence_type && a.target == b.target);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_store::StoreFact;

    #[test]
    fn classifies_calendar_customer_action() {
        let proposal = enrich_action(
            None,
            ActionEnrichmentInput {
                tenant_id: Some("business::acme".to_string()),
                tool_name: "calendar.move_event".to_string(),
                tool_parameters: json!({
                    "event_id": "evt_123",
                    "attendees": ["sarah@example.com", "customer@example.com"],
                    "new_time": "2026-05-08T16:00:00Z"
                }),
                action_description: Some("Move customer meeting to Friday at 4pm".to_string()),
                include_first_party_enrichers: false,
            },
        );

        assert_eq!(proposal.schema, ACTION_ENRICHMENT_SCHEMA);
        assert_eq!(proposal.consequence_metadata.domain, ActionDomain::EmailCalendar);
        assert!(proposal
            .consequence_metadata
            .materiality
            .contains(&Materiality::CreatesExternalObligation));
        assert_eq!(proposal.affected_principals.len(), 2);
        assert!(proposal.narrative.contains("external_obligation"));
        assert!(proposal.enrichment_receipt.is_some());
    }

    #[test]
    fn first_party_enrichment_uses_related_facts_without_raw_values() {
        let mut store = FactStore::new();
        let fact = store.store(StoreFact {
            entity: "business::acme::customer::acme-cfo".to_string(),
            key: "constraint".to_string(),
            value: "Sarah has a Thursday prep constraint for this customer".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        horizon_class: None,
        });

        let proposal = enrich_action(
            Some(&store),
            ActionEnrichmentInput {
                tenant_id: Some("business::acme".to_string()),
                tool_name: "calendar.move_event".to_string(),
                tool_parameters: json!({ "customer": "acme", "attendees": ["sarah@example.com"] }),
                action_description: Some("Move Acme customer meeting".to_string()),
                include_first_party_enrichers: true,
            },
        );

        assert_eq!(proposal.enrichment_mode, "first_party");
        assert!(proposal.relationship_hits.iter().any(|hit| hit.fact_id == fact.fact_id));
        assert!(proposal.narrative.contains("first_party_hits=1"));
        assert!(!serde_json::to_string(&proposal.relationship_hits)
            .unwrap()
            .contains("Thursday prep"));
    }

    #[test]
    fn first_party_enrichment_uses_domain_enricher_boundary() {
        let mut store = FactStore::new();
        store.store(StoreFact {
            entity: "business::acme::calendar::customer-meeting".to_string(),
            key: "availability".to_string(),
            value: "Acme CFO meeting has external customer attendee and conflict context".to_string(),
            source_receipt: Some("calendar:receipt".to_string()),
            confidence: 1.0,
            private: false,
        horizon_class: None,
        });

        let proposal = enrich_action(
            Some(&store),
            ActionEnrichmentInput {
                tenant_id: Some("business::acme".to_string()),
                tool_name: "calendar.reschedule_event".to_string(),
                tool_parameters: json!({
                    "event_id": "evt_acme",
                    "attendees": ["cfo@acme.example"],
                    "new_time": "2026-05-08T16:00:00Z"
                }),
                action_description: Some("Reschedule customer meeting with Acme CFO".to_string()),
                include_first_party_enrichers: true,
            },
        );

        assert!(proposal
            .enricher_versions
            .contains(&"email-calendar-domain-enricher-v1.local".to_string()));
        assert!(proposal
            .relationship_hits
            .iter()
            .any(|hit| hit.match_strength == "email-calendar-domain-enricher-v1.local:fact_store_match"));
        assert!(proposal
            .consequences
            .iter()
            .any(|consequence| consequence.consequence_type == "schedule_or_message_change"));
        assert!(proposal
            .consequences
            .iter()
            .any(|consequence| consequence.consequence_type == "customer_facing_commitment"));
    }

    #[test]
    fn delete_payment_is_irreversible_and_must_not_retry() {
        let metadata = consequence_metadata_for_tool(
            "billing.delete_payment",
            Some(&json!({"customer_id": "c_1", "payment_id": "pay_1"})),
            None,
        );

        assert_eq!(metadata.domain, ActionDomain::CrmCustomer);
        assert_eq!(metadata.reversibility, Reversibility::Irreversible);
        assert_eq!(metadata.idempotency_class, IdempotencyClass::MustNotRetry);
        assert!(metadata.materiality.contains(&Materiality::TouchesMoney));
    }

    #[test]
    fn classifier_covers_domain_materiality_and_compensation_edges() {
        let code = consequence_metadata_for_tool(
            "github.deploy_release",
            Some(&json!({"repo": "cuecrux/crux", "branch": "main", "environment": "production", "project": "crux"})),
            Some("Deploy production route and API changes"),
        );
        assert_eq!(code.domain, ActionDomain::Code);
        assert_eq!(code.blast_radius, BlastRadius::Tenant);
        assert_eq!(code.reversibility, Reversibility::ReversibleWithCompensation);
        assert_eq!(code.idempotency_class, IdempotencyClass::MustNotRetry);
        assert_eq!(
            code.compensating_tool.as_deref(),
            Some("github.deploy_release.rollback")
        );
        assert!(code.materiality.contains(&Materiality::TouchesProduction));

        let file = consequence_metadata_for_tool(
            "drive.rename_document",
            Some(&json!({"document_id": "doc_1", "path": "/Team/Plan.md", "new_name": "Plan v2.md"})),
            None,
        );
        assert_eq!(file.domain, ActionDomain::File);
        assert_eq!(file.reversibility, Reversibility::ReversibleWithCompensation);
        assert_eq!(file.idempotency_class, IdempotencyClass::RequiresKey);
        assert_eq!(
            file.compensating_tool.as_deref(),
            Some("drive.rename_document.restore_previous_state")
        );

        let sync = consequence_metadata_for_tool(
            "tenant.promote_collection",
            Some(&json!({"tenant_id": "business::acme", "collection": "facts"})),
            None,
        );
        assert_eq!(sync.domain, ActionDomain::Sync);
        assert_eq!(sync.blast_radius, BlastRadius::Tenant);
        assert_eq!(sync.reversibility, Reversibility::ReversibleWithCompensation);

        let memory = consequence_metadata_for_tool(
            "facts.store_private_session",
            Some(&json!({"passport_id": "pass_1", "session_id": "sess_1", "private": true})),
            None,
        );
        assert_eq!(memory.domain, ActionDomain::Memory);
        assert!(memory.materiality.contains(&Materiality::LocalPrivateMemory));

        let extension = consequence_metadata_for_tool(
            "extension.invoke_wasm",
            Some(&json!({"manifest": "tool.json", "tool": "summarise"})),
            None,
        );
        assert_eq!(extension.domain, ActionDomain::Extension);
        assert_eq!(extension.blast_radius, BlastRadius::SelfOnly);

        let read = consequence_metadata_for_tool("status.list", Some(&json!({"preview": true})), None);
        assert_eq!(read.reversibility, Reversibility::Reversible);
        assert_eq!(read.idempotency_class, IdempotencyClass::Safe);

        let unknown = consequence_metadata_for_tool("opaque_tool", Some(&json!({"value": 7})), None);
        assert_eq!(unknown.domain, ActionDomain::General);
        assert_eq!(unknown.reversibility, Reversibility::Unknown);
        assert_eq!(unknown.idempotency_class, IdempotencyClass::Unknown);
    }

    #[test]
    fn first_party_enrichers_cover_code_file_crm_and_memory_domains() {
        let mut store = FactStore::new();
        store.store(StoreFact {
            entity: "business::acme::repo::crux".to_string(),
            key: "route".to_string(),
            value: "API route deploy requires command ledger evidence".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        horizon_class: None,
        });
        store.store(StoreFact {
            entity: "business::acme::file::plan".to_string(),
            key: "document".to_string(),
            value: "Drive document contains launch checklist".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        horizon_class: None,
        });
        store.store(StoreFact {
            entity: "business::acme::customer::acme".to_string(),
            key: "contract".to_string(),
            value: "Customer contract invoice and opportunity context".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        horizon_class: None,
        });
        store.store(StoreFact {
            entity: "__constraints__::business::acme::policy".to_string(),
            key: "policy".to_string(),
            value: "Never promote tenant memory without approval".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
        horizon_class: None,
        });
        store.store(StoreFact {
            entity: "business::acme::private::session".to_string(),
            key: "memory".to_string(),
            value: "private session memory should be skipped by enrichers".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
        horizon_class: None,
        });

        let cases = [
            (
                "github.update_route",
                json!({"repo": "crux", "route": "/v1/query/answer", "deploy": true}),
                "Update API route before deploy",
                "code-domain-enricher-v1.local",
                "route_or_api_surface_touch",
            ),
            (
                "drive.update_file",
                json!({"path": "/Team/launch.md", "document_id": "doc_launch"}),
                "Update launch document",
                "file-domain-enricher-v1.local",
                "file_or_document_touch",
            ),
            (
                "crm.update_opportunity",
                json!({"customer_id": "acme", "invoice_id": "inv_1"}),
                "Update Acme customer opportunity",
                "crm-customer-domain-enricher-v1.local",
                "customer_commercial_record_touch",
            ),
            (
                "memory.promote_constraint",
                json!({"tenant_id": "business::acme", "constraint_id": "policy"}),
                "Promote tenant policy memory",
                "tenant-memory-domain-enricher-v1.local",
                "policy_context",
            ),
        ];

        for (tool_name, tool_parameters, description, version, expected_consequence) in cases {
            let proposal = enrich_action(
                Some(&store),
                ActionEnrichmentInput {
                    tenant_id: Some("business::acme".to_string()),
                    tool_name: tool_name.to_string(),
                    tool_parameters,
                    action_description: Some(description.to_string()),
                    include_first_party_enrichers: true,
                },
            );
            assert!(
                proposal.enricher_versions.iter().any(|item| item.ends_with(".local")),
                "expected a local domain enricher in {:?}, wanted {version}",
                proposal.enricher_versions
            );
            assert!(proposal
                .consequences
                .iter()
                .any(|consequence| consequence.consequence_type == expected_consequence));
            assert!(proposal
                .relationship_hits
                .iter()
                .all(|hit| !hit.entity.contains("private::session")));
            assert!(proposal
                .enrichment_receipt
                .as_ref()
                .unwrap()
                .proposal_hash
                .starts_with("blake3:"));
        }
    }

    #[test]
    fn first_party_requested_without_store_reports_degraded_domain_versions() {
        let cases = [
            (
                "github.deploy",
                json!({"repo": "crux"}),
                "code-domain-enricher-v1.local",
            ),
            (
                "drive.update_file",
                json!({"path": "/docs/a.md"}),
                "file-domain-enricher-v1.local",
            ),
            (
                "calendar.send_invite",
                json!({"attendees": ["customer@example.com"]}),
                "email-calendar-domain-enricher-v1.local",
            ),
            (
                "crm.refund_invoice",
                json!({"invoice_id": "inv_1", "customer_id": "acme"}),
                "crm-customer-domain-enricher-v1.local",
            ),
            (
                "facts.update_memory",
                json!({"entity": "memory", "private": true}),
                "tenant-memory-domain-enricher-v1.local",
            ),
        ];

        for (tool_name, tool_parameters, version) in cases {
            let proposal = enrich_action(
                None,
                ActionEnrichmentInput {
                    tenant_id: Some("business::acme".to_string()),
                    tool_name: tool_name.to_string(),
                    tool_parameters,
                    action_description: None,
                    include_first_party_enrichers: true,
                },
            );
            assert!(
                proposal.enricher_versions.len() >= 2,
                "expected degraded first-party version marker {version}, got {:?}",
                proposal.enricher_versions
            );
            assert!(proposal
                .consequences
                .iter()
                .any(|consequence| consequence.consequence_type == "first_party_context_unavailable"));
            assert!(proposal.narrative.contains("first_party_context_unavailable"));
        }
    }

    #[test]
    fn enrichment_deduplicates_principals_resources_and_tracks_state_diff() {
        let proposal = enrich_action(
            None,
            ActionEnrichmentInput {
                tenant_id: None,
                tool_name: "calendar.update_event".to_string(),
                tool_parameters: json!({
                    "attendees": ["sarah@example.com", "sarah@example.com"],
                    "event_id": "evt_1",
                    "meeting": "evt_1",
                    "before": { "start": "2026-05-08T10:00:00Z" },
                    "after": { "start": "2026-05-08T11:00:00Z" },
                    "target_time": "2026-05-08T11:00:00Z",
                    "status": "confirmed"
                }),
                action_description: None,
                include_first_party_enrichers: false,
            },
        );

        assert_eq!(proposal.tenant_id, "local");
        assert_eq!(proposal.affected_principals.len(), 1);
        assert_eq!(proposal.affected_resources.len(), 2);
        assert!(proposal.state_diff.before.is_some());
        assert!(proposal.state_diff.after.is_some());
        assert!(proposal.state_diff.fields_changed.contains(&"target_time".to_string()));
        assert!(proposal.state_diff.fields_changed.contains(&"status".to_string()));
        assert!(proposal
            .narrative
            .contains("affected_principals=recipient:sarah@example.com"));
    }

    #[test]
    fn hash_and_receipt_outputs_are_stable_shape_for_nested_values() {
        let value = json!({
            "z": [3, 2, 1],
            "nested": { "flag": true, "count": 4, "none": null }
        });
        let hash = hash_json(&value);
        assert!(hash.starts_with("blake3:"));

        let proposal = enrich_action(
            None,
            ActionEnrichmentInput {
                tenant_id: Some("business::acme".to_string()),
                tool_name: "opaque_tool".to_string(),
                tool_parameters: value,
                action_description: Some("Inspect opaque payload".to_string()),
                include_first_party_enrichers: false,
            },
        );
        let receipt = proposal.enrichment_receipt.as_ref().unwrap();
        assert_eq!(receipt.schema, ACTION_ENRICHMENT_RECEIPT_SCHEMA);
        assert_eq!(receipt.event_type, "action_enrichment_capsule");
        assert_eq!(receipt.tenant_id, "business::acme");
        assert!(receipt.receipt_id.starts_with("action_enrichment:"));
        assert!(receipt.tool_call_hash.starts_with("blake3:"));
        assert!(receipt.proposal_hash.starts_with("blake3:"));
    }
}
