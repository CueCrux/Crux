// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sync client — pull facts from a remote CoreCrux instance and push local
//! facts back. Uses cursor-based pagination and best-effort error handling.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fact_store::{Fact, FactStore};
use crate::semantic::MemoryRecord;

/// Default entity prefixes that are never pushed to remote. Users can add
/// more via `CORECRUXD_SYNC_PRIVATE_PREFIXES`.
const DEFAULT_PRIVATE_PREFIXES: &[&str] = &[
    "finance:",
    "health:",
    "medical:",
    "personal:",
    "private:",
    "salary:",
    "tax:",
    "password:",
    "credential:",
    "secret:",
    "ssn:",
    "bank:",
    "__ops__::",
    "__bootstrap__::",
];

/// Client that synchronises facts between a local FactStore and a remote
/// CoreCrux HTTP API.
pub struct SyncClient {
    remote_url: String,
    api_key: String,
    cursor_path: PathBuf,
    /// Entity prefixes that are never pushed to the remote.
    private_prefixes: Vec<String>,
}

/// Persisted cursor tracking pull/push progress.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncCursor {
    pub last_pull_at: Option<String>,
    pub last_pull_cursor: Option<String>,
    pub last_push_at: Option<String>,
    pub pull_count: u64,
    pub push_count: u64,
    #[serde(default)]
    pub collection_pull_cursors: BTreeMap<String, String>,
    #[serde(default)]
    pub collection_push_cursors: BTreeMap<String, String>,
}

/// Result of a pull operation.
#[derive(Debug)]
pub struct SyncPullResult {
    pub facts_pulled: usize,
    pub new_cursor: Option<String>,
}

/// Result of a push operation.
#[derive(Debug)]
pub struct SyncPushResult {
    pub facts_pushed: usize,
}

/// Preview of what a push would send — no data leaves the machine.
#[derive(Debug)]
pub struct SyncPushPreview {
    /// Number of facts that would be pushed.
    pub pushable_count: usize,
    /// Number of facts skipped because they are private (flag or prefix).
    pub private_count: usize,
    /// Number of facts skipped because they came from sync (not locally created).
    pub synced_count: usize,
    /// Summary of entities that would be pushed (entity name → count).
    pub entity_summary: Vec<(String, usize)>,
}

pub const TENANT_SYNC_MANIFEST_SCHEMA: &str = "crux.sync.tenant_manifest.v1";
pub const TENANT_COLLECTION_PAGE_SCHEMA: &str = "crux.sync.collection_page.v1";
pub const TENANT_PROMOTION_PREVIEW_SCHEMA: &str = "crux.sync.promotion_preview.v1";
pub const TENANT_WIPE_RECEIPT_SCHEMA: &str = "crux.sync.tenant_wipe_receipt.v1";

pub const SYNC_COLLECTION_FACTS: &str = "facts";
pub const SYNC_COLLECTION_CONSTRAINTS: &str = "constraints";
pub const SYNC_COLLECTION_PLANS: &str = "plans";
pub const SYNC_COLLECTION_RECEIPTS: &str = "receipts";
pub const SYNC_COLLECTION_DOSSIERS: &str = "dossiers";
pub const SYNC_COLLECTION_PROJECTION_REVISIONS: &str = "projection_revisions";
pub const SYNC_COLLECTION_SEMANTIC_PROFILES: &str = "semantic_profiles";
pub const SYNC_COLLECTION_TOMBSTONES: &str = "tombstones";

pub const SYNC_COLLECTIONS: &[&str] = &[
    SYNC_COLLECTION_FACTS,
    SYNC_COLLECTION_CONSTRAINTS,
    SYNC_COLLECTION_PLANS,
    SYNC_COLLECTION_RECEIPTS,
    SYNC_COLLECTION_DOSSIERS,
    SYNC_COLLECTION_PROJECTION_REVISIONS,
    SYNC_COLLECTION_SEMANTIC_PROFILES,
    SYNC_COLLECTION_TOMBSTONES,
];

/// Input metadata for building a tenant sync manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantManifestInput {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub membership_epoch: u64,
    #[serde(default)]
    pub role_grants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantSyncManifest {
    pub schema: String,
    pub tenant_id: String,
    pub tenant_category: String,
    pub owner_hash: String,
    pub membership_epoch: u64,
    pub membership_hash: String,
    pub role_grant_hash: String,
    pub generated_at: String,
    pub collections: Vec<SyncCollectionCursor>,
    pub manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncCollectionCursor {
    pub collection: String,
    pub cursor: Option<String>,
    pub updated_since: Option<String>,
    pub record_count: usize,
    pub tombstone_count: usize,
    pub content_hash: String,
    #[serde(default)]
    pub merkle_ranges: Vec<SyncMerkleRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncMerkleRange {
    pub start_record_id: Option<String>,
    pub end_record_id: Option<String>,
    pub record_count: usize,
    pub range_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCollectionRecord {
    pub collection: String,
    pub record_id: String,
    pub entity: String,
    pub key: String,
    #[serde(default)]
    pub identity_hash: String,
    #[serde(default)]
    pub content_hash: String,
    pub value_hash: String,
    pub updated_at: String,
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_receipt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<Fact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCollectionPage {
    pub schema: String,
    pub tenant_id: String,
    pub collection: String,
    pub records: Vec<SyncCollectionRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub collection_hash: String,
    #[serde(default)]
    pub merkle_ranges: Vec<SyncMerkleRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPromotionPreview {
    pub schema: String,
    pub tenant_id: String,
    pub tenant_category: String,
    pub allowlist: Vec<String>,
    pub promote_count: usize,
    pub skipped_private: usize,
    pub skipped_synced: usize,
    pub skipped_not_allowlisted: usize,
    pub records: Vec<SyncCollectionRecord>,
    pub preview_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WipedCollection {
    pub collection: String,
    pub deleted_count: usize,
    pub pre_wipe_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantWipeReceipt {
    pub schema: String,
    pub tenant_id: String,
    pub tenant_category: String,
    pub membership_epoch: u64,
    pub wiped_at: String,
    pub wiped_collections: Vec<WipedCollection>,
    pub deleted_fact_ids: Vec<String>,
    pub tombstone_fact_ids: Vec<String>,
    pub receipt_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

pub fn tenant_category_from_id(tenant_id: &str) -> &'static str {
    let lower = tenant_id.to_ascii_lowercase();
    if lower.starts_with("business::") || lower.starts_with("work::") || lower.starts_with("team::") {
        "business"
    } else if lower.starts_with("public::") {
        "public"
    } else {
        "personal"
    }
}

pub fn build_tenant_manifest(store: &FactStore, input: TenantManifestInput) -> TenantSyncManifest {
    let tenant_category = input
        .tenant_category
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| tenant_category_from_id(&input.tenant_id).to_string());
    let owner_hash = hash_string(input.owner_id.as_deref().unwrap_or(&input.tenant_id));
    let mut role_grants = input.role_grants;
    role_grants.sort();
    role_grants.dedup();
    let role_grant_hash = hash_json(&role_grants);
    let membership_hash = hash_json(&serde_json::json!({
        "tenant_id": input.tenant_id,
        "tenant_category": tenant_category,
        "owner_hash": owner_hash,
        "membership_epoch": input.membership_epoch,
        "role_grant_hash": role_grant_hash,
    }));

    let collections = SYNC_COLLECTIONS
        .iter()
        .map(|collection| collection_cursor(store, &input.tenant_id, collection))
        .collect::<Vec<_>>();
    let mut manifest = TenantSyncManifest {
        schema: TENANT_SYNC_MANIFEST_SCHEMA.to_string(),
        tenant_id: input.tenant_id,
        tenant_category,
        owner_hash,
        membership_epoch: input.membership_epoch,
        membership_hash,
        role_grant_hash,
        generated_at: Utc::now().to_rfc3339(),
        collections,
        manifest_hash: String::new(),
    };
    manifest.manifest_hash = hash_manifest_without_hash(&manifest);
    manifest
}

pub fn tenant_collection_page(
    store: &FactStore,
    tenant_id: &str,
    collection: &str,
    cursor: Option<&str>,
    limit: usize,
    include_content: bool,
) -> Result<SyncCollectionPage, String> {
    validate_collection(collection)?;
    let mut records = collection_records(store, tenant_id, collection, include_content);
    records.sort_by(|a, b| {
        a.updated_at
            .cmp(&b.updated_at)
            .then_with(|| a.record_id.cmp(&b.record_id))
    });
    let start = cursor
        .and_then(|cursor| {
            records
                .iter()
                .position(|record| record.record_id == cursor)
                .map(|idx| idx + 1)
        })
        .unwrap_or(0);
    let limit = limit.clamp(1, 1000);
    let remaining = &records[start..];
    let page_records = remaining.iter().take(limit).cloned().collect::<Vec<_>>();
    let has_more = remaining.len() > limit;
    let next_cursor = if has_more {
        page_records.last().map(|record| record.record_id.clone())
    } else {
        None
    };
    let collection_hash = hash_records(&page_records);
    let merkle_ranges = merkle_ranges(&page_records);
    Ok(SyncCollectionPage {
        schema: TENANT_COLLECTION_PAGE_SCHEMA.to_string(),
        tenant_id: tenant_id.to_string(),
        collection: collection.to_string(),
        records: page_records,
        next_cursor,
        has_more,
        collection_hash,
        merkle_ranges,
    })
}

pub fn promotion_preview(
    store: &FactStore,
    tenant_id: &str,
    allowlist: &[String],
    include_content: bool,
) -> SyncPromotionPreview {
    let allowlist = normalise_allowlist(allowlist);
    let mut skipped_private = 0;
    let mut skipped_synced = 0;
    let mut skipped_not_allowlisted = 0;
    let mut records = Vec::new();
    for fact in store.all_facts() {
        if fact.deleted || !fact_belongs_to_tenant(fact, tenant_id) {
            continue;
        }
        if fact.source_receipt.as_deref().is_some_and(is_synced_receipt) {
            skipped_synced += 1;
            continue;
        }
        if fact.private {
            skipped_private += 1;
            continue;
        }
        let collection = classify_fact_collection(fact);
        if !promotion_allowlist_matches(&allowlist, collection, &fact.entity) {
            skipped_not_allowlisted += 1;
            continue;
        }
        records.push(record_from_fact(tenant_id, fact, collection, include_content));
    }
    records.sort_by(|a, b| {
        a.collection
            .cmp(&b.collection)
            .then_with(|| a.record_id.cmp(&b.record_id))
    });
    let preview_hash = hash_records(&records);
    SyncPromotionPreview {
        schema: TENANT_PROMOTION_PREVIEW_SCHEMA.to_string(),
        tenant_id: tenant_id.to_string(),
        tenant_category: tenant_category_from_id(tenant_id).to_string(),
        allowlist,
        promote_count: records.len(),
        skipped_private,
        skipped_synced,
        skipped_not_allowlisted,
        records,
        preview_hash,
    }
}

pub fn apply_promoted_records(store: &mut FactStore, records: &[SyncCollectionRecord], remote_url: &str) -> usize {
    let mut applied = 0;
    for record in records {
        let Some(mut fact) = record.fact.clone() else {
            continue;
        };
        if fact.private {
            continue;
        }
        fact.source_receipt = Some(format!(
            "sync-promotion:{}:{}",
            remote_url.trim_end_matches('/'),
            fact.fact_id
        ));
        store.store_synced(fact);
        applied += 1;
    }
    applied
}

pub fn offboard_tenant_mirror(store: &mut FactStore, tenant_id: &str, membership_epoch: u64) -> TenantWipeReceipt {
    let mut by_collection: BTreeMap<String, Vec<Fact>> = BTreeMap::new();
    for fact in store.all_facts() {
        if fact.deleted || !fact_belongs_to_tenant(fact, tenant_id) || !is_mirror_fact(fact) {
            continue;
        }
        by_collection
            .entry(classify_fact_collection(fact).to_string())
            .or_default()
            .push(fact.clone());
    }

    let mut wiped_collections = Vec::new();
    let mut deleted_fact_ids = Vec::new();
    let mut tombstone_fact_ids = Vec::new();
    for &collection in SYNC_COLLECTIONS {
        let facts = by_collection.remove(collection).unwrap_or_default();
        if facts.is_empty() {
            continue;
        }
        let pre_wipe_hash = hash_facts(tenant_id, &facts);
        let mut deleted_this_collection = 0usize;
        for fact in facts {
            if store.delete(&fact.fact_id) {
                deleted_this_collection += 1;
                deleted_fact_ids.push(fact.fact_id.clone());
                let tombstone = store.store(crate::fact_store::StoreFact {
                    entity: format!("__sync_tombstone__::{tenant_id}::{}", fact.fact_id),
                    key: "record".to_string(),
                    value: serde_json::json!({
                        "schema": "crux.sync.tombstone.v1",
                        "tenant_id": tenant_id,
                        "collection": collection,
                        "fact_id": fact.fact_id,
                        "entity": fact.entity,
                        "value_hash": hash_string(&fact.value),
                        "deleted_at": Utc::now().to_rfc3339(),
                    })
                    .to_string(),
                    source_receipt: Some(format!("sync-wipe:{tenant_id}")),
                    confidence: 1.0,
                    private: true,
                    horizon_class: None,
                });
                tombstone_fact_ids.push(tombstone.fact_id);
            }
        }
        wiped_collections.push(WipedCollection {
            collection: collection.to_string(),
            deleted_count: deleted_this_collection,
            pre_wipe_hash,
        });
    }

    let mut receipt = TenantWipeReceipt {
        schema: TENANT_WIPE_RECEIPT_SCHEMA.to_string(),
        tenant_id: tenant_id.to_string(),
        tenant_category: tenant_category_from_id(tenant_id).to_string(),
        membership_epoch,
        wiped_at: Utc::now().to_rfc3339(),
        wiped_collections,
        deleted_fact_ids,
        tombstone_fact_ids,
        receipt_hash: String::new(),
        signed_by: None,
        signature: None,
    };
    receipt.receipt_hash = hash_wipe_receipt_without_signature(&receipt);
    receipt
}

fn hash_string(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}

fn hash_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

fn hash_manifest_without_hash(manifest: &TenantSyncManifest) -> String {
    let mut clone = manifest.clone();
    clone.manifest_hash.clear();
    hash_json(&clone)
}

fn hash_wipe_receipt_without_signature(receipt: &TenantWipeReceipt) -> String {
    let mut clone = receipt.clone();
    clone.receipt_hash.clear();
    clone.signed_by = None;
    clone.signature = None;
    hash_json(&clone)
}

fn validate_collection(collection: &str) -> Result<(), String> {
    if SYNC_COLLECTIONS.contains(&collection) {
        Ok(())
    } else {
        Err(format!("unknown sync collection: {collection}"))
    }
}

fn tenant_prefixes(tenant_id: &str) -> Vec<String> {
    vec![
        format!("{tenant_id}::"),
        format!("{tenant_id}:"),
        format!("tenant::{tenant_id}::"),
        format!("tenant:{tenant_id}:"),
        format!("tenant://{tenant_id}/"),
        format!("__tenant__::{tenant_id}::"),
        format!("__tenant_mirror__::{tenant_id}::"),
        format!("__sync_tombstone__::{tenant_id}::"),
    ]
}

fn fact_belongs_to_tenant(fact: &Fact, tenant_id: &str) -> bool {
    if fact.entity == tenant_id {
        return true;
    }
    tenant_prefixes(tenant_id)
        .iter()
        .any(|prefix| fact.entity.starts_with(prefix))
}

fn is_synced_receipt(receipt: &str) -> bool {
    receipt.starts_with("sync:")
        || receipt.starts_with("sync-promotion:")
        || receipt.starts_with("mirror:")
        || receipt.starts_with("cloud:")
}

fn is_mirror_fact(fact: &Fact) -> bool {
    fact.entity.starts_with("__tenant_mirror__::") || fact.source_receipt.as_deref().is_some_and(is_synced_receipt)
}

fn tenant_sync_revoked(store: &FactStore, tenant_id: &str) -> bool {
    let receipt_entity = format!("__sync_wipe_receipt__::{tenant_id}");
    let wipe_source = format!("sync-wipe:{tenant_id}");
    store.all_facts().any(|fact| {
        !fact.deleted
            && (fact.entity == receipt_entity
                || fact
                    .source_receipt
                    .as_deref()
                    .is_some_and(|receipt| receipt == wipe_source))
    })
}

fn classify_fact_collection(fact: &Fact) -> &'static str {
    let entity = fact.entity.to_ascii_lowercase();
    let key = fact.key.to_ascii_lowercase();
    if fact.deleted || entity.starts_with("__sync_tombstone__::") || key.contains("tombstone") {
        return SYNC_COLLECTION_TOMBSTONES;
    }
    if entity.starts_with("__constraints__::") || entity.contains("::constraint::") || key.contains("constraint") {
        return SYNC_COLLECTION_CONSTRAINTS;
    }
    if entity.starts_with("__receipt__::") || key == "receipt" || key.ends_with("_receipt") {
        return SYNC_COLLECTION_RECEIPTS;
    }
    if entity.starts_with("__dossier__::") || entity.starts_with("__storybook__::") || key.contains("dossier") {
        return SYNC_COLLECTION_DOSSIERS;
    }
    if entity.starts_with("__projection__::")
        || entity.contains("::projection::")
        || key.contains("projection_revision")
    {
        return SYNC_COLLECTION_PROJECTION_REVISIONS;
    }
    if entity.starts_with("__semantic_profile__::") || key == "semantic_profile" || key.contains("semantic_profile") {
        return SYNC_COLLECTION_SEMANTIC_PROFILES;
    }
    if entity.starts_with("__work__::")
        || entity.starts_with("__project__::")
        || entity.contains("::plan::")
        || key == "plan"
        || key.ends_with("_plan")
        || key.contains("session_plan")
    {
        return SYNC_COLLECTION_PLANS;
    }
    SYNC_COLLECTION_FACTS
}

fn record_from_fact(tenant_id: &str, fact: &Fact, collection: &str, include_content: bool) -> SyncCollectionRecord {
    let memory_record = MemoryRecord::from_fact(tenant_id, collection, fact, false, None, None);
    SyncCollectionRecord {
        collection: collection.to_string(),
        record_id: fact.fact_id.clone(),
        entity: fact.entity.clone(),
        key: fact.key.clone(),
        identity_hash: memory_record.identity_hash,
        content_hash: memory_record.content_hash,
        value_hash: hash_string(&fact.value),
        updated_at: fact.stored_at.to_rfc3339(),
        deleted: fact.deleted,
        source_receipt: fact.source_receipt.clone(),
        semantic_profile_id: None,
        local_semantic_profile_id: None,
        fact: include_content.then(|| fact.clone()),
    }
}

fn collection_records(
    store: &FactStore,
    tenant_id: &str,
    collection: &str,
    include_content: bool,
) -> Vec<SyncCollectionRecord> {
    let mut records = store
        .all_facts()
        .filter(|fact| fact_belongs_to_tenant(fact, tenant_id))
        .filter(|fact| classify_fact_collection(fact) == collection)
        .map(|fact| record_from_fact(tenant_id, fact, collection, include_content))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.updated_at
            .cmp(&right.updated_at)
            .then_with(|| left.record_id.cmp(&right.record_id))
    });
    records
}

fn collection_cursor(store: &FactStore, tenant_id: &str, collection: &str) -> SyncCollectionCursor {
    let records = collection_records(store, tenant_id, collection, false);
    let updated_since = records
        .iter()
        .map(|record| record.updated_at.as_str())
        .max()
        .map(str::to_string);
    let tombstone_count = records.iter().filter(|record| record.deleted).count();
    SyncCollectionCursor {
        collection: collection.to_string(),
        cursor: records.last().map(|record| record.record_id.clone()),
        updated_since,
        record_count: records.len(),
        tombstone_count,
        content_hash: hash_records(&records),
        merkle_ranges: merkle_ranges(&records),
    }
}

fn hash_records(records: &[SyncCollectionRecord]) -> String {
    let stable = records
        .iter()
        .map(|record| {
            serde_json::json!({
                "collection": record.collection,
                "record_id": record.record_id,
                "entity": record.entity,
                "key": record.key,
                "identity_hash": record.identity_hash,
                "content_hash": record.content_hash,
                "value_hash": record.value_hash,
                "updated_at": record.updated_at,
                "deleted": record.deleted,
                "source_receipt": record.source_receipt,
                "semantic_profile_id": record.semantic_profile_id,
                "local_semantic_profile_id": record.local_semantic_profile_id,
            })
        })
        .collect::<Vec<_>>();
    hash_json(&stable)
}

pub fn sync_records_hash(records: &[SyncCollectionRecord]) -> String {
    hash_records(records)
}

fn merkle_ranges(records: &[SyncCollectionRecord]) -> Vec<SyncMerkleRange> {
    const RANGE_SIZE: usize = 128;
    records
        .chunks(RANGE_SIZE)
        .map(|chunk| SyncMerkleRange {
            start_record_id: chunk.first().map(|record| record.record_id.clone()),
            end_record_id: chunk.last().map(|record| record.record_id.clone()),
            record_count: chunk.len(),
            range_hash: hash_records(chunk),
        })
        .collect()
}

fn hash_facts(tenant_id: &str, facts: &[Fact]) -> String {
    let mut records = facts
        .iter()
        .map(|fact| record_from_fact(tenant_id, fact, classify_fact_collection(fact), false))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.collection
            .cmp(&right.collection)
            .then_with(|| left.record_id.cmp(&right.record_id))
    });
    hash_records(&records)
}

fn normalise_allowlist(allowlist: &[String]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for item in allowlist {
        let trimmed = item.trim().to_ascii_lowercase();
        if !trimmed.is_empty() {
            out.insert(trimmed);
        }
    }
    out.into_iter().collect()
}

fn promotion_allowlist_matches(allowlist: &[String], collection: &str, entity: &str) -> bool {
    let entity = entity.to_ascii_lowercase();
    allowlist.iter().any(|item| {
        item == collection
            || item == &format!("collection:{collection}")
            || item == "*"
            || item
                .strip_prefix("entity:")
                .is_some_and(|prefix| entity.starts_with(prefix))
    })
}

fn cursor_collection_key(tenant_id: &str, collection: &str) -> String {
    format!("{tenant_id}/{collection}")
}

fn encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// Runtime sync posture exposed to operators and agents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncRuntimeStatus {
    /// High-level operating mode: `local_only`, `manual_sync`, `sync_enabled`, or `degraded`.
    pub mode: String,
    /// Whether the remote sync target is fully configured.
    pub configured: bool,
    /// Whether the daemon background sync loop is enabled.
    pub background_sync_enabled: bool,
    /// Remote CoreCrux base URL when configured.
    pub remote_url: String,
    /// Whether an API key is configured for remote sync.
    pub api_key_configured: bool,
    /// Best-effort remote platform reachability probe result.
    pub platform_online: Option<bool>,
    /// Whether the node is operating in a degraded sync mode.
    pub degraded: bool,
    /// Human-readable reason when operating in a degraded or local-only mode.
    pub degraded_reason: Option<String>,
}

impl SyncRuntimeStatus {
    pub fn from_settings(background_sync_enabled: bool, remote_url: Option<&str>, api_key_configured: bool) -> Self {
        let remote_url = remote_url.unwrap_or_default().trim().to_string();
        let has_remote = !remote_url.is_empty();

        if !has_remote {
            return Self {
                mode: "local_only".to_string(),
                configured: false,
                background_sync_enabled,
                remote_url,
                api_key_configured,
                platform_online: None,
                degraded: false,
                degraded_reason: Some(
                    "remote sync is not configured; continuing with the local fact and session store only".to_string(),
                ),
            };
        }

        if !api_key_configured {
            return Self {
                mode: "degraded".to_string(),
                configured: false,
                background_sync_enabled,
                remote_url,
                api_key_configured,
                platform_online: None,
                degraded: true,
                degraded_reason: Some(
                    "sync remote is configured but CORECRUXD_SYNC_API_KEY is missing; continuing local-only"
                        .to_string(),
                ),
            };
        }

        Self {
            mode: if background_sync_enabled {
                "sync_enabled".to_string()
            } else {
                "manual_sync".to_string()
            },
            configured: true,
            background_sync_enabled,
            remote_url,
            api_key_configured,
            platform_online: None,
            degraded: false,
            degraded_reason: None,
        }
    }

    pub fn with_probe_result(mut self, probe: Result<(), String>) -> Self {
        if self.remote_url.is_empty() {
            return self;
        }

        match probe {
            Ok(()) => {
                self.platform_online = Some(true);
            }
            Err(err) => {
                self.platform_online = Some(false);
                self.mode = "degraded".to_string();
                self.degraded = true;
                self.degraded_reason = Some(format!(
                    "remote platform health check failed: {err}; continuing with the local fact and session store"
                ));
            }
        }
        self
    }
}

/// Best-effort health probe for a remote CoreCrux node.
pub fn probe_remote_health(remote_url: &str) -> Result<(), String> {
    let health_url = format!("{}/healthz", remote_url.trim_end_matches('/'));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(2)))
        .timeout_recv_response(Some(Duration::from_secs(2)))
        .timeout_recv_body(Some(Duration::from_secs(2)))
        .build()
        .into();
    agent.get(&health_url).call().map(|_| ()).map_err(|err| err.to_string())
}

impl SyncClient {
    /// Create a new sync client.
    ///
    /// * `remote_url` — base URL of the remote CoreCrux instance (e.g. `http://host:14800`)
    /// * `api_key` — bearer token for authentication
    /// * `data_dir` — directory where `sync-cursor.json` is persisted
    pub fn new(remote_url: &str, api_key: &str, data_dir: &std::path::Path) -> Self {
        // Merge default private prefixes with user-configured ones.
        let mut prefixes: Vec<String> = DEFAULT_PRIVATE_PREFIXES.iter().map(|s| (*s).to_string()).collect();
        if let Ok(extra) = std::env::var("CORECRUXD_SYNC_PRIVATE_PREFIXES") {
            for p in extra.split(',') {
                let p = p.trim();
                if !p.is_empty() {
                    prefixes.push(p.to_string());
                }
            }
        }
        Self {
            remote_url: remote_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            cursor_path: data_dir.join("sync-cursor.json"),
            private_prefixes: prefixes,
        }
    }

    /// Check whether a fact should be excluded from sync push.
    fn is_private(&self, fact: &Fact) -> bool {
        // Explicit private flag
        if fact.private {
            return true;
        }
        // Entity prefix blocklist
        let entity_lower = fact.entity.to_lowercase();
        self.private_prefixes
            .iter()
            .any(|prefix| entity_lower.starts_with(&prefix.to_lowercase()))
    }

    // ── Cursor persistence ───────────────────────────────────────────

    /// Load the sync cursor from disk, returning a default if the file is
    /// missing or unreadable.
    pub fn load_cursor(&self) -> SyncCursor {
        if !self.cursor_path.exists() {
            return SyncCursor::default();
        }
        match std::fs::read_to_string(&self.cursor_path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(err) => {
                tracing::warn!(?err, path = %self.cursor_path.display(), "sync-cursor-load-failed");
                SyncCursor::default()
            }
        }
    }

    /// Atomically save the sync cursor (write to temp file + rename).
    pub fn save_cursor(&self, cursor: &SyncCursor) {
        let result = (|| -> std::io::Result<()> {
            let tmp = self.cursor_path.with_extension("json.tmp");
            let data = serde_json::to_string_pretty(cursor).map_err(std::io::Error::other)?;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.cursor_path)?;
            Ok(())
        })();
        if let Err(err) = result {
            tracing::warn!(?err, path = %self.cursor_path.display(), "sync-cursor-save-failed");
        }
    }

    // ── Pull ─────────────────────────────────────────────────────────

    /// Pull facts from the remote export endpoint into the local store.
    ///
    /// Resumes from the last pull cursor. Pulled facts are tagged with a
    /// `source_receipt` starting with `sync:` so they are not pushed back.
    pub fn pull(&self, store: &mut FactStore) -> Result<SyncPullResult, String> {
        let cursor = self.load_cursor();
        let mut total_pulled = 0usize;
        let mut current_cursor = cursor.last_pull_cursor.clone();
        let since = cursor.last_pull_at.clone();

        loop {
            let mut url = format!("{}/v1/facts/export?limit=1000", self.remote_url);
            if let Some(ref s) = since {
                use std::fmt::Write;
                let _ = write!(url, "&since={s}");
            }
            if let Some(ref c) = current_cursor {
                use std::fmt::Write;
                let _ = write!(url, "&cursor={c}");
            }

            let mut resp = ureq::get(&url)
                .header("Authorization", &format!("Bearer {}", self.api_key))
                .call()
                .map_err(|e| format!("sync pull failed: {e}"))?;

            let body: serde_json::Value = resp
                .body_mut()
                .read_json()
                .map_err(|e| format!("sync pull parse error: {e}"))?;

            let facts: Vec<Fact> =
                serde_json::from_value(body["facts"].clone()).map_err(|e| format!("sync facts parse: {e}"))?;

            for mut fact in facts {
                // Tag as synced so we don't push it back
                fact.source_receipt = Some(format!("sync:{}:{}", self.remote_url, fact.fact_id));
                store.store_synced(fact);
                total_pulled += 1;
            }

            let has_more = body["has_more"].as_bool().unwrap_or(false);
            current_cursor = body["next_cursor"].as_str().map(String::from);

            if !has_more {
                break;
            }
        }

        // Update cursor
        let mut cursor = self.load_cursor();
        cursor.last_pull_at = Some(Utc::now().to_rfc3339());
        cursor.last_pull_cursor.clone_from(&current_cursor);
        cursor.pull_count += total_pulled as u64;
        self.save_cursor(&cursor);

        Ok(SyncPullResult {
            facts_pulled: total_pulled,
            new_cursor: current_cursor,
        })
    }

    /// Pull every collection in a tenant sync manifest into the local mirror.
    ///
    /// This uses the collection-aware `/v1/sync/tenants/*` API rather than the
    /// legacy all-facts export. Pulled facts are still tagged with `sync:` so
    /// they remain mirror data and are excluded from local promotion previews.
    pub fn pull_tenant_mirror(&self, store: &mut FactStore, tenant_id: &str) -> Result<SyncPullResult, String> {
        if tenant_sync_revoked(store, tenant_id) {
            return Err(format!(
                "tenant mirror sync is locally revoked for {tenant_id}; business offboarding wipe proof is present"
            ));
        }
        let tenant = encode_path_segment(tenant_id);
        let manifest_url = format!("{}/v1/sync/tenants/{tenant}/manifest", self.remote_url);
        let mut resp = ureq::get(&manifest_url)
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .call()
            .map_err(|e| format!("tenant sync manifest pull failed: {e}"))?;
        let manifest: TenantSyncManifest = resp
            .body_mut()
            .read_json()
            .map_err(|e| format!("tenant sync manifest parse error: {e}"))?;

        let mut cursor = self.load_cursor();
        let mut total_pulled = 0usize;
        for collection in manifest.collections {
            if collection.record_count == 0 {
                continue;
            }
            let key = cursor_collection_key(tenant_id, &collection.collection);
            let mut current_cursor = cursor.collection_pull_cursors.get(&key).cloned();
            loop {
                let mut url = format!(
                    "{}/v1/sync/tenants/{tenant}/collections/{}?limit=1000&include_content=true",
                    self.remote_url, collection.collection
                );
                if let Some(current) = current_cursor.as_deref() {
                    use std::fmt::Write as _;
                    let _ = write!(url, "&cursor={}", encode_path_segment(current));
                }
                let mut resp = ureq::get(&url)
                    .header("Authorization", &format!("Bearer {}", self.api_key))
                    .call()
                    .map_err(|e| format!("tenant collection pull failed: {e}"))?;
                let page: SyncCollectionPage = resp
                    .body_mut()
                    .read_json()
                    .map_err(|e| format!("tenant collection page parse error: {e}"))?;

                for record in page.records {
                    let Some(mut fact) = record.fact else {
                        continue;
                    };
                    fact.source_receipt = Some(format!("sync:{}:{}", self.remote_url, fact.fact_id));
                    store.store_synced(fact);
                    total_pulled += 1;
                }

                current_cursor.clone_from(&page.next_cursor);
                if let Some(next) = current_cursor.as_deref() {
                    cursor.collection_pull_cursors.insert(key.clone(), next.to_string());
                }
                if !page.has_more {
                    break;
                }
            }
        }

        cursor.last_pull_at = Some(Utc::now().to_rfc3339());
        cursor.pull_count += total_pulled as u64;
        self.save_cursor(&cursor);
        Ok(SyncPullResult {
            facts_pulled: total_pulled,
            new_cursor: None,
        })
    }

    // ── Push ─────────────────────────────────────────────────────────

    /// Preview what a push would send. No data leaves the machine.
    pub fn push_preview(&self, store: &FactStore) -> SyncPushPreview {
        let cursor = self.load_cursor();
        let since = cursor
            .last_push_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let mut pushable_count = 0usize;
        let mut private_count = 0usize;
        let mut synced_count = 0usize;
        let mut entity_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for fact in store.all_facts() {
            if fact.deleted {
                continue;
            }
            if since.is_some_and(|s| fact.stored_at <= s) {
                continue;
            }
            if fact.source_receipt.as_deref().is_some_and(|r| r.starts_with("sync:")) {
                synced_count += 1;
                continue;
            }
            if self.is_private(fact) {
                private_count += 1;
                continue;
            }
            pushable_count += 1;
            *entity_counts.entry(fact.entity.clone()).or_default() += 1;
        }

        let mut entity_summary: Vec<(String, usize)> = entity_counts.into_iter().collect();
        entity_summary.sort_by(|a, b| b.1.cmp(&a.1));

        SyncPushPreview {
            pushable_count,
            private_count,
            synced_count,
            entity_summary,
        }
    }

    /// Push local-only facts to the remote `/v1/facts/bulk` endpoint.
    ///
    /// Only non-deleted facts that were NOT received via sync (i.e. whose
    /// `source_receipt` does not start with `sync:`) are pushed.
    pub fn push(&self, store: &FactStore) -> Result<SyncPushResult, String> {
        let local_facts = self.pushable_facts(store);
        self.push_facts(&local_facts)
    }

    /// Snapshot pushable facts while the caller holds any store lock.
    pub fn pushable_facts(&self, store: &FactStore) -> Vec<Fact> {
        let cursor = self.load_cursor();
        let since = cursor
            .last_push_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        store
            .all_facts()
            .filter(|f| !f.deleted)
            .filter(|f| !self.is_private(f))
            .filter(|f| f.source_receipt.as_deref().is_none_or(|r| !r.starts_with("sync:")))
            .filter(|f| since.is_none_or(|s| f.stored_at > s))
            .cloned()
            .collect()
    }

    /// Push an already-snapshotted set of facts without touching the store.
    pub fn push_facts(&self, local_facts: &[Fact]) -> Result<SyncPushResult, String> {
        if local_facts.is_empty() {
            return Ok(SyncPushResult { facts_pushed: 0 });
        }

        // Convert to StoreFact-compatible JSON for bulk upload
        let store_facts: Vec<serde_json::Value> = local_facts
            .iter()
            .map(|f| {
                serde_json::json!({
                    "entity": f.entity,
                    "key": f.key,
                    "value": f.value,
                    "confidence": f.confidence,
                    "source_receipt": f.source_receipt,
                })
            })
            .collect();

        // Push in batches of 500
        let mut pushed = 0;
        for batch in store_facts.chunks(500) {
            ureq::put(&format!("{}/v1/facts/bulk", self.remote_url))
                .header("Authorization", &format!("Bearer {}", self.api_key))
                .send_json(serde_json::Value::Array(batch.to_vec()))
                .map_err(|e| format!("sync push failed: {e}"))?;
            pushed += batch.len();
        }

        // Update cursor
        let mut cursor = self.load_cursor();
        cursor.last_push_at = Some(Utc::now().to_rfc3339());
        cursor.push_count += pushed as u64;
        self.save_cursor(&cursor);

        Ok(SyncPushResult { facts_pushed: pushed })
    }

    /// Promote collection-aware tenant records to a remote CoreCrux node.
    pub fn push_tenant_promotion(
        &self,
        tenant_id: &str,
        records: &[SyncCollectionRecord],
    ) -> Result<SyncPushResult, String> {
        if records.is_empty() {
            return Ok(SyncPushResult { facts_pushed: 0 });
        }

        let tenant = encode_path_segment(tenant_id);
        let record_hash = sync_records_hash(records);
        let url = format!("{}/v1/sync/tenants/{tenant}/promotions/confirm", self.remote_url);
        let mut resp = ureq::post(&url)
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .send_json(serde_json::json!({
                "records": records,
                "confirm_hash": record_hash,
            }))
            .map_err(|e| format!("tenant promotion push failed: {e}"))?;
        let body: serde_json::Value = resp
            .body_mut()
            .read_json()
            .map_err(|e| format!("tenant promotion response parse error: {e}"))?;
        let applied = body["applied_count"]
            .as_u64()
            .map_or(records.len(), |value| value as usize);

        let mut cursor = self.load_cursor();
        cursor.last_push_at = Some(Utc::now().to_rfc3339());
        cursor.push_count += applied as u64;
        for collection in records.iter().map(|record| record.collection.as_str()) {
            let key = cursor_collection_key(tenant_id, collection);
            cursor.collection_push_cursors.insert(key, record_hash.clone());
        }
        self.save_cursor(&cursor);

        Ok(SyncPushResult { facts_pushed: applied })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_store::StoreFact;

    #[test]
    fn test_sync_cursor_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let client = SyncClient::new("http://localhost:14800", "test-key", dir.path());

        // Default cursor
        let cursor = client.load_cursor();
        assert!(cursor.last_pull_at.is_none());
        assert!(cursor.last_pull_cursor.is_none());
        assert!(cursor.last_push_at.is_none());
        assert_eq!(cursor.pull_count, 0);
        assert_eq!(cursor.push_count, 0);

        // Save and reload
        let cursor = SyncCursor {
            last_pull_at: Some("2026-04-07T12:00:00+00:00".to_string()),
            last_pull_cursor: Some("f_abc123".to_string()),
            last_push_at: Some("2026-04-07T11:00:00+00:00".to_string()),
            pull_count: 42,
            push_count: 10,
            collection_pull_cursors: BTreeMap::new(),
            collection_push_cursors: BTreeMap::new(),
        };
        client.save_cursor(&cursor);

        let loaded = client.load_cursor();
        assert_eq!(loaded.last_pull_at, cursor.last_pull_at);
        assert_eq!(loaded.last_pull_cursor, cursor.last_pull_cursor);
        assert_eq!(loaded.last_push_at, cursor.last_push_at);
        assert_eq!(loaded.pull_count, 42);
        assert_eq!(loaded.push_count, 10);
    }

    #[test]
    fn test_store_synced_preserves_identity() {
        let mut store = FactStore::new();

        let original_id = "f_remote_abc123".to_string();
        let original_stored_at = Utc::now() - chrono::Duration::hours(1);

        let fact = Fact {
            fact_id: original_id.clone(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: Some("sync:http://remote:14800:f_remote_abc123".to_string()),
            confidence: 0.95,
            stored_at: original_stored_at,
            tokens: 2,
            deleted: false,
            version: 3,
            supersedes: Some("f_remote_prev".to_string()),
            private: false,
            horizon_class: crate::fact_store::HorizonClass::None,
            reverified_at: None,
        };

        store.store_synced(fact);

        // The fact should be retrievable with its original identity
        let retrieved = store.get(&original_id).unwrap();
        assert_eq!(retrieved.fact_id, original_id);
        assert_eq!(retrieved.version, 3);
        assert_eq!(retrieved.supersedes, Some("f_remote_prev".to_string()));
        assert_eq!(retrieved.stored_at, original_stored_at);
        assert_eq!(retrieved.entity, "proj");
        assert_eq!(retrieved.key, "status");
        assert_eq!(retrieved.value, "active");
        assert_eq!(retrieved.confidence, 0.95);
    }

    #[test]
    fn test_store_synced_persists_to_journal() {
        let dir = tempfile::tempdir().unwrap();
        let original_id = "f_synced_persist".to_string();

        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let fact = Fact {
                fact_id: original_id.clone(),
                entity: "e".to_string(),
                key: "k".to_string(),
                value: "v".to_string(),
                source_receipt: Some("sync:http://remote:14800:f_synced_persist".to_string()),
                confidence: 1.0,
                stored_at: Utc::now(),
                tokens: 1,
                deleted: false,
                version: 1,
                supersedes: None,
                private: false,
                horizon_class: crate::fact_store::HorizonClass::None,
                reverified_at: None,
            };
            store.store_synced(fact);
            assert_eq!(store.count(), 1);
        }

        // Rebuild from journal — synced fact should survive
        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 1);
            let retrieved = store.get(&original_id).unwrap();
            assert_eq!(retrieved.fact_id, original_id);
            assert_eq!(retrieved.value, "v");
        }
    }

    #[test]
    fn test_sync_cursor_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let client = SyncClient::new("http://localhost:14800", "key", dir.path());
        // No file saved — should return default
        let cursor = client.load_cursor();
        assert_eq!(cursor.pull_count, 0);
        assert_eq!(cursor.push_count, 0);
    }

    #[test]
    fn test_sync_cursor_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let cursor_path = dir.path().join("sync-cursor.json");
        std::fs::write(&cursor_path, "not valid json!!!").unwrap();

        let client = SyncClient::new("http://localhost:14800", "key", dir.path());
        let cursor = client.load_cursor();
        // Should fall back to default
        assert_eq!(cursor.pull_count, 0);
    }

    #[test]
    fn test_push_filters_synced_facts() {
        let mut store = FactStore::new();

        // Store a local fact
        store.store(StoreFact {
            entity: "local".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
        });

        // Store a synced fact (should be excluded from push)
        let synced = Fact {
            fact_id: "f_synced_remote".to_string(),
            entity: "remote".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: Some("sync:http://remote:14800:f_synced_remote".to_string()),
            confidence: 1.0,
            stored_at: Utc::now(),
            tokens: 1,
            deleted: false,
            version: 1,
            supersedes: None,
            private: false,
            horizon_class: crate::fact_store::HorizonClass::None,
            reverified_at: None,
        };
        store.store_synced(synced);

        // Verify: all_facts should see both, but local-only filter sees 1
        assert_eq!(store.all_facts().count(), 2);

        let local_only: Vec<_> = store
            .all_facts()
            .filter(|f| !f.deleted)
            .filter(|f| f.source_receipt.as_deref().is_none_or(|r| !r.starts_with("sync:")))
            .collect();
        assert_eq!(local_only.len(), 1);
        assert_eq!(local_only[0].entity, "local");
    }

    #[test]
    fn tenant_manifest_tracks_collection_hashes_and_membership() {
        let mut store = FactStore::new();
        store.store(StoreFact {
            entity: "work::acme::topic".to_string(),
            key: "summary".to_string(),
            value: "shared project context".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
        });
        store.store(StoreFact {
            entity: "work::acme::constraint::deploy".to_string(),
            key: "constraint".to_string(),
            value: "deploys require approval".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
        });

        let manifest = build_tenant_manifest(
            &store,
            TenantManifestInput {
                tenant_id: "work::acme".to_string(),
                tenant_category: None,
                owner_id: Some("owner-123".to_string()),
                membership_epoch: 7,
                role_grants: vec!["writer".to_string(), "reader".to_string(), "reader".to_string()],
            },
        );

        assert_eq!(manifest.schema, TENANT_SYNC_MANIFEST_SCHEMA);
        assert_eq!(manifest.tenant_category, "business");
        assert_eq!(manifest.membership_epoch, 7);
        assert!(manifest.owner_hash.starts_with("blake3:"));
        assert!(manifest.role_grant_hash.starts_with("blake3:"));
        assert!(manifest.manifest_hash.starts_with("blake3:"));
        assert_eq!(
            manifest
                .collections
                .iter()
                .find(|collection| collection.collection == SYNC_COLLECTION_FACTS)
                .unwrap()
                .record_count,
            1
        );
        assert_eq!(
            manifest
                .collections
                .iter()
                .find(|collection| collection.collection == SYNC_COLLECTION_CONSTRAINTS)
                .unwrap()
                .record_count,
            1
        );
    }

    #[test]
    fn tenant_collection_page_paginates_and_optionally_includes_content() {
        let mut store = FactStore::new();
        for idx in 0..3 {
            store.store(StoreFact {
                entity: format!("personal::one::note::{idx}"),
                key: "note".to_string(),
                value: format!("value {idx}"),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
        }

        let first = tenant_collection_page(&store, "personal::one", SYNC_COLLECTION_FACTS, None, 2, false).unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(first.has_more);
        assert!(first.records.iter().all(|record| record.fact.is_none()));
        assert!(first.records[0].identity_hash.starts_with("blake3:"));
        assert!(first.records[0].content_hash.starts_with("blake3:"));
        assert!(first.records[0].semantic_profile_id.is_none());

        let second = tenant_collection_page(
            &store,
            "personal::one",
            SYNC_COLLECTION_FACTS,
            first.next_cursor.as_deref(),
            2,
            true,
        )
        .unwrap();
        assert_eq!(second.records.len(), 1);
        assert!(!second.has_more);
        assert!(second.records[0].fact.is_some());
        assert!(second.collection_hash.starts_with("blake3:"));
    }

    #[test]
    fn promotion_preview_respects_allowlist_and_skip_rules() {
        let mut store = FactStore::new();
        let local = store.store(StoreFact {
            entity: "business::acme::memory".to_string(),
            key: "summary".to_string(),
            value: "promote me".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
        });
        store.store(StoreFact {
            entity: "business::acme::private".to_string(),
            key: "summary".to_string(),
            value: "do not promote".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
        });
        store.store_synced(Fact {
            fact_id: "f_synced_business".to_string(),
            entity: "business::acme::remote".to_string(),
            key: "summary".to_string(),
            value: "already synced".to_string(),
            source_receipt: Some("sync:http://cloud:f_synced_business".to_string()),
            confidence: 1.0,
            stored_at: Utc::now(),
            tokens: 2,
            deleted: false,
            version: 1,
            supersedes: None,
            private: false,
            horizon_class: crate::fact_store::HorizonClass::None,
            reverified_at: None,
        });
        store.store(StoreFact {
            entity: "business::acme::constraint::deploy".to_string(),
            key: "constraint".to_string(),
            value: "not allowlisted".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
        });

        let preview = promotion_preview(&store, "business::acme", &["facts".to_string()], true);
        assert_eq!(preview.promote_count, 1);
        assert_eq!(preview.skipped_private, 1);
        assert_eq!(preview.skipped_synced, 1);
        assert_eq!(preview.skipped_not_allowlisted, 1);
        assert_eq!(preview.records[0].record_id, local.fact_id);
        assert!(preview.records[0].identity_hash.starts_with("blake3:"));
        assert!(preview.records[0].content_hash.starts_with("blake3:"));
        assert!(preview.records[0].fact.is_some());
        assert!(preview.preview_hash.starts_with("blake3:"));
    }

    #[test]
    fn offboard_tenant_mirror_deletes_only_synced_tenant_data_and_writes_tombstones() {
        let mut store = FactStore::new();
        let local = store.store(StoreFact {
            entity: "business::acme::local".to_string(),
            key: "summary".to_string(),
            value: "local-only should stay".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
        });
        let other = store.store(StoreFact {
            entity: "business::other::remote".to_string(),
            key: "summary".to_string(),
            value: "other tenant should stay".to_string(),
            source_receipt: Some("sync:http://cloud:f_other".to_string()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
        });
        store.store_synced(Fact {
            fact_id: "f_mirror_fact".to_string(),
            entity: "business::acme::remote".to_string(),
            key: "summary".to_string(),
            value: "delete mirrored fact".to_string(),
            source_receipt: Some("sync:http://cloud:f_mirror_fact".to_string()),
            confidence: 1.0,
            stored_at: Utc::now(),
            tokens: 3,
            deleted: false,
            version: 1,
            supersedes: None,
            private: false,
            horizon_class: crate::fact_store::HorizonClass::None,
            reverified_at: None,
        });

        let receipt = offboard_tenant_mirror(&mut store, "business::acme", 11);

        assert!(store.get(&local.fact_id).is_some());
        assert!(store.get(&other.fact_id).is_some());
        assert!(store.get("f_mirror_fact").is_none());
        assert_eq!(receipt.membership_epoch, 11);
        assert_eq!(receipt.deleted_fact_ids, vec!["f_mirror_fact".to_string()]);
        assert_eq!(receipt.tombstone_fact_ids.len(), 1);
        assert_eq!(receipt.wiped_collections[0].deleted_count, 1);
        assert!(receipt.receipt_hash.starts_with("blake3:"));
        assert_eq!(store.get(&receipt.tombstone_fact_ids[0]).unwrap().private, true);

        let dir = tempfile::tempdir().unwrap();
        let client = SyncClient::new("http://example.test:14800", "test-key", dir.path());
        let err = client.pull_tenant_mirror(&mut store, "business::acme").unwrap_err();
        assert!(err.contains("locally revoked"));
    }
}
