// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Coordinator client (`CoordinatorClient`) — wraps shard-coordinator HTTP for `corecruxctl shard` subcommands.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug)]
pub struct CoordinatorClient {
    base: String,
}

impl CoordinatorClient {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        let p = path.trim_start_matches('/');
        format!("{}/{}", self.base, p)
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.url(path);
        let text = ureq::get(&url).call()?.into_body().read_to_string()?;
        Ok(serde_json::from_str(&text)?)
    }

    fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.url(path);
        let text = ureq::post(&url)
            .send_json(serde_json::to_value(body)?)?
            .into_body()
            .read_to_string()?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn create_move(
        &self,
        req: &MoveCreateRequest,
    ) -> Result<OrchestrationRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.post_json("/v1/moves", req)
    }

    pub fn create_split(
        &self,
        req: &SplitCreateRequest,
    ) -> Result<OrchestrationRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.post_json("/v1/splits", req)
    }

    pub fn list_moves(&self) -> Result<Vec<OrchestrationRecord>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_json("/v1/moves")
    }

    pub fn list_splits(&self) -> Result<Vec<OrchestrationRecord>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_json("/v1/splits")
    }

    pub fn list_leases(&self) -> Result<Vec<LeaseRecord>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_json("/v1/leases")
    }
}

#[derive(Debug)]
pub struct CoreCruxClient {
    base: String,
}

impl CoreCruxClient {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        let p = path.trim_start_matches('/');
        format!("{}/{}", self.base, p)
    }

    pub fn get_shard_map(&self) -> Result<corecrux_types::ShardMapV1, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.url("/v1/shard-map");
        let text = ureq::get(&url).call()?.into_body().read_to_string()?;
        let parsed: ShardMapResponse = serde_json::from_str(&text)?;
        Ok(parsed.shard_map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveCreateRequest {
    #[serde(rename = "jobId", skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "shardId")]
    pub shard_id: String,
    #[serde(rename = "sourceNodeId")]
    pub source_node_id: String,
    #[serde(rename = "targetNodeId")]
    pub target_node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitCreateRequest {
    #[serde(rename = "jobId", skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "shardId")]
    pub shard_id: String,
    #[serde(rename = "atHashHex")]
    pub at_hash_hex: String,
    #[serde(rename = "newShardId")]
    pub new_shard_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationRecord {
    #[serde(rename = "jobId")]
    pub job_id: String,
    pub kind: String,
    #[serde(rename = "shardId")]
    pub shard_id: String,
    #[serde(rename = "sourceNodeId")]
    pub source_node_id: Option<String>,
    #[serde(rename = "targetNodeId")]
    pub target_node_id: Option<String>,
    #[serde(rename = "atHashHex")]
    pub at_hash_hex: Option<String>,
    #[serde(rename = "newShardId")]
    pub new_shard_id: Option<String>,
    pub status: String,
    #[serde(rename = "createdUnixMs")]
    pub created_unix_ms: i64,
    #[serde(rename = "updatedUnixMs")]
    pub updated_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRecord {
    #[serde(rename = "shardId")]
    pub shard_id: String,
    #[serde(rename = "leaderNodeId")]
    pub leader_node_id: String,
    pub epoch: u64,
    #[serde(rename = "leaseExpiresUnixMs")]
    pub lease_expires_unix_ms: i64,
    #[serde(rename = "updatedUnixMs")]
    pub updated_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShardMapResponse {
    #[serde(rename = "shardMap")]
    shard_map: corecrux_types::ShardMapV1,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubmitReport {
    pub ok: bool,
    #[serde(rename = "coordinatorBase")]
    pub coordinator_base: String,
    #[serde(rename = "record")]
    pub record: OrchestrationRecord,
    #[serde(rename = "next")]
    pub next_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    pub ok: bool,
    #[serde(rename = "coordinatorBase")]
    pub coordinator_base: String,
    #[serde(rename = "shardFilter", skip_serializing_if = "Option::is_none")]
    pub shard_filter: Option<String>,
    #[serde(rename = "jobIdFilter", skip_serializing_if = "Option::is_none")]
    pub job_id_filter: Option<String>,
    pub leases: Vec<LeaseRecord>,
    pub moves: Vec<OrchestrationRecord>,
    pub splits: Vec<OrchestrationRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub kind: String,
    #[serde(rename = "coordinatorBase")]
    pub coordinator_base: String,
    #[serde(rename = "corecruxBase")]
    pub corecrux_base: String,
    #[serde(rename = "shardMapVersion")]
    pub shard_map_version: u64,
    #[serde(rename = "selectedRecord", skip_serializing_if = "Option::is_none")]
    pub selected_record: Option<OrchestrationRecord>,
    pub checks: Vec<VerifyCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

pub fn submit_move(
    coordinator_base: &str,
    req: MoveCreateRequest,
) -> Result<SubmitReport, Box<dyn std::error::Error + Send + Sync>> {
    let client = CoordinatorClient::new(coordinator_base);
    let record = client.create_move(&req)?;
    Ok(SubmitReport {
        ok: true,
        coordinator_base: coordinator_base.trim_end_matches('/').to_string(),
        record,
        next_hint: "Run: corecruxctl shard status --coordinator <url> --shard <id>".to_string(),
    })
}

pub fn submit_split(
    coordinator_base: &str,
    req: SplitCreateRequest,
) -> Result<SubmitReport, Box<dyn std::error::Error + Send + Sync>> {
    let client = CoordinatorClient::new(coordinator_base);
    let record = client.create_split(&req)?;
    Ok(SubmitReport {
        ok: true,
        coordinator_base: coordinator_base.trim_end_matches('/').to_string(),
        record,
        next_hint: "Run: corecruxctl shard status --coordinator <url> --shard <id>".to_string(),
    })
}

pub fn status(
    coordinator_base: &str,
    shard_filter: Option<&str>,
    job_id_filter: Option<&str>,
) -> Result<StatusReport, Box<dyn std::error::Error + Send + Sync>> {
    let client = CoordinatorClient::new(coordinator_base);
    let leases = client
        .list_leases()?
        .into_iter()
        .filter(|r| shard_filter.is_none_or(|s| r.shard_id == s))
        .collect::<Vec<_>>();
    let moves = client
        .list_moves()?
        .into_iter()
        .filter(|r| shard_filter.is_none_or(|s| r.shard_id == s))
        .filter(|r| job_id_filter.is_none_or(|j| r.job_id == j))
        .collect::<Vec<_>>();
    let splits = client
        .list_splits()?
        .into_iter()
        .filter(|r| shard_filter.is_none_or(|s| r.shard_id == s))
        .filter(|r| job_id_filter.is_none_or(|j| r.job_id == j))
        .collect::<Vec<_>>();

    Ok(StatusReport {
        ok: true,
        coordinator_base: coordinator_base.trim_end_matches('/').to_string(),
        shard_filter: shard_filter.map(ToString::to_string),
        job_id_filter: job_id_filter.map(ToString::to_string),
        leases,
        moves,
        splits,
    })
}

pub fn verify_move(
    coordinator_base: &str,
    corecrux_base: &str,
    shard_id: &str,
    job_id: Option<&str>,
    expected_target_node_id: Option<&str>,
    require_lease_match: bool,
) -> Result<VerifyReport, Box<dyn std::error::Error + Send + Sync>> {
    let cc = CoordinatorClient::new(coordinator_base);
    let cx = CoreCruxClient::new(corecrux_base);

    let map = cx.get_shard_map()?;
    let moves = cc.list_moves()?;
    let leases = cc.list_leases()?;
    let selected = select_record(&moves, shard_id, job_id);
    let target = expected_target_node_id
        .map(ToString::to_string)
        .or_else(|| selected.as_ref().and_then(|r| r.target_node_id.clone()));

    let checks = build_move_checks(&map, &leases, shard_id, target.as_deref(), require_lease_match);
    let ok = checks.iter().all(|c| c.ok);

    Ok(VerifyReport {
        ok,
        kind: "move".to_string(),
        coordinator_base: coordinator_base.trim_end_matches('/').to_string(),
        corecrux_base: corecrux_base.trim_end_matches('/').to_string(),
        shard_map_version: map.version,
        selected_record: selected,
        checks,
    })
}

pub fn verify_split(
    coordinator_base: &str,
    corecrux_base: &str,
    parent_shard_id: &str,
    new_shard_id: &str,
    split_point_hex: Option<&str>,
    job_id: Option<&str>,
) -> Result<VerifyReport, Box<dyn std::error::Error + Send + Sync>> {
    let cc = CoordinatorClient::new(coordinator_base);
    let cx = CoreCruxClient::new(corecrux_base);

    let map = cx.get_shard_map()?;
    let splits = cc.list_splits()?;
    let selected = select_record(&splits, parent_shard_id, job_id);

    let expected_split = split_point_hex
        .map(ToString::to_string)
        .or_else(|| selected.as_ref().and_then(|r| r.at_hash_hex.clone()));
    let expected_new_shard = if new_shard_id.is_empty() {
        selected
            .as_ref()
            .and_then(|r| r.new_shard_id.clone())
            .unwrap_or_default()
    } else {
        new_shard_id.to_string()
    };

    let checks = build_split_checks(&map, parent_shard_id, &expected_new_shard, expected_split.as_deref());
    let ok = checks.iter().all(|c| c.ok);

    Ok(VerifyReport {
        ok,
        kind: "split".to_string(),
        coordinator_base: coordinator_base.trim_end_matches('/').to_string(),
        corecrux_base: corecrux_base.trim_end_matches('/').to_string(),
        shard_map_version: map.version,
        selected_record: selected,
        checks,
    })
}

fn select_record(records: &[OrchestrationRecord], shard_id: &str, job_id: Option<&str>) -> Option<OrchestrationRecord> {
    if let Some(j) = job_id {
        return records.iter().find(|r| r.job_id == j).cloned();
    }
    records.iter().find(|r| r.shard_id == shard_id).cloned()
}

fn build_move_checks(
    map: &corecrux_types::ShardMapV1,
    leases: &[LeaseRecord],
    shard_id: &str,
    expected_target: Option<&str>,
    require_lease_match: bool,
) -> Vec<VerifyCheck> {
    let mut checks = Vec::new();

    let map_valid = corecrux_types::validate_shard_map_v1(map).is_ok();
    checks.push(VerifyCheck {
        name: "shard_map_valid".to_string(),
        ok: map_valid,
        detail: if map_valid {
            "shard map validates (coverage/digest/invariants)".to_string()
        } else {
            "shard map validation failed".to_string()
        },
    });

    let shard = map.shards.iter().find(|s| s.shard_id == shard_id);
    checks.push(VerifyCheck {
        name: "shard_exists".to_string(),
        ok: shard.is_some(),
        detail: if shard.is_some() {
            format!("{shard_id} present in current shard map")
        } else {
            format!("{shard_id} missing from current shard map")
        },
    });

    if let (Some(s), Some(target)) = (shard, expected_target) {
        let ok = s.leader.node_id == target;
        checks.push(VerifyCheck {
            name: "leader_matches_target".to_string(),
            ok,
            detail: format!("leaderNodeId={} expectedTarget={target}", s.leader.node_id),
        });
    }

    if let Some(s) = shard {
        let lease = leases.iter().find(|l| l.shard_id == shard_id);
        checks.push(VerifyCheck {
            name: "lease_record_present".to_string(),
            ok: lease.is_some(),
            detail: if let Some(l) = lease {
                format!(
                    "leaderNodeId={} epoch={} expiresUnixMs={}",
                    l.leader_node_id, l.epoch, l.lease_expires_unix_ms
                )
            } else {
                "no coordinator lease record for shard".to_string()
            },
        });
        if require_lease_match {
            let ok = lease.is_some_and(|l| l.leader_node_id == s.leader.node_id && l.epoch == s.epoch);
            checks.push(VerifyCheck {
                name: "lease_matches_shard_map".to_string(),
                ok,
                detail: if let Some(l) = lease {
                    format!(
                        "lease(leader={},epoch={}) shardMap(leader={},epoch={})",
                        l.leader_node_id, l.epoch, s.leader.node_id, s.epoch
                    )
                } else {
                    "cannot compare: missing lease".to_string()
                },
            });
        }
    }

    checks
}

fn build_split_checks(
    map: &corecrux_types::ShardMapV1,
    parent_shard_id: &str,
    new_shard_id: &str,
    split_point_hex: Option<&str>,
) -> Vec<VerifyCheck> {
    let mut checks = Vec::new();

    let map_valid = corecrux_types::validate_shard_map_v1(map).is_ok();
    checks.push(VerifyCheck {
        name: "shard_map_valid".to_string(),
        ok: map_valid,
        detail: if map_valid {
            "shard map validates (coverage/digest/invariants)".to_string()
        } else {
            "shard map validation failed".to_string()
        },
    });

    let parent = map.shards.iter().find(|s| s.shard_id == parent_shard_id);
    checks.push(VerifyCheck {
        name: "parent_shard_exists".to_string(),
        ok: parent.is_some(),
        detail: if parent.is_some() {
            format!("{parent_shard_id} present in current shard map")
        } else {
            format!("{parent_shard_id} missing from current shard map")
        },
    });

    let child = map.shards.iter().find(|s| s.shard_id == new_shard_id);
    checks.push(VerifyCheck {
        name: "new_shard_exists".to_string(),
        ok: child.is_some(),
        detail: if child.is_some() {
            format!("{new_shard_id} present in current shard map")
        } else {
            format!("{new_shard_id} missing from current shard map")
        },
    });

    if let Some(split_hex) = split_point_hex {
        let split_norm = match corecrux_types::parse_u64_hex(split_hex) {
            Ok(v) => corecrux_types::format_u64_hex(v),
            Err(err) => {
                checks.push(VerifyCheck {
                    name: "split_point_parseable".to_string(),
                    ok: false,
                    detail: err.to_string(),
                });
                return checks;
            }
        };

        let parent_boundary =
            parent.is_some_and(|s| s.ranges.iter().any(|r| canonical_hex(&r.end_exclusive) == split_norm));
        let child_boundary =
            child.is_some_and(|s| s.ranges.iter().any(|r| canonical_hex(&r.start_inclusive) == split_norm));
        checks.push(VerifyCheck {
            name: "split_point_boundary_present".to_string(),
            ok: parent_boundary && child_boundary,
            detail: format!(
                "splitPoint={} parentHasEnd={} childHasStart={}",
                split_norm, parent_boundary, child_boundary
            ),
        });
    } else {
        // D-28: with no split point supplied — and none recoverable from the
        // coordinator record — the boundary check was simply OMITTED, so
        // `ok = checks.iter().all(...)` passed on a verification that never
        // examined the split at all. Emit the check as unevaluated instead.
        checks.push(VerifyCheck {
            name: "split_point_boundary_present".to_string(),
            ok: false,
            detail: "no split point supplied and none recorded on the split job; the boundary was NOT verified"
                .to_string(),
        });
    }

    if let (Some(p), Some(c)) = (parent, child) {
        checks.push(VerifyCheck {
            name: "epoch_nonzero".to_string(),
            ok: p.epoch > 0 && c.epoch > 0,
            detail: format!("parentEpoch={} childEpoch={}", p.epoch, c.epoch),
        });
    }

    checks
}

fn canonical_hex(input: &str) -> String {
    match corecrux_types::parse_u64_hex(input) {
        Ok(v) => corecrux_types::format_u64_hex(v),
        Err(_) => input.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use corecrux_types::{
        compute_shard_map_v1_blake3_hex, HashRange, NodeAddr, ShardDescriptor, ShardMapV1, ShardState,
        SHARDMAP_HASH_FN_V1, SHARDMAP_KEY_ENCODING_V1, SHARDMAP_V1,
    };

    fn node(id: &str) -> NodeAddr {
        NodeAddr {
            node_id: id.to_string(),
            grpc_addr: format!("http://{id}:4007"),
            http_addr: format!("http://{id}:4006"),
        }
    }

    fn sample_map() -> ShardMapV1 {
        let mut map = ShardMapV1 {
            v: SHARDMAP_V1,
            cluster_id: "dev".to_string(),
            version: 7,
            created_at: "2026-02-11T00:00:00Z".to_string(),
            hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
            key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
            shards: vec![
                ShardDescriptor {
                    shard_id: "shard-0001".to_string(),
                    epoch: 3,
                    state: ShardState::Active,
                    ranges: vec![HashRange {
                        start_inclusive: "0x0000000000000000".to_string(),
                        end_exclusive: "0x8000000000000000".to_string(),
                    }],
                    leader: node("node-b"),
                    followers: Some(vec![node("node-a")]),
                    data_dir: None,
                    gpu_id: Some(0),
                },
                ShardDescriptor {
                    shard_id: "shard-0002".to_string(),
                    epoch: 1,
                    state: ShardState::Active,
                    ranges: vec![HashRange {
                        start_inclusive: "0x8000000000000000".to_string(),
                        end_exclusive: "0x0000000000000000".to_string(),
                    }],
                    leader: node("node-c"),
                    followers: Some(vec![node("node-a")]),
                    data_dir: None,
                    gpu_id: Some(1),
                },
            ],
            blake3: String::new(),
            prev_blake3: None,
        };
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");
        map
    }

    #[test]
    fn coordinator_client_url_normalizes_trailing_slashes() {
        let client = CoordinatorClient::new("http://example.com/");
        assert_eq!(client.url("/v1/moves"), "http://example.com/v1/moves");
        assert_eq!(client.url("v1/moves"), "http://example.com/v1/moves");
    }

    #[test]
    fn corecrux_client_url_normalizes_trailing_slashes() {
        let client = CoreCruxClient::new("http://example.com/");
        assert_eq!(client.url("/v1/shard-map"), "http://example.com/v1/shard-map");
        assert_eq!(client.url("v1/shard-map"), "http://example.com/v1/shard-map");
    }

    #[test]
    fn move_create_request_serializes() {
        let req = MoveCreateRequest {
            job_id: Some("job-1".to_string()),
            shard_id: "shard-0001".to_string(),
            source_node_id: "node-a".to_string(),
            target_node_id: "node-b".to_string(),
            status: None,
        };
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["shardId"], "shard-0001");
        assert_eq!(json["sourceNodeId"], "node-a");
        assert_eq!(json["targetNodeId"], "node-b");
        assert_eq!(json["jobId"], "job-1");
        assert!(json.get("status").is_none());
    }

    #[test]
    fn move_create_request_omits_none_job_id() {
        let req = MoveCreateRequest {
            job_id: None,
            shard_id: "shard-0001".to_string(),
            source_node_id: "node-a".to_string(),
            target_node_id: "node-b".to_string(),
            status: None,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(!json.contains("jobId"));
    }

    #[test]
    fn split_create_request_serializes() {
        let req = SplitCreateRequest {
            job_id: None,
            shard_id: "shard-0001".to_string(),
            at_hash_hex: "0x4000000000000000".to_string(),
            new_shard_id: "shard-0003".to_string(),
            status: None,
        };
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["shardId"], "shard-0001");
        assert_eq!(json["atHashHex"], "0x4000000000000000");
        assert_eq!(json["newShardId"], "shard-0003");
    }

    #[test]
    fn orchestration_record_round_trip() {
        let record = OrchestrationRecord {
            job_id: "job-1".to_string(),
            kind: "move".to_string(),
            shard_id: "shard-0001".to_string(),
            source_node_id: Some("node-a".to_string()),
            target_node_id: Some("node-b".to_string()),
            at_hash_hex: None,
            new_shard_id: None,
            status: "completed".to_string(),
            created_unix_ms: 1700000000000,
            updated_unix_ms: 1700000001000,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let parsed: OrchestrationRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.job_id, "job-1");
        assert_eq!(parsed.status, "completed");
    }

    #[test]
    fn lease_record_serializes() {
        let lease = LeaseRecord {
            shard_id: "shard-0001".to_string(),
            leader_node_id: "node-a".to_string(),
            epoch: 5,
            lease_expires_unix_ms: 1700000000000,
            updated_unix_ms: 1700000000000,
        };
        let json = serde_json::to_value(&lease).expect("serialize");
        assert_eq!(json["shardId"], "shard-0001");
        assert_eq!(json["leaderNodeId"], "node-a");
        assert_eq!(json["epoch"], 5);
    }

    #[test]
    fn select_record_by_job_id() {
        let records = vec![
            OrchestrationRecord {
                job_id: "job-1".to_string(),
                kind: "move".to_string(),
                shard_id: "shard-0001".to_string(),
                source_node_id: None,
                target_node_id: None,
                at_hash_hex: None,
                new_shard_id: None,
                status: "pending".to_string(),
                created_unix_ms: 0,
                updated_unix_ms: 0,
            },
            OrchestrationRecord {
                job_id: "job-2".to_string(),
                kind: "move".to_string(),
                shard_id: "shard-0002".to_string(),
                source_node_id: None,
                target_node_id: None,
                at_hash_hex: None,
                new_shard_id: None,
                status: "done".to_string(),
                created_unix_ms: 0,
                updated_unix_ms: 0,
            },
        ];
        // Find by job_id.
        let found = select_record(&records, "ignored", Some("job-2"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().job_id, "job-2");

        // Find by shard_id when no job_id.
        let found = select_record(&records, "shard-0001", None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().job_id, "job-1");

        // Not found.
        let found = select_record(&records, "nonexistent", None);
        assert!(found.is_none());
    }

    #[test]
    fn canonical_hex_normalizes_input() {
        assert_eq!(canonical_hex("0x0000000000000000"), "0x0000000000000000");
        assert_eq!(canonical_hex("0x4000000000000000"), "0x4000000000000000");
    }

    #[test]
    fn build_move_checks_missing_shard() {
        let map = sample_map();
        let leases = Vec::new();
        let checks = build_move_checks(&map, &leases, "nonexistent", None, false);
        let shard_check = checks.iter().find(|c| c.name == "shard_exists").unwrap();
        assert!(!shard_check.ok);
    }

    #[test]
    fn build_move_checks_lease_mismatch() {
        let map = sample_map();
        let leases = vec![LeaseRecord {
            shard_id: "shard-0001".to_string(),
            leader_node_id: "node-WRONG".to_string(),
            epoch: 99,
            lease_expires_unix_ms: 0,
            updated_unix_ms: 0,
        }];
        let checks = build_move_checks(&map, &leases, "shard-0001", Some("node-b"), true);
        let lease_match = checks.iter().find(|c| c.name == "lease_matches_shard_map").unwrap();
        assert!(!lease_match.ok);
    }

    #[test]
    fn build_split_checks_missing_child_shard() {
        let map = sample_map();
        let checks = build_split_checks(&map, "shard-0001", "shard-9999", None);
        let child_check = checks.iter().find(|c| c.name == "new_shard_exists").unwrap();
        assert!(!child_check.ok);
    }

    #[test]
    fn submit_report_serializes() {
        let report = SubmitReport {
            ok: true,
            coordinator_base: "http://example.com".to_string(),
            record: OrchestrationRecord {
                job_id: "j1".to_string(),
                kind: "move".to_string(),
                shard_id: "s1".to_string(),
                source_node_id: None,
                target_node_id: None,
                at_hash_hex: None,
                new_shard_id: None,
                status: "pending".to_string(),
                created_unix_ms: 0,
                updated_unix_ms: 0,
            },
            next_hint: "run status".to_string(),
        };
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["ok"], true);
        assert_eq!(json["coordinatorBase"], "http://example.com");
    }

    #[test]
    fn status_report_serializes_with_filters() {
        let report = StatusReport {
            ok: true,
            coordinator_base: "http://example.com".to_string(),
            shard_filter: Some("shard-0001".to_string()),
            job_id_filter: None,
            leases: Vec::new(),
            moves: Vec::new(),
            splits: Vec::new(),
        };
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["shardFilter"], "shard-0001");
        assert!(json.get("jobIdFilter").is_none());
    }

    #[test]
    fn verify_report_serializes() {
        let report = VerifyReport {
            ok: true,
            kind: "move".to_string(),
            coordinator_base: "http://example.com".to_string(),
            corecrux_base: "http://localhost:14800".to_string(),
            shard_map_version: 5,
            selected_record: None,
            checks: vec![VerifyCheck {
                name: "test_check".to_string(),
                ok: true,
                detail: "everything fine".to_string(),
            }],
        };
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["shardMapVersion"], 5);
        assert_eq!(json["checks"][0]["name"], "test_check");
    }

    #[test]
    fn verify_move_checks_target_and_lease() {
        let map = sample_map();
        let leases = vec![LeaseRecord {
            shard_id: "shard-0001".to_string(),
            leader_node_id: "node-b".to_string(),
            epoch: 3,
            lease_expires_unix_ms: 1_700_000_000_000,
            updated_unix_ms: 1_700_000_000_000,
        }];
        let checks = build_move_checks(&map, &leases, "shard-0001", Some("node-b"), true);
        assert!(checks.iter().all(|c| c.ok), "checks={checks:?}");
    }

    #[test]
    fn verify_split_checks_split_boundary() {
        let mut map = sample_map();
        map.shards[0].ranges[0].end_exclusive = "0x4000000000000000".to_string();
        map.shards.push(ShardDescriptor {
            shard_id: "shard-0003".to_string(),
            epoch: 1,
            state: ShardState::Active,
            ranges: vec![HashRange {
                start_inclusive: "0x4000000000000000".to_string(),
                end_exclusive: "0x8000000000000000".to_string(),
            }],
            leader: node("node-b"),
            followers: Some(vec![node("node-a")]),
            data_dir: None,
            gpu_id: Some(0),
        });
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");

        let checks = build_split_checks(&map, "shard-0001", "shard-0003", Some("0x4000000000000000"));
        assert!(checks.iter().all(|c| c.ok), "checks={checks:?}");
    }

    // ── select_record: edge cases ──────────────────────────────────────

    #[test]
    fn select_record_empty_list() {
        assert!(select_record(&[], "shard-0001", None).is_none());
        assert!(select_record(&[], "shard-0001", Some("job-1")).is_none());
    }

    #[test]
    fn select_record_prefers_job_id_over_shard_id() {
        let records = vec![
            OrchestrationRecord {
                job_id: "job-1".to_string(),
                kind: "move".to_string(),
                shard_id: "shard-0001".to_string(),
                source_node_id: None,
                target_node_id: None,
                at_hash_hex: None,
                new_shard_id: None,
                status: "pending".to_string(),
                created_unix_ms: 0,
                updated_unix_ms: 0,
            },
            OrchestrationRecord {
                job_id: "job-2".to_string(),
                kind: "move".to_string(),
                shard_id: "shard-0001".to_string(),
                source_node_id: None,
                target_node_id: None,
                at_hash_hex: None,
                new_shard_id: None,
                status: "done".to_string(),
                created_unix_ms: 0,
                updated_unix_ms: 0,
            },
        ];
        // job_id takes priority: shard_id arg is "ignored"
        let found = select_record(&records, "shard-0001", Some("job-2")).unwrap();
        assert_eq!(found.job_id, "job-2");
    }

    // ── canonical_hex: invalid input ──────────────────────────────────

    #[test]
    fn canonical_hex_invalid_returns_original() {
        assert_eq!(canonical_hex("not-a-hex"), "not-a-hex");
    }

    // ── build_move_checks: all checks pass ──────────────────────────

    #[test]
    fn build_move_checks_all_pass_without_lease_match() {
        let map = sample_map();
        let leases = vec![LeaseRecord {
            shard_id: "shard-0001".to_string(),
            leader_node_id: "node-b".to_string(),
            epoch: 3,
            lease_expires_unix_ms: 1_700_000_000_000,
            updated_unix_ms: 1_700_000_000_000,
        }];
        // require_lease_match=false: skips the lease_matches_shard_map check
        let checks = build_move_checks(&map, &leases, "shard-0001", Some("node-b"), false);
        assert!(checks.iter().all(|c| c.ok), "checks={checks:?}");
        // Should NOT have the lease_matches_shard_map check
        assert!(checks.iter().all(|c| c.name != "lease_matches_shard_map"));
    }

    #[test]
    fn build_move_checks_no_lease_record() {
        let map = sample_map();
        let leases = Vec::new();
        let checks = build_move_checks(&map, &leases, "shard-0001", Some("node-b"), false);
        let lease_check = checks.iter().find(|c| c.name == "lease_record_present").unwrap();
        assert!(!lease_check.ok);
    }

    #[test]
    fn build_move_checks_leader_mismatch() {
        let map = sample_map();
        let leases = Vec::new();
        let checks = build_move_checks(&map, &leases, "shard-0001", Some("node-WRONG"), false);
        let leader_check = checks.iter().find(|c| c.name == "leader_matches_target").unwrap();
        assert!(!leader_check.ok);
    }

    // ── build_split_checks: missing parent ────────────────────────────

    #[test]
    fn build_split_checks_missing_parent() {
        let map = sample_map();
        let checks = build_split_checks(&map, "shard-9999", "shard-0002", None);
        let parent_check = checks.iter().find(|c| c.name == "parent_shard_exists").unwrap();
        assert!(!parent_check.ok);
    }

    #[test]
    fn build_split_checks_both_present_no_split_point() {
        let map = sample_map();
        let checks = build_split_checks(&map, "shard-0001", "shard-0002", None);
        // All basic checks should pass (parent and child exist)
        let parent_check = checks.iter().find(|c| c.name == "parent_shard_exists").unwrap();
        assert!(parent_check.ok);
        let child_check = checks.iter().find(|c| c.name == "new_shard_exists").unwrap();
        assert!(child_check.ok);
        // Should have epoch_nonzero check
        let epoch_check = checks.iter().find(|c| c.name == "epoch_nonzero").unwrap();
        assert!(epoch_check.ok);
    }

    // ── Report structs serialization ──────────────────────────────────

    #[test]
    fn status_report_no_filters_omits_fields() {
        let report = StatusReport {
            ok: true,
            coordinator_base: "http://example.com".to_string(),
            shard_filter: None,
            job_id_filter: None,
            leases: Vec::new(),
            moves: Vec::new(),
            splits: Vec::new(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("shardFilter"));
        assert!(!json.contains("jobIdFilter"));
    }

    #[test]
    fn verify_report_no_selected_record_omits_field() {
        let report = VerifyReport {
            ok: true,
            kind: "split".to_string(),
            coordinator_base: "http://example.com".to_string(),
            corecrux_base: "http://localhost:14800".to_string(),
            shard_map_version: 1,
            selected_record: None,
            checks: Vec::new(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("selectedRecord"));
    }

    // ── MoveCreateRequest: with status ──────────────────────────────

    #[test]
    fn move_create_request_with_status() {
        let req = MoveCreateRequest {
            job_id: None,
            shard_id: "s1".to_string(),
            source_node_id: "n1".to_string(),
            target_node_id: "n2".to_string(),
            status: Some("pending".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["status"], "pending");
    }

    // ── SplitCreateRequest: with all fields ─────────────────────────

    #[test]
    fn split_create_request_all_fields() {
        let req = SplitCreateRequest {
            job_id: Some("j1".to_string()),
            shard_id: "s1".to_string(),
            at_hash_hex: "0xABCD".to_string(),
            new_shard_id: "s2".to_string(),
            status: Some("completed".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jobId"], "j1");
        assert_eq!(json["status"], "completed");
    }

    // ── LeaseRecord: round-trip ─────────────────────────────────────

    #[test]
    fn lease_record_round_trip() {
        let lease = LeaseRecord {
            shard_id: "shard-0001".to_string(),
            leader_node_id: "node-a".to_string(),
            epoch: 7,
            lease_expires_unix_ms: 1700000000000,
            updated_unix_ms: 1700000000000,
        };
        let json = serde_json::to_string(&lease).unwrap();
        let parsed: LeaseRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.epoch, 7);
        assert_eq!(parsed.leader_node_id, "node-a");
    }

    // ── CoordinatorClient / CoreCruxClient: url normalization ────────

    #[test]
    fn coordinator_client_empty_base() {
        let client = CoordinatorClient::new("");
        assert_eq!(client.url("/v1/test"), "/v1/test");
    }

    #[test]
    fn corecrux_client_empty_base() {
        let client = CoreCruxClient::new("");
        assert_eq!(client.url("/v1/test"), "/v1/test");
    }

    // ── canonical_hex: various hex values ───────────────────────────

    #[test]
    fn canonical_hex_normalizes_uppercase() {
        // parse_u64_hex should handle 0x prefix and normalize
        let h = canonical_hex("0x00000000DEADBEEF");
        assert!(h.starts_with("0x"));
    }

    #[test]
    fn canonical_hex_zero() {
        assert_eq!(canonical_hex("0x0000000000000000"), "0x0000000000000000");
    }

    // ── build_split_checks: invalid split point ─────────────────────

    #[test]
    fn build_split_checks_invalid_split_point() {
        let map = sample_map();
        let checks = build_split_checks(&map, "shard-0001", "shard-0002", Some("not-hex"));
        let parse_check = checks.iter().find(|c| c.name == "split_point_parseable");
        assert!(parse_check.is_some());
        assert!(!parse_check.unwrap().ok);
    }

    // ── build_move_checks: require_lease_match with matching lease ──

    #[test]
    fn build_move_checks_lease_matches() {
        let map = sample_map();
        let leases = vec![LeaseRecord {
            shard_id: "shard-0001".to_string(),
            leader_node_id: "node-b".to_string(),
            epoch: 3,
            lease_expires_unix_ms: 1_700_000_000_000,
            updated_unix_ms: 1_700_000_000_000,
        }];
        let checks = build_move_checks(&map, &leases, "shard-0001", Some("node-b"), true);
        let lease_match = checks.iter().find(|c| c.name == "lease_matches_shard_map").unwrap();
        assert!(lease_match.ok);
    }

    // ── VerifyCheck fields ──────────────────────────────────────────

    #[test]
    fn verify_check_debug_and_clone() {
        let check = VerifyCheck {
            name: "test".to_string(),
            ok: false,
            detail: "failed reason".to_string(),
        };
        let cloned = check.clone();
        assert_eq!(cloned.name, "test");
        assert!(!cloned.ok);
        let dbg = format!("{:?}", check);
        assert!(dbg.contains("test"));
    }

    // ── OrchestrationRecord: all optional fields ────────────────────

    #[test]
    fn orchestration_record_all_fields() {
        let record = OrchestrationRecord {
            job_id: "j1".to_string(),
            kind: "split".to_string(),
            shard_id: "s1".to_string(),
            source_node_id: Some("n1".to_string()),
            target_node_id: Some("n2".to_string()),
            at_hash_hex: Some("0x4000".to_string()),
            new_shard_id: Some("s2".to_string()),
            status: "completed".to_string(),
            created_unix_ms: 100,
            updated_unix_ms: 200,
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["atHashHex"], "0x4000");
        assert_eq!(json["newShardId"], "s2");
        assert_eq!(json["sourceNodeId"], "n1");
        assert_eq!(json["targetNodeId"], "n2");
    }

    // ── build_split_checks: epoch_nonzero check ────────────────────

    #[test]
    fn build_split_checks_epoch_zero_fails() {
        let mut map = sample_map();
        map.shards[0].epoch = 0;
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");
        let checks = build_split_checks(&map, "shard-0001", "shard-0002", None);
        let epoch_check = checks.iter().find(|c| c.name == "epoch_nonzero").unwrap();
        assert!(!epoch_check.ok);
    }

    // ── build_split_checks: split boundary mismatch ─────────────────

    #[test]
    fn build_split_checks_split_boundary_mismatch() {
        let map = sample_map();
        // Use a split point that doesn't match any boundary
        let checks = build_split_checks(&map, "shard-0001", "shard-0002", Some("0x1234567890ABCDEF"));
        let boundary_check = checks
            .iter()
            .find(|c| c.name == "split_point_boundary_present")
            .unwrap();
        assert!(!boundary_check.ok);
    }

    // ── canonical_hex: max u64 ──────────────────────────────────────

    #[test]
    fn canonical_hex_max_u64() {
        let result = canonical_hex("0xFFFFFFFFFFFFFFFF");
        assert!(result.starts_with("0x"));
        assert_eq!(result.len(), 18); // "0x" + 16 hex chars
    }

    #[test]
    fn canonical_hex_empty_returns_original() {
        assert_eq!(canonical_hex(""), "");
    }

    // ── CoordinatorClient: Debug ────────────────────────────────────

    #[test]
    fn coordinator_client_debug() {
        let client = CoordinatorClient::new("http://coord:8080");
        let dbg = format!("{:?}", client);
        assert!(dbg.contains("coord:8080"));
    }

    // ── CoreCruxClient: Debug ───────────────────────────────────────

    #[test]
    fn corecrux_client_debug() {
        let client = CoreCruxClient::new("http://localhost:14800");
        let dbg = format!("{:?}", client);
        assert!(dbg.contains("localhost:14800"));
    }

    // ── MoveCreateRequest: all None optionals ───────────────────────

    #[test]
    fn move_create_request_no_optional_fields() {
        let req = MoveCreateRequest {
            job_id: None,
            shard_id: "s1".to_string(),
            source_node_id: "n1".to_string(),
            target_node_id: "n2".to_string(),
            status: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("jobId"));
        assert!(!json.contains("status"));
        assert!(json.contains("shardId"));
    }

    // ── SplitCreateRequest: all None optionals ──────────────────────

    #[test]
    fn split_create_request_no_optional_fields() {
        let req = SplitCreateRequest {
            job_id: None,
            shard_id: "s1".to_string(),
            at_hash_hex: "0x0".to_string(),
            new_shard_id: "s2".to_string(),
            status: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("jobId"));
        assert!(!json.contains("status"));
    }

    // ── OrchestrationRecord: all None optional fields ───────────────

    #[test]
    fn orchestration_record_no_optional_fields() {
        let record = OrchestrationRecord {
            job_id: "j1".to_string(),
            kind: "move".to_string(),
            shard_id: "s1".to_string(),
            source_node_id: None,
            target_node_id: None,
            at_hash_hex: None,
            new_shard_id: None,
            status: "pending".to_string(),
            created_unix_ms: 0,
            updated_unix_ms: 0,
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["sourceNodeId"].is_null());
        assert!(parsed["targetNodeId"].is_null());
        assert!(parsed["atHashHex"].is_null());
        assert!(parsed["newShardId"].is_null());
    }

    // ── VerifyReport: with selected_record ──────────────────────────

    #[test]
    fn verify_report_with_selected_record() {
        let report = VerifyReport {
            ok: false,
            kind: "move".to_string(),
            coordinator_base: "http://example.com".to_string(),
            corecrux_base: "http://localhost:14800".to_string(),
            shard_map_version: 3,
            selected_record: Some(OrchestrationRecord {
                job_id: "j1".to_string(),
                kind: "move".to_string(),
                shard_id: "s1".to_string(),
                source_node_id: None,
                target_node_id: None,
                at_hash_hex: None,
                new_shard_id: None,
                status: "pending".to_string(),
                created_unix_ms: 0,
                updated_unix_ms: 0,
            }),
            checks: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["selectedRecord"].is_object());
        assert_eq!(json["selectedRecord"]["jobId"], "j1");
    }

    // ── StatusReport: with all filters ──────────────────────────────

    #[test]
    fn status_report_with_both_filters() {
        let report = StatusReport {
            ok: true,
            coordinator_base: "http://example.com".to_string(),
            shard_filter: Some("shard-0001".to_string()),
            job_id_filter: Some("job-42".to_string()),
            leases: Vec::new(),
            moves: Vec::new(),
            splits: Vec::new(),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["shardFilter"], "shard-0001");
        assert_eq!(json["jobIdFilter"], "job-42");
    }

    // ── build_move_checks: no target_node_id ────────────────────────

    #[test]
    fn build_move_checks_no_target_node() {
        let map = sample_map();
        let leases = vec![LeaseRecord {
            shard_id: "shard-0001".to_string(),
            leader_node_id: "node-b".to_string(),
            epoch: 3,
            lease_expires_unix_ms: 1_700_000_000_000,
            updated_unix_ms: 1_700_000_000_000,
        }];
        let checks = build_move_checks(&map, &leases, "shard-0001", None, false);
        let leader_check = checks.iter().find(|c| c.name == "leader_matches_target");
        // When target is None, leader_matches_target check should be skipped or trivially pass
        assert!(leader_check.is_none() || leader_check.unwrap().ok);
    }

    // ── SubmitReport: Clone and Debug ───────────────────────────────

    #[test]
    fn submit_report_clone_debug() {
        let report = SubmitReport {
            ok: true,
            coordinator_base: "http://example.com".to_string(),
            record: OrchestrationRecord {
                job_id: "j1".to_string(),
                kind: "move".to_string(),
                shard_id: "s1".to_string(),
                source_node_id: None,
                target_node_id: None,
                at_hash_hex: None,
                new_shard_id: None,
                status: "pending".to_string(),
                created_unix_ms: 0,
                updated_unix_ms: 0,
            },
            next_hint: "check status".to_string(),
        };
        let dbg = format!("{:?}", report);
        assert!(dbg.contains("j1"));
    }

    // ══════════════════════════════════════════════════════════════════
    // HTTP client paths, driven against the shared loopback stub in
    // `crate::test_support`. Note: neither `CoordinatorClient` nor
    // `CoreCruxClient` calls `http_status_as_error(false)`, so a 4xx/5xx
    // reaches the caller as a ureq `Transport`/status error and never
    // produces a parsed body — the assertions below are `is_err()` on
    // purpose, not on a status branch (there is none).
    // ══════════════════════════════════════════════════════════════════

    use crate::test_support::serve_responses;

    fn record_json(job_id: &str, shard_id: &str, kind: &str) -> String {
        serde_json::to_string(&OrchestrationRecord {
            job_id: job_id.to_string(),
            kind: kind.to_string(),
            shard_id: shard_id.to_string(),
            source_node_id: Some("node-a".to_string()),
            target_node_id: Some("node-b".to_string()),
            at_hash_hex: Some("0x4000000000000000".to_string()),
            new_shard_id: Some("shard-0003".to_string()),
            status: "completed".to_string(),
            created_unix_ms: 1,
            updated_unix_ms: 2,
        })
        .expect("record json")
    }

    fn lease_json(shard_id: &str, leader: &str, epoch: u64) -> String {
        serde_json::to_string(&LeaseRecord {
            shard_id: shard_id.to_string(),
            leader_node_id: leader.to_string(),
            epoch,
            lease_expires_unix_ms: 1_700_000_000_000,
            updated_unix_ms: 1_700_000_000_000,
        })
        .expect("lease json")
    }

    fn shard_map_body(map: &ShardMapV1) -> String {
        serde_json::json!({ "shardMap": map }).to_string()
    }

    // ── CoordinatorClient ───────────────────────────────────────────

    #[test]
    fn list_moves_parses_array_body() {
        let body = format!("[{}]", record_json("job-1", "shard-0001", "move"));
        let (port, h) = serve_responses(vec![(200, body)]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        let moves = client.list_moves().expect("list moves");
        let reqs = h.join().expect("stub thread");
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].job_id, "job-1");
        assert!(reqs[0].starts_with("GET /v1/moves "), "req={:?}", reqs[0]);
    }

    #[test]
    fn list_splits_parses_array_body() {
        let body = format!("[{}]", record_json("job-9", "shard-0001", "split"));
        let (port, h) = serve_responses(vec![(200, body)]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        let splits = client.list_splits().expect("list splits");
        let reqs = h.join().expect("stub thread");
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0].kind, "split");
        assert!(reqs[0].starts_with("GET /v1/splits "), "req={:?}", reqs[0]);
    }

    #[test]
    fn list_leases_parses_array_body() {
        let body = format!("[{}]", lease_json("shard-0001", "node-b", 3));
        let (port, h) = serve_responses(vec![(200, body)]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        let leases = client.list_leases().expect("list leases");
        let reqs = h.join().expect("stub thread");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].epoch, 3);
        assert!(reqs[0].starts_with("GET /v1/leases "), "req={:?}", reqs[0]);
    }

    #[test]
    fn list_moves_empty_array_is_not_an_error() {
        let (port, h) = serve_responses(vec![(200, "[]".to_string())]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        let moves = client.list_moves().expect("list moves");
        h.join().ok();
        assert!(moves.is_empty());
    }

    /// A body that is not the expected shape must surface as an error, never
    /// as an empty list that a caller would read as "no in-flight moves".
    #[test]
    fn list_moves_rejects_non_array_body() {
        let (port, h) = serve_responses(vec![(200, r#"{"moves":[]}"#.to_string())]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        let err = client.list_moves().expect_err("object body must not parse as a list");
        h.join().ok();
        assert!(!format!("{err}").is_empty());
    }

    #[test]
    fn list_moves_rejects_truncated_json() {
        let (port, h) = serve_responses(vec![(200, "[{\"jobId\":".to_string())]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        assert!(client.list_moves().is_err());
        h.join().ok();
    }

    /// Coordinator 5xx must propagate as an error rather than a default record.
    #[test]
    fn list_leases_surfaces_server_error() {
        let (port, h) = serve_responses(vec![(503, "unavailable".to_string())]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        assert!(client.list_leases().is_err());
        h.join().ok();
    }

    #[test]
    fn create_move_posts_request_body() {
        let (port, h) = serve_responses(vec![(200, record_json("job-1", "shard-0001", "move"))]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        let record = client
            .create_move(&MoveCreateRequest {
                job_id: Some("job-1".to_string()),
                shard_id: "shard-0001".to_string(),
                source_node_id: "node-a".to_string(),
                target_node_id: "node-b".to_string(),
                status: None,
            })
            .expect("create move");
        let reqs = h.join().expect("stub thread");
        assert_eq!(record.job_id, "job-1");
        assert!(reqs[0].starts_with("POST /v1/moves "), "req={:?}", reqs[0]);
        assert!(reqs[0].contains("\"shardId\": \"shard-0001\""), "req={:?}", reqs[0]);
        assert!(reqs[0].contains("\"targetNodeId\": \"node-b\""), "req={:?}", reqs[0]);
    }

    #[test]
    fn create_split_posts_request_body() {
        let (port, h) = serve_responses(vec![(200, record_json("job-2", "shard-0001", "split"))]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        let record = client
            .create_split(&SplitCreateRequest {
                job_id: None,
                shard_id: "shard-0001".to_string(),
                at_hash_hex: "0x4000000000000000".to_string(),
                new_shard_id: "shard-0003".to_string(),
                status: None,
            })
            .expect("create split");
        let reqs = h.join().expect("stub thread");
        assert_eq!(record.kind, "split");
        assert!(reqs[0].starts_with("POST /v1/splits "), "req={:?}", reqs[0]);
        assert!(
            reqs[0].contains("\"atHashHex\": \"0x4000000000000000\""),
            "req={:?}",
            reqs[0]
        );
        assert!(!reqs[0].contains("jobId"), "None jobId must be omitted: {:?}", reqs[0]);
    }

    #[test]
    fn create_move_surfaces_server_error() {
        let (port, h) = serve_responses(vec![(409, "conflict".to_string())]);
        let client = CoordinatorClient::new(&format!("http://127.0.0.1:{port}"));
        let result = client.create_move(&MoveCreateRequest {
            job_id: None,
            shard_id: "shard-0001".to_string(),
            source_node_id: "node-a".to_string(),
            target_node_id: "node-b".to_string(),
            status: None,
        });
        h.join().ok();
        assert!(result.is_err());
    }

    // ── CoreCruxClient::get_shard_map ───────────────────────────────

    #[test]
    fn get_shard_map_unwraps_envelope() {
        let map = sample_map();
        let (port, h) = serve_responses(vec![(200, shard_map_body(&map))]);
        let client = CoreCruxClient::new(&format!("http://127.0.0.1:{port}"));
        let out = client.get_shard_map().expect("shard map");
        let reqs = h.join().expect("stub thread");
        assert_eq!(out.version, map.version);
        assert_eq!(out.shards.len(), 2);
        assert!(reqs[0].starts_with("GET /v1/shard-map "), "req={:?}", reqs[0]);
    }

    /// A bare shard map (no `shardMap` envelope) must not silently deserialize
    /// into a default/empty map.
    #[test]
    fn get_shard_map_rejects_unenveloped_body() {
        let map = sample_map();
        let body = serde_json::to_string(&map).expect("map json");
        let (port, h) = serve_responses(vec![(200, body)]);
        let client = CoreCruxClient::new(&format!("http://127.0.0.1:{port}"));
        assert!(client.get_shard_map().is_err());
        h.join().ok();
    }

    #[test]
    fn get_shard_map_surfaces_server_error() {
        let (port, h) = serve_responses(vec![(500, "boom".to_string())]);
        let client = CoreCruxClient::new(&format!("http://127.0.0.1:{port}"));
        assert!(client.get_shard_map().is_err());
        h.join().ok();
    }

    // ── submit_move / submit_split ──────────────────────────────────

    #[test]
    fn submit_move_returns_report_with_normalized_base() {
        let (port, h) = serve_responses(vec![(200, record_json("job-1", "shard-0001", "move"))]);
        let report = submit_move(
            &format!("http://127.0.0.1:{port}/"),
            MoveCreateRequest {
                job_id: None,
                shard_id: "shard-0001".to_string(),
                source_node_id: "node-a".to_string(),
                target_node_id: "node-b".to_string(),
                status: None,
            },
        )
        .expect("submit move");
        h.join().ok();
        assert!(report.ok);
        assert_eq!(report.coordinator_base, format!("http://127.0.0.1:{port}"));
        assert_eq!(report.record.job_id, "job-1");
        assert!(report.next_hint.contains("corecruxctl shard status"));
    }

    #[test]
    fn submit_split_returns_report_with_normalized_base() {
        let (port, h) = serve_responses(vec![(200, record_json("job-2", "shard-0001", "split"))]);
        let report = submit_split(
            &format!("http://127.0.0.1:{port}//"),
            SplitCreateRequest {
                job_id: None,
                shard_id: "shard-0001".to_string(),
                at_hash_hex: "0x4000000000000000".to_string(),
                new_shard_id: "shard-0003".to_string(),
                status: None,
            },
        )
        .expect("submit split");
        h.join().ok();
        assert!(report.ok);
        assert_eq!(report.coordinator_base, format!("http://127.0.0.1:{port}"));
        assert_eq!(report.record.kind, "split");
    }

    #[test]
    fn submit_move_propagates_coordinator_failure() {
        let (port, h) = serve_responses(vec![(500, "boom".to_string())]);
        let result = submit_move(
            &format!("http://127.0.0.1:{port}"),
            MoveCreateRequest {
                job_id: None,
                shard_id: "shard-0001".to_string(),
                source_node_id: "node-a".to_string(),
                target_node_id: "node-b".to_string(),
                status: None,
            },
        );
        h.join().ok();
        assert!(result.is_err(), "a failed submit must not report ok:true");
    }

    // ── status ──────────────────────────────────────────────────────

    /// `status` issues leases, then moves, then splits. Filters must drop
    /// records for other shards/jobs on every one of the three lists.
    #[test]
    fn status_applies_shard_and_job_filters() {
        let leases = format!(
            "[{},{}]",
            lease_json("shard-0001", "node-b", 3),
            lease_json("shard-0002", "node-c", 1)
        );
        let moves = format!(
            "[{},{},{}]",
            record_json("job-1", "shard-0001", "move"),
            record_json("job-2", "shard-0001", "move"),
            record_json("job-3", "shard-0002", "move")
        );
        let splits = format!(
            "[{},{}]",
            record_json("job-1", "shard-0001", "split"),
            record_json("job-4", "shard-0002", "split")
        );
        let (port, h) = serve_responses(vec![(200, leases), (200, moves), (200, splits)]);

        let report = status(&format!("http://127.0.0.1:{port}"), Some("shard-0001"), Some("job-1")).expect("status");
        h.join().ok();

        assert!(report.ok);
        assert_eq!(report.leases.len(), 1, "shard filter applies to leases");
        assert_eq!(report.moves.len(), 1);
        assert_eq!(report.moves[0].job_id, "job-1");
        assert_eq!(report.splits.len(), 1);
        assert_eq!(report.shard_filter.as_deref(), Some("shard-0001"));
        assert_eq!(report.job_id_filter.as_deref(), Some("job-1"));
    }

    #[test]
    fn status_without_filters_returns_every_record() {
        let leases = format!("[{}]", lease_json("shard-0002", "node-c", 1));
        let moves = format!(
            "[{},{}]",
            record_json("job-1", "shard-0001", "move"),
            record_json("job-3", "shard-0002", "move")
        );
        let splits = "[]".to_string();
        let (port, h) = serve_responses(vec![(200, leases), (200, moves), (200, splits)]);

        let report = status(&format!("http://127.0.0.1:{port}"), None, None).expect("status");
        h.join().ok();
        assert_eq!(report.leases.len(), 1);
        assert_eq!(report.moves.len(), 2);
        assert!(report.splits.is_empty());
        assert!(report.shard_filter.is_none());
        assert!(report.job_id_filter.is_none());
    }

    /// A filter that matches nothing yields empty lists — but the call still
    /// succeeded, so `ok` stays true. Pins that "no matching records" is not
    /// conflated with "coordinator unreachable" (which errors instead).
    #[test]
    fn status_filter_matching_nothing_is_empty_not_error() {
        let leases = format!("[{}]", lease_json("shard-0001", "node-b", 3));
        let moves = format!("[{}]", record_json("job-1", "shard-0001", "move"));
        let (port, h) = serve_responses(vec![(200, leases), (200, moves), (200, "[]".to_string())]);
        let report = status(&format!("http://127.0.0.1:{port}"), Some("shard-9999"), None).expect("status");
        h.join().ok();
        assert!(report.ok);
        assert!(report.leases.is_empty());
        assert!(report.moves.is_empty());
        assert!(report.splits.is_empty());
    }

    #[test]
    fn status_propagates_lease_fetch_failure() {
        let (port, h) = serve_responses(vec![(500, "boom".to_string())]);
        let result = status(&format!("http://127.0.0.1:{port}"), None, None);
        h.join().ok();
        assert!(result.is_err());
    }

    // ── verify_move / verify_split ──────────────────────────────────

    #[test]
    fn verify_move_end_to_end_passes_for_consistent_cluster() {
        let map = sample_map();
        let moves = format!("[{}]", record_json("job-1", "shard-0001", "move"));
        let leases = format!("[{}]", lease_json("shard-0001", "node-b", 3));
        let (port, h) = serve_responses(vec![(200, shard_map_body(&map)), (200, moves), (200, leases)]);
        let base = format!("http://127.0.0.1:{port}");

        let report = verify_move(&base, &base, "shard-0001", Some("job-1"), None, true).expect("verify move");
        h.join().ok();

        assert_eq!(report.kind, "move");
        assert_eq!(report.shard_map_version, 7);
        assert_eq!(
            report.selected_record.as_ref().map(|r| r.job_id.clone()),
            Some("job-1".to_string())
        );
        assert!(report.ok, "checks={:?}", report.checks);
    }

    /// The lease says a different leader than the shard map. `verify_move`
    /// must report `ok:false` — a mid-move cluster is not a verified move.
    #[test]
    fn verify_move_flags_lease_disagreement() {
        let map = sample_map();
        let moves = format!("[{}]", record_json("job-1", "shard-0001", "move"));
        let leases = format!("[{}]", lease_json("shard-0001", "node-a", 2));
        let (port, h) = serve_responses(vec![(200, shard_map_body(&map)), (200, moves), (200, leases)]);
        let base = format!("http://127.0.0.1:{port}");

        let report = verify_move(&base, &base, "shard-0001", None, None, true).expect("verify move");
        h.join().ok();
        assert!(!report.ok);
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "lease_matches_shard_map")
            .expect("lease check");
        assert!(!check.ok);
    }

    /// With no coordinator record and no explicit `--expect-target`, there is
    /// nothing to compare the leader against, so the `leader_matches_target`
    /// check is omitted entirely and the report can still be `ok`. Pins the
    /// current behaviour: an unverifiable move target is not a failure.
    #[test]
    fn verify_move_without_record_or_expected_target_omits_leader_check() {
        let map = sample_map();
        let leases = format!("[{}]", lease_json("shard-0001", "node-b", 3));
        let (port, h) = serve_responses(vec![
            (200, shard_map_body(&map)),
            (200, "[]".to_string()),
            (200, leases),
        ]);
        let base = format!("http://127.0.0.1:{port}");

        let report = verify_move(&base, &base, "shard-0001", None, None, false).expect("verify move");
        h.join().ok();
        assert!(report.selected_record.is_none());
        assert!(report.checks.iter().all(|c| c.name != "leader_matches_target"));
        assert!(report.ok);
    }

    #[test]
    fn verify_move_explicit_expected_target_overrides_record() {
        let map = sample_map();
        let moves = format!("[{}]", record_json("job-1", "shard-0001", "move"));
        let leases = format!("[{}]", lease_json("shard-0001", "node-b", 3));
        let (port, h) = serve_responses(vec![(200, shard_map_body(&map)), (200, moves), (200, leases)]);
        let base = format!("http://127.0.0.1:{port}");

        let report = verify_move(&base, &base, "shard-0001", None, Some("node-ZZZ"), false).expect("verify move");
        h.join().ok();
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "leader_matches_target")
            .expect("leader check");
        assert!(!check.ok);
        assert!(
            check.detail.contains("expectedTarget=node-ZZZ"),
            "detail={}",
            check.detail
        );
        assert!(!report.ok);
    }

    #[test]
    fn verify_move_propagates_shard_map_failure() {
        let (port, h) = serve_responses(vec![(500, "boom".to_string())]);
        let base = format!("http://127.0.0.1:{port}");
        assert!(verify_move(&base, &base, "shard-0001", None, None, false).is_err());
        h.join().ok();
    }

    #[test]
    fn verify_split_end_to_end_passes_for_consistent_cluster() {
        let mut map = sample_map();
        map.shards[0].ranges[0].end_exclusive = "0x4000000000000000".to_string();
        map.shards.push(ShardDescriptor {
            shard_id: "shard-0003".to_string(),
            epoch: 1,
            state: ShardState::Active,
            ranges: vec![HashRange {
                start_inclusive: "0x4000000000000000".to_string(),
                end_exclusive: "0x8000000000000000".to_string(),
            }],
            leader: node("node-b"),
            followers: Some(vec![node("node-a")]),
            data_dir: None,
            gpu_id: Some(0),
        });
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");

        let splits = format!("[{}]", record_json("job-2", "shard-0001", "split"));
        let (port, h) = serve_responses(vec![(200, shard_map_body(&map)), (200, splits)]);
        let base = format!("http://127.0.0.1:{port}");

        let report = verify_split(&base, &base, "shard-0001", "shard-0003", None, Some("job-2")).expect("verify split");
        h.join().ok();
        assert_eq!(report.kind, "split");
        assert!(report.ok, "checks={:?}", report.checks);
    }

    /// An empty `new_shard_id` falls back to the coordinator record's
    /// `newShardId`; if the record names a shard the map does not have, the
    /// split must be reported as unverified.
    #[test]
    fn verify_split_falls_back_to_record_new_shard_id() {
        let map = sample_map();
        let splits = format!("[{}]", record_json("job-2", "shard-0001", "split"));
        let (port, h) = serve_responses(vec![(200, shard_map_body(&map)), (200, splits)]);
        let base = format!("http://127.0.0.1:{port}");

        let report = verify_split(&base, &base, "shard-0001", "", None, Some("job-2")).expect("verify split");
        h.join().ok();
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "new_shard_exists")
            .expect("child check");
        assert!(!check.ok);
        assert!(check.detail.contains("shard-0003"), "detail={}", check.detail);
        assert!(!report.ok);
    }

    /// DEFECT-ADJACENT PIN: when neither `--at` nor a matching coordinator
    /// record supplies a split point, `split_point_boundary_present` is never
    /// emitted, so a split can be reported `ok` without its boundary ever
    /// being checked.
    #[test]
    fn verify_split_without_split_point_skips_boundary_check() {
        let map = sample_map();
        let (port, h) = serve_responses(vec![(200, shard_map_body(&map)), (200, "[]".to_string())]);
        let base = format!("http://127.0.0.1:{port}");

        let report = verify_split(&base, &base, "shard-0001", "shard-0002", None, None).expect("verify split");
        h.join().ok();
        assert!(report.selected_record.is_none());
        assert!(report.checks.iter().all(|c| c.name != "split_point_boundary_present"));
        assert!(report.ok);
    }

    #[test]
    fn verify_split_propagates_coordinator_failure() {
        let map = sample_map();
        let (port, h) = serve_responses(vec![(200, shard_map_body(&map)), (503, "down".to_string())]);
        let base = format!("http://127.0.0.1:{port}");
        assert!(verify_split(&base, &base, "shard-0001", "shard-0002", None, None).is_err());
        h.join().ok();
    }

    // ══════════════════════════════════════════════════════════════════
    // Boundary + malformed-id cases for the pure check builders.
    // ══════════════════════════════════════════════════════════════════

    /// `parse_u64_hex` treats the `0x` prefix as optional, so a split point
    /// given without it still normalizes onto a shard-map boundary.
    #[test]
    fn build_split_checks_split_point_without_0x_prefix_matches_boundary() {
        let mut map = sample_map();
        map.shards[0].ranges[0].end_exclusive = "0x4000000000000000".to_string();
        map.shards.push(ShardDescriptor {
            shard_id: "shard-0003".to_string(),
            epoch: 1,
            state: ShardState::Active,
            ranges: vec![HashRange {
                start_inclusive: "4000000000000000".to_string(),
                end_exclusive: "0x8000000000000000".to_string(),
            }],
            leader: node("node-b"),
            followers: Some(vec![node("node-a")]),
            data_dir: None,
            gpu_id: Some(0),
        });
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");

        let checks = build_split_checks(&map, "shard-0001", "shard-0003", Some("4000000000000000"));
        let boundary = checks
            .iter()
            .find(|c| c.name == "split_point_boundary_present")
            .expect("boundary check");
        assert!(boundary.ok, "detail={}", boundary.detail);
    }

    /// A split point that overflows u64 is unparsable: the builder reports it
    /// and returns immediately, so no later check can mask the failure.
    #[test]
    fn build_split_checks_overflowing_split_point_short_circuits() {
        let map = sample_map();
        let checks = build_split_checks(&map, "shard-0001", "shard-0002", Some("0x1FFFFFFFFFFFFFFFF"));
        let parse = checks
            .iter()
            .find(|c| c.name == "split_point_parseable")
            .expect("parse check");
        assert!(!parse.ok);
        assert!(
            checks.iter().all(|c| c.name != "epoch_nonzero"),
            "must return before the epoch check"
        );
    }

    #[test]
    fn build_split_checks_empty_split_point_is_unparsable() {
        let map = sample_map();
        let checks = build_split_checks(&map, "shard-0001", "shard-0002", Some(""));
        let parse = checks
            .iter()
            .find(|c| c.name == "split_point_parseable")
            .expect("parse check");
        assert!(!parse.ok);
        assert!(parse.detail.contains("empty hex"), "detail={}", parse.detail);
    }

    /// The parent's `end_exclusive` matches but no child range starts there:
    /// half a boundary is not a boundary.
    #[test]
    fn build_split_checks_parent_boundary_without_child_boundary_fails() {
        let mut map = sample_map();
        map.shards[0].ranges[0].end_exclusive = "0x4000000000000000".to_string();
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");

        let checks = build_split_checks(&map, "shard-0001", "shard-0002", Some("0x4000000000000000"));
        let boundary = checks
            .iter()
            .find(|c| c.name == "split_point_boundary_present")
            .expect("boundary check");
        assert!(!boundary.ok);
        assert!(
            boundary.detail.contains("parentHasEnd=true"),
            "detail={}",
            boundary.detail
        );
        assert!(
            boundary.detail.contains("childHasStart=false"),
            "detail={}",
            boundary.detail
        );
    }

    /// A shard map whose recorded digest no longer covers its contents must
    /// fail `shard_map_valid` on both builders.
    #[test]
    fn build_checks_flag_tampered_shard_map_digest() {
        let mut map = sample_map();
        map.blake3 = "0".repeat(64);

        let move_checks = build_move_checks(&map, &[], "shard-0001", None, false);
        let move_valid = move_checks
            .iter()
            .find(|c| c.name == "shard_map_valid")
            .expect("valid check");
        assert!(!move_valid.ok);
        assert_eq!(move_valid.detail, "shard map validation failed");

        let split_checks = build_split_checks(&map, "shard-0001", "shard-0002", None);
        let split_valid = split_checks
            .iter()
            .find(|c| c.name == "shard_map_valid")
            .expect("valid check");
        assert!(!split_valid.ok);
    }

    /// Shard ids are compared byte-for-byte: a differently-formatted id
    /// ("shard-1" vs "shard-0001") must NOT resolve to the same shard.
    #[test]
    fn build_move_checks_shard_id_matching_is_exact() {
        let map = sample_map();
        for malformed in ["shard-1", "SHARD-0001", "shard-0001 ", "0001"] {
            let checks = build_move_checks(&map, &[], malformed, None, false);
            let exists = checks.iter().find(|c| c.name == "shard_exists").expect("exists check");
            assert!(!exists.ok, "'{malformed}' must not match shard-0001");
            // A missing shard also suppresses the lease checks entirely.
            assert!(checks.iter().all(|c| c.name != "lease_record_present"));
        }
    }

    #[test]
    fn build_split_checks_parent_and_child_can_be_the_same_shard() {
        // Degenerate input: the caller passed the parent id as the new shard.
        let map = sample_map();
        let checks = build_split_checks(&map, "shard-0001", "shard-0001", None);
        assert!(checks
            .iter()
            .find(|c| c.name == "parent_shard_exists")
            .is_some_and(|c| c.ok));
        assert!(checks
            .iter()
            .find(|c| c.name == "new_shard_exists")
            .is_some_and(|c| c.ok));
    }

    /// `select_record` with an explicit job id never falls back to the shard
    /// id, so an unknown job must not silently select a same-shard record.
    #[test]
    fn select_record_unknown_job_id_does_not_fall_back_to_shard() {
        let records = vec![OrchestrationRecord {
            job_id: "job-1".to_string(),
            kind: "move".to_string(),
            shard_id: "shard-0001".to_string(),
            source_node_id: None,
            target_node_id: None,
            at_hash_hex: None,
            new_shard_id: None,
            status: "pending".to_string(),
            created_unix_ms: 0,
            updated_unix_ms: 0,
        }];
        assert!(select_record(&records, "shard-0001", Some("job-999")).is_none());
    }

    #[test]
    fn canonical_hex_normalizes_short_and_unprefixed_forms() {
        assert_eq!(canonical_hex("0x0"), "0x0000000000000000");
        assert_eq!(canonical_hex("4000000000000000"), "0x4000000000000000");
        assert_eq!(canonical_hex("0X4000000000000000"), "0X4000000000000000");
    }

    #[test]
    fn canonical_hex_overflowing_value_is_returned_verbatim() {
        assert_eq!(canonical_hex("0x1FFFFFFFFFFFFFFFF"), "0x1FFFFFFFFFFFFFFFF");
    }
}
