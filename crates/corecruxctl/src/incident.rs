// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl incident create|show|export` HTTP client.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Serialize)]
pub struct IncidentWindowRequest {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentCreateRequest {
    pub tenant_id: String,
    pub title: String,
    pub window: IncidentWindowRequest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .http_status_as_error(false)
        .build()
        .into()
}

fn read_json_response(response: ureq::http::Response<ureq::Body>) -> Result<Value, DynErr> {
    let status = response.status().as_u16();
    let body = response.into_body().read_to_string()?;
    if status >= 300 {
        return Err(format!("incident request failed (HTTP {status}): {body}").into());
    }
    Ok(serde_json::from_str(&body)?)
}

pub fn create(base: &str, bearer: Option<&str>, request: &IncidentCreateRequest) -> Result<Value, DynErr> {
    let url = format!("{}/v1/incidents", base.trim_end_matches('/'));
    let mut req = agent().post(&url).header("content-type", "application/json");
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    read_json_response(req.send_json(request)?)
}

pub fn show(base: &str, bearer: Option<&str>, id: &str) -> Result<Value, DynErr> {
    let url = format!(
        "{}/v1/incidents/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(id)
    );
    let mut req = agent().get(&url).header("accept", "application/json");
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    read_json_response(req.call()?)
}

pub fn export(base: &str, bearer: Option<&str>, id: &str, out: &Path) -> Result<usize, DynErr> {
    let url = format!(
        "{}/v1/incidents/{}/export",
        base.trim_end_matches('/'),
        urlencoding::encode(id)
    );
    let mut req = agent().post(&url).header("accept", "application/zstd");
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let response = req.send_empty()?;
    let status = response.status().as_u16();
    let bytes = response.into_body().read_to_vec()?;
    if status >= 300 {
        return Err(format!(
            "incident export failed (HTTP {status}): {}",
            String::from_utf8_lossy(&bytes)
        )
        .into());
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, &bytes)?;
    Ok(bytes.len())
}

#[allow(clippy::too_many_arguments)]
pub fn run_create(
    url: Option<String>,
    tenant_id: String,
    title: String,
    from: String,
    to: String,
    session_ids: Vec<String>,
    agent_ids: Vec<String>,
    entities: Vec<String>,
    notes: Option<String>,
) -> Result<(), DynErr> {
    let base = crate::machine::resolve_daemon(url)?;
    let bearer = crate::login::resolve_fresh_bearer(&base)?;
    let response = create(
        &base,
        bearer.as_deref(),
        &IncidentCreateRequest {
            tenant_id,
            title,
            window: IncidentWindowRequest { from, to },
            session_ids,
            agent_ids,
            entities,
            notes,
        },
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub fn run_show(url: Option<String>, id: String) -> Result<(), DynErr> {
    let base = crate::machine::resolve_daemon(url)?;
    let bearer = crate::login::resolve_fresh_bearer(&base)?;
    let response = show(&base, bearer.as_deref(), &id)?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub fn run_export(url: Option<String>, id: String, out: PathBuf) -> Result<(), DynErr> {
    let base = crate::machine::resolve_daemon(url)?;
    let bearer = crate::login::resolve_fresh_bearer(&base)?;
    let bytes = export(&base, bearer.as_deref(), &id, &out)?;
    println!("incident {id}: wrote {bytes} bytes to {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_uses_route_contract_shape() {
        let request = IncidentCreateRequest {
            tenant_id: "tenant-a".to_string(),
            title: "Outage".to_string(),
            window: IncidentWindowRequest {
                from: "2026-07-13T00:00:00Z".to_string(),
                to: "2026-07-13T01:00:00Z".to_string(),
            },
            session_ids: vec!["s1".to_string()],
            agent_ids: vec!["p1".to_string()],
            entities: vec!["service".to_string()],
            notes: None,
        };
        let value = serde_json::to_value(request).expect("serialise request");
        assert_eq!(value["window"]["from"], "2026-07-13T00:00:00Z");
        assert_eq!(value["session_ids"][0], "s1");
        assert!(value.get("notes").is_none());
    }
}
