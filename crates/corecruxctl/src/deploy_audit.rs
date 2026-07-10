// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Pre-deploy assertion for the daemon's network bind and authentication mode.
//!
//! This deliberately reads local launch configuration instead of probing the
//! public daemon API: `/healthz`, `/readyz`, and `/v1/version` do not disclose
//! auth mode, and adding that disclosure would weaken the public-probe policy.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

type DynError = Box<dyn std::error::Error + Send + Sync>;

const DEFAULT_BIND: &str = "127.0.0.1";
const DEFAULT_AUTH_MODE: &str = "dev_scopes";

#[derive(Debug, Clone, Default)]
pub struct DeployAuditOptions {
    pub config_path: Option<PathBuf>,
    pub auth_mode: Option<String>,
    pub http_bind: Option<String>,
    pub grpc_bind: Option<String>,
    pub network_exposed: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployAuthMode {
    Off,
    DevScopes,
    JwtHs256,
    JwtJwks,
    Invalid,
}

impl DeployAuthMode {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            // The daemon filters empty env values to unset (config.rs
            // `env_string`) and unset resolves to dev_scopes, so an explicit
            // empty string must audit as dev_scopes, not off.
            "" | "dev" | "dev_scopes" | "devscopes" => Self::DevScopes,
            "off" => Self::Off,
            "jwt" | "jwt_hs256" => Self::JwtHs256,
            "jwt_jwks" | "jwks" | "oidc" | "jwt_oidc" => Self::JwtJwks,
            _ => Self::Invalid,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::DevScopes => "dev_scopes",
            Self::JwtHs256 => "jwt_hs256",
            Self::JwtJwks => "jwt_jwks",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindClass {
    Local,
    Network,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    LocalOnly,
    NetworkExposed,
    Unknown,
}

impl Exposure {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::NetworkExposed => "network_exposed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedSetting {
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BindReport {
    pub value: String,
    pub source: String,
    pub class: BindClass,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployAuditReport {
    pub schema: &'static str,
    pub verdict: Verdict,
    pub auth_mode: ResolvedSetting,
    pub auth_mode_defaulted: bool,
    pub http_bind: BindReport,
    pub grpc_bind: BindReport,
    pub exposure: Exposure,
    pub exposure_reasons: Vec<String>,
    pub reason: String,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileConfig {
    daemon: FileDaemonConfig,
    enterprise: FileEnterpriseConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileDaemonConfig {
    listen_addr: Option<String>,
    auth_mode: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileEnterpriseConfig {
    enabled: Option<bool>,
}

#[derive(Debug, Clone, Default)]
struct LoadedFileConfig {
    path: Option<PathBuf>,
    config: FileConfig,
    warnings: Vec<String>,
}

pub fn classify_bind(raw: &str) -> BindClass {
    let value = raw.trim();
    if value.starts_with("unix:") || value.starts_with('/') {
        return BindClass::Local;
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return classify_ip(addr.ip());
    }
    let unbracketed = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(value);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return classify_ip(ip);
    }
    BindClass::Unknown
}

fn classify_ip(ip: IpAddr) -> BindClass {
    if ip.is_loopback() {
        BindClass::Local
    } else {
        BindClass::Network
    }
}

pub fn effective_exposure(http: BindClass, grpc: BindClass, forced_network_exposure: bool) -> Exposure {
    if forced_network_exposure || matches!(http, BindClass::Network) || matches!(grpc, BindClass::Network) {
        Exposure::NetworkExposed
    } else if matches!(http, BindClass::Unknown) || matches!(grpc, BindClass::Unknown) {
        Exposure::Unknown
    } else {
        Exposure::LocalOnly
    }
}

pub fn decide(auth_mode: DeployAuthMode, exposure: Exposure) -> (Verdict, &'static str) {
    match (auth_mode, exposure) {
        (DeployAuthMode::JwtHs256 | DeployAuthMode::JwtJwks, _) => (
            Verdict::Pass,
            "JWT authentication satisfies the networked-host deploy assertion.",
        ),
        (DeployAuthMode::DevScopes, Exposure::LocalOnly) => (
            Verdict::Pass,
            "dev_scopes is permitted because every audited daemon listener is local-only.",
        ),
        (DeployAuthMode::DevScopes, Exposure::NetworkExposed) => (
            Verdict::Fail,
            "network-exposed daemon listeners must use jwt_hs256 or jwt_jwks; dev_scopes trusts caller-provided scopes.",
        ),
        (DeployAuthMode::DevScopes, Exposure::Unknown) => (
            Verdict::Warn,
            "the bind could not be classified, so dev_scopes safety cannot be established.",
        ),
        (DeployAuthMode::Off, Exposure::LocalOnly) => (
            Verdict::Warn,
            "auth mode off is only appropriate for throwaway local development.",
        ),
        (DeployAuthMode::Off, Exposure::NetworkExposed) => (
            Verdict::Fail,
            "network-exposed daemon listeners must use jwt_hs256 or jwt_jwks; auth mode off performs no authentication.",
        ),
        (DeployAuthMode::Off, Exposure::Unknown) => (
            Verdict::Warn,
            "the bind could not be classified and auth mode off performs no authentication.",
        ),
        (DeployAuthMode::Invalid, _) => (
            Verdict::Fail,
            "the auth mode is invalid; valid deploy values are dev_scopes, jwt_hs256, and jwt_jwks (off is local-development only).",
        ),
    }
}

pub fn audit(options: &DeployAuditOptions) -> DeployAuditReport {
    let loaded = load_file_config(options.config_path.as_deref());
    let config_source = loaded
        .path
        .as_ref()
        .map_or_else(|| "config".to_string(), |path| format!("config:{}", path.display()));

    let auth_mode_defaulted = options.auth_mode.is_none()
        && env_value("CORECRUXD_AUTH_MODE").is_none()
        && loaded.config.daemon.auth_mode.is_none();
    let auth_mode = resolve_setting(
        options.auth_mode.as_deref(),
        "CORECRUXD_AUTH_MODE",
        loaded.config.daemon.auth_mode.as_deref(),
        DEFAULT_AUTH_MODE,
        &config_source,
    );
    let http_bind = resolve_setting(
        options.http_bind.as_deref(),
        "CORECRUXD_HTTP_HOST",
        loaded.config.daemon.listen_addr.as_deref(),
        DEFAULT_BIND,
        &config_source,
    );
    let grpc_bind = resolve_setting(
        options.grpc_bind.as_deref(),
        "CORECRUXD_GRPC_HOST",
        loaded.config.daemon.listen_addr.as_deref(),
        DEFAULT_BIND,
        &config_source,
    );

    let enterprise_enabled = env_value("CORECRUXD_ENTERPRISE_ENABLED").map_or_else(
        || loaded.config.enterprise.enabled.unwrap_or(false),
        |value| bool_value(&value),
    );
    let hosted_mode = env_value("CORECRUXD_OPERATING_MODE")
        .or_else(|| env_value("CRUX_OPERATING_MODE"))
        .is_some_and(|value| hosted_or_tenant_mode(&value));

    let mut exposure_reasons = Vec::new();
    if options.network_exposed {
        exposure_reasons.push("--network-exposed".to_string());
    }
    if enterprise_enabled {
        exposure_reasons.push("enterprise configuration is enabled".to_string());
    }
    if hosted_mode {
        exposure_reasons.push("hosted/tenant operating mode is enabled".to_string());
    }

    let http_class = classify_bind(&http_bind.value);
    let grpc_class = classify_bind(&grpc_bind.value);
    if matches!(http_class, BindClass::Network) {
        exposure_reasons.push(format!("HTTP binds {}", http_bind.value));
    }
    if matches!(grpc_class, BindClass::Network) {
        exposure_reasons.push(format!("gRPC binds {}", grpc_bind.value));
    }
    let forced_network_exposure = options.network_exposed || enterprise_enabled || hosted_mode;
    let exposure = effective_exposure(http_class, grpc_class, forced_network_exposure);
    let parsed_auth = DeployAuthMode::parse(&auth_mode.value);
    let (mut verdict, reason) = decide(parsed_auth, exposure);

    let mut warnings = loaded.warnings;
    if matches!(http_class, BindClass::Unknown) {
        warnings.push(format!(
            "HTTP bind `{}` is not an IP address or Unix socket",
            http_bind.value
        ));
    }
    if matches!(grpc_class, BindClass::Unknown) {
        warnings.push(format!(
            "gRPC bind `{}` is not an IP address or Unix socket",
            grpc_bind.value
        ));
    }
    if !warnings.is_empty()
        && matches!(verdict, Verdict::Pass)
        && !matches!(parsed_auth, DeployAuthMode::JwtHs256 | DeployAuthMode::JwtJwks)
    {
        verdict = Verdict::Warn;
    }

    let mut limitations = Vec::new();
    if matches!(exposure, Exposure::LocalOnly) {
        limitations.push(
            "a local-only listener may still be published by a reverse proxy or port forward; rerun with --network-exposed when it is"
                .to_string(),
        );
    }
    limitations.push(
        "public health/version endpoints do not report auth mode; run this command in the daemon's launch environment or pass explicit overrides"
            .to_string(),
    );

    DeployAuditReport {
        schema: "corecrux.deploy_audit.v1",
        verdict,
        auth_mode: ResolvedSetting {
            value: if matches!(parsed_auth, DeployAuthMode::Invalid) {
                auth_mode.value
            } else {
                parsed_auth.as_str().to_string()
            },
            source: auth_mode.source,
        },
        auth_mode_defaulted,
        http_bind: BindReport {
            value: http_bind.value,
            source: http_bind.source,
            class: http_class,
        },
        grpc_bind: BindReport {
            value: grpc_bind.value,
            source: grpc_bind.source,
            class: grpc_class,
        },
        exposure,
        exposure_reasons,
        reason: reason.to_string(),
        warnings,
        limitations,
    }
}

pub fn run(options: DeployAuditOptions) -> Result<(), DynError> {
    let report = audit(&options);
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report);
    }
    if matches!(report.verdict, Verdict::Fail) {
        return Err(std::io::Error::other("deploy auth audit failed").into());
    }
    Ok(())
}

fn print_human_report(report: &DeployAuditReport) {
    println!("{}: deploy auth audit", report.verdict.as_str().to_ascii_uppercase());
    println!(
        "  auth_mode: {} ({}){}",
        report.auth_mode.value,
        report.auth_mode.source,
        if report.auth_mode_defaulted {
            "; unset -> dev_scopes"
        } else {
            ""
        }
    );
    println!(
        "  HTTP bind: {} ({}, {:?})",
        report.http_bind.value, report.http_bind.source, report.http_bind.class
    );
    println!(
        "  gRPC bind: {} ({}, {:?})",
        report.grpc_bind.value, report.grpc_bind.source, report.grpc_bind.class
    );
    println!("  exposure: {}", report.exposure.as_str());
    for exposure_reason in &report.exposure_reasons {
        println!("  exposure reason: {exposure_reason}");
    }
    println!("  {}", report.reason);
    for warning in &report.warnings {
        println!("WARN: {warning}");
    }
    for limitation in &report.limitations {
        if limitation.starts_with("a local-only listener") {
            println!("WARN: {limitation}");
        } else {
            println!("NOTE: {limitation}");
        }
    }
}

fn resolve_setting(
    cli: Option<&str>,
    env_key: &str,
    config: Option<&str>,
    default: &str,
    config_source: &str,
) -> ResolvedSetting {
    if let Some(value) = cli {
        return ResolvedSetting {
            value: value.to_string(),
            source: "cli".to_string(),
        };
    }
    if let Some(value) = env_value(env_key) {
        return ResolvedSetting {
            value,
            source: format!("environment:{env_key}"),
        };
    }
    if let Some(value) = config {
        return ResolvedSetting {
            value: value.to_string(),
            source: config_source.to_string(),
        };
    }
    ResolvedSetting {
        value: default.to_string(),
        source: "default".to_string(),
    }
}

fn load_file_config(explicit_path: Option<&Path>) -> LoadedFileConfig {
    let (path, explicitly_configured) = configured_config_path(explicit_path);
    let Some(path) = path else {
        return LoadedFileConfig::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(raw) => match serde_yaml::from_str::<FileConfig>(&raw) {
            Ok(config) => LoadedFileConfig {
                path: Some(path),
                config,
                warnings: Vec::new(),
            },
            Err(err) => LoadedFileConfig {
                path: Some(path.clone()),
                config: FileConfig::default(),
                warnings: vec![format!("could not parse config {}: {err}", path.display())],
            },
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !explicitly_configured => LoadedFileConfig::default(),
        Err(err) => LoadedFileConfig {
            path: Some(path.clone()),
            config: FileConfig::default(),
            warnings: vec![format!("could not read config {}: {err}", path.display())],
        },
    }
}

fn configured_config_path(explicit_path: Option<&Path>) -> (Option<PathBuf>, bool) {
    if let Some(path) = explicit_path {
        return (Some(path.to_path_buf()), true);
    }
    if let Some(path) = env_value("CORECRUXD_CONFIG_PATH") {
        return (Some(PathBuf::from(path)), true);
    }
    let path = env_value("XDG_CONFIG_HOME").map(|base| PathBuf::from(base).join("crux").join("config.yaml"));
    (path, false)
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn bool_value(value: &str) -> bool {
    matches!(value, "1" | "true" | "TRUE" | "yes" | "YES")
}

fn hosted_or_tenant_mode(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().replace('-', "_").as_str(),
        "pro_cloud_only"
            | "cloud_only"
            | "pro_hybrid"
            | "hybrid"
            | "pro"
            | "max_private"
            | "max"
            | "private"
            | "onsite"
            | "on_site"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_classifier_distinguishes_loopback_network_unix_and_unknown() {
        for value in [
            "127.0.0.1",
            "127.42.0.9:14800",
            "::1",
            "[::1]:14800",
            "unix:/run/crux.sock",
        ] {
            assert_eq!(classify_bind(value), BindClass::Local, "{value}");
        }
        for value in ["0.0.0.0", "10.0.0.8:14800", "::", "[2001:db8::1]:14800"] {
            assert_eq!(classify_bind(value), BindClass::Network, "{value}");
        }
        assert_eq!(classify_bind("localhost"), BindClass::Unknown);
    }

    #[test]
    fn setting_resolution_prefers_cli_then_config_then_default() {
        let from_cli = resolve_setting(
            Some("cli-value"),
            "CORECRUXCTL_DEPLOY_AUDIT_TEST_UNSET",
            Some("config-value"),
            "default-value",
            "config:test.yaml",
        );
        assert_eq!(from_cli.value, "cli-value");
        assert_eq!(from_cli.source, "cli");

        let from_config = resolve_setting(
            None,
            "CORECRUXCTL_DEPLOY_AUDIT_TEST_UNSET",
            Some("config-value"),
            "default-value",
            "config:test.yaml",
        );
        assert_eq!(from_config.value, "config-value");
        assert_eq!(from_config.source, "config:test.yaml");

        let from_default = resolve_setting(
            None,
            "CORECRUXCTL_DEPLOY_AUDIT_TEST_UNSET",
            None,
            "default-value",
            "config:test.yaml",
        );
        assert_eq!(from_default.value, "default-value");
        assert_eq!(from_default.source, "default");
    }

    #[test]
    fn yaml_shape_matches_daemon_bind_auth_and_enterprise_fields() {
        let config: FileConfig = serde_yaml::from_str(
            r#"
daemon:
  listen_addr: "0.0.0.0"
  auth_mode: "jwt_jwks"
enterprise:
  enabled: true
"#,
        )
        .expect("valid daemon config");
        assert_eq!(config.daemon.listen_addr.as_deref(), Some("0.0.0.0"));
        assert_eq!(config.daemon.auth_mode.as_deref(), Some("jwt_jwks"));
        assert_eq!(config.enterprise.enabled, Some(true));
    }

    #[test]
    fn decision_matrix_allows_loopback_dev_scopes() {
        assert_eq!(decide(DeployAuthMode::DevScopes, Exposure::LocalOnly).0, Verdict::Pass);
    }

    #[test]
    fn decision_matrix_rejects_networked_dev_scopes_and_off() {
        assert_eq!(
            decide(DeployAuthMode::DevScopes, Exposure::NetworkExposed).0,
            Verdict::Fail
        );
        assert_eq!(decide(DeployAuthMode::Off, Exposure::NetworkExposed).0, Verdict::Fail);
    }

    #[test]
    fn decision_matrix_allows_both_jwt_modes_on_network() {
        assert_eq!(
            decide(DeployAuthMode::JwtHs256, Exposure::NetworkExposed).0,
            Verdict::Pass
        );
        assert_eq!(
            decide(DeployAuthMode::JwtJwks, Exposure::NetworkExposed).0,
            Verdict::Pass
        );
    }

    #[test]
    fn decision_matrix_warns_when_dev_exposure_is_unknown() {
        assert_eq!(decide(DeployAuthMode::DevScopes, Exposure::Unknown).0, Verdict::Warn);
    }

    #[test]
    fn forced_network_exposure_overrides_loopback_bind() {
        assert_eq!(
            effective_exposure(BindClass::Local, BindClass::Local, true),
            Exposure::NetworkExposed
        );
    }

    #[test]
    fn unset_auth_defaults_to_dev_scopes_and_fails_on_network() {
        let resolved = resolve_setting(
            None,
            "CORECRUXCTL_DEPLOY_AUDIT_TEST_UNSET",
            None,
            DEFAULT_AUTH_MODE,
            "config",
        );
        assert_eq!(resolved.value, "dev_scopes");
        assert_eq!(
            decide(DeployAuthMode::parse(&resolved.value), Exposure::NetworkExposed).0,
            Verdict::Fail
        );
    }

    #[test]
    fn explicit_network_exposure_rejects_loopback_dev_scopes() {
        let options = DeployAuditOptions {
            auth_mode: Some("dev_scopes".to_string()),
            http_bind: Some("127.0.0.1".to_string()),
            grpc_bind: Some("::1".to_string()),
            network_exposed: true,
            json: false,
            config_path: None,
        };
        assert_eq!(audit(&options).verdict, Verdict::Fail);
    }
}
