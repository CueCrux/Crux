// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::json::{self, JsonValue};
use crate::{validate_attach_url, ConnectionError};

pub const PROFILE_SCHEMA_VERSION: u32 = 1;
const MAX_PROFILE_BYTES: u64 = 1_048_576;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileMode {
    Bundled,
    Attach,
}

impl ProfileMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bundled => "bundled",
            Self::Attach => "attach",
        }
    }

    fn parse(value: &str) -> Result<Self, ConnectionError> {
        match value {
            "bundled" => Ok(Self::Bundled),
            "attach" => Ok(Self::Attach),
            _ => Err(ConnectionError::new("profile mode must be bundled or attach")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub mode: ProfileMode,
    pub url: String,
    pub token_ref: Option<String>,
    pub local_plan_root: Option<PathBuf>,
}

impl Profile {
    pub fn bundled(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: ProfileMode::Bundled,
            url: String::new(),
            token_ref: None,
            local_plan_root: None,
        }
    }

    pub fn attach(
        name: impl Into<String>,
        url: impl Into<String>,
        token_ref: impl Into<String>,
    ) -> Result<Self, ConnectionError> {
        let mut profile = Self {
            name: name.into(),
            mode: ProfileMode::Attach,
            url: url.into(),
            token_ref: Some(token_ref.into()),
            local_plan_root: None,
        };
        profile.normalize_and_validate()?;
        Ok(profile)
    }

    fn normalize_and_validate(&mut self) -> Result<(), ConnectionError> {
        validate_label(&self.name, "profile name", 128)?;
        if let Some(root) = &self.local_plan_root {
            let root = root
                .to_str()
                .ok_or_else(|| ConnectionError::new("profile local-plan-root must be valid UTF-8"))?;
            if root.is_empty() || root.chars().any(char::is_control) {
                return Err(ConnectionError::new("profile local-plan-root is empty or invalid"));
            }
        }
        match self.mode {
            ProfileMode::Bundled => {
                if self.token_ref.is_some() {
                    return Err(ConnectionError::new(
                        "bundled profiles must not contain a token reference",
                    ));
                }
                if !self.url.is_empty() {
                    let validated = validate_attach_url(&self.url)?;
                    if validated.scheme() != "http"
                        || validated
                            .host()
                            .parse::<std::net::IpAddr>()
                            .ok()
                            .is_none_or(|ip| !ip.is_loopback())
                    {
                        return Err(ConnectionError::new("bundled profile URL must be loopback HTTP"));
                    }
                    self.url = validated.as_str().to_string();
                }
            }
            ProfileMode::Attach => {
                let token_ref = self
                    .token_ref
                    .as_deref()
                    .ok_or_else(|| ConnectionError::new("attach profiles require a token reference"))?;
                validate_token_reference(token_ref)?;
                self.url = validate_attach_url(&self.url)?.as_str().to_string();
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSet {
    pub schema_version: u32,
    pub active_profile: String,
    pub profiles: Vec<Profile>,
}

impl ProfileSet {
    pub fn new(active_profile: impl Into<String>, mut profiles: Vec<Profile>) -> Result<Self, ConnectionError> {
        for profile in &mut profiles {
            profile.normalize_and_validate()?;
        }
        let value = Self {
            schema_version: PROFILE_SCHEMA_VERSION,
            active_profile: active_profile.into(),
            profiles,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn active_profile(&self) -> Result<&Profile, ConnectionError> {
        self.profiles
            .iter()
            .find(|profile| profile.name == self.active_profile)
            .ok_or_else(|| ConnectionError::new("active profile does not identify a configured profile"))
    }

    pub fn set_active(&mut self, name: &str) -> Result<(), ConnectionError> {
        if self.profiles.iter().any(|profile| profile.name == name) {
            self.active_profile = name.to_string();
            Ok(())
        } else {
            Err(ConnectionError::new("selected profile does not exist"))
        }
    }

    pub fn from_json(input: &str) -> Result<Self, ConnectionError> {
        let value = json::parse(input)?;
        let object = value
            .as_object()
            .ok_or_else(|| ConnectionError::new("profile document must be a JSON object"))?;
        require_fields(object, &["schema_version", "active_profile", "profiles"])?;
        let schema_version = object
            .get("schema_version")
            .and_then(JsonValue::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| ConnectionError::new("profile schema_version must be an integer"))?;
        let active_profile = required_string(object, "active_profile")?.to_string();
        let raw_profiles = object
            .get("profiles")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| ConnectionError::new("profiles must be a JSON array"))?;
        let mut profiles = Vec::with_capacity(raw_profiles.len());
        for raw_profile in raw_profiles {
            profiles.push(parse_profile(raw_profile)?);
        }
        let mut result = Self {
            schema_version,
            active_profile,
            profiles,
        };
        for profile in &mut result.profiles {
            profile.normalize_and_validate()?;
        }
        result.validate()?;
        Ok(result)
    }

    pub fn to_json(&self) -> Result<String, ConnectionError> {
        self.validate()?;
        let mut output = String::from("{\"schema_version\":1,\"active_profile\":");
        json::push_string(&mut output, &self.active_profile);
        output.push_str(",\"profiles\":[");
        for (index, profile) in self.profiles.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push_str("{\"name\":");
            json::push_string(&mut output, &profile.name);
            output.push_str(",\"mode\":");
            json::push_string(&mut output, profile.mode.as_str());
            output.push_str(",\"url\":");
            json::push_string(&mut output, &profile.url);
            output.push_str(",\"token-ref\":");
            match &profile.token_ref {
                Some(value) => json::push_string(&mut output, value),
                None => output.push_str("null"),
            }
            output.push_str(",\"local-plan-root\":");
            match &profile.local_plan_root {
                Some(value) => {
                    let value = value
                        .to_str()
                        .ok_or_else(|| ConnectionError::new("profile local-plan-root must be valid UTF-8"))?;
                    json::push_string(&mut output, value);
                }
                None => output.push_str("null"),
            }
            output.push('}');
        }
        output.push_str("]}\n");
        Ok(output)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConnectionError> {
        ProfileStore::new(path).load()
    }

    pub fn store_atomic(&self, path: impl AsRef<Path>) -> Result<(), ConnectionError> {
        ProfileStore::new(path).save(self)
    }

    fn validate(&self) -> Result<(), ConnectionError> {
        if self.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(ConnectionError::new("unsupported profile schema_version"));
        }
        if self.profiles.is_empty() {
            return Err(ConnectionError::new("at least one connection profile is required"));
        }
        let mut names = BTreeSet::new();
        for profile in &self.profiles {
            if !names.insert(profile.name.as_str()) {
                return Err(ConnectionError::new("connection profile names must be unique"));
            }
        }
        if !names.contains(self.active_profile.as_str()) {
            return Err(ConnectionError::new("exactly one configured profile must be active"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProfileStore {
    path: PathBuf,
}

impl ProfileStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<ProfileSet, ConnectionError> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|_| ConnectionError::new("could not open the connection profile store"))?;
        let metadata = file
            .metadata()
            .map_err(|_| ConnectionError::new("could not inspect the connection profile store"))?;
        if metadata.len() > MAX_PROFILE_BYTES {
            return Err(ConnectionError::new("connection profile store exceeds the size limit"));
        }
        let mut document = String::new();
        file.read_to_string(&mut document)
            .map_err(|_| ConnectionError::new("could not read the connection profile store"))?;
        ProfileSet::from_json(&document)
    }

    pub fn save(&self, profiles: &ProfileSet) -> Result<(), ConnectionError> {
        let document = profiles.to_json()?;
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|_| ConnectionError::new("could not create the connection profile directory"))?;
        let temporary = temporary_path(&self.path)?;
        let result = write_and_replace(&temporary, &self.path, document.as_bytes());
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn write_and_replace(temporary: &Path, target: &Path, bytes: &[u8]) -> Result<(), ConnectionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .map_err(|_| ConnectionError::new("could not create a temporary connection profile store"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ConnectionError::new("could not durably write the connection profile store"))?;
    drop(file);
    replace_profile_file(temporary, target)
        .map_err(|_| ConnectionError::new("could not safely replace the connection profile store"))?;
    if let Some(parent) = target.parent().filter(|path| !path.as_os_str().is_empty()) {
        if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

/// Unix rename-over-target is atomic. Windows `rename` refuses to replace an
/// existing file, so that platform uses a same-directory backup: move the old
/// store aside, install the new store, remove the backup, and restore the old
/// store if installation fails. The Windows sequence is recoverable rather
/// than single-operation atomic, and no valid previous store is discarded
/// before a replacement exists.
#[cfg(not(windows))]
fn replace_profile_file(temporary: &Path, target: &Path) -> std::io::Result<()> {
    fs::rename(temporary, target)
}

#[cfg(windows)]
fn replace_profile_file(temporary: &Path, target: &Path) -> std::io::Result<()> {
    let backup = replacement_backup_path(target);
    replace_with_backup(temporary, target, &backup)
}

#[cfg(any(windows, test))]
fn replace_with_backup(temporary: &Path, target: &Path, backup: &Path) -> std::io::Result<()> {
    let had_target = target.try_exists()?;
    if had_target {
        fs::rename(target, backup)?;
    }
    match fs::rename(temporary, target) {
        Ok(()) => {
            if had_target {
                let _ = fs::remove_file(backup);
            }
            Ok(())
        }
        Err(error) => {
            if had_target {
                let _ = fs::rename(backup, target);
            }
            Err(error)
        }
    }
}

#[cfg(windows)]
fn replacement_backup_path(target: &Path) -> PathBuf {
    let mut backup_name = OsString::from(".");
    if let Some(filename) = target.file_name() {
        backup_name.push(filename);
    } else {
        backup_name.push("profiles.json");
    }
    backup_name.push(format!(
        ".backup-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    target.with_file_name(backup_name)
}

fn temporary_path(target: &Path) -> Result<PathBuf, ConnectionError> {
    let filename = target
        .file_name()
        .ok_or_else(|| ConnectionError::new("connection profile store path has no filename"))?;
    let mut temporary_name = OsString::from(".");
    temporary_name.push(filename);
    temporary_name.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(target.with_file_name(temporary_name))
}

fn parse_profile(value: &JsonValue) -> Result<Profile, ConnectionError> {
    let object = value
        .as_object()
        .ok_or_else(|| ConnectionError::new("each profile must be a JSON object"))?;
    require_fields_with_optional(object, &["name", "mode", "url", "token-ref"], &["local-plan-root"])?;
    let token_ref = match object.get("token-ref") {
        Some(JsonValue::Null) => None,
        Some(JsonValue::String(value)) => Some(value.clone()),
        _ => return Err(ConnectionError::new("profile token-ref must be a string or null")),
    };
    let local_plan_root = match object.get("local-plan-root") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::String(value)) => Some(PathBuf::from(value)),
        _ => return Err(ConnectionError::new("profile local-plan-root must be a string or null")),
    };
    Ok(Profile {
        name: required_string(object, "name")?.to_string(),
        mode: ProfileMode::parse(required_string(object, "mode")?)?,
        url: required_string(object, "url")?.to_string(),
        token_ref,
        local_plan_root,
    })
}

fn require_fields(object: &BTreeMap<String, JsonValue>, expected: &[&str]) -> Result<(), ConnectionError> {
    if object.len() != expected.len() || expected.iter().any(|field| !object.contains_key(*field)) {
        return Err(ConnectionError::new(
            "profile JSON contains missing or unknown fields; plaintext secret fields are forbidden",
        ));
    }
    Ok(())
}

fn require_fields_with_optional(
    object: &BTreeMap<String, JsonValue>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ConnectionError> {
    if required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err(ConnectionError::new(
            "profile JSON contains missing or unknown fields; plaintext secret fields are forbidden",
        ));
    }
    Ok(())
}

fn required_string<'a>(object: &'a BTreeMap<String, JsonValue>, field: &str) -> Result<&'a str, ConnectionError> {
    object
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| ConnectionError::new(format!("profile field {field} must be a string")))
}

fn validate_label(value: &str, label: &str, maximum: usize) -> Result<(), ConnectionError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ConnectionError::new(format!("{label} is empty or invalid")));
    }
    Ok(())
}

fn validate_token_reference(value: &str) -> Result<(), ConnectionError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-' | b':'))
    {
        return Err(ConnectionError::new("token reference is empty or invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{Profile, ProfileSet, ProfileStore};

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "crux-connection-{name}-{}-{}",
            std::process::id(),
            super::TEMP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    #[test]
    fn round_trip_has_one_active_profile_and_no_secret() {
        let profiles = ProfileSet::new(
            "remote",
            vec![
                Profile::bundled("local"),
                Profile::attach("remote", "https://daemon.example", "keychain:remote").unwrap(),
            ],
        )
        .unwrap();
        let encoded = profiles.to_json().unwrap();
        assert!(encoded.contains("\"token-ref\""));
        assert!(encoded.contains("\"local-plan-root\":null"));
        assert!(!encoded.contains("\"token_ref\""));
        assert!(!encoded.contains("actual-static-token"));
        assert_eq!(ProfileSet::from_json(&encoded).unwrap(), profiles);

        let directory = test_dir("round-trip");
        let path = directory.join("profiles.json");
        let store = ProfileStore::new(&path);
        store.save(&profiles).unwrap();
        assert_eq!(store.load().unwrap(), profiles);
        let leftovers = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(leftovers, 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn optional_local_plan_root_defaults_none_and_round_trips() {
        let legacy = r#"{"schema_version":1,"active_profile":"x","profiles":[{"name":"x","mode":"bundled","url":"","token-ref":null}]}"#;
        let legacy_profiles = ProfileSet::from_json(legacy).unwrap();
        assert_eq!(legacy_profiles.active_profile().unwrap().local_plan_root, None);

        let mut profile = Profile::bundled("x");
        profile.local_plan_root = Some(PathBuf::from("/srv/crux/execplans"));
        let profiles = ProfileSet::new("x", vec![profile]).unwrap();
        let encoded = profiles.to_json().unwrap();
        assert!(encoded.contains("\"local-plan-root\":\"/srv/crux/execplans\""));
        assert_eq!(ProfileSet::from_json(&encoded).unwrap(), profiles);
    }

    #[test]
    fn rejects_invalid_local_plan_root_fields() {
        let wrong_type = r#"{"schema_version":1,"active_profile":"x","profiles":[{"name":"x","mode":"bundled","url":"","token-ref":null,"local-plan-root":[]}]}"#;
        assert!(ProfileSet::from_json(wrong_type).is_err());
        let empty = r#"{"schema_version":1,"active_profile":"x","profiles":[{"name":"x","mode":"bundled","url":"","token-ref":null,"local-plan-root":""}]}"#;
        assert!(ProfileSet::from_json(empty).is_err());
    }

    #[test]
    fn rejects_unknown_plaintext_and_invalid_active_profiles() {
        let plaintext = r#"{"schema_version":1,"active_profile":"x","profiles":[{"name":"x","mode":"attach","url":"https://example.test","token-ref":"ref","token":"secret"}]}"#;
        assert!(ProfileSet::from_json(plaintext).is_err());
        let wrong_field = r#"{"schema_version":1,"active_profile":"x","profiles":[{"name":"x","mode":"attach","url":"https://example.test","token_ref":"ref"}]}"#;
        assert!(ProfileSet::from_json(wrong_field).is_err());
        let missing = r#"{"schema_version":1,"active_profile":"missing","profiles":[{"name":"x","mode":"bundled","url":"","token-ref":null}]}"#;
        assert!(ProfileSet::from_json(missing).is_err());
        let duplicate = ProfileSet::new("x", vec![Profile::bundled("x"), Profile::bundled("x")]);
        assert!(duplicate.is_err());
    }

    #[test]
    fn attach_requires_token_reference_and_bundled_forbids_it() {
        let missing_ref = r#"{"schema_version":1,"active_profile":"x","profiles":[{"name":"x","mode":"attach","url":"https://example.test","token-ref":null}]}"#;
        assert!(ProfileSet::from_json(missing_ref).is_err());
        let bundled_ref = r#"{"schema_version":1,"active_profile":"x","profiles":[{"name":"x","mode":"bundled","url":"","token-ref":"ref"}]}"#;
        assert!(ProfileSet::from_json(bundled_ref).is_err());
        for token_ref in ["bad reference", "bad;reference", "bad$reference"] {
            assert!(Profile::attach("x", "https://example.test", token_ref).is_err());
        }
    }

    #[test]
    fn windows_style_replacement_updates_and_restores_existing_store() {
        let directory = test_dir("replacement");
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join("profiles.json");
        let temporary = directory.join("profiles.tmp");
        let backup = directory.join("profiles.backup");
        fs::write(&target, b"old").unwrap();
        fs::write(&temporary, b"new").unwrap();
        super::replace_with_backup(&temporary, &target, &backup).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!backup.exists());

        fs::write(&target, b"known-good").unwrap();
        let missing_temporary = directory.join("missing.tmp");
        assert!(super::replace_with_backup(&missing_temporary, &target, &backup).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"known-good");
        assert!(!backup.exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
