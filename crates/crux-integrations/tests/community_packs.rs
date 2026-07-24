// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crux_integrations::{EntryKind, IntegrationManifest, ValidationPolicy, FIRST_PARTY_PASSPORT};
use serde_json::Value;

const DANGEROUS_CAPABILITIES: &[&str] = &[
    "admin:read",
    "facts:private:read",
    "integrations:grant",
    "integrations:install",
    "sessions:write",
    "tenant:content:preview",
];

#[derive(Debug, serde::Deserialize)]
struct ReviewGate {
    maintainer_approval: bool,
    rationale: String,
}

#[test]
fn community_pack_manifests_are_safe_and_reviewable() -> Result<(), Box<dyn Error>> {
    let community_root = repo_root().join("integrations/community");
    assert!(
        community_root.exists(),
        "integrations/community must exist for public pack PRs"
    );

    let mut manifests = Vec::new();
    collect_manifests(&community_root, &mut manifests)?;
    for manifest_path in manifests {
        validate_manifest_file(&manifest_path)?;
    }
    Ok(())
}

/// Build a validation policy that trusts a community pack's OWN inline
/// signing key. At PR-submission time the publisher's key is not yet in any
/// operator keyring or the curator-signed index — the only key available is
/// the `signature.public_key_hex` the manifest carries. So the CI gate's job
/// is to prove the pack is well-formed and *validly self-signed* (schema +
/// hash + a real Ed25519 signature over the payload by the declared key);
/// curator endorsement + operator keyring trust happen later, at install time.
///
/// (Without this, `ValidationPolicy::default()` carries an empty keyring, so
/// EVERY signed pack would fail `MissingTrustedKey` — the gate only passed
/// while `integrations/community/` was empty. A tampered payload still fails
/// here: the signature won't verify and/or the hash won't match.)
fn policy_trusting_inline_key(manifest: &IntegrationManifest) -> ValidationPolicy {
    let mut policy = ValidationPolicy::default();
    if let Some(sig) = &manifest.signature {
        if let Some(public_key_hex) = &sig.public_key_hex {
            policy
                .trusted_public_keys
                .insert(sig.passport_fpr.clone(), public_key_hex.clone());
        }
    }
    policy
}

fn validate_manifest_file(manifest_path: &Path) -> Result<(), Box<dyn Error>> {
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest: IntegrationManifest = serde_json::from_str(&manifest_text)?;
    manifest.validate(&policy_trusting_inline_key(&manifest))?;

    assert_ne!(
        manifest.publisher_passport_fpr,
        FIRST_PARTY_PASSPORT,
        "{} must not claim first-party publisher identity",
        manifest_path.display()
    );
    assert!(
        manifest.hashes.manifest.is_some(),
        "{} must include hashes.manifest",
        manifest_path.display()
    );
    assert!(
        manifest.signature.is_some(),
        "{} must include an Ed25519 Passport signature",
        manifest_path.display()
    );
    assert!(
        manifest.entry.kind != EntryKind::ExternalHelper,
        "{} uses external_helper; community v1 packs are declarative only",
        manifest_path.display()
    );
    assert!(
        is_safe_relative_path(&manifest.entry.path),
        "{} has unsafe entry.path '{}'",
        manifest_path.display(),
        manifest.entry.path
    );

    let pack_dir = manifest_path.parent().ok_or("manifest path has no parent")?;
    assert!(
        pack_dir.join("README.md").exists(),
        "{} must include README.md with setup and safety notes",
        pack_dir.display()
    );
    if requires_maintainer_review(&manifest) {
        let review_path = pack_dir.join("review.json");
        let review: ReviewGate = serde_json::from_str(&fs::read_to_string(&review_path)?)?;
        assert!(
            review.maintainer_approval,
            "{} must set maintainer_approval=true",
            review_path.display()
        );
        assert!(
            !review.rationale.trim().is_empty(),
            "{} must include a non-empty rationale",
            review_path.display()
        );
    }

    Ok(())
}

fn collect_manifests(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_manifests(&path, out)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("manifest.json") {
            out.push(path);
        }
    }
    Ok(())
}

fn requires_maintainer_review(manifest: &IntegrationManifest) -> bool {
    manifest
        .capabilities
        .iter()
        .any(|capability| DANGEROUS_CAPABILITIES.contains(&capability.as_str()))
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && !value.is_empty()
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").clone()
}

// ── Example Studio pack generator (console-surfaces-remediation M15) ─────────
//
// Writes + signs `integrations/community/studio-board-example/0.1.0/`. Ignored
// by default (it mutates checked-in files); run explicitly to regenerate:
//
//   cargo test -p crux-integrations --test community_packs -- --ignored regen_studio_board_example
//
// The example is a real, importable Studio board pack: a `crux.studio.v1`
// payload (a facts stat, a sessions stat, a text-search tile, a note) wrapped
// in a signed `crux.integration.v1` manifest. It carries a DETERMINISTIC
// EXAMPLE identity (a fixed seed) — NOT a real publisher key — so the artefact
// is reproducible and the fingerprint is stable across regens. Capabilities
// derive to the minimal non-dangerous read set (integrations:read + facts:read
// + sessions:read), so no `review.json` is required.

/// Fixed example signing seed. Documented as a non-production identity: it
/// exists only to make the committed example reproducible and validly
/// self-signed for the CI gate. A real publisher signs with their own key.
const EXAMPLE_SEED: [u8; 32] = *b"cuecrux-studio-board-example-v1!";

/// Recursively sort object keys so the bundle hash is key-order independent —
/// must match `corecruxd::http::studio_pack::canonicalize` so the daemon's
/// verify route accepts this committed pack.
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonicalize(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

fn blake3_hash(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn example_studio_payload() -> Value {
    serde_json::json!({
        "schema": "crux.studio.v1",
        "version": 1,
        "created_at_unix_ms": 1_753_000_000_000_u64,
        "board": {
            "id": "studio-board-example",
            "doc": {
                "nodes": [
                    { "id": "facts", "kind": "api", "x": 40, "y": 40, "w": 220, "h": 140, "z": 2,
                      "label": "Facts",
                      "api": { "route": "/v1/console/summary", "params": "", "jsonPath": "stores.facts",
                               "preset": "stat", "fields": "", "max": "", "refresh": "live", "tokenBudget": "" } },
                    { "id": "sessions", "kind": "api", "x": 300, "y": 40, "w": 220, "h": 140, "z": 2,
                      "label": "Sessions",
                      "api": { "route": "/v1/console/sessions", "params": "", "jsonPath": "count",
                               "preset": "stat", "fields": "", "max": "", "refresh": "off", "tokenBudget": "" } },
                    { "id": "search", "kind": "search", "x": 40, "y": 220, "w": 480, "h": 240, "z": 2,
                      "label": "Search",
                      "search": { "route": "/v1/query/text-search", "query": "execplan", "tenant": "default",
                                  "tokenBudget": "800", "refresh": "off" } },
                    { "id": "note", "kind": "note", "x": 560, "y": 40, "w": 260, "h": 180, "z": 2,
                      "label": "About", "sub": "Example board",
                      "body": "A portable Studio board: two live-capable stat tiles, a text-search tile, this note." }
                ],
                "links": [],
                "texts": [],
                "pan": { "x": 0, "y": 0 },
                "zoom": 1,
                "version": 1
            }
        },
        "designs": [],
        "settings": {
            "grid": 20,
            "refresh": "live",
            "accent": "cool",
            "title": "Example board",
            "description": "A minimal, portable Studio board demonstrating the pack format."
        }
    })
}

#[test]
#[ignore = "writer: run with -- --ignored regen_studio_board_example to regenerate the example pack"]
fn regen_studio_board_example() {
    use crux_integrations::{
        fingerprint_from_public_key, sign_manifest, DataAccess, IntegrationEntry, ManifestHashes, NetworkAccess,
        SafetyPolicy, INTEGRATION_SCHEMA_V1,
    };
    use ed25519_dalek::SigningKey;

    let dir = repo_root().join("integrations/community/studio-board-example/0.1.0");
    fs::create_dir_all(&dir).expect("create example pack dir");

    let studio = example_studio_payload();
    let bundle_hash = blake3_hash(&serde_json::to_vec(&canonicalize(&studio)).expect("canonical studio bytes"));

    let key = SigningKey::from_bytes(&EXAMPLE_SEED);
    let publisher_fpr = fingerprint_from_public_key(&key.verifying_key());

    let mut manifest = IntegrationManifest {
        schema: INTEGRATION_SCHEMA_V1.to_string(),
        id: "studio-board-example".to_string(),
        name: "Example Studio Board".to_string(),
        version: "0.1.0".to_string(),
        publisher_passport_fpr: publisher_fpr,
        summary: "A portable Canvas Studio board (facts + sessions stats, a text-search tile, a note).".to_string(),
        entry: IntegrationEntry {
            kind: EntryKind::SdkRecipe,
            path: "studio-board.json".to_string(),
        },
        capabilities: vec![
            "facts:read".to_string(),
            "integrations:read".to_string(),
            "sessions:read".to_string(),
        ],
        network: NetworkAccess::default(),
        data_access: DataAccess::default(),
        safety: SafetyPolicy::default(),
        hashes: ManifestHashes {
            manifest: None,
            bundle: Some(bundle_hash),
        },
        signature: None,
        external_tool_endpoint: None,
        tools: Vec::new(),
        wasm_module_path: None,
        wasm_module_url: None,
        wasm_module_sha256: None,
    };
    // Signs + fills hashes.manifest; hashes.bundle is preserved.
    let publisher_fpr = manifest.publisher_passport_fpr.clone();
    sign_manifest(&mut manifest, &key, publisher_fpr).expect("sign example manifest");

    // manifest.json = the manifest object + the embedded studio payload.
    let mut pack = match serde_json::to_value(&manifest).expect("manifest to value") {
        Value::Object(map) => map,
        _ => panic!("manifest did not serialise to an object"),
    };
    pack.insert("studio".to_string(), studio.clone());
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&Value::Object(pack)).expect("encode manifest"),
    )
    .expect("write manifest.json");

    fs::write(
        dir.join("studio-board.json"),
        serde_json::to_vec_pretty(&studio).expect("encode studio payload"),
    )
    .expect("write studio-board.json");

    fs::write(dir.join("README.md"), EXAMPLE_README).expect("write README.md");
}

const EXAMPLE_README: &str = r#"# Example Studio Board pack

A portable **Canvas Studio** board, exported as a `crux.studio.v1` payload
wrapped in a signed `crux.integration.v1` manifest. Import it from the console
Studio ("Import pack"), or install it as a community integration.

## What it contains

- A **Facts** stat tile (`/v1/console/summary` → `stores.facts`, live-refresh).
- A **Sessions** stat tile (`/v1/console/sessions` → `count`).
- A **text-search** tile (`/v1/query/text-search`, honest coverage score).
- A **note** describing the board.

## Trust + safety

- `publisher_passport_fpr` is a deterministic **example identity**, not a real
  publisher. Re-sign with your own Passport key before publishing your own pack.
- Capabilities are the minimal read set the tiles need: `integrations:read`,
  `facts:read`, `sessions:read` — no dangerous capabilities, so no `review.json`
  is required. The pack is inert until an operator grants those capabilities.
- Both hashes are bound: `hashes.manifest` (blake3 over the manifest signing
  payload) and `hashes.bundle` (blake3 over the canonical studio payload).

## Regenerate

```bash
cargo test -p crux-integrations --test community_packs -- --ignored regen_studio_board_example
```

## Publish (the real rail)

Open a PR adding this directory under `integrations/community/`. CI runs
`cargo test -p crux-integrations --test community_packs`; once merged, the
curator-signed community index endorses it for one-click install. There is no
"upload" endpoint — the community registry PR + curator index IS the rail.
"#;
