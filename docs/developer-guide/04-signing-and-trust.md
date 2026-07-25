# 4. Signing and trust

## 4.1 The algorithm

Ed25519, and only Ed25519. `signature.alg` must be the literal string
`ed25519`; anything else fails with
`unsupported signature algorithm '<alg>'`
([crates/crux-integrations/src/lib.rs:1416](../../crates/crux-integrations/src/lib.rs#L1416)).

The signature envelope ([lib.rs:280](../../crates/crux-integrations/src/lib.rs#L280)):

| Field | Type | Notes |
|---|---|---|
| `alg` | string | `"ed25519"` |
| `passport_fpr` | string | Key identifier looked up in the trusted keyring |
| `public_key_hex` | string, optional | 64 hex chars. Advisory only — see §4.3 |
| `sig` | string | Base64 (standard alphabet) of the 64 raw signature bytes |

Signing helper: `sign_manifest(&mut manifest, &signing_key, passport_fpr)`
([signing.rs:163](../../crates/crux-integrations/src/signing.rs#L163)). It fills
`signature` **and** recomputes `hashes.manifest`, so a signed manifest always
carries a matching manifest hash.

Fingerprint helper: `fingerprint_from_public_key` returns
`p_<32 hex chars>` — BLAKE3 of the 32 raw public-key bytes, truncated to 16 bytes
([signing.rs:186](../../crates/crux-integrations/src/signing.rs#L186)).

## 4.2 What is signed

The payload is `ManifestSigningPayload`
([lib.rs:466](../../crates/crux-integrations/src/lib.rs#L466)) — `schema`, `id`, `name`,
`version`, `publisher_passport_fpr`, `summary`, `entry`, `capabilities`,
`network`, `data_access`, `safety`. Serialised with `serde_json::to_vec`, in
struct-declaration order.

`external_tool_endpoint`, `tools[]`, `wasm_module_*`, `hashes` and `signature`
itself are **outside** the signature. See §2.4 for what that means in practice
and which layer closes the gap.

## 4.3 The trusted keyring

`<data_dir>/extensions/trusted-keys.json`, schema
`crux.extensions.trusted-keys.v1`
([signing.rs:66](../../crates/crux-integrations/src/signing.rs#L66)):

```json
{
  "schema": "crux.extensions.trusted-keys.v1",
  "keys": {
    "p_community_alice": {
      "public_key_hex": "4c00e9689fc124fbdf7d4afb2d43632cf529eae10234c17f08ecb3a2f569bedf",
      "trust_tier": "community_reviewed",
      "added_at_unix_ms": 1753440000000,
      "added_by": "operator@example"
    }
  }
}
```

Load semantics ([signing.rs:78](../../crates/crux-integrations/src/signing.rs#L78)):

- Missing file → empty keyring, no error. That is the expected first-boot state.
- Present but malformed → error.
- Every `public_key_hex` is length-checked at load, so a bad key fails loudly at
  startup rather than silently at first verification. The error is
  `<fpr>: public key must be 32 bytes`.
- Saves are atomic (tmp + rename) ([signing.rs:111](../../crates/crux-integrations/src/signing.rs#L111)).

### The keyring is authoritative over the inline key

`verify_signature` ([lib.rs:1411](../../crates/crux-integrations/src/lib.rs#L1411)):

1. Look up `signature.passport_fpr` in `policy.trusted_public_keys`. Absent →
   `no trusted public key for passport '<fpr>'`.
2. If the manifest carries an inline `public_key_hex` that differs from the
   keyring entry (case-insensitively) → `invalid signature material: signature public_key_hex does not match trusted keyring entry`.
3. Verify against the **keyring's** key, not the inline one.

So a manifest cannot bring its own trust. The inline key is a convenience for
bootstrapping and for the community CI gate, which explicitly builds a policy
trusting the manifest's own inline key because at PR time no operator keyring
exists yet ([tests/community_packs.rs:52](../../crates/crux-integrations/tests/community_packs.rs#L52)).

## 4.4 Trust tiers

`TrustTier` ([lib.rs:290](../../crates/crux-integrations/src/lib.rs#L290)):

| Tier | How it is assigned |
|---|---|
| `first_party` | Pack model only: `publisher_passport_fpr == "cuecrux:first-party"` ([console.rs:3255](../../crates/corecruxd/src/http/console.rs#L3255)) |
| `locally_signed` | Pack model: signed by a non-first-party publisher. Extension model: the operator tagged the signing key this way when adding it |
| `community_reviewed` | Operator tagged the signing key this way — typically a curator key |
| `unknown` | Unsigned (dev bypass), or a signature whose key is not in the keyring |

The tier is a property of **the key in the operator's keyring**, not of the
manifest ([signing.rs:151](../../crates/crux-integrations/src/signing.rs#L151)). An operator
can promote or demote a publisher without anyone re-signing anything.

For extensions, `install_extension` resolves the tier once, at install, and
freezes it on the record; an unsigned install under dev bypass is tagged
`unknown` ([extension_registry.rs:150](../../crates/corecruxd/src/extension_registry.rs#L150)).

## 4.5 Managing keys over HTTP

```bash
# List.
curl -s http://127.0.0.1:14800/v1/extensions/keys \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"

# Add.
curl -s -X POST http://127.0.0.1:14800/v1/extensions/keys \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_operator" \
  -H 'Content-Type: application/json' \
  -d '{
        "passport_fpr": "p_community_alice",
        "public_key_hex": "4c00e9689fc124fbdf7d4afb2d43632cf529eae10234c17f08ecb3a2f569bedf",
        "trust_tier": "community_reviewed",
        "added_by": "operator@example"
      }'

# Remove.
curl -s -X DELETE http://127.0.0.1:14800/v1/extensions/keys/p_community_alice \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
```

| Route | Method | Scopes | Handler |
|---|---|---|---|
| `/v1/extensions/keys` | GET | `admin:read` | [extensions.rs:503](../../crates/corecruxd/src/http/extensions.rs#L503) |
| `/v1/extensions/keys` | POST | `admin:read` + `facts:write` | [extensions.rs:522](../../crates/corecruxd/src/http/extensions.rs#L522) |
| `/v1/extensions/keys/{passport_fpr}` | DELETE | `admin:read` + `facts:write` | [extensions.rs:870](../../crates/corecruxd/src/http/extensions.rs#L870) |

`trust_tier` is deserialised as the enum, so the accepted values are exactly
`first_party`, `locally_signed`, `community_reviewed`, `unknown` (snake_case,
[lib.rs:290](../../crates/crux-integrations/src/lib.rs#L290)).

`POST` is an upsert — `keyring.add` inserts into a `BTreeMap`
([signing.rs:123](../../crates/crux-integrations/src/signing.rs#L123)), so re-posting the
same fingerprint replaces the entry, including its tier. Deleting a fingerprint
that is not present returns 404 `trusted key '<fpr>' not in keyring`
([extensions.rs:886](../../crates/corecruxd/src/http/extensions.rs#L886)).

Removing a key does **not** uninstall extensions already installed under it —
the trust tier was frozen on the install record. It does prevent future installs
and future registry-index verifications with that key.

## 4.6 The community registry index

Schema `crux.community-extensions.index.v1`
([lib.rs:38](../../crates/crux-integrations/src/lib.rs#L38)). Type
`CommunityExtensionsIndex` ([lib.rs:694](../../crates/crux-integrations/src/lib.rs#L694)):

```json
{
  "schema": "crux.community-extensions.index.v1",
  "updated_at_unix_ms": 1753440000000,
  "curator_passport_fpr": "p_curator",
  "entries": [
    {
      "id": "ext.example.quote",
      "name": "Quote of the Day",
      "version": "0.1.0",
      "summary": "Returns a quote.",
      "manifest_url": "https://example.com/ext.example.quote/0.1.0/manifest.json",
      "manifest_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "repo_url": "https://github.com/example/ext-quote",
      "kind": "external_tool",
      "trust_tier": "community_reviewed"
    }
  ],
  "signature": { "alg": "ed25519", "passport_fpr": "p_curator", "sig": "..." }
}
```

Entry fields: [lib.rs:664](../../crates/crux-integrations/src/lib.rs#L664). `kind` is the
same `EntryKind` enum as a manifest, so a console can badge external-tool versus
WASM before anything is downloaded.

Index signing payload ([lib.rs:706](../../crates/crux-integrations/src/lib.rs#L706)) covers
`schema`, `updated_at_unix_ms`, `curator_passport_fpr`, `entries` — the
signature itself is excluded, as you would expect.

`verify()` ([lib.rs:759](../../crates/crux-integrations/src/lib.rs#L759)) applies exactly
the same rules as manifest verification: schema check, `ed25519` only, keyring
lookup, inline-key-must-match, then `verify_strict`. Note that index
verification uses `verify_strict` whereas manifest verification uses `verify`
([lib.rs:792](../../crates/crux-integrations/src/lib.rs#L792) versus
[lib.rs:1445](../../crates/crux-integrations/src/lib.rs#L1445)) — the strict variant
additionally rejects small-order public keys.

`sign()` refuses to sign an index with an empty `curator_passport_fpr`
([lib.rs:740](../../crates/crux-integrations/src/lib.rs#L740)).

## 4.6a The second curator-signed index

`crux.studio.index.v1` — the central Studio template library — reuses this
chapter wholesale: same Ed25519 envelope, same `TrustedKeyring`, same
inline-key-must-match rule, same `verify_strict`
([studio_index.rs:6](../../crates/crux-integrations/src/studio_index.rs#L6),
[studio_index.rs:225](../../crates/crux-integrations/src/studio_index.rs#L225)). One keyring
serves both rails.

Two differences worth carrying in your head:

- `StudioLibraryIndex::verify` runs **shape validation after the signature
  check**, so a validly-signed index with a malformed row is rejected at the
  trust boundary rather than at the point of use
  ([studio_index.rs:219](../../crates/crux-integrations/src/studio_index.rs#L219)).
- Rows carry an advisory `required_tier` the daemon deliberately does not
  enforce. Chapter 8 §8.7 explains why, and where the real gate lives.

Full schema and install semantics: [chapter 8](08-studio-packs-and-workspaces.md#87-the-central-template-library).

## 4.7 The `review.json` rule

The community rail requires a maintainer sign-off file next to any manifest that
declares a dangerous capability
([tests/community_packs.rs:104](../../crates/crux-integrations/tests/community_packs.rs#L104)):

```json
{
  "maintainer_approval": true,
  "rationale": "Why this dangerous capability is necessary and safe."
}
```

The CI gate asserts `maintainer_approval == true` and a non-empty `rationale`.
Chapter 9 covers the rest of the gate.

## 4.8 Development bypasses — the complete list

| Env var | Applies to | Effect |
|---|---|---|
| `CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` | `/v1/extensions/register`, `/v1/extensions/install-from-registry` | Unsigned manifests install with `trust_tier: unknown`. Signed manifests are **still** verified ([extension_registry.rs:143](../../crates/corecruxd/src/extension_registry.rs#L143)) |
| `CORECRUXD_EXTENSIONS_ALLOW_PLAIN_HTTP` | External-tool dispatch | Permits `http://` endpoints ([extension_outbound.rs:151](../../crates/corecruxd/src/extension_outbound.rs#L151)) |
| `CORECRUXD_INTEGRATIONS_ALLOW_EXECUTABLE_HELPERS` | Pack validation | Permits `entry.kind: external_helper` ([config.rs:1383](../../crates/corecruxd/src/config.rs#L1383)) |
| `CORECRUXD_STUDIO_SIGNING_KEY_HEX` | `POST /v1/studio/pack/build` | 64 hex chars (32-byte Ed25519 seed). When set, built packs are really signed; when unset, they come back unsigned with instructions ([studio_pack.rs:64](../../crates/corecruxd/src/http/studio_pack.rs#L64)) |
| `CORECRUXD_STUDIO_ALLOW_UNSIGNED` | `POST /v1/studio/library/{id}/install` | Bypasses the require-signed install policy. Unlike the extensions rail, library install refuses unsigned packs by **default** ([studio_library.rs:66](../../crates/corecruxd/src/http/studio_library.rs#L66)) |

Truthy values for the two `ALLOW_UNSIGNED` switches and the plain-HTTP switch are
`1`, `true`, `yes`, `on` (case-insensitive, trimmed)
([http/extensions.rs:46](../../crates/corecruxd/src/http/extensions.rs#L46),
[studio_library.rs:89](../../crates/corecruxd/src/http/studio_library.rs#L89)). For
the executable-helpers switch they are `1`, `true`, `TRUE`, `yes`, `YES`
(exact match, [config.rs:1383](../../crates/corecruxd/src/config.rs#L1383)).

The daemon tells you when a bypass would have helped: a validation failure on
install appends
` (set CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED=true to bypass signature requirement in dev)`
to the problem detail, but only when the bypass is currently off
([http/extensions.rs:209](../../crates/corecruxd/src/http/extensions.rs#L209)).

`GET /v1/extensions` reports the current state as `allow_unsigned_dev` so a
console can badge the daemon honestly
([http/extensions.rs:88](../../crates/corecruxd/src/http/extensions.rs#L88)).

## 4.9 Verifying a signature yourself

The round trip is pinned by `sign_then_verify_round_trip`
([signing.rs:237](../../crates/crux-integrations/src/signing.rs#L237)), and tampering is
pinned by `tampered_payload_fails_verification`
([signing.rs:266](../../crates/crux-integrations/src/signing.rs#L266)) — which accepts
*either* `SignatureInvalid` or `ManifestHashMismatch`, because whichever check
fires first is a valid rejection.

To reproduce the hash outside Rust: build the 11-field subset in the declared
field order, serialise it as compact JSON, BLAKE3 it, prefix with `blake3:`.

## Ground truth

- [crates/crux-integrations/src/signing.rs:44](../../crates/crux-integrations/src/signing.rs#L44) — `TrustedKeyring`
- [crates/crux-integrations/src/signing.rs:55](../../crates/crux-integrations/src/signing.rs#L55) — `TrustedKeyEntry`
- [crates/crux-integrations/src/signing.rs:163](../../crates/crux-integrations/src/signing.rs#L163) — `sign_manifest`
- [crates/crux-integrations/src/signing.rs:186](../../crates/crux-integrations/src/signing.rs#L186) — `fingerprint_from_public_key`
- [crates/crux-integrations/src/lib.rs:280](../../crates/crux-integrations/src/lib.rs#L280) — `SignatureEnvelope`
- [crates/crux-integrations/src/lib.rs:664](../../crates/crux-integrations/src/lib.rs#L664) — `CommunityExtensionEntry`
- [crates/crux-integrations/src/lib.rs:759](../../crates/crux-integrations/src/lib.rs#L759) — index `verify`
- [crates/crux-integrations/src/lib.rs:1411](../../crates/crux-integrations/src/lib.rs#L1411) — `verify_signature`
- [crates/corecruxd/src/http/extensions.rs:493](../../crates/corecruxd/src/http/extensions.rs#L493) — keyring routes
- [crates/corecruxd/src/extension_registry.rs:108](../../crates/corecruxd/src/extension_registry.rs#L108) — `build_policy`
- [crates/crux-integrations/src/studio_index.rs:225](../../crates/crux-integrations/src/studio_index.rs#L225) — Studio library index `verify`
