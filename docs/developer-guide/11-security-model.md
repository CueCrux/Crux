# 11. Security model

This chapter states what is enforced, what is advisory, and what is not yet
wired. Assume nothing that is not listed as enforced.

The daemon-wide threat model lives in [docs/THREAT_MODEL.md](../THREAT_MODEL.md);
this chapter covers the extension surface specifically.

## 11.1 Trust boundaries

| Boundary | Crossed by | Control |
|---|---|---|
| Publisher → operator | A manifest | Ed25519 signature over the policy surface; operator keyring is authoritative |
| Curator → operator | An index | Ed25519 signature; `manifest_sha256` pins the whole manifest file |
| Operator → extension | A grant | Tool allowlist, fact-prefix scopes, rate cap |
| Extension → fact store | Writes | Grant prefix filter, then the global privacy gate |
| Daemon → extension endpoint | Outbound HTTP | HTTPS requirement, `allowed_hosts`, timeout, size caps |
| WASM module → host | Host ABI calls | Grant scoping, fuel, memory, epoch deadline |

## 11.2 What is enforced

**Cryptographically**

- Manifest signatures: Ed25519 only, verified against the operator keyring, not
  against any key the manifest supplies
  ([lib.rs:1411](../../crates/crux-integrations/src/lib.rs#L1411)).
- Registry index signatures, with `verify_strict`
  ([lib.rs:792](../../crates/crux-integrations/src/lib.rs#L792)).
- `manifest_sha256` at registry install, compared before the manifest is parsed
  ([http/extensions.rs:310](../../crates/corecruxd/src/http/extensions.rs#L310)).
- `pack_sha256` at Studio library install, likewise compared before the pack is
  parsed ([studio_library.rs:329](../../crates/corecruxd/src/http/studio_library.rs#L329)),
  with the pack itself required to be signed
  ([studio_library.rs:364](../../crates/corecruxd/src/http/studio_library.rs#L364)).
- WASM `wasm_module_sha256`, at download and again at **every** dispatch
  ([wasm_dispatcher.rs:124](../../crates/corecruxd/src/wasm_dispatcher.rs#L124)).
- `hashes.manifest`, whenever declared
  ([lib.rs:612](../../crates/crux-integrations/src/lib.rs#L612)).

**By authorisation**

- All 13 extension routes require scopes; every mutation additionally requires
  `facts:write` (chapter 9).
- Grant existence, tool allowlist, and fact-prefix scopes, checked in the
  handler and again in the dispatcher (chapter 5).
- Privacy-gated prefixes are unreachable: rejected at grant issue
  ([extension_grants.rs:92](../../crates/corecruxd/src/extension_grants.rs#L92)) and
  again by `fact_privacy::enforce_global` at every write.
- The MCP catalogue is filtered per calling passport, then again by the RCX
  capability token (chapter 10).

**By resource limit**

- Outbound: timeout, request cap, response cap, rate limit — each with a daemon
  default the manifest can only tighten (chapter 5).
- WASM: fuel, linear memory, wall clock via epoch interruption (chapter 6).
- Downloads: 1 MiB index, 2 MiB manifest, 16 MiB WASM module.
- Vault watcher: 4 MiB per file, 500 files per cycle, 256 KiB cursor.

**By path discipline**

- `safe_path_component` on every pack path element
  ([lib.rs:1363](../../crates/crux-integrations/src/lib.rs#L1363)).
- WASM module paths rejected if absolute or containing `..`, at validation and
  again at resolution ([wasm_dispatcher.rs:63](../../crates/corecruxd/src/wasm_dispatcher.rs#L63)).
- Vault watcher refuses symlinks and re-checks canonical containment
  ([vault_watcher.rs:306](../../crates/corecruxd/src/vault_watcher.rs#L306)).

**By fail-closed defaults**

- Unsigned manifests are rejected unless a named dev flag is on.
- `external_helper` is rejected unless a named operator flag is on.
- Plain HTTP endpoints are rejected unless a named dev flag is on.
- A malformed `allowed_hosts` entry never matches
  ([extension_outbound.rs:357](../../crates/corecruxd/src/extension_outbound.rs#L357)).
- A registry index that fails verification is never cached
  ([corecruxctl/src/extensions.rs:120](../../crates/corecruxctl/src/extensions.rs#L120)).
- An empty `allowed_prefixes_write` accepts no writes.

## 11.3 What is advisory

Do not build a security control on any of these.

| Thing | Why it is advisory |
|---|---|
| `risk_level` | A derived label for operator display, not an enforcement input ([lib.rs:1457](../../crates/crux-integrations/src/lib.rs#L1457)) |
| `trust_tier` | Operator-assigned metadata. It gates nothing at dispatch |
| `safety.sandbox` | A declarative label. The real sandbox is selected by `entry.kind` |
| `network.requires_user_token` | Declared, never read by daemon code |
| `data_access.*` | Feeds `risk_level` only; no runtime check consumes it |
| `tools[].input_schema` | Never validated against ([lib.rs:160](../../crates/crux-integrations/src/lib.rs#L160)) |
| Rate limiting | Best-effort — the limiter tolerates mutex poisoning by design ([extension_outbound.rs:198](../../crates/corecruxd/src/extension_outbound.rs#L198)) |
| Audit completeness | Best-effort. Append failures are warn-logged, and the invoke family is capped at 60 events per extension per minute |
| Console operator posture | A UI gate. The daemon's scope checks are the real control ([tests/route_spec_drift.rs:46](../../crates/corecruxd/tests/route_spec_drift.rs#L46)) |
| `required_tier` on a Studio library row | **Explicitly not enforced by the daemon.** The catalogue server is the gate; the daemon echoes the value and stamps `tier_enforcement: "advisory"` ([studio_library.rs:41](../../crates/corecruxd/src/http/studio_library.rs#L41)) |
| `kind` on a Studio library row | A console badge. The pack payload decides what is written, not the declared kind ([studio_index.rs:60](../../crates/crux-integrations/src/studio_index.rs#L60)) |

## 11.4 What is not wired yet

Stated plainly so you do not design around it:

| Surface | Status |
|---|---|
| `tools[].auth_shared_secret_id` | The transport sends a bearer header, but the invoke handler passes `None`. No `Authorization` reaches your endpoint today ([http/extensions.rs:784](../../crates/corecruxd/src/http/extensions.rs#L784)) |
| `crux::get_secret_decrypted` | Stub, always `-6` `NOT_IMPLEMENTED` ([wasm_host.rs:858](../../crates/corecruxd/src/wasm_host.rs#L858)) |
| `crux::emit_receipt` | Stub, always `-6` ([wasm_host.rs:868](../../crates/corecruxd/src/wasm_host.rs#L868)) |
| WASM response `fact_writes[]` | Parsed then discarded; use `crux::store_fact` ([wasm_dispatcher.rs:156](../../crates/corecruxd/src/wasm_dispatcher.rs#L156)) |
| Six of nine entry kinds | Declared vocabulary with no daemon runtime (chapter 2) |
| Vault-watcher deletions | Recorded in the status detail; no retraction from sealed segments ([vault_watcher.rs:77](../../crates/corecruxd/src/vault_watcher.rs#L77)) |
| Generic encrypted-secrets HTTP surface | Does not exist. Envelopes live inside per-connector files (chapter 7) |

## 11.5 Known-limits an operator should hold in mind

**The signature does not cover the endpoint.** For an `external_tool` manifest
installed by pasting JSON into `/v1/extensions/register`, a valid signature says
nothing about `external_tool_endpoint` or `tools[]`. Only the registry path's
`manifest_sha256` binds the whole document. Prefer registry installs for
anything you did not author.

**`allowed_hosts` is the endpoint allowlist, not an egress firewall.** It
constrains the endpoint the daemon will POST to. It does not constrain what your
service does once called — it can call anything. If egress matters, enforce it
at the network layer.

**Empty `allowed_hosts` means unrestricted host.** The pin is then the endpoint
URL alone ([extension_outbound.rs:349](../../crates/corecruxd/src/extension_outbound.rs#L349)).
For a signed manifest that is still meaningful; for a dev-bypass unsigned
install it is not.

**Prefix grants are string prefixes.** `personal::q` permits
`personal::quotesomething`. Always end a granted prefix at a namespace boundary.

**Uninstall does not revoke grants.** Grant facts survive an uninstall. Reinstall
under the same id and old grants apply to the new manifest. Revoke first if the
replacement is not equivalent.

**Removing a trusted key does not uninstall anything.** The trust tier was frozen
on the install record at install time
([extension_registry.rs:150](../../crates/corecruxd/src/extension_registry.rs#L150)). Key
removal blocks future installs and index verifications.

**Everything writes to tenant `default`.** No extension path lets an extension
choose a tenant.

**Dev bypasses are process-wide.** `CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` is not
per-extension, and `CORECRUXD_STUDIO_ALLOW_UNSIGNED` is not per-template. With
either on, every install on that rail skips its signature requirement. Never set
them on a shared or production daemon.

**A Studio library install writes immediately.** Unlike an extension install,
which is inert until granted, installing a template writes console facts as part
of the call. The compensating controls are: require-signed by default, an
`installed_from` provenance stamp on every write, never overwriting an existing
artefact, and per-write category enforcement against the calling passport
([studio_library.rs:419](../../crates/corecruxd/src/http/studio_library.rs#L419)). A
malicious template still cannot read anything or execute anything — it can only
add dashboards.

## 11.6 Secrets handling — the rules

1. **Never write a secret into a file you construct.** Connector credentials go
   through `encrypted_secrets::seal`
   ([encrypted_secrets.rs:40](../../crates/corecruxd/src/encrypted_secrets.rs#L40)).
2. **The encryption key is derived, not configured.** It comes from the
   daemon-root passport via BLAKE3 `derive_key` with the context string
   `integration-token-encryption-v1`
   ([main.rs:856](../../crates/corecruxd/src/main.rs#L856)). No environment variable
   holds it. Rotating the passport invalidates every envelope, deliberately.
3. **Accept a secret over exactly one POST, and never read it back.** The
   console's own copy states the contract:
   `Credentials are sealed daemon-side. The console posts them once and never reads them back.`
4. **Signing keys stay off the daemon.** `CORECRUXD_STUDIO_SIGNING_KEY_HEX` is a
   local convenience; the canonical rail is a PR that needs no daemon-held
   private key ([studio_pack.rs:61](../../crates/corecruxd/src/http/studio_pack.rs#L61)).
5. **Do not put secrets in manifests.** Manifests are published, hashed, and
   signed. `auth_shared_secret_id` names a secret; it does not carry one.
6. **Do not put secrets in facts.** Facts are readable through
   `GET /v1/facts` by anyone holding the read scope.

## 11.7 A review checklist before granting

1. Is the manifest signed by a key already in the keyring, at a tier you set
   yourself?
2. Did it arrive through the registry (whole-document hash) or as pasted JSON
   (policy-surface hash only)?
3. Do the declared `capabilities[]` match what the tool plausibly needs?
4. For `external_tool`: is `allowed_hosts` non-empty and specific? Is the
   endpoint HTTPS?
5. For `wasm`: is the module already cached with a matching hash?
6. Is `allowed_prefixes_write` the narrowest prefix that works, ending at a
   namespace boundary?
7. Is `allowed_tool_names` explicit rather than empty?
8. Is `rate_limit_per_min` set to something you would tolerate at steady state?
9. Is `CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` off? Confirm with
   `GET /v1/extensions` → `allow_unsigned_dev`.
10. Does `<data_dir>/integrations/audit.jsonl` show the install and grant you
    expect, by the actor you expect?

## Ground truth

- [docs/THREAT_MODEL.md](../THREAT_MODEL.md) — daemon-wide trust boundaries
- [crates/crux-integrations/src/lib.rs:1411](../../crates/crux-integrations/src/lib.rs#L1411) — signature verification
- [crates/corecruxd/src/extension_grants.rs:92](../../crates/corecruxd/src/extension_grants.rs#L92) — ungrantable prefixes
- [crates/corecruxd/src/extension_outbound.rs:405](../../crates/corecruxd/src/extension_outbound.rs#L405) — outbound enforcement
- [crates/corecruxd/src/wasm_host.rs:281](../../crates/corecruxd/src/wasm_host.rs#L281) — WASM grant scoping
- [crates/corecruxd/src/encrypted_secrets.rs:19](../../crates/corecruxd/src/encrypted_secrets.rs#L19) — secret envelope
- [crates/corecruxd/src/main.rs:856](../../crates/corecruxd/src/main.rs#L856) — key derivation
- [crates/corecruxd/tests/route_spec_drift.rs:46](../../crates/corecruxd/tests/route_spec_drift.rs#L46) — double-gate contract
- [crates/corecruxd/src/http/studio_library.rs:22](../../crates/corecruxd/src/http/studio_library.rs#L22) — install invariants
- [crates/corecruxd/src/http/route_auth.rs:144](../../crates/corecruxd/src/http/route_auth.rs#L144) — the install write-class carve-out
