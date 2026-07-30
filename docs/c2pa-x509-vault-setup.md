# C2PA X.509 Vault PKI — Operator Runbook

agent-ux-07 M6 ships a Vault-custodied X.509 trust anchor for C2PA Content
Credentials. This document captures the prod Vault setup state, anchor
distribution policy, rotation playbook, the EU AI Act Article 50 mapping,
and the one known limitation.

> **Status (2026-05-28).** Vault prod (`https://100.76.91.69:8200`) has the
> `pki-c2pa/` mount + `c2pa-leaf` role configured and verified. Daemon-side
> signer (`VaultPkiX509Signer`) and CLI (`corecruxctl c2pa-cert-status`,
> `c2pa-rotate-leaf`, `c2pa-verify`) ship in this PR. Public C2PA Viewer
> green-tick is commercial-CA-gated; offline + AI-Act conformance is
> achieved by the self-signed anchor below.

---

## 1. One-shot Vault setup (COMPLETED 2026-05-28)

The commands below were run on the prod cuecrux-vault by the operator on
2026-05-28. **Do not re-run on prod** — they replace the root and would
invalidate every existing leaf and verifier copy of the anchor. Reproduce on
a fresh Vault only.

```bash
# 1. Enable the PKI secrets engine at pki-c2pa/
vault secrets enable -path=pki-c2pa pki

# 2. Configure a 10-year max TTL on the mount
vault secrets tune -max-lease-ttl=87600h pki-c2pa

# 3. Generate the root cert (P-256, ecdsa-with-SHA256). NEVER leaves Vault.
vault write -format=json pki-c2pa/root/generate/internal \
  common_name="CueCrux C2PA Root CA" \
  organization="CueCrux Ltd" \
  country="GB" \
  key_type=ec \
  key_bits=256 \
  ttl=87600h \
  > /tmp/c2pa-root.json

# Save the public cert for distribution (see §3).
jq -r .data.certificate /tmp/c2pa-root.json \
  > ~/.config/cuecrux/c2pa/cuecrux-c2pa-root.pem

# 4. Configure issuer URLs (optional; lets `vault read pki-c2pa/issuer/...`
#    populate the AIA + CRL distribution point extensions).
vault write pki-c2pa/config/urls \
  issuing_certificates="https://100.76.91.69:8200/v1/pki-c2pa/ca" \
  crl_distribution_points="https://100.76.91.69:8200/v1/pki-c2pa/crl"

# 5. Define the c2pa-leaf role with the STRICT C2PA profile:
#    - 30-day TTL on leaves
#    - KU = DigitalSignature only
#    - EKU = EmailProtection only
#    - BasicConstraints CA:FALSE asserted
#    - all auxiliary fields disabled
vault write pki-c2pa/roles/c2pa-leaf \
  ttl=720h \
  max_ttl=720h \
  allow_any_name=true \
  enforce_hostnames=false \
  key_type=ec \
  key_bits=256 \
  use_csr_common_name=true \
  use_csr_sans=false \
  basic_constraints_valid_for_non_ca=true \
  key_usage="DigitalSignature" \
  ext_key_usage="EmailProtection" \
  no_store=false \
  generate_lease=false \
  client_flag=false \
  server_flag=false \
  code_signing_flag=false \
  email_protection_flag=true
```

Verify the root profile out-of-band:

```bash
openssl x509 -in ~/.config/cuecrux/c2pa/cuecrux-c2pa-root.pem \
  -noout -subject -issuer -dates -fingerprint -sha256
# Subject = Issuer = "CueCrux C2PA Root CA" (self-signed)
# SHA256 Fingerprint = 9F:BE:91:9D:E7:75:74:1B:2C:4A:E9:8C:30:A1:11:F1:
#                      4B:96:64:F8:E7:15:6D:FF:30:E1:93:51:C0:67:60:B7
```

---

## 2. Profile verification — `verify-profile.sh`

Run this from any operator workstation with `VAULT_ADDR` + `VAULT_TOKEN` in
the env. It mints a throwaway leaf, asserts the strict KU/EKU/BC profile,
and fails non-zero on drift. Hook it into CI to catch accidental Vault
config edits.

The script lives at [`docs/verify-profile.sh`](./verify-profile.sh) and is
executable.

Expected output on a healthy Vault:

```
PROFILE OK: leaf has KU=DigitalSignature only, EKU=EmailProtection only,
            BasicConstraints CA:FALSE asserted.
```

---

## 3. Anchor distribution

Third-party verifiers need the root certificate to validate any leaf the
daemon emits. The canonical anchor lives at:

```
~/.config/cuecrux/c2pa/cuecrux-c2pa-root.pem   (716 bytes)
```

with SHA-256 fingerprint:

```
9F:BE:91:9D:E7:75:74:1B:2C:4A:E9:8C:30:A1:11:F1:4B:96:64:F8:E7:15:6D:FF:30:E1:93:51:C0:67:60:B7
```

Distribution channels:

| Audience | Channel | Pin |
|---|---|---|
| End-users running `corecruxctl c2pa-verify` | Operator-installed PEM obtained through an authenticated channel; pass its path with `--root-anchor` | SHA-256 fingerprint above |
| Partner integrations | Out-of-band over a TLS-pinned channel (Slack DM, signed email, GPG-encrypted file) | SHA-256 fingerprint above |
| Public CLI users | `https://cuecrux.com/.well-known/c2pa-anchor.pem` (TLS via Let's Encrypt) | SHA-256 fingerprint above |
| Adobe Content Credentials Verify | Not accepted (requires commercial CA) — see §6 |

Whatever channel: **the fingerprint must be displayed alongside the PEM**.
The CLI treats the configured PEM as the root of trust and reports its
`anchor_sha256`; it does not embed a globally pinned fingerprint. The operator
or provisioning layer MUST compare that reported fingerprint with the
out-of-band published value and refuse a mismatch.

`corecruxctl c2pa-verify` resolves its trust anchor in this order:
`--root-anchor`, `CORECRUXD_C2PA_ROOT_ANCHOR_PATH`, then the daemon-local
default `/var/lib/corecruxd/c2pa-root.cert.pem`. End-user CLI packages therefore
must pass the path of an operator-pinned certificate (as the emitted
verification-command placeholder requires) or set the environment variable to
that path. No current release package installs a public anchor automatically.

Verification is offline and evaluates the certificate path at the verifier's
current system time. The local clock and selected anchor file are trust inputs.
CRL and OCSP revocation are not checked, even when a certificate contains a CRL
distribution URL.

---

## 4. Rotation playbook

### 4.a Leaf rotation (automatic, 7-day pre-expiry)

The `VaultPkiX509Signer` rotation watcher checks every 1h. When the active
leaf has <7d remaining (the `ROTATION_THRESHOLD_HOURS` constant), it
mints a fresh CSR, POSTs to Vault, atomically swaps the on-disk PEMs, and
updates the in-memory state. **No operator action required.**

To force an early rotation (e.g. after operator suspects key compromise):

```bash
corecruxctl c2pa-rotate-leaf --json
```

This calls `regenerate_leaf` directly; the new leaf replaces the old one
atomically. The previous leaf remains embedded in manifests and can still prove
the manifest signature, but `corecruxctl c2pa-verify` accepts its trust path only
while that leaf is valid at the verifier's current system time. Durable
historical trust beyond certificate expiry requires a separately validated
trusted timestamp; the manifest's `signed_at` field is not itself a trusted
timestamp.

### 4.b Root rotation (manual, OPERATOR-GATED)

If the root is suspected compromised:

1. **Quarantine the daemon** — set `CORECRUXD_FEATURE_C2PA_X509_SIGNER=0`
   on every node so no new X.509 manifests are emitted.
2. **Mint a new root** on Vault (see §1 step 3, but write to a NEW mount
   `pki-c2pa-v2/` — never reuse the same mount).
3. **Issue all-new leaves** by pointing the daemon's
   `CORECRUXD_VAULT_PKI_MOUNT` env to `pki-c2pa-v2`.
4. **Re-distribute the new anchor** via every channel in §3 with the new
   fingerprint clearly marked. Old anchors should be marked "REVOKED — do
   not trust manifests after `<date>`."
5. **Document the incident** with
   `mcp__crux__store_fact(entity="incident:<date>", value={symptom, cause, fix_sha, repro_steps})`.

Existing manifests signed by leaves under the OLD root require an explicitly
selected old anchor and a certificate path that is still valid at the
verifier's current system time. After expiry of the last old leaf (max 30 days
post-cutover), the old anchor should be archived and removed from active
distribution channels. Historical verification after that point requires a
separately validated trusted timestamp; do not substitute the unsigned
manifest `signed_at` field.

---

## 5. EU AI Act Article 50 mapping

Article 50 of the EU AI Act requires providers of generative AI to mark
synthetic output in a machine-readable way. The CueCrux output stack
satisfies this through three layered receipts:

1. **`c2pa.actions` assertion** — every manifest carries `action =
   "c2pa.created"` + `digitalSourceType = "trainedAlgorithmicMedia"`
   (the IPTC value the C2PA v2.3 spec defines for fully AI-generated
   media). This is the AI-Act-visible label.
2. **`x5chain` header (this PR)** — the Vault-custodied X.509 chain
   binds the assertion to a verifiable trust anchor, so verifiers can
   cryptographically attribute the manifest to the CueCrux daemon
   without trusting our word for it.
3. **`cuecrux.crown_receipt` custom assertion** — links the C2PA
   manifest to the daemon's internal CROWN receipt chain (Ed25519,
   unchanged), so internal auditors can re-derive the exact agent
   action that produced the artefact.

The self-signed root is sufficient for AI-Act conformance: the spec only
requires the marking to be "in machine-readable format and detectable as
artificially generated or manipulated" (Art. 50(2)). It does not require
a public CA.

A commercial CA-issued anchor remains a future SKU enhancement (it
unlocks the Adobe Content Credentials Verify green tick); the engineering
scaffolding here is identical, only the root cert provenance changes.

> **Legal banner.** This document is engineering best practice aligned
> with the EU AI Act. It is not a legal opinion. Conformity assessment
> for any specific deployment remains the operator's responsibility.

---

## 6. Known gaps

### 6.a EKU non-critical

Vault PKI's role configuration cannot mark the ExtendedKeyUsage
extension as critical (the `ext_key_usage` field always emits a
non-critical extension). The C2PA spec recommends but does not require
critical EKU; the C2PA reference toolchain (`c2patool`, `c2pa-rs`)
accepts non-critical EKU in practice. The strict-profile assertion test
in `vault_pki_x509_signer.rs` checks the KU/BC bits; EKU criticality is
flagged here as a future Vault-side enhancement (probably via a custom
PKI plugin).

If a future C2PA validator rejects non-critical EKU, the fix path is to
either (a) post-process the Vault-returned cert to flip the critical bit
before stuffing it into the x5chain header, or (b) replace the Vault PKI
mount with a custom CA tool that supports per-extension criticality
config.

### 6.b Adobe Content Credentials Verify green tick

Adobe's hosted Verify (https://contentcredentials.org/verify) only
displays the green "verified" tick for manifests signed by a leaf
chained to a CA in their trust list. Self-signed roots will display the
manifest contents but show a "untrusted issuer" warning.

The fix is to migrate the trust anchor to a commercial CA-issued
intermediate (per the C2PA Hardware-Software Binding spec). This is a
future commercial SKU; the engineering scaffolding (Vault PKI custody,
CSR-sign-only daemon, atomic rotation, offline verifier) is unchanged.

---

## 7. References

- C2PA v2.3 spec: https://c2pa.org/specifications/specifications/2.3/
- RFC 9360 (COSE Receipts / `x5chain` header): https://www.rfc-editor.org/rfc/rfc9360
- Vault PKI secrets engine: https://developer.hashicorp.com/vault/docs/secrets/pki
- EU AI Act Article 50: https://artificialintelligenceact.eu/article/50/
- Crux fact `decision:vault-pki-p256-anchor-path` on
  `execplan:agent-ux-07-verifiable-output-receipts-2026-05-27` —
  architectural decision record.
- Crux fact `vault:pki-c2pa-prod-setup` on the same entity — prod Vault
  state snapshot from 2026-05-28.
