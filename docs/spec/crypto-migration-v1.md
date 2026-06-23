# Crypto Migration v1

Receipt v1 is algorithm-agile by construction: every signature carries an
explicit `alg` discriminator (`ReceiptSigV1.alg`, currently `ed25519`) and every
capability token carries a `spec_version`. The format anticipated a future
signature-algorithm change, but it shipped without a documented *path* to
retire one algorithm and re-anchor existing chain heads under another. This spec
defines that path.

The goal is to retire a signature algorithm (call it **alg A**, e.g. `ed25519`)
and re-anchor existing chain heads under a new algorithm (**alg B**, e.g.
`p256-ecdsa-sha256`) **without invalidating the originals**. The original
alg-A signature remains the canonical anchor for everything signed before the
migration; the re-anchor receipt is an *additive* attestation that the same head
is now also vouched for under alg B. No existing verification behaviour changes:
a verifier that only understands alg A continues to verify pre-migration
receipts exactly as before.

This is distinct from the `chain_reanchor` *hash-algorithm migration* metadata
body in [`receipt-v1.md`](receipt-v1.md) (kind `chain_reanchor`,
`build_chain_reanchor_body_v1`), which records a body-hash-algorithm window
change (e.g. `blake3` → `blake3+tsa`) but does not counter-sign under a new
signature algorithm. The signature-algorithm migration described here uses a
separate kind, `chain_signature_reanchor`, and a separate builder.

## When to migrate

Trigger a signature-algorithm migration when any of the following holds:

- **Algorithm deprecation.** Alg A is being retired across the fleet
  (cryptographic weakness, key-size policy change, or a quantum-readiness
  programme). Old chains signed under alg A must remain verifiable, but new
  trust must be re-established under alg B.
- **Signer-key compromise or rotation beyond a keyring entry.** A new key under
  a new algorithm replaces the old signer and existing heads need a fresh anchor
  that downstream verifiers can pin without trusting the retired key material.
- **Long-retention re-attestation.** A retention-bound dataset (e.g. a
  regulatory hold) outlives the practical confidence horizon of alg A. The
  operator re-anchors heads periodically so that at least one *currently-strong*
  signature always covers each retained head.

Do **not** migrate to silently rewrite history. The original alg-A signature is
never deleted or replaced; the re-anchor only adds an alg-B attestation over the
same chain head.

## What a migration receipt contains

A signature-reanchor receipt is a normal receipt body
(`schema = cuecrux.receipt.body.v1`, `kind = chain_signature_reanchor`) that
binds the original anchor and the new anchor together. Its body fields are:

| Field | Type | Notes |
|---|---|---|
| `schema` | string | `cuecrux.receipt.body.v1`. |
| `kind` | string | `chain_signature_reanchor`. |
| `receipt_id` | string | Stable id of the re-anchor receipt itself. |
| `tenant_id` | string | Tenant scope. |
| `chain_head_hash` | bytes | 32-byte BLAKE3 of the chain-head receipt body being re-anchored. This is the value alg A originally signed (the head's `signed_payload_hash`). |
| `original_alg` | string | The retiring algorithm label, e.g. `ed25519`. |
| `original_signature` | bytes | The original detached signature over the chain head, produced under alg A. Carried verbatim so an independent verifier can re-check it. |
| `original_key_id` | string | Keyring id of the alg-A public key (lookup hint, not trust). |
| `new_alg` | string | The new algorithm label, e.g. `p256-ecdsa-sha256`. |
| `new_key_id` | string | Keyring id of the alg-B public key. |
| `reanchored_at_unix_ns` | uint | Migration timestamp (nanoseconds since the Unix epoch). |

The re-anchor receipt body is itself signed under **alg B** via the detached
`ReceiptSigV1` envelope (`alg = new_alg`). The alg-B signature therefore covers
all of the fields above, including `chain_head_hash` and the carried
`original_signature`. This is the binding: the alg-B signer attests "chain head
X, originally signed under alg A with this exact signature, is re-anchored under
alg B at time T."

### Hybrid mode (longest retention)

For the longest-retention customers a hybrid variant carries **two** signatures
over the *same* re-anchor body bytes: one under alg A and one under alg B. Both
must verify. Hybrid mode gives a transition window in which downstream verifiers
that still pin alg A and verifiers that pin alg B can both independently confirm
the re-anchor body without trusting the other algorithm. The body bytes are
identical in either mode; hybrid mode differs only in carrying a second
`ReceiptSigV1` envelope under alg A alongside the alg-B envelope.

## How an independent verifier confirms the migration

A conforming verifier MUST confirm **both** legs. Confirming only one leg does
not establish a valid migration.

1. **Parse the re-anchor body** as CBOR and assert
   `kind == chain_signature_reanchor`. Extract `chain_head_hash`,
   `original_alg`, `original_signature`, `new_alg`, and the key ids.
2. **Leg A — original head still verifies.** Using the alg-A public key resolved
   from `original_key_id`, verify `original_signature` over the original chain
   head. The verifier supplies the original head body bytes out of band (it is
   the receipt the head id points at); `chain_head_hash` MUST equal
   `BLAKE3(head_body_bytes)`. If alg A no longer verifies the original head, the
   migration is rejected — the re-anchor must not be able to launder a head that
   was never validly signed.
3. **Leg B — re-anchor body verifies under the new algorithm.** Using the alg-B
   public key resolved from `new_key_id`, verify the detached `ReceiptSigV1`
   (`alg = new_alg`) over the re-anchor body bytes exactly as stored (no
   reserialization, per [`receipt-v1.md`](receipt-v1.md)).
4. **Hybrid (optional).** If a second `ReceiptSigV1` under alg A is present, it
   too MUST verify over the same re-anchor body bytes. A hybrid receipt with a
   missing or invalid alg-A signature is rejected.

Only when every applicable leg passes does the verifier attest: *"chain head X,
originally signed under alg A, re-anchored under alg B at time T."* The original
alg-A signature over the head is never required to be re-issued; it is carried
into the re-anchor body and re-checked, so the migration is self-contained and
checkable offline from the re-anchor receipt plus the original head bytes.

## Retention implications

- **Keep both public keys.** The alg-A public key MUST be retained in the
  keyring for as long as any re-anchor receipt references it; Leg A is
  unverifiable without it. Retiring an algorithm retires *signing* under it, not
  *verifying* with it.
- **Keep the original head bytes and signature.** Leg A re-checks the original
  signature over the original head. Crypto-shred or redaction of the head body
  breaks Leg A; a re-anchored head therefore inherits the head's retention
  floor. If a head is later redacted, the re-anchor receipt becomes a record of
  a head that can no longer be content-verified — record that as a retention
  exception, do not delete the re-anchor.
- **Re-anchor receipts are first-class audit records.** They follow the same
  retention defaults as other receipts (90-day minimum, configurable higher) and
  are deletable only by explicit operator action. For long-retention holds,
  prefer hybrid mode so at least one currently-strong signature always covers the
  head even mid-transition.
- **Migrate periodically, not once.** When alg B itself ages out, re-anchor
  again under alg C, carrying forward the alg-B anchor as the new "original."
  The chain of re-anchors forms an auditable ladder of trust across algorithm
  generations.
