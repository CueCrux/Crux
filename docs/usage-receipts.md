# Usage receipts (opt-in adoption signal)

> **CueCrux usage receipts (opt-in, off by default).** When you enable this, the daemon submits a
> *signed, metadata-only* usage receipt — receipt id, content hash, your passport fingerprint, event
> class, and timestamp — to the collector endpoint you configure. **No fact content, query text, or
> corpus data is ever included.** This is the only outbound signal the daemon sends. It requires you
> to (1) set an `https://` collector endpoint and (2) explicitly record consent
> (`CORECRUXD_USAGE_RECEIPTS_CONSENT_AT`). Revoke anytime by unsetting
> `CORECRUXD_USAGE_RECEIPTS_SUBMIT`. It exists so CueCrux can count adoption; it is never required to
> use the daemon.

Crux's trust posture is **no phone-home**: with default configuration the daemon makes zero
non-loopback network calls, and a release gate (`scripts/assert-no-phone-home.sh`) boots the daemon
with default environment and fails the build on any egress attempt. Usage receipts are the single
sanctioned exception, and they are gated behind an explicit, three-part opt-in so that a fresh
install — or any install where the operator has not deliberately turned this on — dials nothing.

## What it is

The daemon already mints a **local, signed `usage_ping` receipt**: a deliberately metadata-only CROWN
receipt that records "a thing happened" (a session opened, a query ran, the daemon started) without
disclosing *what* happened. That receipt is persisted locally like any other signed observation.

When — and only when — you opt in, the daemon additionally **submits a metadata-only copy** of that
receipt to a collector endpoint you control. The submission carries just enough to let the collector
verify the Ed25519 signature and count distinct daemon instances (by passport fingerprint) toward an
adoption number. It never carries the receipt body content, the fact, the query, or the corpus.

## The three-part opt-in gate

The submitter performs **zero** network I/O unless **all three** of the following hold:

| Env var | Default | Meaning |
|---|---|---|
| `CORECRUXD_USAGE_RECEIPTS_SUBMIT` | `false` | Master enable. Must be `1`/`true` to submit. |
| `CORECRUXD_USAGE_RECEIPTS_ENDPOINT` | *(unset)* | The `https://` collector URL. **There is no hardcoded default** — if unset, nothing is sent. Plaintext `http://` endpoints are rejected. |
| `CORECRUXD_USAGE_RECEIPTS_CONSENT_AT` | *(unset)* | Your recorded consent act. Set it to an RFC3339 timestamp, or to the literal `yes` to stamp the current time. The submitter refuses to fire unless this is set. |

If any one of the three is missing, the submitter is a no-op. It is also never wired into the boot
path or a background timer — it is triggered **only** by an explicit `usage_ping` mint on the
`/v1/mediation/receipts` surface, and only *after* the local signed receipt has been persisted.

> Note: submitting also requires the `CORECRUXD_FEATURE_USAGE_RECEIPTS=1` feature flag so that the
> daemon accepts `usage_ping` drafts at all. Without it, no `usage_ping` is minted and there is
> nothing to submit.

## What is sent

The wire payload is metadata only. Exactly these fields, and nothing else:

| Field | Example | What it is |
|---|---|---|
| `receipt_id` | `r_9f1c…` | The signed receipt's id. |
| `body_hash` | `blake3:5e88…` | A hash of the canonical receipt body — a digest, not the body. |
| `passport_fpr` | `p_1a2b…` | The daemon's passport fingerprint (the adoption unit counted). |
| `event_class` | `session` | One of the closed set `session` / `query` / `daemon_start`. |
| `created_at` | `2026-07-03T00:00:00Z` | The receipt timestamp. |
| `sig` | `{alg, key_id, signed_at, signature_hex}` | The Ed25519 signature envelope, so the collector can verify the ping. |

## What is NOT sent

- **No fact content** — not the value, not the key, not the entity.
- **No query text** and no prompt text.
- **No corpus identity** or corpus data.
- **No receipt body** — only its hash.
- No general telemetry, no host metrics, no environment, no IP-derived data beyond what the transport
  layer inherently exposes to the endpoint you chose.

## How to enable

```bash
# All three legs — a fresh install would dial nothing without these.
export CORECRUXD_FEATURE_USAGE_RECEIPTS=1                       # mint usage_ping receipts locally
export CORECRUXD_USAGE_RECEIPTS_SUBMIT=1                        # master enable for submit
export CORECRUXD_USAGE_RECEIPTS_ENDPOINT="https://collector.example.com/usage"
export CORECRUXD_USAGE_RECEIPTS_CONSENT_AT="yes"               # or an explicit RFC3339 timestamp
```

## How to revoke

Unset (or set to `0`/`false`) `CORECRUXD_USAGE_RECEIPTS_SUBMIT` and restart the daemon. The submitter
is immediately inert again; local `usage_ping` receipts (if `CORECRUXD_FEATURE_USAGE_RECEIPTS` is
still on) continue to be minted and stored locally, but nothing is submitted. Clearing the endpoint or
the consent timestamp
also disables submission — the gate requires all three.
