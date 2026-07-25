# Identity candidate links — inference proposes, consent disposes

> How the daemon proposes that two identities are the same principal, and how an
> operator confirms (or rejects) that proposal. Anchored by **symbol name**
> (greppable), not line number. Feature-gated behind `CORECRUXD_IDENTITY_LINKS`.

## The two record kinds

| Kind | Store | Resolves a principal? | Written by |
|---|---|---|---|
| `candidate_link` (`CANDIDATE_LINK_KIND`) | `EntityStore` | **No** — a proposal only; `principal::resolve_by_session` ignores this kind | the propose route (below) |
| `identity_link` (`IDENTITY_LINK_KIND`) | `EntityStore` | **Yes** — a cross-signed edge the resolver walks | confirming a candidate, or `POST /v1/identity/links` |

A **candidate** is a suggestion that a local passport and an `observed_subject`
fingerprint are the same principal. It never resolves anything on its own —
that is the "consent disposes" half: a candidate becomes authoritative only when
an operator confirms it into an `identity_link` by supplying a cross-signature
proof (`confirm_candidate_with_link`, `candidate_links.rs`).

## Who writes candidates (the gap this closes)

Before M6 the proposers `propose_from_session_bindings` and
`propose_from_observations` (`corecruxd/src/candidate_links.rs`) were
**library-only** — no route, CLI, MCP tool, or boot task called them, so
`GET /v1/identity/candidates` was permanently empty on any fresh workspace.

`POST /v1/identity/candidates/propose`
(`http::identity_links::post_identity_candidates_propose`) is the deliberate
seed path and the **only shipped producer** of `candidate_link` records. It is
`admin:write`, 404s when the feature flag is off, and runs both proposers over
two evidence sources:

| Source | Evidence | Builder |
|---|---|---|
| `bindings` | session→passport bindings — two **distinct** passports co-occurring in one tenant + project inside the temporal window | `candidate_links::observations_from_session_bindings` |
| `observations` | observation-journal principals — two **distinct** signing identities co-occurring in one session | `http::identity_links::journal_candidate_observations` |

Response shape:

```json
{ "created": N, "examined": M,
  "by_source": { "bindings":      { "created": …, "examined": … },
                 "observations":  { "created": …, "examined": … } } }
```

**Idempotent.** `create_candidate` derives the candidate id from the payload
content (`candidate_link_id`) and returns `AlreadyExists` for a duplicate, which
`propose_from_observations` swallows — so re-running the route over the same
evidence creates nothing.

### Why the observations source is usually 0

`proposal_input_for_pair` only emits a candidate for two observations that share
a `project_id` (the session id) **and** carry different `observed_subject`
principals. Most sessions are signed by a single agent passport, so the
journal source drops every single-principal session and typically yields 0 —
that is honest, not a bug. The `bindings` source is the practical producer on a
CE workspace. `journal_candidate_observations` deduplicates to one observation
per `(session, principal)` and drops single-signer sessions before the O(n²)
proposer runs (the mirror carries ~140k observation records across ~39k
sessions — a global pairwise scan would never return).

## How consent disposes

| Action | Route | Handler | Effect |
|---|---|---|---|
| confirm | `POST /v1/identity/candidates/{id}/confirm` | `post_identity_candidate_confirm` | verifies BOTH signatures, mints a resolving `identity_link`, marks the candidate `confirmed` |
| reject | `POST /v1/identity/candidates/{id}/reject` | `post_identity_candidate_reject` | marks `rejected`, keeps the versioned audit trail, never resolves |
| revoke | `POST /v1/identity/links/{id}/revoke` | `post_identity_link_revoke` | retires a confirmed link (upsert with audit) |

Confirmation requires the cross-signature proof (`CreateLinkRequest`:
`local_passport_id`, `remote_fpr`, `remote_public_key_hex`, `created_at`,
`sig_local`, `sig_remote`). The daemon mints the `identity_link` only after both
signatures verify — the console cannot fabricate a link.

## Console surface

`#/trust/cx-identity` (`render.js::renderIdentityBrowser`) documents this
pipeline in-page, lists live candidates from `GET /v1/identity/candidates`, and
carries an operator-gated **Seed candidates** button wired to the propose route
through `operatorGatedCall` (disabled with a reason in customer posture). When
the flag is off the page shows the honest 404 copy naming
`CORECRUXD_IDENTITY_LINKS`.

## Flag

`CORECRUXD_IDENTITY_LINKS=1` enables the whole `/v1/identity/*` group
(`AppState.identity_links_enabled`, parsed in `config.rs`). With it unset every
identity route returns `404 "identity links disabled (set
CORECRUXD_IDENTITY_LINKS=1)"`. Prod flag state is an operator decision.
