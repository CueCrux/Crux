<!-- Copyright (c) 2026 CueCrux Ltd. All rights reserved. -->
<!-- Licensed under the CueCrux Community Licence (CCL v1.0). -->

# M1 — Gated Auto-Capture (design)

ExecPlan `crux-daemon-buyer-fit-buildout-2026-07-13`, milestone M1 (knock-out #1
+ table-stake #1). Knock-out #1 in the buyer analysis: *"auto-capture that is
gated, inspectable, receipted, and decay-aware — capture without a human calling
a tool, but never blindly; every auto-written fact is reviewable and
reversible."* This is the marquee capability and the field's #1 failure mode
(Mem0's 97.8% junk; ChatGPT Dreaming silently poisoning answers).

## The one invariant that defines success

**An auto-extracted fact is NEVER visible to recall until an explicit review
promotes it.** A poisoned/false candidate must be catchable at the review gate
and provably absent from `GET /v1/facts` / MCP `query_facts` recall. Unscored ⇒
review-only, never promoted (the exact inversion of CruxEngine's fail-open
verifier at `ingest-extraction.ts:757-758,884-892`).

## Reuse vs build (grounded)

- **REUSE (CruxEngine schemas):** the candidate shape `ExtractedSessionFact
  {subject, predicate, object, date?, confidence, rule}` and the receipt
  provenance shape (`ExtractionReceiptFact` + content-addressed hash). Keeps the
  paid managed-LLM path schema-compatible.
- **PORT (deterministic rules, `memory-facts.ts:1257-1548`):** 10 pure rules —
  money, count_item, date_iso, date_month_day, project_pred, acquire,
  previous_occupation, family_trip_destination, version_previous,
  version_current — plus `scrubNoise` (strip code fences + URLs) and helpers
  (normaliseMoney, cleanClauseValue, looksLikeOccupation, in-batch dedup).
  Validate against a coding-agent shadow corpus, not blind-port.
- **BUILD (greenfield in the daemon):** the candidate/review/promotion lifecycle
  + the fail-closed gate. CruxEngine has no status column ("quarantine" =
  silent omission) — nothing to port here.
- **DO NOT COPY:** the consolidation-review template writes `private:false`
  (visible); `candidate_links.rs` is identity-resolution, not facts.

## Storage model — the review-only candidate

Candidates are ordinary `Fact`s under a **new reserved prefix
`__candidate_fact__::<candidate_id>`**, born-private (so invisible to recall by
construction) and receipted:

- `entity = "__candidate_fact__::<candidate_id>"`, `key = "candidate"`.
- `value` = JSON `crux.memory_candidate.v1`:
  `{schema, candidate_id, status, proposed_entity, proposed_key,
    proposed_value, rule, confidence, decay_class, source: {session_id,
    observation_seq, evidence, evidence_offset}, verifier_score|null,
    receipt: <ReceiptEnvelopeV1>, created_at, promoted_fact_id?|reject_reason?}`.
- `private = true` (forced via `fact_privacy` prefix registry), `horizon_class`
  explicit (Medium — a candidate pending review is not long-lived), `actor =
  "auto-capture"`, `source_receipt = <receipt body_hash>`.
- `status ∈ {candidate, promoted, rejected}`. State transitions are new
  same-`(entity,key)` versions (audit chain via existing supersession), so
  history is preserved and reversible.

**Three-place wiring for the prefix (CI-enforced):**
`fact_privacy.rs::private_prefixes` + `CRUXPACK_RESERVED_PREFIXES` (subset test)
+ `HorizonClass::default_for_entity` (Medium).

## The fail-closed gate (the safety core)

`promote(candidate_id, reviewer)`:
1. Load the candidate; reject if not `status=candidate`.
2. **Gate:** promotion requires an explicit reviewer action OR a passing
   deterministic score. A candidate with **no `verifier_score` / unscored /
   unavailable** is NEVER auto-promoted — it stays `candidate` (review-only).
   (Inverts CruxEngine's "no score ⇒ promote".)
3. On promote: write the proposed fact under its true `(proposed_entity,
   proposed_key)` via the normal store path (so it goes through born-private,
   passport, supersession) with `source_receipt` linking the candidate receipt;
   then write a new candidate version `status=promoted, promoted_fact_id=…`.
4. `reject(candidate_id, reason)`: new version `status=rejected, reject_reason`.
   Reversible — a rejected candidate can be re-promoted (new version).

Auto-promotion is **off by default**. Even with a passing deterministic score,
the default is review-queue-only; an operator opt-in
(`CORECRUXD_AUTO_CAPTURE_AUTOPROMOTE`) may enable score-gated auto-promote later,
never for unscored candidates.

## Surfaces (flag-gated: `CORECRUXD_AUTO_CAPTURE`, default OFF)

- `POST /v1/memory/extract` — body `{session_id?|text?, profile?}`; runs the
  deterministic extractor over supplied text or the session's observation JSONL;
  writes candidates; returns the candidate list. 0-LLM on the free path.
- `GET /v1/memory/candidates?status=candidate` — the review queue.
- `POST /v1/memory/candidates/{id}/promote` / `/reject` — the review ceremony
  (authenticated actor, like the consolidation review route).
- MCP mirror tools (later sub-step).

## Sub-step decomposition

- **M1.1 — Candidate store + safety foundation** (mine): reserved prefix +
  three-place wiring; `crux.memory_candidate.v1` schema; a `candidate_store`
  helper writing born-private receipted candidates; per-candidate CROWN receipt.
  Test: a written candidate is invisible to `GET /v1/facts` recall.
- **M1.2 — Deterministic extractor** (codex-drafted, I review): port the 10
  rules + scrubNoise to `memory_extract.rs`; unit tests mirroring CruxEngine
  rule outputs + confidences.
- **M1.3 — Review lifecycle + fail-closed gate** (mine): promote/reject state
  machine; the unscored⇒review-only inversion; reversibility.
- **M1.4 — Surfaces**: routes + flag + eval-profile wiring + MCP tools.
- **M1.5 — Gate tests**: poison test (false candidate → never in recall →
  visible in review), Claude-Code+Codex session → reviewable candidates,
  fail-closed (unscored not promoted), promote→recall→reject→gone round-trip.

## Gate (from the ExecPlan)

A Claude Code + Codex session yields reviewable candidates; a poison test
(inject a false fact) is caught at the review gate, never surfaced in recall;
unscored candidates are review-only. Free = deterministic local extraction;
paid = optional managed LLM extraction via the Platform (same candidate/receipt
schema, opt-in).
