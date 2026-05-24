# Licence Recommendation — switch CCL v1.0 → BUSL 1.1

**Status:** Research / recommendation. **No licence change has been made.**
**Author:** Wave-1 audit follow-up (C-as-research).
**Date:** 2026-05-24.

---

> **This is engineering research, not a legal opinion.** The recommendation below is grounded in licence-text comparison and the published practice of comparable projects (MariaDB, CockroachDB, Sentry). Any licence change must be reviewed by counsel; this document is structured to be the input to that conversation, not a substitute for it.

## Recommendation

Switch from the bespoke **CueCrux Community Licence (CCL v1.0)** to **Business Source License 1.1 (BUSL 1.1)**, with:

- **Change Date:** Three years after each versioned release.
- **Change Licence:** Apache License, Version 2.0.
- **Additional Use Grant:** explicit grants matching CCL §1.1, §1.2, §1.3, §1.6 (internal commercial use, audit/verification, internal modification, building internal tooling on the API).
- **Trademark:** separate; no grant via the licence (matches CCL §3.2).
- **Contribution Licence:** preserve the CCL §3.1 dual-grant pattern as a project CLA, applied via a standard DCO or a one-line `CONTRIBUTING.md` clause referencing the same flow-through to the Change Licence.

## Why this conversation now

An external code review of this repository in May 2026 identified the bespoke CCL as a real adoption speed bump:

- CCL v1.0 is **not SPDX-recognised**, so GitHub's repo header reads "Unknown and 2 other licenses found." The default-MIT/Apache developer audience reads "Unknown" and bounces.
- The 3-year Apache 2.0 conversion is a genuinely fair touch that's buried in the licence file rather than surfaced.
- The licence's own footer acknowledges it is "modelled on the Business Source License 1.1 with CueCrux-specific terms" — i.e. BUSL was already the template; we just diverged from the wire format.

Moving to BUSL keeps every substantive guarantee the operator cares about and trades only "bespoke wording" for "instant SPDX recognition + an enterprise-recognised template." The README rework (Wave-1 milestone A) handles the conversion-clause surfacing in parallel — the licence change handles the recognition gap.

## Side-by-side: CCL v1.0 vs proposed BUSL 1.1 parameterisation

| Concern | CCL v1.0 (today) | BUSL 1.1 (proposed) |
|---|---|---|
| **SPDX identifier** | None — repo shows "Other" / "Unknown" | `BUSL-1.1` (recognised; GitHub identifies it) |
| **Change Date** | "Three years after each versioned release" (§Parameters) | Same — set as the `Change Date` parameter per release. |
| **Change Licence** | Apache 2.0 (§Parameters, §Change Date) | Same — set as the `Change License` parameter. |
| **Internal commercial use** | §1.1 explicit | Covered by Additional Use Grant (draft below). |
| **Audit / verify rights** | §1.2 explicit, with named CROWN-receipt and BLAKE3 examples | Implicit in BUSL's "any use other than Production Use", but should be made explicit in Additional Use Grant to remove ambiguity. |
| **Internal modification** | §1.3 explicit | Covered by Additional Use Grant. |
| **Academic use** | §1.5 explicit | Covered by Additional Use Grant. |
| **Build on the API internally** | §1.6 explicit | Covered by Additional Use Grant. |
| **Prohibit competing managed service** | §2.1, §2.2 explicit | BUSL's default "Production Use" prohibition covers this; Production Use should be defined to mean "offering the Software, or a derivative work, as a managed/hosted/cloud service to third parties" (verbatim from CCL §2.2). |
| **Prohibit removal of licence headers / receipt generation** | §2.3 explicit | Not native to BUSL; preserve as an Additional Term or via project policy + CI guard. The CROWN-receipt-generation rule especially is enforced in code (not just licence) by `verify-store` — the licence clause is belt-and-braces. |
| **Contribution dual-grant** | §3.1 explicit (contributions licensed under both CCL and Change Licence) | Move to a separate `CONTRIBUTING.md` clause or DCO. BUSL itself is silent on contribution. |
| **Trademark grant** | §3.2 — none | Same — BUSL does not grant trademark. |
| **Warranty disclaimer** | §Disclaimer | Identical clause in BUSL. |

## Draft Additional Use Grant (for legal review)

The text below is the proposed `Additional Use Grant` parameter; it consolidates CCL §1.1, §1.2, §1.3, §1.5, §1.6 into BUSL's vocabulary. Legal should redline this before any switch.

> **Additional Use Grant.** You may use the Licensed Work without limitation for any of the following purposes:
>
> 1. Internal use within your organisation, including commercial internal use.
> 2. Reading, auditing, and verifying the source code to confirm the integrity of CROWN receipts, BLAKE3 hash chains, tenant isolation, signing-key handling, or any other claimed behaviour of the Software.
> 3. Modifying the Software for internal use within your organisation.
> 4. Building internal tooling that calls the Software's APIs.
> 5. Academic research and publication, provided attribution is given to the Licensor.
>
> **Production Use** means offering the Licensed Work, or any derivative work, as a managed, hosted, or cloud service to third parties; or redistributing the Licensed Work, or any derivative work, as part of a product or service that competes with the Licensor's commercial offerings. Production Use is not granted under this Additional Use Grant and remains subject to the terms of the Business Source License 1.1 until the Change Date.

## What changes in the repo (estimate)

If the operator approves the switch after legal review, the mechanical changes are bounded:

| Surface | Change |
|---|---|
| `LICENCE.md` | Replace with BUSL 1.1 template + filled parameters + Additional Use Grant + warranty disclaimer. |
| `LICENCE-CONTENT.md` | Unchanged — the Content Licence is separate from the code licence. |
| `LICENCE-CODE.md` | Reconcile with `LICENCE.md` (currently both exist; review whether one supersedes the other). |
| Crate `//` headers | ~250 `.rs` files currently say `Licensed under the CueCrux Community Licence (CCL v1.0)`. Mechanical `sed` to `Licensed under the Business Source License 1.1`. |
| `Cargo.toml` `license` field | Currently `CCL-1.0` (custom). Change to `BUSL-1.1` (SPDX). |
| `crates/*/Cargo.toml` `license.workspace = true` | No change (inherits from workspace). |
| `README.md` | Replace "CueCrux Community Licence (CCL v1.0)" badge text; the README rework already surfaced the conversion clause separately. |
| `CHANGELOG.md` | Add an entry under `[Unreleased]` noting the licence change with an effective date. |
| `crux-config-wizard` profile mentioning CCL | None today; verify by grep. |
| `SECURITY.md` | Check for licence references; update if any. |
| `_typos.toml`, `deny.toml` | Check for hardcoded `CCL` strings; update. |
| New file: `CONTRIBUTING.md` (if not present) or addition to the existing one | The dual-grant DCO/CLA text matching CCL §3.1's intent. |

**Effort:** half a day of mechanical edits + an hour to verify the `Cargo.toml` license field doesn't break `cargo deny` checks + however long legal review takes. The CI's `cargo audit` and `cargo deny` jobs should pass unchanged once `license = "BUSL-1.1"` lands.

## Specific questions for legal counsel

1. **Coverage equivalence.** Does the draft Additional Use Grant above functionally cover the rights presently granted in CCL §1.1, §1.2, §1.3, §1.5, §1.6, with no narrowing of permitted use?
2. **Production Use scope.** Is the proposed Production Use definition (CCL §2.2 verbatim) enforceable under BUSL 1.1's framing? Comparable products (CockroachDB, Sentry) use similar wording — is ours legally clean?
3. **Contribution flow-through.** Existing contributors signed CCL §3.1's perpetual dual-grant. Does that grant carry forward under a switch to BUSL+Apache as the Change Licence, or do we need a fresh contributor agreement before the switch?
4. **Header replacement.** Is `sed`-replacement of `Licensed under the CueCrux Community Licence (CCL v1.0)` → `Licensed under the Business Source License 1.1` in every file's header valid notice, or do existing forks/copies need anything more to maintain licence continuity?
5. **Trademark continuity.** CCL §3.2 says "no trademark grant." BUSL is silent. Should we add an explicit trademark-reservation clause as an Additional Term, or rely on standard trademark law?
6. **`LICENCE-CODE.md` reconciliation.** This file exists alongside `LICENCE.md` today. Should the switch make one of them authoritative and remove the other, or maintain a code-vs-content split?

## Alternatives considered

### C1 — Register CCL v1.0 with SPDX (rejected)

Filing a submission to <https://github.com/spdx/license-list-XML> would get CCL v1.0 a `LicenseRef-` identifier and eventually a full SPDX-recognised name. Process is 4–8 weeks. **Rejected** because:

- It preserves bespoke wording that the licence's own footer acknowledges is "modelled on" BUSL anyway — we'd be reinventing in public.
- Until merged, "Unknown" persists on GitHub's repo header; the adoption friction stays.
- Future BUSL revisions (the FSF-style maintenance) don't reach a bespoke fork; we'd own all forward-compatibility work.
- Enterprise legal teams already know BUSL; CCL v1.0 needs full re-review every time.

### C2 — Switch to MIT or Apache 2.0 directly (rejected)

Drop the source-available constraint entirely. **Rejected** because:

- It surrenders the explicit prohibition on offering Crux as a competing managed service, which is the commercial spine the audit identified.
- The 3-year Apache conversion already provides the eventual permissive licensing; the BUSL Change Date mechanism is the right pattern, not the wrong one.

### C3 — Switch to Elastic License v2 (ELv2) (rejected)

Used by Elastic, MongoDB (SSPL), Redis. **Rejected** because:

- ELv2 prohibits "providing the software to others as a managed service" but does *not* have a Change Date / eventual-OSS-conversion pattern. The audit specifically valued the 3-year conversion as a fair touch; ELv2 would lose it.
- ELv2 is associated with more aggressive enforcement than the audit's intended posture; BUSL is more permissive in spirit.

## Decision record

| Field | Value |
|---|---|
| `entity` | `execplan:crux-licence-spdx-and-surface-2026-05-28` (planned, not yet created) |
| `key` | `decision:licence-route` |
| `value` | `{"chosen": "BUSL-1.1", "rationale": "see docs/design/licence-recommendation.md", "needs_legal_review": true, "commit_sha": "TBD-at-switch-time"}` |
| Status | **Pending legal review.** Do not change `LICENCE.md` until counsel has signed off on the Additional Use Grant draft. |

## What this document is NOT

- Not authority to swap `LICENCE.md`. The operator + counsel decide; this is the engineering input.
- Not a guarantee that BUSL 1.1's wording in some future court interpretation will be identical to CCL v1.0's. Bespoke wording always allows for more specific intent; what BUSL gives up in specificity it gains in precedent.
- Not a blocker for the Wave-1 README + audit-doc work (which has already shipped on this branch under the existing CCL).
