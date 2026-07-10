# Licence FAQ — CueCrux Community Licence (CCL v1.0)

Plain-English answers about the licence that covers the code in this
repository. The full text is [`LICENCE.md`](../LICENCE.md); curated content
under `content/` is covered separately by
[`content/LICENCE-CONTENT.md`](../content/LICENCE-CONTENT.md). If this page and
`LICENCE.md` ever disagree, `LICENCE.md` wins.

## Is this open source?

No. Crux Daemon is **source-available**, not open source. The licence text
says so directly: it "is modelled on the Business Source License 1.1 with
CueCrux-specific terms. It is not an OSI-approved open-source licence."

What that means in practice: you can read every line, build it, run it, and
modify it — but the **Prohibited Uses** section withholds two rights that
OSI-approved licences grant (redistribution in competing products, and
offering it as a hosted service). Everything else is granted up front,
including production and commercial use.

## What can I do for free?

Everything in the **Permitted Uses** section, with no payment, registration,
or seat limits:

1. **Run it** for any internal purpose, including commercial internal use.
   Production use is granted in the **Terms**, subject to the conditions
   below it.
2. **Read, audit, and verify** the source — explicitly including confirming
   the integrity of CROWN receipts, BLAKE3 chains, and tenant isolation.
3. **Modify it** for internal use within your organisation.
4. **Contribute** improvements, corrections, citations, gap reports, and
   skills back via the published contribution process.
5. **Use it for academic research and publication**, provided attribution is
   given.
6. **Build internal tooling** that calls the daemon's APIs.

The grant also covers copying, creating derivative works, redistributing, and
non-production use generally — bounded only by the prohibitions below.

## What can't I do?

The **Prohibited Uses** section lists exactly three things:

1. **Redistribute** the Software or a derivative as part of a product or
   service that **competes with CueCrux products**.
2. **Offer** the Software or a derivative **as a managed, hosted, or cloud
   service to third parties**. Note this clause has no "competing"
   qualifier — hosting Crux for third parties is prohibited outright.
3. **Remove or alter** licence headers, CROWN receipt generation, or
   attribution notices. The receipt chain is part of the product's integrity
   claim; stripping it is a licence violation, not a configuration choice.

Hosting Crux for yourself (your own team, your own infrastructure, your own
agents) is internal use and is fine. The line is offering it *to third
parties* as a service.

## When does it become Apache 2.0?

Three years after **each versioned release**, per the **Change Date**
section: "On the Change Date (three years after each versioned release), the
Licensor hereby grants you rights under the terms of the Change Licence
(Apache Licence, Version 2.0), and the rights granted under this licence
terminate."

The conversion is **per release**, not per project. Each tagged version
carries its own clock: the code as released in `v0.4.0` converts to Apache
2.0 three years after the `v0.4.0` release date, `v0.5.0` three years after
its own date, and so on. There is no scenario where the code stays
proprietary forever — every shipped version has a fixed expiry on its
restrictions.

## Why this licence?

Honestly: it prevents free-rider hosted clones while keeping local use free
forever. Managed hosting is the thing CueCrux sells; if a cloud vendor could
take the daemon and offer "hosted Crux" the day after a release, there would
be no revenue to fund the development you're auditing. The CCL keeps the two
rights that protect that business (no competing redistribution, no
third-party hosting) and grants everything else — and the per-release
three-year Apache 2.0 conversion is the commitment that this is a head
start, not a lock-in.

## I want to contribute. What am I agreeing to?

The **Contribution Licence** condition in **Additional Conditions**: by
contributing code, documentation, or other materials, you grant CueCrux Ltd
a perpetual, worldwide, non-exclusive, royalty-free licence to use,
reproduce, modify, and distribute your contribution under **both** the CCL
and the Change Licence (Apache 2.0). You keep your own copyright; there is
no separate CLA document to sign — the grant is in the licence itself.

## Can I use the CueCrux name?

Not beyond describing where the software came from. The **No Trademark
Grant** condition: the licence "does not grant permission to use the trade
names, trademarks, service marks, or product names of the Licensor, except
as required for reasonable and customary use in describing the origin of the
Software." Saying "built on Crux Daemon" is fine; calling your product
"CueCrux-anything" is not.

## Is there a warranty?

No. The **Disclaimer of Warranty** section applies: the software is provided
"AS IS", without warranty of any kind.

## How do licence scanners see this? (machine-readable metadata)

The CCL is a custom licence, so GitHub's `licensee` and similar heuristic
detectors will report the repository licence as "Unknown" — that is expected
and accepted; it does not mean the code is unlicensed. Two machine-readable
signals are published so SBOM/compliance tooling gets a parseable answer:

1. **SPDX identifier `LicenseRef-CCL-1.0`.** `LicenseRef-` is SPDX's standard
   prefix for a licence with no SPDX-registered ID. It appears as the second
   line of every `.rs` source header
   (`// SPDX-License-Identifier: LicenseRef-CCL-1.0`) and as the `license`
   field in every crate manifest.
2. **Cargo manifest metadata.** The workspace sets
   `license = "LicenseRef-CCL-1.0"` in `[workspace.package]`; every member
   crate inherits it via `license.workspace = true`. So `cargo metadata` and
   any SBOM generator that reads it (e.g. `cargo-sbom`, `syn`-based scanners,
   CycloneDX) report `LicenseRef-CCL-1.0` for all crates rather than a blank.

Scanners that resolve `LicenseRef-` identifiers back to text should point at
[`LICENCE.md`](../LICENCE.md), the authoritative CCL text.
