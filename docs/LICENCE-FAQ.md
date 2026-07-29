# Licence FAQ — Apache License, Version 2.0

Plain-English answers about the licence that covers the code in this
repository. The full text is [`LICENSE`](../LICENSE); curated content under
`content/` is covered separately by
[`content/LICENCE-CONTENT.md`](../content/LICENCE-CONTENT.md). If this page and
`LICENSE` ever disagree, `LICENSE` wins.

## Is this open source?

Yes. Crux Daemon is licensed under the **Apache License, Version 2.0** — an
OSI-approved, GPL-compatible, permissive open-source licence. The `LICENSE`
file is the unmodified upstream Apache text.

This replaced the CueCrux Community Licence (CCL v1.0), a source-available
BSL-style licence that withheld redistribution-in-competing-products and
third-party-hosting rights. Those restrictions are gone. The CCL already named
Apache 2.0 as its Change Licence, so this change brings that conversion
forward for all versions rather than waiting out the per-release three-year
clock.

## What can I do?

Everything a permissive licence allows, with no payment, registration, or seat
limits:

1. **Run it** for any purpose — internal, commercial, or production.
2. **Read, audit, and verify** the source, including confirming the integrity
   of CROWN receipts, BLAKE3 chains, and tenant isolation.
3. **Modify it**, for internal use or to ship to others.
4. **Redistribute** it, in source or binary form, including inside a
   proprietary or competing product.
5. **Offer it as a managed, hosted, or cloud service** to third parties.
6. **Sublicense** it, including under a different licence, subject to the
   conditions below.
7. **Use it for academic research and publication.** Citation is appreciated
   (see [`CITATION.cff`](../CITATION.cff)) but is no longer a licence
   condition.

Apache-2.0 also grants an **express patent licence** (section 3) from every
contributor — a right the CCL did not address.

## What are the conditions?

Apache-2.0 asks for four things when you redistribute (section 4):

1. **Include the licence.** Ship a copy of `LICENSE` with any distribution.
2. **State your changes.** Modified files must carry prominent notices saying
   they changed.
3. **Retain notices.** Keep the copyright, patent, trademark, and attribution
   notices from the source you copied — including the per-file headers.
4. **Pass on the NOTICE.** If you redistribute, include the attribution text
   from [`NOTICE`](../NOTICE).

That is the whole obligation set. There is no copyleft: your own modifications
and surrounding code can be licensed however you like.

## Can I strip CROWN receipt generation?

Legally, yes — Apache-2.0 imposes no such restriction, and the CCL clause that
prohibited it is gone. Practically, don't: the receipt chain is what makes the
daemon's integrity claims verifiable, and a build with receipts removed cannot
honestly be described as satisfying the
[Trust Contract](../TRUST-CONTRACT.md). If you ship a modified build, section
4(b) requires you to state what you changed.

## Can I use the CueCrux name?

Not beyond describing where the software came from. Apache-2.0 section 6
explicitly grants **no trademark rights**. "CueCrux", "Crux", and "CROWN" are
trade names of CueCrux Ltd. Saying "built on Crux Daemon" is fine; calling
your product "CueCrux-anything", or presenting a fork as official, is not.

## I want to contribute. What am I agreeing to?

Inbound=outbound under section 5: contributions you submit are licensed under
Apache-2.0 on the same terms, unless you explicitly state otherwise. You keep
your own copyright and there is no separate CLA to sign. See
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Is there a warranty?

No. Sections 7 and 8 apply: the software is provided "AS IS", without
warranties or conditions of any kind, and contributors are not liable for
damages arising from its use.

## How do licence scanners see this? (machine-readable metadata)

Apache-2.0 is a registered SPDX identifier, so detection is now
straightforward — GitHub's `licensee` and comparable scanners resolve the
repository licence from the verbatim `LICENSE` file. Three signals are
published:

1. **Repository licence file.** `LICENSE` is the unmodified upstream Apache
   2.0 text, which is what heuristic detectors match against.
2. **SPDX identifier `Apache-2.0`.** Present as the second line of every
   `.rs` source header (`// SPDX-License-Identifier: Apache-2.0`), enforced by
   [`scripts/check-licence-headers.sh`](../scripts/check-licence-headers.sh)
   in CI.
3. **Cargo manifest metadata.** The workspace sets `license = "Apache-2.0"` in
   `[workspace.package]`; every member crate inherits it via
   `license.workspace = true`. So `cargo metadata` and any SBOM generator that
   reads it (`cargo-sbom`, CycloneDX, and similar) report `Apache-2.0` for all
   crates.

The crates are marked `publish = false` and are not on crates.io — the
workspace uses unversioned path dependencies that a registry publish would
reject. That is a packaging detail, not a licensing one.
