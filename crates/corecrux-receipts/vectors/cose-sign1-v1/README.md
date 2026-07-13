# COSE_Sign1 v1 vectors

These fixtures exercise the
[CROWN SCITT Application Profile v0.2](https://github.com/CueCrux/ResearchCrux/blob/main/protocol/scitt-compat/crown-scitt-profile.md)
and its normative
[CROWN receipt CDDL](https://github.com/CueCrux/ResearchCrux/blob/main/protocol/scitt-compat/crown-receipt.cddl).

`deterministic-dev/receipt.json` is the reviewable source for
`deterministic-dev/signed-statement.cose`. Regenerate the signed statement from
the repository root with the command below. The resulting 1,138-byte fixture's
SHA-256 is `429fcfcc9192aaed86f5215f62761b4d8540f6e3c234a3d2a108300fbf2017a4`.
The source receipt's `receiptHash` was independently recomputed with
ResearchCrux's canonical-payload and sorted-JSON rules before export.

```bash
cargo run -p corecruxctl -- receipts export-cose \
  crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/receipt.json \
  --out crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/signed-statement.cose \
  --gen-dev-key \
  --iss https://crux.local \
  --kid crux-cose-vector-v1
```

Verify it offline with the fixed development public key:

```bash
cargo run -p corecruxctl -- receipts verify-cose \
  crates/corecrux-receipts/vectors/cose-sign1-v1/deterministic-dev/signed-statement.cose
```

The deterministic development key is intentionally public test material. Never
use `--gen-dev-key` to sign production receipts; use `--key-b64` or `--key-file`
and retain the corresponding public key for offline verification.

`researchcrux-v0.2/signed-statement.cbor` is copied byte-for-byte from the
[ResearchCrux worked example](https://github.com/CueCrux/ResearchCrux/tree/main/protocol/scitt-compat/cose-example)
for protected-header decoder interop. Its SHA-256 is
`ad5ca0651c0828fedfda8ac17cf1efe7a7508a2cfaef8f86d4102a87ca461441`; its
signature uses the ResearchCrux example key and is not expected to verify with
the Crux development key.
