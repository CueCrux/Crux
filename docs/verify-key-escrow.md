# Verify for yourself that we cannot read your vault

Most products ask you to believe a sentence like *"your data is encrypted and we cannot
access it"*. This page instead tells you exactly what the server stores, and gives you two
independent tools to check that what it stores cannot open your vault.

You should not have to trust us. You should be able to check.

## What the server stores

Exactly three fields, and nothing else:

```json
{
  "vault_id": "my-vault",
  "nonce": [24 bytes],
  "ciphertext": [48 bytes]
}
```

- **`vault_id`** — the name you chose. Not secret. It is bound to the ciphertext as
  authenticated data, so a blob moved to another vault stops decrypting.
- **`nonce`** — 24 random bytes, fresh for every wrap. A nonce is not a key and not a
  secret; it exists so that encrypting the same thing twice does not produce the same
  output.
- **`ciphertext`** — your 32-byte data encryption key, sealed under a 16-byte
  authentication tag. 48 bytes total. There is no room in it for anything else, and the
  verification below checks that length precisely.

There is no fourth field. No password hint, no salt, no key-derivation parameter, no
"account recovery" record. **The server holds no input to your key**, which is why it
cannot compute your key no matter how it is asked.

## How your key is actually protected

At setup your client generates a **recovery code**: 256 bits from a cryptographically
secure random number generator, shown to you once, in nine groups of six characters.

```
wrapping key = BLAKE3-derive-key(context, your recovery code)
ciphertext   = XChaCha20-Poly1305(wrapping key, nonce, your key, aad = vault_id)
```

Both the algorithm and the context string are published — you will find the context string
in [`crates/crux-escrow/src/lib.rs`](../crates/crux-escrow/src/lib.rs) and repeated in the
verification script. That is deliberate: you can only reproduce our checks if we tell you
exactly how the key is derived. Publishing the method is what makes the claim testable.
The **only** secret is your recovery code, and it never reaches us.

## Check it yourself

Two implementations. They print the same lines, so you can run both and compare.

**The readable one.** About 120 lines of Python, no dependency on anything we ship. Read it
first — that is the point of it.

```bash
pip install pynacl blake3
python3 scripts/verify-escrow.py --vault-id my-vault --token "$CORECRUXD_TOKEN"
```

**The one that ships with the daemon.**

```bash
corecruxctl verify-escrow --vault-id my-vault
```

Both print:

```
vault my-vault on http://127.0.0.1:14800
  PASS the server stores exactly ciphertext, nonce, vault_id, and nothing else
  PASS the stored ciphertext is 48 bytes: a 32-byte key under a 16-byte tag, with no room for anything else
  PASS a key derived from the vault id did not open the vault
  PASS a key derived from the stored nonce did not open the vault
  PASS a key derived from the stored ciphertext did not open the vault
  PASS a key derived from the whole stored record did not open the vault
  PASS a key derived from an empty secret did not open the vault
  PASS a key derived from the published KDF context itself did not open the vault

All checks passed: the server holds ciphertext and nothing that opens it.
```

The interesting checks are the middle ones. It is not news that a *random* key fails to
decrypt something. What those lines do is take **every field the server actually holds**,
run each one through the published key derivation, and show that none of them opens the
vault. If the server had quietly kept any input to your real key, one of those attempts —
or an obvious variation you can add yourself, in a script you can edit — would succeed.

These checks need **no secret from you**. You never type your recovery code to run them.

### The positive control

"Nothing opens the vault" would also be true if the server had stored garbage. So both
tools take an optional flag that proves the blob is genuinely yours:

```bash
corecruxctl verify-escrow --vault-id my-vault --with-recovery-code
```

It reads your recovery code from standard input — never from the command line, because
command-line arguments are visible to every process on the machine via `ps` and are
recorded in shell history. The code is used in that process, on your machine, and is not
sent anywhere. You can confirm that in the source of either tool.

### If the two tools disagree

Tell us. Two implementations that agree are evidence; two that disagree is a finding, and
we would rather hear it from you than not hear it. A test in our CI runs both on identical
records and fails the build if their verdicts differ, or if the reference script cannot be
run at all
([`crates/crux-escrow/tests/python_reference_agrees.rs`](../crates/crux-escrow/tests/python_reference_agrees.rs)),
but a test we wrote is not a substitute for a check you ran.

## What this page does not claim

Being precise about the edges is the point of publishing at all.

- **This proves a property of the stored record, not a promise about our conduct.** It
  shows the blob cannot be opened with what the server holds. It does not, and cannot,
  prove that a future version will not store something more. That is what re-running the
  check is for — it takes a second, and you can put it in a cron job.
- **Shamir escrow is not live yet.** The design splits a wrapping key into three shares,
  one of which we would hold, so that losing your recovery code is survivable. It is
  designed and implemented, but **no share custody service exists**, so today there is
  nothing of yours in our custody at all. When it ships, this page will be updated and the
  checks extended. Until then, treat any claim about 2-of-3 escrow as future tense.
- **Release notifications are not delivered.** The design says every registered device is
  told when someone asks for a custodian share. The record of that notification exists in
  your receipt timeline; the delivery mechanism does not exist yet. Do not rely on being
  notified.
- **There is no public demo vault yet.** You verify against the daemon you run. A vault
  anyone can attack, hosted by us, is more convincing to a stranger and we intend to
  publish one once there is a hosted surface to put it on.
- **We can be compelled, and it would not help.** A court can order us to hand over
  everything we hold for your vault. Everything we hold is on this page. It does not open
  your vault, which is the honest answer, and it is the reason the design is arranged this
  way.

## Losing your recovery code

If you lose your recovery code today, **your vault is not recoverable**. Not by you, not by
us, not by support.

This is a design decision, not a gap we intend to close. The only way to make that case
recoverable is for our own holdings to be sufficient to reconstruct your key — and a
server that can recover your data on request is a server that can be compelled, breached,
or mistaken into doing so for someone else. We would rather lose the rare vault than build
the thing that loses all of them at once.

Print your recovery code. Put it somewhere you would keep a passport.

## Related

- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) § "Key Escrow and Recovery" — the adversary
  model, including what we do **not** defend against.
- [`crates/crux-escrow/`](../crates/crux-escrow/) — the implementation, Apache-2.0, with
  the tests that pin these properties.
