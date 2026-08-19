# Work-gate oversight — adversarial pass (M5)

Adversarial review of the gate-resolution path shipped in #707, #708 and #709.
Milestone M5 of ExecPlan `gate-oversight-across-deployment-postures-2026-08-18`.
Every attack below is either refused with a named test, or written up here as an
accepted risk. Nothing is dressed as a refusal that is not one.

## Finding A — an approver could grant scopes it did not hold (**fixed here**)

**Severity: high. Live on `main` before this change.**

`POST /v1/auth/device/approve` required `admin:write` and then granted whatever
scopes the request named. The module contract claimed otherwise:

> the issued `tenant_id` + scopes are a concrete subset of the authenticated
> approver's verified grants, never authority supplied by the polling client or
> approval form.

Nothing enforced it, and `missing_scopes` is exact-match — there is no scope
hierarchy, so `admin:write` does **not** imply `facts:write`. An approver
holding only `admin:write` could therefore mint a device credential carrying
authority it never had.

M1 widened the blast radius: with `bind_passport`, such a credential also
carries a canonical passport, so it can resolve work gates — the Art.14
boundary this whole line of work exists to protect.

**Fixed:** approve now refuses any scope the approver does not hold, naming the
offending scopes. Test `attack_device_approve_cannot_grant_scopes_the_approver_lacks`,
positive-controlled (without the fix, the escalating call passes attenuation and
reaches the `user_code` lookup instead of a 403).

> **Overlap:** a fuller `attenuate_device_grant` — adding tenant hardening and a
> stricter approver check — exists on the unmerged branch
> `codex/crux-red-steel-remediation-2026-07-30`. This change is deliberately the
> minimal containment fix so the live escalation does not wait on that branch;
> whoever merges should resolve to the fuller version and drop this one.

## Attacks refused, with tests

| attack | outcome | test |
|---|---|---|
| Replay a captured rail token after its TTL | refused — `exp` validated with 30s leeway | `attack_replay_after_ttl_is_refused` |
| Present a token minted by another issuer/audience | refused — `iss`/`aud` pinned | `attack_token_minted_for_another_audience_is_refused` |
| Use a gate-resolution token on an admin route | refused — exact scope match, no implied hierarchy | `attack_gate_token_cannot_reach_an_admin_route` |
| Resolve a gate whose work item is in another tenant | refused — `TENANT_FORBIDDEN` | `attack_cross_tenant_resolution_is_refused` |
| Override a rail token's identity with a passport header | refused — `PASSPORT_HEADER_MISMATCH`, and gate resolution independently refuses any context where an override was used | `attack_passport_header_cannot_override_a_rail_tokens_identity` |
| Spoof the identity header from a non-trusted peer | refused — loopback-or-listed-CIDR only, fail-closed on absent peer | `non_loopback_peer_untrusted_without_cidr`, `missing_peer_fails_closed` |
| Bind a passport using an agent token or a passport-header override | refused with a named reason | guards in `post_device_approve` |
| Resolve a gate with an unbound (`passport_id: None`) rail token | refused — canonical claim required | `a_rail_minted_token_without_a_passport_still_cannot_resolve_a_gate` |
| Enumerate another tenant's pending gates as an unverified remote reader | refused — narrowing keyed on reachability | `daemon.rs` proxied-read guard (#707) |

## Accepted risks — attacks that succeed by design

These are **not** refused. They are recorded so the operator decides, rather
than being hidden behind a test that asserts something weaker.

### R1 — a rail token is replayable within its TTL

It is a bearer token. Anyone who captures one inside its **300-second** life can
use it. There is no proof-of-possession, no nonce, no single-use binding.

The mitigation is the TTL and nothing else. That is a deliberate trade — the
alternative (DPoP-style proof-of-possession) is a much larger contract change
across every client. **Consequence:** treat a rail token like a password with a
five-minute life; do not log it, do not put it in a URL.

### R2 — non-self-review is defeated by one human holding two passports

`resolve_gate_http` compares the requesting passport with the approving one. A
single person controlling two passports can request as one and approve as the
other, and every check passes. The receipt is honest about *which passports*
acted; it cannot know they are the same person.

Closing this needs an identity-linking notion the substrate does not have — the
candidate-links surface (`/v1/identity/candidates`) proposes such links but
deliberately never resolves them without operator confirmation. **This is an
operator-signed accepted risk, not a defect to fix in this plan.**

### R3 — `bind_passport` on someone else's device grants them your identity — **DECIDED 2026-08-19, conditional**

**Resolution, in three parts:**

1. **Shipped now.** Lending is a *fallback*, never a feature. Where a stronger
   rung can name the device's own human, `bind_passport` is **refused** — the
   device user must arrive as themselves. A stronger rung that is configured but
   *unusable* also refuses, matching the ladder's no-silent-downgrade rule: a
   misconfigured identity rail must surface, not become a licence to lend.
2. **On SSO landing** (`cross-site-auth-sso-cuecrux-2026-07-13`, currently M0
   done / M1–M5 not started, `app.cuecrux.com` dark): the hosted posture stops
   using `bind_passport` at all, because the issuer can name each human.
3. **Residual, accepted and named:** self-hosted **and** multi-human **and** no
   proxy **and** no SSO. That quadrant keeps the original exposure. On a *solo*
   deployment lending to your own second machine is correct behaviour — see the
   approver-count policy — so the risk is one specific configuration, not a
   general hole.

> **The subscription tier gates SSO, not this.** An entitlement check controls
> feature *availability*, not a security property; a free self-hosted deployment
> would keep the full exposure. Self-hosters with no proxy and no VPN are exactly
> the audience OD-57 optimised for when Tailscale-only was rejected, so part 1
> deliberately requires no tier, no SSO and no infrastructure.

Original statement of the risk follows.

#### As originally found

The device grant binds *the approving admin's own* passport, which is what makes
it safe against impersonation-by-admin. But an admin who ticks it while
approving **someone else's** machine hands that person their approver identity,
and every approval that device makes is attributed to the admin.

No mechanism can distinguish "my second laptop" from "a colleague's laptop" —
the whole premise of the device grant is that the approver vouches. The
mitigation is the `/activate` label, which states it plainly: *"Only tick this
for a machine you control: it acts with your approver identity, and every
approval it makes is attributed to you."*

### R4 — a proxy that forwards rather than overwrites the identity header

Covered at length in `docs/agent-guide.md` and `config.example.env`. A trusted
CIDR proves the proxy *sent* the request, not that it *authored* the header. The
daemon cannot verify the proxy's own configuration. Where strip-then-set cannot
be guaranteed, use the device grant, which takes identity from an approver
rather than a header.

## Verdict

One finding fixed (A). Four accepted risks recorded (R1–R4), of which R2 and R3
want an explicit operator decision before a production enable, per the
`eu-ai-act` profile's human-gate requirement.
