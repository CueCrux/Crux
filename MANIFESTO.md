# Receipts Over Vibes
## The Crux Daemon Manifesto

> Adapted from [`PlanCrux/docs/manifesto/Crux-Manifesto-v2.2.md`](https://github.com/CueCrux/PlanCrux/blob/main/docs/manifesto/Crux-Manifesto-v2.2.md), scoped to what the Crux Daemon itself ships. The canonical, portfolio-wide manifesto lives in PlanCrux.

---

## The Problem Nobody Names Correctly

Every team has a filing cabinet problem.

Code lives in GitHub. Decisions live in pages nobody updates. The reasoning behind those decisions — the *why* — lives in chat threads that scrolled past eighteen months ago, in design reviews attended by three people, two of whom have since left.

The information exists. That's not the problem.

The problem is the synthesis layer. Today, that layer is human brains. Bandwidth-limited, context-switching-impaired, and available only until a better offer comes along. When a senior engineer quits, the filing cabinets are still full. What's gone is the person who knew which ones to open — and how to connect what was inside them into something that actually led to a decision.

Every team is one resignation away from institutional amnesia.

---

## What Everyone Is Getting Wrong

The response to this so far has been bigger models and longer context windows.

That is the wrong answer. A trillion tokens of organisational history fed to a model without rigorous retrieval isn't institutional memory. It is an institutional hallucination system: confident synthesis from the wrong evidence, the right-sounding answer drawn from a context that no longer applies, a thread from before the architectural pivot that looks relevant because the vocabulary matches.

A context platform that accumulates without receipts doesn't compound in value over time. It compounds in liability. Every confident wrong synthesis from stale evidence is a decision made on false premises. Every answer the platform produces from superseded context is a step toward a conclusion that cannot be defended. And it gets *worse*, not better, as the corpus grows — because a larger corpus means more opportunities for near-miss retrieval and more surface area for confident hallucination.

The question is not *how much* context your system can hold. The question is *whether you can trust what it retrieves* — and whether you can prove it.

---

## The Crux Answer

The Crux Daemon is built from a single, non-negotiable premise:

**Every answer must be provable. Every retrieval must be receipted. Every piece of context must carry evidence of when it was retrieved, from what, under what conditions — cryptographically signed and verifiable.**

This is not a compliance feature bolted on after the fact. It is the architecture. **CROWN receipts** — BLAKE3 hash chains with ed25519 signatures — mean that every answer the daemon produces carries an immutable record of the evidence that produced it. Not a citation. Not a link. A cryptographic receipt that proves the evidence was current, the retrieval was legitimate, and the synthesis followed from the evidence actually retrieved.

A receipt that only the issuer can verify is a vendor claim. CROWN receipts are designed as an open, independently verifiable format — readable and checkable without any Crux infrastructure. That is what makes them proof rather than marketing.

---

## What Proof Means in Software

Most systems treat proof as a citation problem — a link to a document, a reference to a source. In a knowledge-management context that is partially sufficient. In a software context it is not even close.

A claim about code is not proven until it is anchored to a repository state and an execution trace. The question "why did we build it this way?" is not answered by a wiki page. It is answered by the commit that introduced the pattern, the test run that validated it, the security scan that cleared it, and the dependency lock that fixed its constraints at the time. These are not supplementary context. They are the evidence. Everything else is commentary.

The Crux Daemon treats software artefacts as first-class evidence: commit hashes and diffs as proof of state, test outputs and build results as proof of execution, security scan results as proof of clearance, toolchain versions and dependency locks as proof of environment. A receipt for a software decision is not complete unless it anchors to all three — what the code was, what ran against it, and what environment it ran in.

Citations are easy. Proof-carrying software work is the hard problem, and it is the one that matters.

---

## Agents May Propose. Only Receipts May Approve.

Agentic systems are not a future capability. They are a present operational reality — writing code, opening pull requests, running commands, calling external services, modifying infrastructure. And as their capabilities expand, so does their attack surface.

The risk is not theoretical. Extension supply chains can be compromised. Prompt injection can redirect agent behaviour mid-execution. Autonomous tools operating with broad permissions and no verifiable audit trail create exactly the kind of unattributable, unreplayable failure mode that security teams cannot investigate after the fact.

The Crux Daemon's approach to agent execution rests on three non-negotiable principles:

**Least privilege by default.** Agents operate with the minimum capability required for the declared task. Network access, file system access, and secret use are explicit grants, not ambient permissions.

**Receipts gate execution, not just record it.** Agents may propose changes. They may draft pull requests, suggest configuration updates, recommend architectural decisions. But state-changing execution — anything that modifies code, infrastructure, or data — requires a cryptographically receipted approval before it proceeds. Proposals are cheap. Approvals are on the record.

**Everything is auditable, including the agent itself.** The commands an agent ran, the tools it invoked, the context it was given, the approvals it received — all of it is append-only, hash-chained, and replayable. If something goes wrong, you can reconstruct exactly what the agent knew, what it was authorised to do, and what it actually did. No ambiguity. No attribution gap.

The default posture is least privilege, local when sensitive, and always auditable. This is not a constraint on what agents can accomplish. It is the foundation that makes autonomous execution trustworthy enough to operate at scale.

---

## Local-First, By Design

Every major platform building toward enterprise context accumulation assumes cloud deployment. For a large and systematically underserved segment of regulated and security-conscious teams — financial services, government, defence, healthcare, legal practices with client confidentiality requirements — that pitch is structurally inaccessible. The most sensitive organisational knowledge these teams hold is precisely the knowledge they cannot send to any third-party provider, regardless of the contract terms.

The Crux Daemon runs within your boundary. Free-tier operation is local-first, CPU-only, accountless, and offline-capable. Wire egress is capability-token gated. Local documents remain on the daemon unless a token explicitly authorises the relevant data class. Every call produces a receipt with the token-selected receipt class. Community mods cannot bypass token policy.

The receipts remain independently verifiable — cryptographic proof of what the system knew, what it retrieved, and what it concluded, without requiring any content to cross an organisational perimeter.

This is not a concession to IT preferences. It is the only architecture that works for a substantial portion of the market the cloud-first context race is, by design, unable to serve.

---

## Receipts Over Vibes

Most of the AI tooling market is running a race to accumulate context. Most players are betting that scale wins — more tokens, more infrastructure, more context captured.

The Crux Daemon is built on a different bet:

A context system without measurable context quality is not a neutral asset that compounds over time. It is a liability that compounds over time. The synthesis layer that cannot prove what it retrieved, cannot demonstrate that its context was current, and cannot produce a verifiable audit trail for its conclusions is not building institutional memory. It is building institutional confidence that will fail at the worst possible moment.

The Crux Daemon is built on the premise that every claim requires a receipt. Not a citation. Not a confidence score. A cryptographic proof that the evidence was current, the retrieval was correct, and the synthesis followed from what was actually found.

**Receipts over vibes.**

That is what this daemon is. The broader CueCrux portfolio (WatchCrux for confidence drift, MiSES for minimal-sufficient-evidence framing, the Private Knowledge Plane, and the cloud-managed control plane) extends this premise to higher-level workflows. The premise itself — and the open, source-available, on-prem-deployable receipt engine — lives here.

---

*The Crux Daemon is source-available under the [CueCrux Community Licence](LICENCE.md) (CCL v1.0). The canonical portfolio-wide manifesto, vision, and roadmap live in [PlanCrux](https://github.com/CueCrux/PlanCrux).*
