+++
name = "code-minimalism"
version = 1
description = "Write the least code that actually works. Ladder of cheaper alternatives checked before writing, with safety carve-outs. Measured on frontier models: -70% LOC on Opus, no correctness regression (AuditCrux benchmarks/ponytail, corpus ponytail-fastapi-cd83fc1)."
targets = ["claude_md", "agents_md"]
order = 41
risk_class = "low"
+++

## Code Minimalism

The cheapest code to maintain is the code that was never written. This profile governs **how much
code you write**, not how you talk — it pairs with `code-grounding` (which governs whether your
claims are true) and `token-conservation` (which governs response length).

### Why this is on

Measured on this workspace's own benchmark (`AuditCrux/benchmarks/ponytail`, corpus
`ponytail-fastapi-cd83fc1`, 12 real-repo feature tasks, n=2, both arms correct 1.00):

| model | code written vs unconstrained | wall-clock |
|---|--:|--:|
| Sonnet-4-6 | −48% | −35% |
| Fable-5 | −58% | −36% |
| Opus-4.8 | **−70%** | **−55%** |

The effect **scales with model capability**: left unconstrained, stronger models over-build *more*
(pooled baseline 1566 LOC on Sonnet → 2242 on Opus for identical tasks), while constrained output
converges (~680–815 LOC). So this discipline matters **most** on the strongest models, not least.

### The ladder

Understand the problem first, then take the highest rung that actually holds:

1. **Does it need to exist?** Speculative need — a feature nobody asked for, a hook for a future that
   may not arrive — is not built. Say in one line that you skipped it.
2. **Does it already exist here?** Grep before you write. Re-implementing a helper that lives three
   files over is the most common form of waste.
3. **Does the standard library do it?** Use it.
4. **Does the platform do it?** A native input type, a CSS rule, a DB constraint — prefer it over
   hand-rolled application code.
5. **Does an already-installed dependency do it?** Use it. Do not add a new dependency for something
   a few lines cover.
6. **Can it be one line?** Then it is one line.
7. **Otherwise:** the minimum code that works.

The ladder shortens the **solution**, never the **reading**. Trace the real flow — every file the
change touches — before choosing a rung. A small diff in the wrong place is not minimal, it is a
second bug wearing a disguise.

### Root cause, not symptom

A bug report names a symptom. Before editing, check every caller of the function you are about to
touch. One guard in the shared function is both the smaller diff and the correct fix; patching only
the path the ticket names leaves every sibling caller broken.

### Never minimise away

These are not negotiable and are never traded for a shorter diff:

- Input validation at trust boundaries.
- Error handling that prevents data loss.
- Security controls and authorisation checks.
- Accessibility basics.
- Anything the user explicitly asked for. If they want the full version, build it — do not re-argue.

Per `eu-ai-act` and `pre-deploy-gate`, minimalism never overrides a required gate, receipt, or
passport attribution.

### Leave the check

Non-trivial logic (a branch, a loop, a parser, a money or auth path) leaves **one** runnable check
behind — the smallest thing that fails if the logic breaks. A `__main__`/`demo()` assert block or one
small test. No frameworks, no fixtures, no per-function suites unless asked. Trivial one-liners need
no test; YAGNI applies to tests too.

### Name the shortcut

A deliberate simplification with a known ceiling (a global lock, an O(n²) scan, a naive heuristic)
carries a `crux-min:` comment naming the ceiling and the upgrade trigger:

```python
# crux-min: global lock; per-account locks if throughput becomes the bottleneck
```

These are harvestable — the comment is the debt ledger. An unmarked shortcut is not minimalism, it is
a landmine.

### What this trades

Minimalism buys smaller diffs with **more reading**. Expect input/read tokens to rise while written
lines fall — in our benchmark, token savings were real but *secondary and variable* (−19% to −49%
depending on model), while the code-volume saving was consistent. **Optimise for less code, not fewer
tokens**; the token saving is a side effect and on some tasks it does not appear at all.

---

*Lineage: independently implements the "laziness ladder" pattern popularised by the MIT-licensed
[Ponytail](https://github.com/DietrichGebert/ponytail) skill. Text here is original; the measurements
above are this workspace's own replay (`AuditCrux/benchmarks/ponytail`), not upstream's figures.*
