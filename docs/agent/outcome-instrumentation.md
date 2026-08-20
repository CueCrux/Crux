# `crux.outcome` — when a call site earns the outcome dimension

> A captured span already says whether it *failed* (`had_error`). This dimension
> says whether its work came back **empty**. It is deliberately **curated**: a
> signal that fires on healthy behaviour is noise, and noise gets ignored. This
> note is the admission bar for adding a site, the recipe for doing it, and the
> two ways to get it silently wrong. Enforcing code: `crux-observe` →
> `SpanOutcome`, `OUTCOME_FIELD`, `record_outcome`, `OutcomeExt`. Proving tests:
> `record_outcome_is_inert_when_the_span_never_declared_the_field`,
> `the_workspace_scan_loader_records_whether_it_found_anything`.
> Anchored by **symbol name**, never line number.

## Why the dimension exists

Two shipped bugs, both since fixed, both invisible to every signal the daemon had:

1. `load_latest_workspace_blocking` (`corecruxd/src/context_graph.rs`) looked the
   workspace scan up with `query:` + `top_k`, so the one fact it wanted could be
   ranked out by unrelated facts. It ran on **every** storybook generation and
   returned `None`; the storybook reported 0 LOC, 0 stubs, 0 dead code —
   indistinguishable from "no scan has ever been run". Fixed in `20ba145`,
   verified live 0 → 9151 LOC.
2. `list_dossier_ids_internal` (`corecruxd/src/http/dossier.rs`) had the same
   defect and returned **zero of eight** dossiers as a `200 OK` with an empty
   array. One of fourteen prefix scans repaired in `741562a4` (Crux#558).

Neither produced an error, a log line, or a non-zero exit. `code_intel`'s
`liveness` reported `executed: true`, which was correct and useless. `had_error`
covers the loud failure; this covers the quiet one.

## The three states

`SpanOutcome` (`crux-observe/src/span_layer.rs`):

| State | Means |
|---|---|
| `Unrecorded` | The site never declared an outcome. The `Default`, and what every pre-existing `spans.jsonl` line and every uninstrumented site reads as. **Not** a claim that work was produced. |
| `Empty` | Ran and produced nothing: `None`, an empty collection, a zero count. |
| `NonEmpty` | Ran and produced something. |

Three states rather than a `bool` is the whole point: an absent signal must not
read as a pass. Collapsing `Unrecorded` into `NonEmpty` would reproduce the exact
defect the dimension exists to catch — the same failure shape as
`chain_valid.unwrap_or(true)` (Crux#603) and the permissive `tool_tier` default
(Crux#546 / #548), all filed under `incident:2026-07-28`.

Persistence is backward compatible: `StoredSpan` (`corecruxd/src/trace_store.rs`)
flattens `SpanRecord` into `spans.jsonl` and the field is `#[serde(default)]`, so
lines written before the dimension existed load as `Unrecorded`. Capture itself
is off unless `CORECRUXD_TRACE_CAPTURE` is set (`TRACE_CAPTURE_ENV`,
`CruxSpanLayer::from_env`) — with capture off, none of this executes.

## The admission bar

> **If this site returned empty on every call, would that be a bug?**

If the answer is *no* — if there is any ordinary, healthy state of the system in
which this site correctly returns nothing — **do not instrument it**. There is no
second criterion, and "it is the same code shape as one that is instrumented" is
not one. Adding sites is a curation decision; make it deliberately, and record it
in the ExecPlan's decision log rather than in a drive-by commit.

### The curated set (complete, as of ExecPlan `crux-code-intel-silent-empty-outcomes-2026-08-03` M2)

| Symbol | File | Why empty is suspicious |
|---|---|---|
| `load_latest_workspace_blocking` | `corecruxd/src/context_graph.rs` | Bug 1 verbatim. A daemon with a workspace scan on disk must be able to read it back; always-`None` means the lookup is broken. |
| `list_dossier_ids_internal` | `corecruxd/src/http/dossier.rs` | Bug 2 verbatim — the lister that returned 0 of 8 as a `200 OK`. The caller is listing a project that has dossiers. |
| `list_storybook_versions_internal` | `corecruxd/src/http/storybook.rs` | Same defect class, same PR. Every project that has ever generated a storybook has at least one version, and here an empty list reads as "nothing generated" rather than "the read failed". |

### What was deliberately left out, and why

The other prefix scans repaired by Crux#558 share the defect class exactly and
are still **not** instrumented, because each has an ordinary healthy state in
which it correctly returns nothing:

| Left out | Healthy empty state |
|---|---|
| `extension_registry::list_extensions` | A daemon with no extensions installed — i.e. a fresh install. |
| `extension_grants::list_grants_for_extension`, `extension_grants::list_grants_for_passport` | An extension nobody has granted anything to yet; a passport holding no grants. |
| `project_repo_links::list_links` | A project with no repository linked. That is the default state. |
| `http::planes::get_plane_layers`, `http::projects::get_project_layers`, `storybook::read_project_layers`, `storybook::read_plane_layers`, `dossier::read_plane_layers` | Planes and projects carry layers only once somebody authors them. Zero layers is the starting condition, not a fault. |
| `dossier::latest_storybook_ts` | A project whose storybook has never been generated. |
| `context_graph::query_prefix`, `context_graph::count_facts_with_prefix` | Generic helpers over many prefixes. The span name is the helper's, not the caller's, so an `always_empty` reading could not be attributed to a call site — and it would be `Empty` constantly from callers for whom empty is correct. |

Instrumenting these would make `always_empty` fire on correct behaviour. That is
the failure mode that makes a gate signal worthless, and it is the same reasoning
that kept `checks_skipped` narrow in Crux#603.

## How to instrument a site

Two edits, in the same function. Both are required — see the sharp edges below.

```rust
/// Admission bar: if this returned empty on every call, that would be a bug —
/// <say why, here, in the doc comment>.
#[tracing::instrument(level = "info", skip_all, fields(crux.outcome = tracing::field::Empty))]
async fn list_dossier_ids_internal(/* … */) -> Vec<(String, u64, String)> {
    let mut out: Vec<_> = /* … */;
    out.sort_by(|a, b| b.1.cmp(&a.1));
    crux_observe::span_layer::OutcomeExt::record_outcome_through(out)
}
```

- `OutcomeExt::record_outcome_through` records the outcome and returns the value
  unchanged, so instrumenting does not mean restructuring the returns. It is
  implemented for `Option<T>`, `Vec<T>`, and `Result<T, E> where T: OutcomeExt`.
- For a `Result`, an `Err` is **not** empty — only the `Ok` payload is judged.
  `had_error` already covers failure, and conflating the two would let a loud
  failure masquerade as a silent one.
- For a shape `OutcomeExt` does not cover, call `record_outcome(is_empty)`
  directly. Note the argument is **`is_empty`**, not "did it find something":
  `record_outcome(scan.is_some())` is backwards and will report every healthy
  call as `Empty`.
- Record on **every** return path, including the not-found one. That path is the
  entire point; `load_latest_workspace_blocking` uses `and_then` rather than `?`
  precisely so the empty case still reaches the recorder.
- A stored-but-unparseable value is `Empty`, not `NonEmpty`. The caller gets
  `None` either way, and recording it non-empty because a fact happened to exist
  would put the blind spot exactly where the bug was
  (`a_corrupt_scan_fact_records_empty_not_found`).

## Sharp edge 1 — declaring the helper without declaring the field records nothing, silently

`record_outcome` is `Span::current().record(OUTCOME_FIELD, …)`. `tracing`
dispatches a record only for a field present in the span's metadata, so a span
that never declared `fields(crux.outcome = tracing::field::Empty)` **discards the
value with no error, no warning, and no panic**. The site then reads
`Unrecorded` forever — which looks exactly like a site nobody instrumented.

That property is also what keeps the cost off every other span: an uninstrumented
span cannot reach `CruxSpanLayer::on_record` at all. It is a deliberate
trade-off, not an oversight, and it is pinned by
`record_outcome_is_inert_when_the_span_never_declared_the_field`.

**The mitigation is the test.** Every curated site has one that asserts `Empty`
on the empty path and `NonEmpty` on the full one, in order. Drop the `fields(…)`
clause and both observations read `Unrecorded` and the test fails, instead of the
signal going quiet in production. A new site is not instrumented until it has
that test.

## Sharp edge 2 — `Unrecorded` is not `NonEmpty`

An absent signal is not a pass. When reading the dimension back:

- `Unrecorded` means **nobody spoke**. It carries no information about whether
  work was produced. Today it is the value on the overwhelming majority of spans,
  because only three sites are instrumented and every historical `spans.jsonl`
  line predates the field.
- Never infer health from the absence of `Empty`. Use `SpanOutcome::is_recorded`
  to ask whether a site spoke at all before reading what it said, and
  `SpanOutcome::is_empty_result`, which is `true` only for `Empty`.
- Any aggregate must count `Unrecorded` separately and must refuse to conclude
  anything from a set that contains one.

## Reading it back

`spans.jsonl` carries the raw value per span. The reader-facing surface is
`code_intel`'s `liveness` (`GET /v1/code-intel/liveness`, admin-read; MCP
`code_liveness`), which is being extended by milestone M3 of the same ExecPlan —
`executions_empty`, `executions_outcome_unrecorded`, and a conservative
`always_empty` that is false on zero executions and false when *any* execution is
unrecorded. That work is in review as CueCrux/Crux#730 and is **not on `main`
yet**; until it lands, read the field off the span records directly. The
`verdict` string is not changed by any of this — it is a stable contract other
tools match on, and the new data is read from explicit fields instead.

## Testing a new site

Use `corecruxd/src/span_capture_test_support.rs`: `capture_spans` (sync),
`capture_spans_async` (async body, driven on the calling thread), and
`outcomes_of(&spans, "<span name>")`, which yields `Unrecorded` for a site that
declared nothing rather than omitting it.

Two things that look optional and are not:

- **Drive the real handler, not the internal function**, where one exists. These
  listers' emptiness is partly a function of tenant scope, and a test that
  bypasses scope resolution proves less than it appears to.
- **Assert the count first.** `assert_eq!(body["count"], 0)` before the outcome
  assertion, so a green `Empty` cannot be reading a case that was empty for an
  unrelated reason.

The capture subscriber is installed **once, globally**, for a reason documented
at length in that module: `tracing` caches callsite `Interest` process-wide, so a
scoped subscriber lets an unrelated test on another thread cache an instrumented
callsite as "nothing is interested" — after which the span is never built and the
assertion reads "the site recorded nothing". Do not replace it with
`tracing::subscriber::with_default`.

## Checklist before adding a site

1. Answer the admission bar out loud, in the function's doc comment: *if this
   returned empty on every call, would that be a bug?* If there is a healthy
   empty state, stop.
2. Add `fields(crux.outcome = tracing::field::Empty)` to the `#[tracing::instrument]`.
3. Record on every return path, `is_empty` semantics, `Err` is not empty.
4. Add a capture test covering both paths, count asserted before outcome.
5. Record the admission in the owning ExecPlan's decision log, and add the new
   symbol and test to `docs/agent/repo-manifest.yaml` → `ci_assertions`.
