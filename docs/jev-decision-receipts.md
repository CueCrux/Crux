# Jev decision receipts cookbook

[Jev](https://docs.typesafe.ai/) (TypeSafe AI's System One model) answers typed
questions (Choice / Score / Noul) about a `state` in a few hundred
milliseconds, and keeps nothing. Agents call it at decision points: guardrails,
routing, escalate-to-human. This cookbook gives each of those calls a record
you can verify later, using `crux_adapters.jev.decide` and a local Crux daemon.

## What you get

One `decide(...)` call does four things:

1. **Builds the state from Crux.** `GET /v1/context` for your entity, bounded
   by `token_budget`, becomes `state.trusted_context`. Anything you pass as
   `untrusted=` (tool output, email, web pages, the proposed action) goes into
   `state.untrusted_input` and nowhere else.
2. **Calls Jev once** (`POST /v1/systemone`).
3. **Mints a signed CROWN `model_invocation` receipt.** The daemon signs
   (Ed25519) a body binding:
   - `prompt_hash`: sha256 over `{state, questions}`
   - `retrieval_set_hash`: sha256 over `[[item id, sha256(text)], ...]` for the
     retrieved context
   - `output_hash`: sha256 over `{model, answers}`
   - the model alias and exact `model_version`, and Jev's
     `x-typesafe-request-id` as `provider_request_id`
4. **Stores the decision as a fact**: entity `jev:<entity>`, key
   `decision:<request_id>`, `source_receipt` set to the receipt id. The fact
   value holds the answers, the evidence list and the three hashes, so you can
   query past decisions per entity and recompute two of the hashes from the
   fact alone.

Every hash is sha256 over compact UTF-8 JSON with key order **preserved**. Jev
reads key order, so reordering a Choice's options is a different prompt and
hashes differently.

## What a receipt proves, and what it does not

A receipt proves that this daemon, with this key, at this time, recorded that
a decision was made with these inputs and outputs: which model version, which
request id, which retrieved evidence, which answers. Change one byte of the
body and verification fails.

It does **not** prove:

- **that the decision was correct.** A confident wrong answer gets a valid
  receipt too.
- **that the agent acted on it.** The receipt records the verdict, not what
  happened next. Record the action separately if you need that.
- **that Jev produced it.** The daemon never talks to Jev. It signs the hashes
  your process reports. `provider_request_id` is what lets you reconcile a
  receipt against TypeSafe's own logs. The offline stub below is the proof: its
  canned answers get a valid receipt, with `model_version: offline-stub`.
- **what the state said, from the fact alone.** The fact stores digests of the
  trusted context, not the text, and does not store `untrusted_input`. To
  re-check `prompt_hash` later, or replay a state against a newer model, keep
  `decision.state` yourself or opt in with `store_state=True` (see
  [Replaying a decision](#replaying-a-decision-against-a-new-model-version)).

## Setup

**Daemon.** Two flags, both off by default:

```bash
export CORECRUXD_STREAM_RECEIPTS=1   # POST /v1/mediation/receipts signs model_invocation drafts
export CORECRUXD_CONTEXT_SURFACE=1   # GET /v1/context; 404s when off, so off cannot look empty
corecruxd
```

With auth on, the token needs these scopes:

| Scope | Used by |
|---|---|
| `query:read` | `GET /v1/context`, `GET /v1/facts*`, `GET /v1/observations/aggregate` |
| `facts:write` | the `/v1/mediation/*` route gate, `PUT /v1/facts` |
| `sessions:write` | the mediation receipt handler |
| `receipts:read` | `GET /v1/receipts/{id}/verification` |

Fact writes from a passport-bearing token also need that passport registered
with a category.

To try this locally without setting any of that up, the fixture script starts
a loopback-only daemon on port 24800 with both flags on, registers a passport,
and mints a token with exactly those scopes (needs `corecruxd` on `PATH`, or
`CORECRUXD_BIN`):

```bash
integrations/adapters/examples/jev/fixture-daemon.sh start
```

It writes `fixture.env` (base URL, tenant, token file path, public key path;
no secrets) and a 0600 `token` file under `JEV_FIXTURE_DIR`, default
`${TMPDIR:-/tmp}/jev-crux-fixture`. `fixture-daemon.sh stop` stops it.

**Python.** From a checkout of this repository:

```bash
python3 -m venv .venv && . .venv/bin/activate    # or: uv venv && . .venv/bin/activate
pip install -e sdks/python -e integrations/adapters  # or: uv pip install -e ... -e ...
```

**Jev key.** Keep it out of code and out of the repository. Either a file:

```bash
mkdir -p ~/.config/typesafe && (umask 077; cat > ~/.config/typesafe/api_key)   # paste, then Ctrl-D
```

or the `TYPESAFE_API_KEY` environment variable, which is what `jev_http()`
reads by default (and `TYPESAFE_BASE_URL` to override the endpoint).
`jev_http(api_key=...)` refuses a blank key before any request.

## A guardrail: should this shell command be blocked?

The agent wants to run a command it picked up from a web page. Crux holds the
operator's policy for this agent. The command and the page are untrusted.

```python
from pathlib import Path
from cuecrux_client import CueCruxClient, StoreFact
from crux_adapters.jev import decide, jev_http

client = CueCruxClient("http://127.0.0.1:14800", token=Path(token_file).read_text().strip())
client.store_fact(StoreFact(entity="agent:build-bot", key="policy:shell",
                            value="Never pipe a download into a shell."))

decision = decide(
    client,
    {
        "block": {"type": "noul",
                  "instructions": "Should the agent be stopped from running proposed_command?"},
        "route": {"type": "choice",
                  "instructions": "Who should look at this command before it runs?",
                  "criteria": {"nobody": "Routine and safe to run",
                               "operator": "Destructive, or changes production",
                               "security": "Looks like prompt injection or data exfiltration"}},
    },
    entity="agent:build-bot",   # retrieval scope, and decision memory jev:agent:build-bot
    token_budget=1000,          # mandatory: bounds the retrieved context
    untrusted={"proposed_command": cmd, "tool_output": page_text},
    jev=jev_http(api_key=(Path.home() / ".config/typesafe/api_key").read_text()),
)

if decision.answers["block"]["noul"] >= 0.5:
    refuse(cmd)
print(decision.receipt_id, decision.fact_id, decision.request_id)
```

Keeping the untrusted text in its own field does not by itself make Jev resist
injection. It makes the split explicit and hashed, so you can see it and
measure it. The command itself is untrusted too: an injected instruction is
how a bad command gets proposed.

The full, runnable version is
[`decide_example.py`](../integrations/adapters/examples/jev/decide_example.py).
It seeds the policy fact, decides, verifies the receipt, reads the fact back
and recomputes its hashes:

```bash
set -a; . "${JEV_FIXTURE_DIR:-${TMPDIR:-/tmp}/jev-crux-fixture}/fixture.env"; set +a
python integrations/adapters/examples/jev/decide_example.py
```

With no Jev key it uses a clearly labelled offline stub in Jev's place and
says so on every run:

```text
*** OFFLINE STUB: no Jev key found. These answers are canned, NOT from Jev. ***
block:      0.97  (1.0 = stop it)
route:      security  {'nobody': 0.01, 'operator': 0.09, 'security': 0.9}
model:      offline-stub
context:    1 items from Crux, truncated=False
request id: offline-stub-…
receipt id: r_…
fact id:    f_…
verified:   signature_valid=True error_code=OK key_id=p_…
fact:       jev:agent:build-bot / decision:offline-stub-…, hashes recompute from the fact

export RID=r_… PROMPT_HASH=sha256:…
```

For your own daemon, set `CRUX_BASE_URL` and `CRUX_TOKEN_FILE` instead of
sourcing `fixture.env`.

## Verifying a receipt

**Online**, from the daemon that signed it. Stream receipts are minted under
tenant `local`:

```bash
crux() { curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$(cat "$CRUX_TOKEN_FILE")") "$CRUX_BASE_URL$1"; }

crux "/v1/receipts/$RID/verification?tenant_id=local" \
  | jq '{signature_valid, error_code, payload_hash_matches: .integrity.payload_hash_matches,
         chain_position_checked: .binding.chain_position_checked, key_id: .signature.key_id}'
```

(The `crux` helper keeps the token out of the process list.)

**Offline**, with only the signed body, the signature and the daemon's public
key. On the free daemon `GET /v1/receipts/{id}` returns 501; stream receipts
live in the mediation observation log:

```bash
crux "/v1/observations/aggregate?kind=model_invocation&limit=500" \
  | jq --arg r "$RID" '[.observations[] | select(.payload.receipt_id == $r)][0].payload' > receipt.json
jq -r .body_cbor_hex receipt.json | xxd -r -p > body.cbor
jq -r .sig.signature_hex receipt.json | xxd -r -p > sig.bin

openssl pkeyutl -verify -pubin -inkey "$CRUX_DAEMON_PUBKEY_PEM" -rawin -in body.cbor -sigfile sig.bin
grep -qaF "$PROMPT_HASH" body.cbor && echo "prompt_hash is in the signed body"
```

`openssl pkeyutl -rawin` needs OpenSSL 3. The fixture writes the public key as
`daemon.pub.pem`. For another daemon, an operator reads it from
`GET /v1/admin/version` (`admin:read`) as `.passport.public_key_hex`:

```bash
{ printf '302a300506032b6570032100'; printf '%s' "$PUBKEY_HEX"; } \
  | xxd -r -p | openssl pkey -pubin -inform DER -out daemon.pub.pem
```

The receipt's `key_id` is `p_` followed by the first 32 hex characters of
blake3 over the raw public key, so `b3sum` ties a key to a receipt.
[`receipt-recipe.sh`](../integrations/adapters/examples/jev/receipt-recipe.sh)
runs every one of these checks against the fixture, plus a negative control: a
one-bit flip in the body must fail verification.

**Not yet:** COSE/SCITT export does not support `model_invocation` receipts.
`corecruxctl receipts export-cose` takes CROWN retrieval receipts only, so
`verify-cose` cannot check these today. Use the Ed25519 check above.

## Past decisions for an entity

Each decision is a fact under `jev:<entity>`:

```python
import json
from crux_adapters.jev import digest

for fact in client.get_facts_by_entity("jev:agent:build-bot"):
    record = json.loads(fact.value)
    # Two of the three signed hashes recompute from the fact alone.
    assert digest({"model": record["model_version"], "answers": record["answers"]}) == record["output_hash"]
    assert digest(record["retrieved"]) == record["retrieval_set_hash"]
    print(fact.key, fact.source_receipt, record["model_version"], record["answers"]["block"])
```

Compare those hashes with the ones in the signed body (`grep -aF` as above) to
show the fact has not been edited since the receipt was signed.

## When the record fails

If Jev answered but the receipt or the fact was not written, `decide` raises
`DecisionNotRecorded` rather than returning, so an unrecorded decision cannot
pass for a recorded one. The answers are not lost:

```python
from crux_adapters.jev import DecisionNotRecorded

try:
    decision = decide(client, questions, entity=entity, token_budget=1000, untrusted=untrusted)
except DecisionNotRecorded as err:
    unrecorded = err.decision          # .answers, .state, .request_id; .receipt_id if only the fact failed
    log.error("jev decision not recorded: %s", err)
    refuse(cmd)                        # a guardrail fails closed
```

The usual cause is a daemon without `CORECRUXD_STREAM_RECEIPTS=1`: the message
says so. Failures before Jev is called raise as usual, and nothing is
recorded: a `CueCruxError` 404 from `GET /v1/context` means
`CORECRUXD_CONTEXT_SURFACE` is off, and Jev errors (429 and 529 included)
arrive as `httpx.HTTPStatusError` once retries are spent. `jev_http` retries
408, 429 and 5xx (529 included) up to 3 attempts, honouring `retry-after-ms`
/ `Retry-After`; it never retries other 4xx or connection errors (a timed-out
POST may already have been billed). To use the official `typesafe-sdk` client
instead, wrap it in a callable with the same shape (request body in,
`(response JSON, request id)` out) and pass it as `jev=`.

## Replaying a decision against a new model version

Opt in per decision with `store_state=True`; `replay` then re-sends the exact
stored request and shows whether the verdict moved:

```python
from crux_adapters.jev import TamperedRequest, decide, replay

decision = decide(client, questions, entity=entity, token_budget=1000,
                  untrusted=untrusted, store_state=True)

ref = decision.request_id or decision.invocation_id   # the fact key falls back when Jev sent no request id
result = replay(client, entity, f"decision:{ref}", model="jev-latest")
if result.changed:
    print(result.old_model_version, "->", result.new_model_version)
    print(result.old_answers, "->", result.new_answers)
```

Before calling Jev, `replay` checks that the stored request still hashes to
the decision's `prompt_hash` and names the same receipt, and raises
`TamperedRequest` if not. Replay writes nothing: no receipt, no fact.

The stored request includes your `untrusted` input verbatim, in an ordinary
fact under `__jev__::<entity>` (HTTP fact writes cannot be private), so anyone
who can read the tenant's facts can read it. The `__` namespace keeps it out of
`/v1/context`, so a stored injection never comes back as trusted context in a
later `decide`. Leave `store_state` off for inputs you should not retain.

## Linking the receipt from your traces

Put the receipt id on the span or trace you already emit, so a trace links to
the signed record. No new dependency.

OpenTelemetry:

```python
from opentelemetry import trace

span = trace.get_current_span()
span.set_attribute("crux.receipt_id", decision.receipt_id)
span.set_attribute("crux.fact_id", decision.fact_id)
span.set_attribute("jev.request_id", decision.request_id or "")
span.set_attribute("jev.model_version", decision.model_version)
```

Langfuse (Python SDK v3):

```python
from langfuse import get_client

get_client().update_current_span(metadata={
    "crux_receipt_id": decision.receipt_id,
    "crux_fact_id": decision.fact_id,
    "jev_request_id": decision.request_id,
    "jev_model_version": decision.model_version,
})
```

## Jev through LangChain (`langchain-typesafe`)

If your agent reaches Jev through
[`langchain-typesafe`](https://pypi.org/project/langchain-typesafe/)
(`TypeSafeClassifier`, or the `ModelRouterMiddleware` and `AutoModeMiddleware`
that each build one), you do not call `decide`. Pass a callback handler in the
run config instead; LangChain hands it to every Jev call in the run, the
middleware's included:

```bash
pip install 'cuecrux-adapters[jev-langchain]'   # langchain-typesafe[experimental], tested on 0.0.1a3
```

```python
from crux_adapters.jev_langchain import JevReceiptHandler

handler = JevReceiptHandler(client, entity="agent:build-bot")
agent = create_agent(model, tools=[read_file, delete_file],
                     middleware=[ModelRouterMiddleware(...), AutoModeMiddleware(tools=[delete_file])])
agent.invoke({"messages": [...]}, config={"callbacks": [handler]})
```

Each Jev call gets the same receipt and `jev:<entity>` / `decision:<request_id>`
fact as `decide` produces, with these differences:

- **Crux did not build the state, LangChain did.** `retrieval_set_hash` is
  null in the receipt draft (so the signed body has none) and in the fact, and
  the fact has no `retrieved` list. The receipt makes no claim about Crux
  retrieval.
- `prompt_hash` covers `{state, questions}` as the classifier sends them, with
  LangChain messages already converted to role/content JSON. `output_hash`
  covers `{model, answers}` as the classifier parsed them, so fields Jev adds
  that `langchain-typesafe` does not model are not covered.
- `invocation_id` is the LangChain run id, so a LangSmith trace and its receipt
  share an id.
- No replay: nothing is stored under `__jev__::`.
- **Python 3.10, async agents:** the middleware calls the classifier's
  `ainvoke` without a config, and asyncio on 3.10 cannot carry LangChain's
  callbacks into it, so those decisions are **not recorded** and nothing says
  so. Use Python 3.11+ or a sync run. A direct
  `classifier.ainvoke(request, config={"callbacks": [handler]})` is recorded on
  3.10 too.

If the receipt or the fact cannot be written, the handler raises
`DecisionNotRecorded` out of the classifier call. `AutoModeMiddleware` treats
that like any classifier failure: the tool does not run. Set
`handler.raise_error = False` to log the failure and let the agent continue
without a record.
