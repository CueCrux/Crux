# Using Crux as Your Memory & Retrieval Backend

CoreCrux provides agents with append-only event storage, BM25 full-text retrieval, a receipted fact store, session persistence, and multi-agent handoff — all from a single binary on port 14800.

## Authentication

Set the `CRUX_AGENT_TOKEN` environment variable. Every HTTP request must include it as a Bearer token:

```bash
export CRUX_AGENT_TOKEN="your-token-here"

curl -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  http://localhost:14800/v1/facts?query=project
```

If the token is missing or invalid, the server returns `401 Unauthorized`.

## Tool Decision Tree

Choose the right query endpoint based on what you need:

```
Do you need full document content right now?
├── YES → POST /v1/query/text-search (standard query)
│         Returns scored results with full content, coverage report.
│
└── NO → Do you need metadata first to decide what to fetch?
         ├── YES → POST /v1/query/text-search with mode=scan
         │         Returns titles, scores, token counts — no content.
         │         Then: POST /v1/query/text-search/expand with result_ids
         │         to fetch full content for selected results only.
         │
         └── Do you need related/connected documents?
              └── YES → POST /v1/query/graph-expand
                        Traverses entity relationships with a hop budget.
                        Use when you need "what else is related to X?"
```

**Summary:**

| Endpoint | Use when | Returns |
|---|---|---|
| `text-search` | You know what to search for | Full results + coverage |
| `text-search` (mode=scan) + `expand` | Large corpus, token-conscious | Metadata first, then selected content |
| `graph-expand` | Exploring relationships | Connected documents via entity graph |
| `time-range` | Temporal queries | Events within a time window |

## Fact Store Patterns

The fact store is a receipted key-value memory scoped by entity. Each fact costs ~12 tokens vs ~3000 tokens for replaying the original conversation.

### Store a fact

```bash
curl -X PUT http://localhost:14800/v1/facts \
  -H "Content-Type: application/json" \
  -d '{
    "entity": "project-alpha",
    "key": "status",
    "value": "Phase 1 complete, 12 milestones delivered",
    "confidence": 0.95
  }'
```

Response:
```json
{
  "fact_id": "f_01J...",
  "receipt_id": "rcpt_01J...",
  "created_at": "2026-04-03T10:00:00Z"
}
```

### Query facts

```bash
curl "http://localhost:14800/v1/facts?query=project+status&token_budget=500"
```

Returns facts matching the query, fitted within your token budget.

### Private facts

Set `private: true` to scope a fact to your agent only. Other agents sharing the same tenant cannot see private facts.

```bash
curl -X PUT http://localhost:14800/v1/facts \
  -H "Content-Type: application/json" \
  -d '{
    "entity": "my-agent",
    "key": "internal_state",
    "value": "Waiting for user confirmation on budget",
    "confidence": 1.0,
    "private": true
  }'
```

## Session Persistence Patterns

Sessions store structured state (decisions, open questions, constraints) at ~87 tokens vs ~15K tokens for replaying the full conversation.

### Save session state

```bash
curl -X PUT http://localhost:14800/v1/sessions/session-42/state \
  -H "Content-Type: application/json" \
  -d '{
    "decisions": ["Use PostgreSQL for primary store", "Deploy to eu-west-1"],
    "open_questions": ["Which caching layer?"],
    "constraints": ["Budget < $500/mo", "GDPR compliant"],
    "context": "Architecture review for Project Alpha"
  }'
```

### Resume a session

```bash
curl http://localhost:14800/v1/sessions/session-42/state
```

Returns the full session state, ready to inject into your context window.

## Multi-Agent Handoff Workflow

When Agent A finishes a task and needs to pass context to Agent B:

### Agent A: Create handoff package

```bash
curl -X POST http://localhost:14800/v1/handoff \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "session-42",
    "include_facts": true,
    "summary": "Completed architecture review. Three decisions made, one open question remaining."
  }'
```

Response:
```json
{
  "handoff_id": "ho_01J...",
  "package": {
    "session_state": { "..." },
    "facts": [ "..." ],
    "summary": "Completed architecture review..."
  }
}
```

Pass `handoff_id` to Agent B (e.g., via a shared channel or orchestrator).

### Agent B: Accept handoff

```bash
curl -X POST http://localhost:14800/v1/handoff/accept \
  -H "Content-Type: application/json" \
  -d '{
    "handoff_id": "ho_01J...",
    "agent_id": "agent-b"
  }'
```

Agent B now has full session state and facts from Agent A's work.

## Coverage Awareness

Every `text-search` response includes a `coverage` object:

```json
{
  "coverage": {
    "score": 0.33,
    "gaps": ["quantum", "entanglement"]
  }
}
```

**What to do when `score < 0.5`:**

1. **Broaden your query.** Try synonyms or more general terms.
2. **Check gaps.** Call `GET /v1/gaps` to see what the corpus is missing.
3. **Inform the user.** If the corpus genuinely does not cover the topic, say so rather than hallucinating an answer.
4. **Store a gap fact.** Record the coverage gap so future agents know:
   ```bash
   curl -X PUT http://localhost:14800/v1/facts \
     -d '{"entity":"coverage-gaps","key":"quantum-physics","value":"Corpus has no quantum physics content","confidence":1.0}'
   ```

## Token Reduction Strategies

### Use `token_budget` instead of `top_k`

```bash
curl -X POST http://localhost:14800/v1/query/text-search \
  -H "Content-Type: application/json" \
  -d '{"query": "deployment strategy", "token_budget": 4000}'
```

The engine returns the best results that fit within 4000 tokens. This reduces prompt cost by 60-80% compared to fixed `top_k`.

### Progressive retrieval (scan then expand)

For large corpora, use the two-pass pattern:

1. **Scan** — get metadata only (titles, scores, token counts):
   ```bash
   curl -X POST http://localhost:14800/v1/query/text-search \
     -d '{"query": "deployment", "mode": "scan", "top_k": 20}'
   ```

2. **Expand** — fetch full content for the results you actually need:
   ```bash
   curl -X POST http://localhost:14800/v1/query/text-search/expand \
     -d '{"result_ids": ["r_01", "r_05", "r_12"], "token_budget": 3000}'
   ```

This avoids pulling content you will discard.

## Example Workflow: Research, Store, Save, Handoff

A complete agent workflow showing all patterns together:

```bash
# 1. Research: search the corpus
curl -X POST http://localhost:14800/v1/query/text-search \
  -H "Content-Type: application/json" \
  -d '{"query": "database migration best practices", "token_budget": 4000}'

# 2. Store facts extracted from results
curl -X PUT http://localhost:14800/v1/facts \
  -d '{"entity":"db-migration","key":"rollback-strategy","value":"Always use reversible migrations with down scripts","confidence":0.9}'

curl -X PUT http://localhost:14800/v1/facts \
  -d '{"entity":"db-migration","key":"zero-downtime","value":"Use expand-contract pattern for schema changes","confidence":0.85}'

# 3. Save session state
curl -X PUT http://localhost:14800/v1/sessions/research-42/state \
  -d '{
    "decisions": ["Use expand-contract pattern", "Require down migrations"],
    "open_questions": ["Which migration tool?"],
    "context": "Researching DB migration strategy for Project Alpha"
  }'

# 4. Handoff to implementation agent
curl -X POST http://localhost:14800/v1/handoff \
  -d '{
    "session_id": "research-42",
    "include_facts": true,
    "summary": "Research complete. Two key decisions made. See facts for details."
  }'
# Pass the handoff_id to the implementation agent
```

## Rate Limiting

In standalone mode, Crux has no built-in HTTP rate limiting. For production deployments,
place Crux behind a reverse proxy (Caddy, nginx) with rate limiting configured.
The gRPC append path has built-in per-tenant throttling via `CRUX_TENANT_THROTTLE_*` env vars.

Every HTTP endpoint has a **30-second request timeout** enforced by Tower middleware.
Requests exceeding the deadline receive a `408 Request Timeout` response.
