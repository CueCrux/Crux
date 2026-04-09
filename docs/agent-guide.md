# Using Crux as Your Memory & Retrieval Backend

CoreCrux gives agents three distinct surfaces:

- HTTP on `14800` for the shared REST API (`/v1/query/*`, `/v1/facts`,
  `/v1/sessions/*`, health/metrics).
- gRPC on `4007` for the data plane.
- MCP on `14801` for agent-facing tools such as private facts, agent-scoped
  sessions, and handoff.

Use HTTP for shared application data. Use MCP when you need agent identity,
private memory, or handoff between agents.

## Your First 3 Calls

New to CoreCrux? Start here:

```
1. get_bootstrap("patterns")
   → Learn token reduction, scan-expand, fact memory, and session patterns.

2. store_fact(entity="test", key="hello", value="world")
   → Store your first fact. Confirm you get a fact_id back.

3. query_facts(query="hello")
   → Retrieve it. You should see your fact with confidence=1.0.
```

That's it — you're connected and working. Read on for authentication, tool selection, and advanced patterns.

## Authentication

HTTP and MCP use different authentication models:

- HTTP auth is controlled by `CORECRUXD_AUTH_MODE`.
- MCP auth is controlled by `CRUX_AGENT_TOKEN` / `CRUX_AGENT_TOKENS`.

### HTTP

Set `CORECRUXD_AUTH_MODE` on the server. If the selected mode requires bearer
tokens, send `Authorization: Bearer <token>` on HTTP requests.

### MCP

If the server has no MCP agent tokens configured, MCP requests may run as
`anonymous`. If the server sets `CRUX_AGENT_TOKEN` or `CRUX_AGENT_TOKENS`,
every `POST /mcp` request must include the matching bearer token.

```bash
export CRUX_AGENT_TOKEN="your-token-here"

curl -s -X POST http://localhost:14801/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_agent_identity","arguments":{}}}'
```

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

The fact store is a receipted key-value memory scoped by entity. Each fact
costs about 12 tokens versus replaying the original conversation.

### Shared facts over HTTP

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

HTTP `/v1/facts` is a shared surface. It does not support `private=true`.

### Private facts over MCP

Set `private: true` with the `store_fact` MCP tool to scope a fact to your
authenticated agent only. Other agents cannot see it, and handoff packages do
not export private facts.

```bash
curl -s -X POST http://localhost:14801/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "store_fact",
      "arguments": {
        "entity": "my-agent",
        "key": "internal_state",
        "value": "Waiting for user confirmation on budget",
        "confidence": 1.0,
        "private": true
      }
    }
  }'
```

## Session Persistence Patterns

Sessions store structured state such as decisions, open questions, and
constraints.

### Shared sessions over HTTP

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

### Agent-scoped sessions over MCP

When you access sessions through MCP, authenticated agents read and write
inside their own session namespace:

```bash
curl -s -X POST http://localhost:14801/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "save_session",
      "arguments": {
        "session_id": "session-42",
        "state": {
          "decisions": ["Use PostgreSQL for primary store"],
          "open_questions": ["Which caching layer?"],
          "context": "Architecture review for Project Alpha"
        }
      }
    }
  }'
```

## Multi-Agent Handoff Workflow (MCP Only)

When Agent A finishes a task and needs to pass context to Agent B:

### Agent A: Create handoff package

```bash
PACKAGE_JSON=$(curl -s -X POST http://localhost:14801/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "create_handoff",
      "arguments": {
        "session_id": "session-42",
        "include_facts": true,
        "target_agent": "agent-b",
        "message": "Completed architecture review. Three decisions made, one open question remaining."
      }
    }
  }' | jq -r '.result.content[0].text')
```

Pass `PACKAGE_JSON` to Agent B. The package is server-authenticated and
includes only relevant non-private facts.

### Agent B: Accept handoff

```bash
curl -s -X POST http://localhost:14801/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -d "$(jq -nc --arg package "$PACKAGE_JSON" '{
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "accept_handoff",
      arguments: {
        package: $package
      }
    }
  }')"
```

Agent B now has full session state and facts from Agent A's work.

If handoff packages must survive daemon restarts or move between replicas, set
the same `CRUX_MCP_HANDOFF_SECRET` on every server instance.

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

# 4. Handoff to implementation agent via MCP
curl -s -X POST http://localhost:14801/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "create_handoff",
      "arguments": {
        "session_id": "research-42",
        "include_facts": true,
        "target_agent": "implementer",
        "message": "Research complete. Two key decisions made. See facts for details."
      }
    }
  }'
```

## Rate Limiting

In standalone mode, Crux has no built-in HTTP rate limiting. For production deployments,
place Crux behind a reverse proxy (Caddy, nginx) with rate limiting configured.
The gRPC append path has built-in per-tenant throttling via `CRUX_TENANT_THROTTLE_*` env vars.

Every HTTP endpoint has a **30-second request timeout** enforced by Tower middleware.
Requests exceeding the deadline receive a `408 Request Timeout` response.
