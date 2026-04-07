# Operations Guide

## Rate Limiting

CoreCrux Community Edition does not include application-level rate limiting.
Deploy behind a reverse proxy (nginx, Caddy, Envoy) with rate limits configured.

### Recommended Limits

| Endpoint | Recommended limit | Rationale |
|----------|-------------------|-----------|
| POST /v1/append | 100 req/s | Write path; disk I/O bound |
| POST /v1/query/* | 200 req/s | Read path; CPU-bound BM25 |
| PUT /v1/facts | 50 req/s | In-memory + journal write |
| GET /v1/facts/export | 10 req/s | Full scan; expensive |
| GET /healthz | Unlimited | Health probes |
| GET /metrics | 10 req/s | Prometheus scrape |

### Example: Caddy rate limiting

Use the `rate_limit` directive from the
[caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) plugin:

```caddyfile
:14800 {
    reverse_proxy localhost:14801

    rate_limit {
        zone append {
            key    {remote_host}
            events 100
            window 1s
        }
        zone query {
            key    {remote_host}
            events 200
            window 1s
        }
        zone facts_export {
            key    {remote_host}
            events 10
            window 1s
        }
    }

    @append  path /v1/append
    @query   path /v1/query/*
    @export  path /v1/facts/export

    handle @append  { rate_limit append }
    handle @query   { rate_limit query }
    handle @export  { rate_limit facts_export }
}
```

### Example: nginx rate limiting

```nginx
http {
    # Define rate-limit zones (per client IP)
    limit_req_zone $binary_remote_addr zone=append:10m  rate=100r/s;
    limit_req_zone $binary_remote_addr zone=query:10m   rate=200r/s;
    limit_req_zone $binary_remote_addr zone=facts_w:10m rate=50r/s;
    limit_req_zone $binary_remote_addr zone=export:10m  rate=10r/s;
    limit_req_zone $binary_remote_addr zone=metrics:10m rate=10r/s;

    server {
        listen 14800;

        location /v1/append {
            limit_req zone=append burst=20 nodelay;
            proxy_pass http://127.0.0.1:14801;
        }

        location /v1/query/ {
            limit_req zone=query burst=40 nodelay;
            proxy_pass http://127.0.0.1:14801;
        }

        location = /v1/facts {
            limit_req zone=facts_w burst=10 nodelay;
            proxy_pass http://127.0.0.1:14801;
        }

        location = /v1/facts/export {
            limit_req zone=export burst=2 nodelay;
            proxy_pass http://127.0.0.1:14801;
        }

        location = /healthz {
            # No rate limit — health probes must always succeed.
            proxy_pass http://127.0.0.1:14801;
        }

        location = /metrics {
            limit_req zone=metrics burst=2 nodelay;
            proxy_pass http://127.0.0.1:14801;
        }

        location / {
            proxy_pass http://127.0.0.1:14801;
        }
    }
}
```

### What happens without rate limiting

Without rate limiting, a burst of append requests can:

- Exhaust disk I/O bandwidth (sealed segment writes)
- Cause backpressure on the JSONL journal
- Increase response latency for all endpoints

The daemon will not crash but will degrade gracefully.
