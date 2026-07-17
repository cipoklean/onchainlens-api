# OnchainLens — Token Security Audit API

A production-grade token security scanning API. It takes a contract address +
chain and returns a scored risk report (honeypot, ownership, taxes, proxy,
liquidity lock, mint/freeze authority, and more).

- **EVM chains** (ethereum, bsc, polygon, arbitrum, optimism, base, avalanche,
  fantom) — scanned via [GoPlus Security](https://gopluslabs.io/).
- **Solana** — scanned via [RugCheck](https://rugcheck.xyz/) (GoPlus does NOT
  support Solana, so a dedicated Solana source is used).

## Endpoints

| Method | Path    | Body                                  | Notes                          |
|--------|---------|---------------------------------------|--------------------------------|
| POST   | /audit  | `{"contract_address": "...", "chain": "ethereum"}` | Returns `AuditResponse` |
| GET    | /health | —                                     | Liveness probe                 |
| GET    | /       | —                                     | Service info + endpoint list   |

### Example

```bash
curl -X POST https://your-app.onrender.com/audit \
  -H "Content-Type: application/json" \
  -d '{"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"}'
```

Response (abridged):

```json
{
  "contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "chain": "ethereum",
  "provider": "goplus",
  "risk_score": 0,
  "risk_level": "SAFE",
  "is_honeypot": false,
  "findings": [ { "severity": "info", "title": "No Issues Found", "description": "..." } ],
  "scan_timestamp": "2026-07-17T12:00:00.000000+00:00"
}
```

## Production behavior (vs the original MVP)

- **No more false "SAFE".** A non-existent / unindexed token returns `404`,
  never a clean pass. An invalid address returns `400` before any upstream call.
- **Solana actually works.** The old Solscan endpoint was dead (404). Solana is
  now scanned through RugCheck with real mint/freeze-authority, LP-lock and risk
  data.
- **`liquidity_locked` is honest.** Previously it meant "trades on a DEX"; now it
  is only `true` when LP-lock evidence exists.
- **Resilience.** Upstream timeouts/5xx/429 surface as clean `502`/`504` (never a
  raw crash). Responses are cached (TTL) and rate-limited per IP.
- **Security.** Optional bearer-token auth on `/audit`, configurable CORS, and a
  shared HTTP client via app lifespan.

## Configuration (environment variables)

All optional. Copy `.env.example` to `.env` for local dev.

| Variable           | Default | Purpose                                                      |
|--------------------|---------|--------------------------------------------------------------|
| `GOPLUS_API_KEY`   | unset   | Bearer token for GoPlus (raises rate limits).               |
| `API_BEARER_TOKEN` | unset   | If set, `/audit` requires `Authorization: Bearer ***         |
| `CORS_ORIGINS`     | `*`     | Comma-separated allowed origins (no credentials sent).      |
| `CACHE_TTL`        | `120`   | Upstream cache TTL (seconds).                               |
| `RATE_LIMIT`       | `60`    | Max `/audit` requests per IP / 60s (`0` disables).          |
| `LOG_LEVEL`        | `INFO`  | Logging verbosity.                                          |

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
# docs at http://localhost:8000/docs
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Upstream calls are mocked, so the suite runs offline.

## Deploy (Render)

1. Push to GitHub.
2. Create a new **Web Service** on Render, link the repo, and use the included
   `render.yaml` (Python runtime, auto-deploy). Set any of the env vars above in
   the Render dashboard if desired.
3. `healthCheckPath: /health` is configured for free-tier health checks.

## A2MCP / agent marketplace

The service is agent-callable: a public HTTPS `POST /audit` returning structured
JSON. To list it as an ASP on OKX.AI (or any A2MCP registry), deploy it, then
register the live `https://` endpoint. No dead/mock endpoints are exposed.
