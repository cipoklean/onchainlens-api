# OnchainLens — Token Security Audit API

A production-grade token security scanning API. It takes a contract address +
chain and returns a scored risk report (honeypot, ownership, taxes, proxy,
liquidity lock, mint/freeze authority, and more).

- **EVM chains** (ethereum, bsc, polygon, arbitrum, optimism, base, avalanche,
  fantom) — scanned via [GoPlus Security](https://gopluslabs.io/).
- **Solana** — scanned via [RugCheck](https://rugcheck.xyz/) (GoPlus does NOT
  support Solana, so a dedicated Solana source is used).

## Hosts

- **Canonical:** `https://onchainlens.dpdns.org` — use this one.
- **Legacy:** `https://onchainlens-api.vercel.app` — kept for backward compatibility. Note: some buyer/agent security policies block `vercel.app` (deploy-platform host); they should use the canonical host.
- A second custom-domain mirror is planned. Exact hostnames are documented here so policy-restricted buyers can pre-clear them with their security tooling.

## Endpoints

| Method | Path    | Body                                  | Notes                          |
|--------|---------|---------------------------------------|--------------------------------|
| POST   | /audit  | `{"contract_address": "...", "chain": "ethereum"}` | Returns `AuditResponse` |
| GET    | /health | —                                     | Liveness probe                 |
| GET    | /       | —                                     | Service info + endpoint list   |

### Example

```bash
curl -X POST https://onchainlens.dpdns.org/audit \
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
| `OKX_API_KEY`      | unset   | OKX Developer Portal API key — enables x402 paid `/audit`. |
| `OKX_SECRET_KEY`   | unset   | OKX API secret (paired with `OKX_API_KEY`).                |
| `OKX_PASSPHRASE`   | unset   | OKX API passphrase (paired with `OKX_API_KEY`).            |
| `X402_PAY_TO`      | 0xf5fbbf…59c4 | x402 recipient X Layer address (your wallet; where USDT0 is paid). |
| `X402_PRICE`       | `$0.20` | Price per `/audit` call, e.g. `$0.20` (= 0.2 USDT0).       |

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

## Deploy (Vercel)

1. Push to GitHub and import the repo at vercel.com (Hobby/Free, no card).
2. Build: `pip install -r requirements.txt`; start: `uvicorn main:app --host 0.0.0.0 --port $PORT`.
3. For paid mode, add `OKX_API_KEY` / `OKX_SECRET_KEY` / `OKX_PASSPHRASE` (from the
   OKX Developer Portal) in the Vercel project env vars.
4. Auto-deploy on push. `GET /health` is the health probe.

## Paid mode (x402 / OKX A2MCP)

When `OKX_API_KEY` + `OKX_SECRET_KEY` + `OKX_PASSPHRASE` are set, `POST /audit`
becomes an **x402** endpoint. An unpaying caller receives `HTTP 402` with a
`PAYMENT-REQUIRED` challenge; after paying **0.2 USDT0** on X Layer (gas-free,
scheme `exact`, `network: eip155:196`), the request is replayed and served.

- Settlement asset: `USD₮0` (`0x779ded0c9e1022225f8e0630b35a9b54be713736`)
- Recipient (`payTo`): your EVM wallet (default 0xf5fbbf…59c4; override via `X402_PAY_TO`)
- Price: `X402_PRICE` (default `$0.20` → `200000` base units)
- With no OKX key set, `/audit` stays **free** (graceful fallback).

Powered by `okxweb3-app-x402` (OKX-branded Coinbase x402 SDK — Alpha).

## A2MCP / agent marketplace

The service is agent-callable: a public HTTPS `POST /audit` returning structured
JSON. To list it as an ASP on OKX.AI (or any A2MCP registry), deploy it, then
register the live `https://` endpoint. No dead/mock endpoints are exposed.
