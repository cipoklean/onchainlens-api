"""OnchainLens — Token Security Audit API

Production-grade token security scanning for EVM chains (via GoPlus Security)
and Solana (via RugCheck). Returns a structured, scored risk report.

Endpoints
  POST /audit   — audit a token contract (chain + address)
  GET  /health  — liveness probe
  GET  /        — service info

Environment (all optional)
  GOPLUS_API_KEY   Bearer token for GoPlus (lifts rate limits)
  API_BEARER_TOKEN If set, /audit requires `Authorization: Bearer <token>`
  CORS_ORIGINS     Comma-separated allowed origins (default: * public, no creds)
  CACHE_TTL        Upstream response cache TTL in seconds (default: 120)
  RATE_LIMIT       Max /audit requests per IP per 60s (default: 60, 0 = off)
  LOG_LEVEL        logging level (default: INFO)
  PORT             overridden by the platform at startup
  OKX_API_KEY / OKX_SECRET_KEY / OKX_PASSPHRASE  OKX Developer Portal key — enables x402 paid /audit
  X402_PAY_TO      x402 recipient X Layer address (default: your EVM wallet)
  X402_PRICE       x402 price per call, e.g. "$0.20" (default: "$0.20" = 0.2 USDT0)
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime, timezone

VERSION = "1.1.0"

# ── Configuration (env-driven) ───────────────────────────────────────────────
GOPLUS_API_KEY = os.getenv("GOPLUS_API_KEY")
API_BEARER_TOKEN = os.getenv("API_BEARER_TOKEN")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
CACHE_TTL = int(os.getenv("CACHE_TTL", "120"))
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "60"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [onchainlens] %(message)s",
)
logger = logging.getLogger("onchainlens")

GOPLUS_URL = "https://api.gopluslabs.io/api/v1/token_security"
RUGCHECK_URL = "https://api.rugcheck.xyz/v1/tokens"

# ── Chain mapping ────────────────────────────────────────────────────────────
# EVM chains map to GoPlus numeric chain ids; "solana" is a sentinel handled
# separately (GoPlus does NOT support Solana — RugCheck is used instead).
CHAIN_IDS: dict[str, str] = {
    "ethereum": "1", "eth": "1", "1": "1",
    "bsc": "56", "binance": "56", "56": "56",
    "polygon": "137", "matic": "137", "137": "137",
    "arbitrum": "42161", "arb": "42161", "42161": "42161",
    "optimism": "10", "op": "10", "10": "10",
    "avalanche": "43114", "avax": "43114", "43114": "43114",
    "base": "8453", "8453": "8453",
    "fantom": "250", "ftm": "250", "250": "250",
    "solana": "solana", "sol": "solana",
}

EVM_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
# Solana addresses are base58 (no 0,O,I,l) and 32-44 chars.
SOLANA_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

# ── Shared HTTP client (lifespan-managed) ────────────────────────────────────
HTTP_CLIENT: Optional[httpx.AsyncClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global HTTP_CLIENT
    HTTP_CLIENT = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0),
        headers={"User-Agent": f"OnchainLens/{VERSION}"},
    )
    logger.info(
        "OnchainLens %s starting | goplus_key=%s rugcheck=on auth=%s cors=%s cache_ttl=%ss rate_limit=%s",
        VERSION,
        "set" if GOPLUS_API_KEY else "unset",
        "on" if API_BEARER_TOKEN else "off",
        CORS_ORIGINS,
        CACHE_TTL,
        RATE_LIMIT,
    )
    yield
    if HTTP_CLIENT is not None:
        await HTTP_CLIENT.aclose()
        HTTP_CLIENT = None


def get_client() -> httpx.AsyncClient:
    if HTTP_CLIENT is None:
        # Defensive fallback (e.g. tests) — should not happen in normal runtime.
        return httpx.AsyncClient(timeout=httpx.Timeout(30.0))
    return HTTP_CLIENT


# ── In-memory TTL cache ───────────────────────────────────────────────────────
_cache: dict[str, tuple[float, Any]] = {}
_cache_lock = threading.Lock()


async def cache_get(key: str) -> Optional[Any]:
    with _cache_lock:
        item = _cache.get(key)
        if item and item[0] > time.time():
            return item[1]
        _cache.pop(key, None)
    return None


async def cache_set(key: str, value: Any, ttl: int) -> None:
    with _cache_lock:
        _cache[key] = (time.time() + ttl, value)


# ── In-memory per-IP rate limiter (fixed window) ─────────────────────────────
_rl: dict[str, list[float]] = {}
_rl_lock = threading.Lock()


def rate_limit(request: Request) -> None:
    if RATE_LIMIT <= 0:
        return
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    with _rl_lock:
        hits = _rl.get(ip, [])
        hits = [t for t in hits if now - t < 60]
        if len(hits) >= RATE_LIMIT:
            _rl[ip] = hits
            logger.warning("Rate limit hit for %s", ip)
            raise HTTPException(429, "Rate limit exceeded. Please retry later.")
        hits.append(now)
        _rl[ip] = hits


# ── Auth dependency ───────────────────────────────────────────────────────────
def require_auth(request: Request) -> None:
    if not API_BEARER_TOKEN:
        return  # open mode
    auth = request.headers.get("Authorization", "")
    expected = f"Bearer {API_BEARER_TOKEN}"
    if not secrets.compare_digest(auth, expected):
        raise HTTPException(401, "Invalid or missing API token.")


# ── Custom upstream errors ─────────────────────────────────────────────────────
class UpstreamError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class TokenNotFoundError(Exception):
    pass


# ── Pydantic models ─────────────────────────────────────────────────────────────
class AuditRequest(BaseModel):
    contract_address: str = Field(
        ..., description="Token contract address (0x... for EVM, base58 for Solana)"
    )
    chain: str = Field(
        default="ethereum",
        description="Chain name or id: ethereum, bsc, polygon, arbitrum, optimism, "
                    "base, avalanche, fantom, solana",
    )


class AuditFinding(BaseModel):
    severity: str  # critical | high | medium | low | info
    title: str
    description: str


class AuditResponse(BaseModel):
    contract_address: str
    chain: str
    provider: str  # source of the scan: "goplus" | "rugcheck"
    token_name: Optional[str] = None
    token_symbol: Optional[str] = None
    risk_score: int = Field(..., ge=0, le=100, description="0 = safe, 100 = extreme risk")
    risk_level: str  # SAFE | LOW | MEDIUM | HIGH | CRITICAL
    is_honeypot: bool
    buy_tax: Optional[str] = None
    sell_tax: Optional[str] = None
    is_open_source: Optional[bool] = None
    owner_renounced: Optional[bool] = False
    has_proxy: Optional[bool] = False
    liquidity_locked: Optional[bool] = None
    liquidity_locked_pct: Optional[float] = None
    findings: list[AuditFinding] = []
    scan_timestamp: str


# ── Upstream scanners ───────────────────────────────────────────────────────────
async def scan_goplus(chain_id: str, address: str) -> dict:
    """Query GoPlus token_security. Raises TokenNotFoundError / UpstreamError."""
    client = get_client()
    url = f"{GOPLUS_URL}/{chain_id}"
    headers = {"Authorization": f"Bearer {GOPLUS_API_KEY}"} if GOPLUS_API_KEY else {}
    try:
        resp = await client.get(
            url, params={"contract_addresses": address}, headers=headers, timeout=30.0
        )
    except httpx.TimeoutException:
        raise UpstreamError("GoPlus request timed out", 504)
    except httpx.HTTPStatusError as e:
        raise UpstreamError(f"GoPlus returned HTTP {e.response.status_code}", 502)
    except httpx.RequestError as e:
        raise UpstreamError(f"GoPlus unreachable: {e}", 502)

    if resp.status_code != 200:
        raise UpstreamError(f"GoPlus returned HTTP {resp.status_code}", 502)

    try:
        data = resp.json()
    except ValueError:
        raise UpstreamError("GoPlus returned non-JSON response", 502)

    if data.get("code") != 1:
        raise UpstreamError(f"GoPlus error: {data.get('message', 'unknown')}")

    result = data.get("result")
    if not result:
        raise TokenNotFoundError(
            f"Token {address} was not found or is not indexed by GoPlus Security."
        )

    addr_lower = address.lower()
    token = result.get(addr_lower, result.get(address))
    if not isinstance(token, dict):
        raise TokenNotFoundError(
            f"Token {address} was not found or is not indexed by GoPlus Security."
        )
    return token


async def scan_rugcheck(address: str) -> dict:
    """Query RugCheck full report for a Solana mint. Raises TokenNotFoundError / UpstreamError."""
    client = get_client()
    url = f"{RUGCHECK_URL}/{address}/report"
    try:
        resp = await client.get(url, timeout=20.0)
    except httpx.TimeoutException:
        raise UpstreamError("RugCheck request timed out", 504)
    except httpx.HTTPStatusError as e:
        raise UpstreamError(f"RugCheck returned HTTP {e.response.status_code}", 502)
    except httpx.RequestError as e:
        raise UpstreamError(f"RugCheck unreachable: {e}", 502)

    if resp.status_code == 404:
        raise TokenNotFoundError(
            f"Token {address} was not found or has not been scanned by RugCheck."
        )
    if resp.status_code == 429:
        raise UpstreamError("RugCheck rate limit exceeded", 429)
    if resp.status_code != 200:
        raise UpstreamError(f"RugCheck returned HTTP {resp.status_code}", 502)

    try:
        data = resp.json()
    except ValueError:
        raise UpstreamError("RugCheck returned non-JSON response", 502)
    if not isinstance(data, dict):
        raise UpstreamError("RugCheck returned an unexpected response", 502)
    return data


# ── Helpers ──────────────────────────────────────────────────────────────────
def _truthy(v: Any) -> bool:
    return v in ("1", 1, True, "true", "True")


def _tax_str(raw: Any) -> Optional[str]:
    if raw in (None, "", "0", 0, "0.0"):
        return None
    try:
        return f"{float(raw)}%"
    except (TypeError, ValueError):
        return str(raw)


def _risk_level(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 35:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    if score >= 5:
        return "LOW"
    return "SAFE"


# ── Risk assessment: GoPlus (EVM) ──────────────────────────────────────────────
def assess_goplus(tok: dict) -> dict:
    findings: list[AuditFinding] = []
    risk = 0

    is_honeypot = _truthy(tok.get("is_honeypot"))
    if is_honeypot:
        findings.append(AuditFinding(
            severity="critical",
            title="Honeypot Detected",
            description="This token prevents selling. Buyers cannot transfer or sell tokens after purchase.",
        ))
        return {
            "token_name": tok.get("token_name") or None,
            "token_symbol": tok.get("token_symbol") or None,
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "is_honeypot": True,
            "buy_tax": _tax_str(tok.get("buy_tax")),
            "sell_tax": _tax_str(tok.get("sell_tax")),
            "is_open_source": _truthy(tok.get("is_open_source")),
            "owner_renounced": _truthy(tok.get("is_renounced")),
            "has_proxy": _truthy(tok.get("is_proxy")),
            "liquidity_locked": None,
            "liquidity_locked_pct": None,
            "findings": findings,
        }

    buy_tax = float(tok.get("buy_tax") or 0) or 0.0
    sell_tax = float(tok.get("sell_tax") or 0) or 0.0

    if sell_tax > 50:
        findings.append(AuditFinding(
            severity="critical",
            title=f"Sell Tax Extremely High ({sell_tax:.0f}%)",
            description=f"Over {sell_tax:.0f}% sell tax — likely a scam.",
        ))
        risk += 40
    elif sell_tax > 20:
        findings.append(AuditFinding(
            severity="high",
            title=f"High Sell Tax ({sell_tax:.0f}%)",
            description=f"Sell tax of {sell_tax:.0f}% is unusually high.",
        ))
        risk += 20
    elif sell_tax > 10:
        findings.append(AuditFinding(
            severity="medium",
            title=f"Moderate Sell Tax ({sell_tax:.0f}%)",
            description=f"{sell_tax:.0f}% sell tax — above average.",
        ))
        risk += 10

    if buy_tax > 10:
        findings.append(AuditFinding(
            severity="medium",
            title=f"High Buy Tax ({buy_tax:.0f}%)",
            description=f"{buy_tax:.0f}% tax on buy.",
        ))
        risk += 10

    owner = tok.get("owner_address", "")
    if not _truthy(tok.get("is_renounced")) and owner and owner != "0x0000000000000000000000000000000000000000":
        findings.append(AuditFinding(
            severity="medium",
            title="Ownership Not Renounced",
            description=f"Owner ({owner[:10]}...) retains control — they can modify the contract.",
        ))
        risk += 15

    if _truthy(tok.get("is_proxy")):
        findings.append(AuditFinding(
            severity="low",
            title="Proxy Contract",
            description="This is a proxy — the implementation can be upgraded by the owner.",
        ))
        risk += 5

    if not _truthy(tok.get("is_open_source")):
        findings.append(AuditFinding(
            severity="low",
            title="Closed Source",
            description="Contract source is not verified — code cannot be audited.",
        ))
        risk += 10

    # Liquidity lock: only claim a value when we have real evidence.
    lp_holders = tok.get("lp_holders")
    lp_locked: Optional[bool] = None
    if isinstance(lp_holders, list):
        lp_locked = any(h.get("is_locked") == 1 for h in lp_holders)
        if lp_locked is False:
            findings.append(AuditFinding(
                severity="medium",
                title="Liquidity Not Locked",
                description="LP holder data shows liquidity is not locked — rug-pull risk.",
            ))
            risk += 15

    if _truthy(tok.get("transfer_pausable")):
        findings.append(AuditFinding(
            severity="high",
            title="Transfer Can Be Paused",
            description="Owner can freeze all transfers — rug-pull risk.",
        ))
        risk += 20

    if _truthy(tok.get("is_mintable")) and not _truthy(tok.get("is_renounced")):
        findings.append(AuditFinding(
            severity="medium",
            title="Mintable Token",
            description="Owner can mint unlimited new tokens, diluting holders.",
        ))
        risk += 10

    if _truthy(tok.get("is_blacklisted")):
        findings.append(AuditFinding(
            severity="high",
            title="Blacklist Function",
            description="Owner can blacklist addresses, preventing them from trading.",
        ))
        risk += 15

    risk = min(risk, 95)

    if not findings:
        findings.append(AuditFinding(
            severity="info",
            title="No Issues Found",
            description="GoPlus reports no known vulnerabilities for this token.",
        ))

    return {
        "token_name": tok.get("token_name") or None,
        "token_symbol": tok.get("token_symbol") or None,
        "risk_score": risk,
        "risk_level": _risk_level(risk),
        "is_honeypot": False,
        "buy_tax": _tax_str(tok.get("buy_tax")),
        "sell_tax": _tax_str(tok.get("sell_tax")),
        "is_open_source": _truthy(tok.get("is_open_source")),
        "owner_renounced": _truthy(tok.get("is_renounced")),
        "has_proxy": _truthy(tok.get("is_proxy")),
        "liquidity_locked": lp_locked,
        "liquidity_locked_pct": None,
        "findings": findings,
    }


# ── Risk assessment: RugCheck (Solana) ─────────────────────────────────────────
def _sev_from_level(level: Any, text: str) -> str:
    t = (text or "").lower()
    if isinstance(level, str):
        lvl = level.lower()
        if lvl in ("danger", "critical", "high"):
            return "high"
        if lvl in ("warn", "warning", "medium"):
            return "medium"
        if lvl in ("info", "low"):
            return "low"
    if isinstance(level, (int, float)):
        if level >= 4:
            return "high"
        if level == 3:
            return "medium"
        if level <= 2:
            return "low"
    # Keyword fallback (RugCheck level semantics not formally documented).
    if any(k in t for k in ("honeypot", "rugged", "freeze authority", "mint authority", "owner")):
        return "high"
    return "medium"


def assess_rugcheck(report: dict, address: str) -> dict:
    findings: list[AuditFinding] = []
    score_risk = 0  # only genuinely-risky signals feed the numeric score

    try:
        score_norm = float(report.get("score_normalised") or report.get("score") or 0)
    except (TypeError, ValueError):
        score_norm = 0.0

    rugged = bool(report.get("rugged"))
    is_honeypot = rugged or any(
        "honeypot" in str(r.get("name", "") + r.get("desc", "") + r.get("description", "")).lower()
        for r in (report.get("risks") or [])
    )

    if rugged:
        findings.append(AuditFinding(
            severity="critical",
            title="Rugged / Abandoned",
            description="This token has been flagged as rugged or abandoned.",
        ))
        score_risk += 60

    # RugCheck's own risk items feed both the findings list and the score.
    _sev_weight = {"critical": 25, "high": 20, "medium": 10, "low": 5, "info": 0}
    for r in (report.get("risks") or []):
        name = r.get("name") or r.get("title") or "Risk detected"
        desc = r.get("desc") or r.get("description") or ""
        sev = _sev_from_level(r.get("level"), name + " " + desc)
        findings.append(AuditFinding(severity=sev, title=str(name), description=str(desc)))
        score_risk += _sev_weight.get(sev, 10)

    # Informational authority/feature findings. These are standard on Solana
    # (USDC itself has them) so they are SHOWN but NOT scored — RugCheck already
    # accounts for them in score_normalised.
    mint_auth = report.get("mintAuthority")
    freeze_auth = report.get("freezeAuthority")
    if mint_auth:
        findings.append(AuditFinding(
            severity="low",
            title="Mint Authority Enabled",
            description="The mint authority is still active — new tokens can be minted. Common on legitimate tokens but can be abused.",
        ))
    if freeze_auth:
        findings.append(AuditFinding(
            severity="low",
            title="Freeze Authority Enabled",
            description="The freeze authority is still active — holder accounts can be frozen. Common on legitimate tokens but can be abused.",
        ))

    lp_pct = report.get("lpLockedPct")
    liquidity_locked: Optional[bool] = None
    if isinstance(lp_pct, (int, float)):
        liquidity_locked = lp_pct >= 80
        if lp_pct < 50:
            findings.append(AuditFinding(
                severity="high",
                title="Liquidity Mostly Unlocked",
                description=f"Only {lp_pct:.1f}% of liquidity is locked.",
            ))
            score_risk += 20
        elif lp_pct < 80:
            findings.append(AuditFinding(
                severity="medium",
                title="Partial Liquidity Lock",
                description=f"{lp_pct:.1f}% of liquidity is locked.",
            ))
            score_risk += 10

    if report.get("transferFee"):
        findings.append(AuditFinding(
            severity="low",
            title="Transfer Fee Present",
            description=f"Token charges a transfer fee: {report.get('transferFee')}",
        ))

    # Holder concentration (best-effort — shape varies across tokens).
    try:
        top = (report.get("topHolders") or [])[:1]
        if top:
            raw = top[0].get("pct") or top[0].get("percentage") or top[0].get("percent")
            if raw is not None:
                pct = float(raw)
                if pct <= 1:
                    pct *= 100
                if pct > 50:
                    findings.append(AuditFinding(
                        severity="high",
                        title="Holder Concentration",
                        description=f"The top holder controls {pct:.1f}% of supply.",
                    ))
                    score_risk += 20
    except (TypeError, ValueError):
        pass

    # Final score: RugCheck's own normalized risk (authoritative) takes
    # precedence, with our computed signal as a floor so genuinely-risky tokens
    # with a stale/zero upstream score are still flagged.
    risk_score = max(int(round(score_norm)), min(score_risk, 100))

    if not findings:
        findings.append(AuditFinding(
            severity="info",
            title="No Issues Found",
            description="RugCheck reports no known risks for this token.",
        ))

    return {
        "token_name": (report.get("tokenMeta") or {}).get("name") if isinstance(report.get("tokenMeta"), dict) else None,
        "token_symbol": (report.get("tokenMeta") or {}).get("symbol") if isinstance(report.get("tokenMeta"), dict) else None,
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "is_honeypot": is_honeypot,
        "buy_tax": None,
        "sell_tax": None,
        "is_open_source": None,
        "owner_renounced": mint_auth is None,
        "has_proxy": None,
        "liquidity_locked": liquidity_locked,
        "liquidity_locked_pct": float(lp_pct) if isinstance(lp_pct, (int, float)) else None,
        "findings": findings,
    }


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="OnchainLens",
    description="Token Security Audit API — honeypot, ownership, liquidity and authority checks for EVM & Solana.",
    version=VERSION,
    lifespan=lifespan,
)

allow_origins = ["*"] if CORS_ORIGINS.strip() == "*" else [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-RateLimit-Remaining", "Retry-After", "PAYMENT-REQUIRED"],
)
if CORS_ORIGINS.strip() == "*":
    logger.warning("CORS is open to all origins (*). Set CORS_ORIGINS for production.")


@app.get("/")
async def root():
    return {
        "service": "OnchainLens",
        "version": VERSION,
        "endpoints": {
            "audit": "POST /audit  (body: {contract_address, chain})",
            "health": "GET /health",
            "docs": "/docs",
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "OnchainLens", "version": VERSION}


@app.get("/audit")
async def audit_info():
    """Public, unauthenticated info about the /audit endpoint.

    Lets reachability probes (GET/HEAD) see a 200 instead of 405, and tells
    callers how to use the paid POST endpoint.
    """
    return {
        "service": "OnchainLens",
        "endpoint": "POST /audit",
        "description": (
            "Token security audit (EVM via GoPlus, Solana via RugCheck). "
            "When OKX keys are configured, POST is gated by x402 "
            "(0.2 USDT0/call on X Layer, gas-free)."
        ),
        "usage": {
            "contract_address": "0x... (EVM) or base58 (Solana)",
            "chain": "ethereum|bsc|polygon|arbitrum|optimism|base|avalanche|fantom|solana",
        },
        "payment": "POST without payment returns HTTP 402 + PAYMENT-REQUIRED challenge.",
    }


@app.post("/audit", response_model=AuditResponse)
async def audit_token(
    req: AuditRequest,
    request: Request,
    _rl: None = Depends(rate_limit),
    _auth: None = Depends(require_auth),
):
    address = req.contract_address.strip()
    chain_key = req.chain.strip().lower()

    if chain_key not in CHAIN_IDS:
        supported = sorted({k for k in CHAIN_IDS if not k.isdigit() and k != "sol"})
        raise HTTPException(400, f"Unsupported chain: '{req.chain}'. Supported: {', '.join(supported)}")

    chain_id = CHAIN_IDS[chain_key]
    is_solana = chain_id == "solana"

    if is_solana:
        if not SOLANA_RE.match(address):
            raise HTTPException(400, "Invalid Solana address format.")
        provider = "rugcheck"
    else:
        if not EVM_RE.match(address):
            raise HTTPException(400, "Invalid EVM address format (expected 0x + 40 hex chars).")
        provider = "goplus"

    cache_key = f"{provider}:{chain_id}:{address.lower()}"
    cached = await cache_get(cache_key)
    upstream_ms = None

    if cached is not None:
        logger.info("cache HIT %s %s", provider, address)
        raw = cached
    else:
        start = time.time()
        try:
            raw = await (scan_rugcheck(address) if is_solana else scan_goplus(chain_id, address))
        except TokenNotFoundError as e:
            logger.info("not found %s %s", provider, address)
            raise HTTPException(404, str(e))
        except UpstreamError as e:
            logger.error("upstream error %s %s: %s", provider, address, e.message)
            raise HTTPException(e.status_code, e.message)
        upstream_ms = int((time.time() - start) * 1000)
        await cache_set(cache_key, raw, CACHE_TTL)
        logger.info("scan %s %s -> %sms", provider, address, upstream_ms)

    norm = assess_rugcheck(raw, address) if is_solana else assess_goplus(raw)

    return AuditResponse(
        contract_address=address,
        chain=req.chain,
        provider=provider,
        token_name=norm["token_name"],
        token_symbol=norm["token_symbol"],
        risk_score=norm["risk_score"],
        risk_level=norm["risk_level"],
        is_honeypot=norm["is_honeypot"],
        buy_tax=norm["buy_tax"],
        sell_tax=norm["sell_tax"],
        is_open_source=norm["is_open_source"],
        owner_renounced=norm["owner_renounced"],
        has_proxy=norm["has_proxy"],
        liquidity_locked=norm["liquidity_locked"],
        liquidity_locked_pct=norm["liquidity_locked_pct"],
        findings=norm["findings"],
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ── x402 pay-per-call (OKX A2MCP paid mode) ──────────────────────────────────
# When OKX facilitator credentials are present, POST /audit becomes an x402
# endpoint: a caller with no payment gets HTTP 402 + a PAYMENT-REQUIRED challenge;
# after paying (USDT0 on X Layer, gas-free), the request is replayed and served.
# Requires: pip install okxweb3-app-x402[evm,fastapi]  (OKX-branded Coinbase x402 SDK, Alpha)
# Env: OKX_API_KEY, OKX_SECRET_KEY, OKX_PASSPHRASE  (OKX Developer Portal API key)
#      X402_PAY_TO   (default: your EVM wallet)
#      X402_PRICE    (default: "$0.20" = 0.2 USDT0 per call)
OKX_API_KEY = os.getenv("OKX_API_KEY")
OKX_SECRET_KEY = os.getenv("OKX_SECRET_KEY")
OKX_PASSPHRASE = os.getenv("OKX_PASSPHRASE")
X402_PAY_TO = os.getenv("X402_PAY_TO", "0xf5fbbf435ecc12542992db5c9e14e117a90059c4")
X402_PRICE = os.getenv("X402_PRICE", "$0.20")

if OKX_API_KEY and OKX_SECRET_KEY and OKX_PASSPHRASE:
    try:
        from x402.server import x402ResourceServer
        from x402.http.okx_facilitator_client import OKXFacilitatorClient
        from x402.http import (
            OKXFacilitatorConfig,
            OKXAuthConfig,
            RouteConfig,
            PaymentOption,
        )
        from x402.http.middleware.fastapi import payment_middleware
        from x402.mechanisms.evm.exact.server import ExactEvmScheme
        from x402.schemas import SupportedResponse, SupportedKind

        # The SDK calls facilitator.get_supported() -- a *synchronous, blocking*
        # HTTP call to web3.okx.com -- while building the 402 challenge. On
        # serverless (Vercel) this blocks the event loop and the request times
        # out before the 402 is ever returned (this is exactly OKX review reason
        # #3: "no response / timeout"). Our supported set is static (exact scheme,
        # X Layer eip155:196, USDT0), so short-circuit it to a constant -- no
        # network, no blocking call. verify/settle are still real (async) calls.
        _STATIC_SUPPORTED = SupportedResponse(
            kinds=[SupportedKind(x402Version=2, scheme="exact", network="eip155:196")]
        )

        def _static_get_supported(self):
            return _STATIC_SUPPORTED

        OKXFacilitatorClient.get_supported = _static_get_supported
        try:  # sync variant may or may not be present in this SDK build
            from x402.http.okx_facilitator_client import OKXFacilitatorClientSync

            OKXFacilitatorClientSync.get_supported = _static_get_supported
        except Exception:
            pass

        _facilitator = OKXFacilitatorClient(
            OKXFacilitatorConfig(
                auth=OKXAuthConfig(
                    api_key=OKX_API_KEY,
                    secret_key=OKX_SECRET_KEY,
                    passphrase=OKX_PASSPHRASE,
                ),
                base_url="https://web3.okx.com",
            )
        )
        _resource_server = x402ResourceServer(_facilitator)
        _resource_server.register("eip155:196", ExactEvmScheme())
        _routes = {
            "POST /audit": RouteConfig(
                accepts=[
                    PaymentOption(
                        scheme="exact",
                        network="eip155:196",
                        pay_to=X402_PAY_TO,
                        price=X402_PRICE,
                        max_timeout_seconds=300,
                    )
                ],
                description="OnchainLens Token Security Audit (EVM + Solana)",
                mime_type="application/json",
            )
        }
        def _make_x402_middleware():
            """Wrap the SDK payment middleware so the 402 carries the base64
            challenge in BOTH the (uppercase) PAYMENT-REQUIRED header and the
            JSON *body*. The OKX x402 validator reads + base64-decodes the body,
            so the body must contain the *raw* base64 challenge -- not the decoded
            JSON (JSONResponse would quote it into "eyJ...") and not an empty body.

            Done by wrapping payment_middleware directly (not via a separate outer
            middleware) to avoid nested BaseHTTPMiddleware header-propagation
            quirks that bite on serverless (Vercel/uvicorn) runtimes.
            """
            _inner = payment_middleware(routes=_routes, server=_resource_server)

            async def _mw(request, call_next):
                resp = await _inner(request, call_next)
                if resp.status_code == 402:
                    raw = resp.headers.get("Payment-Required")
                    if raw:
                        new = Response(
                            content=raw,
                            media_type="application/json",
                            status_code=402,
                        )
                        for k, v in resp.headers.items():
                            new.headers[k] = v
                        new.headers["PAYMENT-REQUIRED"] = raw
                        return new
                return resp

            return _mw

        app.middleware("http")(_make_x402_middleware())

        logger.info("x402 paid mode ENABLED for POST /audit @ %s/call (X Layer USDT0)", X402_PRICE)
    except Exception as e:  # pragma: no cover - defensive
        logger.exception("x402 init failed; /audit remains free: %s", e)
else:
    logger.info("x402 paid mode DISABLED (set OKX_API_KEY/OKX_SECRET_KEY/OKX_PASSPHRASE to enable). /audit is free.")
