"""OnchainLens — Token Security Audit API

A2MCP-compatible endpoint for real-time token security scanning.
Accepts a contract address + chain, returns a structured risk report.
"""

import asyncio
import os
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="OnchainLens",
    description="Token Security Audit API — honeypot, ownership, and liquidity checks",
    version="1.0.0",
)

# ── Chain mapping ──────────────────────────────────────────────────────────
CHAIN_IDS: dict[str, str] = {
    "ethereum": "1",
    "eth": "1",
    "1": "1",
    "bsc": "56",
    "binance": "56",
    "56": "56",
    "polygon": "137",
    "matic": "137",
    "137": "137",
    "arbitrum": "42161",
    "arb": "42161",
    "42161": "42161",
    "optimism": "10",
    "op": "10",
    "10": "10",
    "avalanche": "43114",
    "avax": "43114",
    "43114": "43114",
    "base": "8453",
    "8453": "8453",
    "fantom": "250",
    "ftm": "250",
    "250": "250",
    "solana": "solana",
    "sol": "solana",
}

# ── Models ──────────────────────────────────────────────────────────────────


class AuditRequest(BaseModel):
    contract_address: str = Field(
        ..., description="Token contract address to audit (0x... for EVM, base58 for Solana)"
    )
    chain: str = Field(
        default="ethereum",
        description="Chain name or ID (ethereum, bsc, polygon, arbitrum, optimism, base, avalanche, solana)",
    )


class AuditFinding(BaseModel):
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str


class AuditResponse(BaseModel):
    contract_address: str
    chain: str
    token_name: Optional[str] = None
    token_symbol: Optional[str] = None
    risk_score: int = Field(..., ge=0, le=100, description="0 = safe, 100 = extreme risk")
    risk_level: str  # "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    is_honeypot: bool
    buy_tax: Optional[str] = None
    sell_tax: Optional[str] = None
    is_open_source: bool = False
    owner_renounced: bool = False
    has_proxy: bool = False
    liquidity_locked: Optional[bool] = None
    findings: list[AuditFinding] = []
    scan_timestamp: str


# ── GoPlus integration ──────────────────────────────────────────────────────

GOPLUS_URL = "https://api.gopluslabs.io/api/v1/token_security"


async def scan_goplus(chain_id: str, address: str) -> dict:
    """Query GoPlus Security API (free tier, no key needed)."""
    url = f"{GOPLUS_URL}/{chain_id}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, params={"contract_addresses": address})
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != 1:
            raise HTTPException(502, f"GoPlus scan failed: {data.get('message', 'unknown error')}")
        result = data.get("result", {})
        address_lower = address.lower()
        return result.get(address_lower, result.get(address, {}))


async def scan_solana(address: str) -> dict:
    """Basic Solana token check via public APIs."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(
                "https://public-api.solscan.io/token/meta",
                params={"tokenAddress": address},
            )
            if resp.status_code == 200:
                meta = resp.json()
                return {
                    "token_name": meta.get("name", ""),
                    "token_symbol": meta.get("symbol", ""),
                    "is_open_source": True,
                    "owner_renounced": False,
                    "is_honeypot": False,
                }
        except Exception:
            pass
    return {}


def assess_risk(goplus_result: dict) -> tuple[int, str, bool, list[AuditFinding]]:
    """Convert GoPlus results into a structured risk report."""
    findings: list[AuditFinding] = []
    risk = 0

    is_honeypot_raw = goplus_result.get("is_honeypot", "0")
    is_honeypot = is_honeypot_raw in ("1", 1, True)

    if is_honeypot:
        findings.append(AuditFinding(
            severity="critical",
            title="Honeypot Detected",
            description="This token prevents selling. Buyers cannot transfer or sell tokens after purchase.",
        ))
        return 100, "CRITICAL", True, findings

    # Buy / sell tax
    buy_tax_str = goplus_result.get("buy_tax", "0")
    sell_tax_str = goplus_result.get("sell_tax", "0")
    buy_tax = float(buy_tax_str) if buy_tax_str else 0
    sell_tax = float(sell_tax_str) if sell_tax_str else 0

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

    # Ownership
    is_renounced = goplus_result.get("is_renounced", "0") in ("1", 1, True)
    if not is_renounced:
        owner = goplus_result.get("owner_address", "")
        if owner and owner != "0x0000000000000000000000000000000000000000":
            findings.append(AuditFinding(
                severity="medium",
                title="Ownership Not Renounced",
                description=f"Owner ({owner[:10]}...) retains control — they can modify the contract.",
            ))
            risk += 15

    # Proxy
    is_proxy = goplus_result.get("is_proxy", "0") in ("1", 1, True)
    if is_proxy:
        findings.append(AuditFinding(
            severity="low",
            title="Proxy Contract",
            description="This is a proxy — the implementation can be upgraded by the owner.",
        ))
        risk += 5

    # Open source
    is_open = goplus_result.get("is_open_source", "0") in ("1", 1, True)
    if not is_open:
        findings.append(AuditFinding(
            severity="low",
            title="Closed Source",
            description="Contract source is not verified — code cannot be audited.",
        ))
        risk += 10

    # Liquidity
    is_lp_locked = goplus_result.get("lp_holders") or goplus_result.get("is_in_dex", "0") in ("1", 1, True)

    # Transfer pausable
    can_pause = goplus_result.get("transfer_pausable", "0") in ("1", 1, True)
    if can_pause:
        findings.append(AuditFinding(
            severity="high",
            title="Transfer Can Be Paused",
            description="Owner can freeze all transfers — rug-pull risk.",
        ))
        risk += 20

    # Mint function
    can_mint = goplus_result.get("is_mintable", "0") in ("1", 1, True)
    if can_mint and not is_renounced:
        findings.append(AuditFinding(
            severity="medium",
            title="Mintable Token",
            description="Owner can mint unlimited new tokens, diluting holders.",
        ))
        risk += 10

    # Blacklist
    can_blacklist = goplus_result.get("is_blacklisted", "0") in ("1", 1, True)
    if can_blacklist:
        findings.append(AuditFinding(
            severity="high",
            title="Blacklist Function",
            description="Owner can blacklist addresses, preventing them from trading.",
        ))
        risk += 15

    risk = min(risk, 95)

    if risk >= 60:
        level = "CRITICAL"
    elif risk >= 35:
        level = "HIGH"
    elif risk >= 15:
        level = "MEDIUM"
    elif risk >= 5:
        level = "LOW"
    else:
        level = "SAFE"

    if not findings:
        findings.append(AuditFinding(
            severity="info",
            title="No Issues Found",
            description="GoPlus reports no known vulnerabilities for this token.",
        ))

    return risk, level, is_honeypot, findings


# ── Routes ──────────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    return {"status": "ok", "service": "OnchainLens", "version": "1.0.0"}


@app.post("/audit", response_model=AuditResponse)
async def audit_token(req: AuditRequest):
    """Audit a token contract for security risks."""
    import datetime

    address = req.contract_address.strip()
    chain_key = req.chain.strip().lower()

    if chain_key not in CHAIN_IDS:
        raise HTTPException(
            400,
            f"Unsupported chain: '{req.chain}'. Supported: {', '.join(sorted(set(k for k in CHAIN_IDS if not k.isdigit())))}",
        )

    chain_id = CHAIN_IDS[chain_key]

    if chain_id == "solana":
        sol_data = await scan_solana(address)
        risk_score = 5
        risk_level = "LOW"
        is_honeypot = False
        findings = [
            AuditFinding(
                severity="info",
                title="Solana — Limited Scan",
                description="Solana audit is basic (meta-only). Full analysis coming soon.",
            )
        ]
        buy_tax = None
        sell_tax = None
        is_open = sol_data.get("is_open_source", False)
        is_renounced = sol_data.get("owner_renounced", False)
        has_proxy = False
        lp_locked = None
        token_name = sol_data.get("token_name")
        token_symbol = sol_data.get("token_symbol")
    else:
        goplus = await scan_goplus(chain_id, address)
        risk_score, risk_level, is_honeypot, findings = assess_risk(goplus)
        buy_tax = goplus.get("buy_tax", "0") + "%" if goplus.get("buy_tax") else None
        sell_tax = goplus.get("sell_tax", "0") + "%" if goplus.get("sell_tax") else None
        is_open = goplus.get("is_open_source", "0") in ("1", 1, True)
        is_renounced = goplus.get("is_renounced", "0") in ("1", 1, True)
        has_proxy = goplus.get("is_proxy", "0") in ("1", 1, True)
        lp_locked = goplus.get("lp_holders") is not None or goplus.get("is_in_dex", "0") in ("1", 1, True)
        token_name = goplus.get("token_name", "")
        token_symbol = goplus.get("token_symbol", "")

    return AuditResponse(
        contract_address=address,
        chain=req.chain,
        token_name=token_name or None,
        token_symbol=token_symbol or None,
        risk_score=risk_score,
        risk_level=risk_level,
        is_honeypot=is_honeypot,
        buy_tax=buy_tax,
        sell_tax=sell_tax,
        is_open_source=is_open,
        owner_renounced=is_renounced,
        has_proxy=has_proxy,
        liquidity_locked=lp_locked,
        findings=findings,
        scan_timestamp=datetime.datetime.utcnow().isoformat() + "Z",
    )
