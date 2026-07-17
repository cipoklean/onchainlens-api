"""Tests for OnchainLens. Upstream scanners are mocked so tests run offline."""

import pytest
from fastapi.testclient import TestClient

import main


# ── Canned upstream payloads ────────────────────────────────────────────────
GOOD_EVM = {
    "buy_tax": "0", "sell_tax": "0", "is_honeypot": "0", "is_renounced": "1",
    "is_proxy": "0", "is_open_source": "1", "token_name": "Test", "token_symbol": "TST",
    "owner_address": "0x0000000000000000000000000000000000000000",
}
HONEYPOT_EVM = {**GOOD_EVM, "is_honeypot": "1"}
LP_UNLOCKED_EVM = {
    **GOOD_EVM,
    "lp_holders": [{"address": "0xabc", "balance": "1", "percent": "1", "is_locked": 0}],
}
GOOD_SOL = {
    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "score": 1, "score_normalised": 5, "rugged": False,
    "mintAuthority": {"owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
    "freezeAuthority": None, "lpLockedPct": 95.4, "risks": [], "topHolders": [],
    "tokenMeta": {"name": "Sol", "symbol": "SOLT"},
}


@pytest.fixture(autouse=True)
def _clear_state(monkeypatch):
    monkeypatch.setattr(main, "_cache", {})
    monkeypatch.setattr(main, "_rl", {})
    yield


@pytest.fixture
def client():
    with TestClient(main.app) as c:
        yield c


# ── Validation ───────────────────────────────────────────────────────────────
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "audit" in r.json()["endpoints"]


def test_invalid_chain(client):
    r = client.post("/audit", json={"contract_address": "0x" + "a" * 40, "chain": "bitcoin"})
    assert r.status_code == 400


def test_invalid_evm_address(client):
    r = client.post("/audit", json={"contract_address": "0x123", "chain": "ethereum"})
    assert r.status_code == 400


def test_invalid_solana_address(client):
    r = client.post("/audit", json={"contract_address": "0x123", "chain": "solana"})
    assert r.status_code == 400


def test_supported_chain_aliases():
    for alias in ["eth", "1", "bsc", "polygon", "arb", "op", "avax", "base", "ftm", "sol"]:
        assert alias in main.CHAIN_IDS


# ── EVM audit path ─────────────────────────────────────────────────────────────
def test_audit_success_evm(client, monkeypatch):
    async def fake(cid, addr):
        return GOOD_EVM
    monkeypatch.setattr(main, "scan_goplus", fake)

    r = client.post("/audit", json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"})
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] == "goplus"
    assert body["risk_score"] == 0
    assert body["risk_level"] == "SAFE"
    assert body["is_honeypot"] is False
    assert body["liquidity_locked"] is None  # no lp_holders present -> unknown, not falsely "locked"


def test_audit_honeypot_evm(client, monkeypatch):
    async def fake(cid, addr):
        return HONEYPOT_EVM
    monkeypatch.setattr(main, "scan_goplus", fake)

    r = client.post("/audit", json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "eth"})
    assert r.status_code == 200
    body = r.json()
    assert body["is_honeypot"] is True
    assert body["risk_score"] == 100
    assert body["risk_level"] == "CRITICAL"


def test_audit_liquidity_not_locked(client, monkeypatch):
    async def fake(cid, addr):
        return LP_UNLOCKED_EVM
    monkeypatch.setattr(main, "scan_goplus", fake)

    r = client.post("/audit", json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"})
    body = r.json()
    assert body["liquidity_locked"] is False
    assert any(f["title"] == "Liquidity Not Locked" for f in body["findings"])


def test_audit_token_not_found(client, monkeypatch):
    async def fake(cid, addr):
        raise main.TokenNotFoundError("nope")
    monkeypatch.setattr(main, "scan_goplus", fake)
    r = client.post("/audit", json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"})
    assert r.status_code == 404


def test_audit_upstream_error(client, monkeypatch):
    async def fake(cid, addr):
        raise main.UpstreamError("boom", 502)
    monkeypatch.setattr(main, "scan_goplus", fake)
    r = client.post("/audit", json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"})
    assert r.status_code == 502


def test_audit_caches_upstream(client, monkeypatch):
    calls = {"n": 0}

    async def fake(cid, addr):
        calls["n"] += 1
        return GOOD_EVM
    monkeypatch.setattr(main, "scan_goplus", fake)

    payload = {"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"}
    r1 = client.post("/audit", json=payload)
    r2 = client.post("/audit", json=payload)
    assert r1.status_code == 200 and r2.status_code == 200
    assert calls["n"] == 1  # second call served from cache


# ── Solana audit path ───────────────────────────────────────────────────────────
def test_audit_solana_success(client, monkeypatch):
    async def fake(addr):
        return GOOD_SOL
    monkeypatch.setattr(main, "scan_rugcheck", fake)

    r = client.post("/audit", json={"contract_address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "chain": "solana"})
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] == "rugcheck"
    assert body["liquidity_locked"] is True  # lpLockedPct 95.4 >= 80
    assert body["owner_renounced"] is False  # mint authority present
    assert 0 <= body["risk_score"] <= 100
    assert body["scan_timestamp"].endswith(("+00:00", "Z")) or "T" in body["scan_timestamp"]


def test_audit_solana_not_found(client, monkeypatch):
    async def fake(addr):
        raise main.TokenNotFoundError("nope")
    monkeypatch.setattr(main, "scan_rugcheck", fake)
    r = client.post("/audit", json={"contract_address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "chain": "solana"})
    assert r.status_code == 404


# ── Auth ────────────────────────────────────────────────────────────────────────
def test_auth_required_rejects_without_token(client, monkeypatch):
    monkeypatch.setattr(main, "API_BEARER_TOKEN", "secret")
    async def fake(cid, addr):
        return GOOD_EVM
    monkeypatch.setattr(main, "scan_goplus", fake)
    r = client.post("/audit", json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"})
    assert r.status_code == 401


def test_auth_required_accepts_valid_token(client, monkeypatch):
    monkeypatch.setattr(main, "API_BEARER_TOKEN", "secret")
    async def fake(cid, addr):
        return GOOD_EVM
    monkeypatch.setattr(main, "scan_goplus", fake)
    r = client.post(
        "/audit",
        json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"},
        headers={"Authorization": "Bearer secret"},
    )
    assert r.status_code == 200


def test_open_mode_allows_unauthenticated(client):
    # API_BEARER_TOKEN unset at import -> open mode
    assert main.API_BEARER_TOKEN is None
