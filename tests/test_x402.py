"""Verify the x402 paid flow with a mocked OKX facilitator.

These tests prove, without any real network / facilitator / blockchain calls:

1. GET /audit is reachable (200) so liveness probes never see 405.
2. An unpaid POST /audit returns a spec-compliant 402 challenge, exposed both
   as the ``PAYMENT-REQUIRED`` header (uppercase, for case-sensitive validators)
   and as the decoded challenge in the JSON *body* (for body-reading validators).
3. When a payment is presented and verified, the real audit handler runs and
   returns 200 + a result (the pay -> verify -> replay -> 200 loop).

The verified-payment case is simulated by short-circuiting the SDK's
``process_http_request`` to "payment-verified" when a payment header is present
(a real signed payment requires a wallet). The unpaid case still exercises the
REAL SDK so the emitted 402 challenge is genuine.
"""
import importlib.util
import json
import os
import sys
import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from x402.schemas import (
    VerifyResponse,
    SettleResponse,
    SupportedResponse,
    SupportedKind,
)
from x402.http.x402_http_server import x402HTTPResourceServer

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MAIN_PATH = os.path.join(PROJECT_ROOT, "main.py")

_SAFE_EVM = {
    "buy_tax": "0", "sell_tax": "0", "is_honeypot": "0",
    "is_renounced": "1", "is_proxy": "0", "is_open_source": "1",
    "token_name": "Test", "token_symbol": "TST",
    "owner_address": "0x0000000000000000000000000000000000000000",
}


async def _safe_goplus(cid, addr):
    return _SAFE_EVM


def _load_paid_app(monkeypatch):
    # Force x402 to activate (needs all three OKX vars).
    monkeypatch.setenv("OKX_API_KEY", "dummy-key")
    monkeypatch.setenv("OKX_SECRET_KEY", "dummy-secret")
    monkeypatch.setenv("OKX_PASSPHRASE", "dummy-pass")
    monkeypatch.setenv("X402_PAY_TO", "0xf5fbbf435ecc12542992db5c9e14e117a90059c4")

    # Mock the OKX facilitator client so no real calls happen.
    def _make_client(*args, **kwargs):
        client = MagicMock()
        client.get_supported = MagicMock(
            return_value=SupportedResponse(
                kinds=[SupportedKind(x402Version=2, scheme="exact", network="eip155:196")]
            )
        )
        client.verify = AsyncMock(return_value=VerifyResponse(isValid=True))
        client.settle = AsyncMock(
            return_value=SettleResponse(
                success=True, status="success", transaction="0xmock", network="eip155:196"
            )
        )
        return client

    monkeypatch.setattr(
        "x402.http.okx_facilitator_client.OKXFacilitatorClient", _make_client
    )

    # Simulate a verified payment when a payment header is present; otherwise
    # fall through to the REAL SDK so the 402 challenge is genuinely produced.
    orig_process = x402HTTPResourceServer.process_http_request

    async def _fake_process(self, context, paywall_config=None):
        if context.payment_header:
            return SimpleNamespace(
                type="payment-verified", payment_payload={}, payment_requirements={}
            )
        return await orig_process(self, context, paywall_config)

    async def _fake_settle(self, *args, **kwargs):
        return SimpleNamespace(success=True, headers={}, response=None)

    monkeypatch.setattr(x402HTTPResourceServer, "process_http_request", _fake_process)
    monkeypatch.setattr(x402HTTPResourceServer, "process_settlement", _fake_settle)

    # Load main.py as a FRESH module (unique name) so we don't disturb the
    # shared `main` import used by the other test files. Registering it in
    # sys.modules first lets Pydantic resolve forward refs (e.g. AuditResponse
    # -> Optional["AuditFlag"]) at model-build time.
    spec = importlib.util.spec_from_file_location("onchainlens_x402_test", MAIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["onchainlens_x402_test"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def paid_app(monkeypatch):
    mod = _load_paid_app(monkeypatch)
    yield mod
    sys.modules.pop("onchainlens_x402_test", None)


def test_audit_info_reachable(paid_app):
    """GET /audit must return 200 (reachability probes must not see 405)."""
    from fastapi.testclient import TestClient

    with TestClient(paid_app.app) as c:
        r = c.get("/audit")
        assert r.status_code == 200
        assert r.json()["endpoint"] == "POST /audit"


def test_x402_unpaid_returns_402_challenge(paid_app, monkeypatch):
    monkeypatch.setattr(paid_app, "scan_goplus", _safe_goplus)

    from fastapi.testclient import TestClient

    with TestClient(paid_app.app) as c:
        r = c.post(
            "/audit",
            json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"},
        )
        assert r.status_code == 402
        # Challenge exposed (case-insensitive header lookup).
        assert "payment-required" in {k.lower() for k in r.headers}
        # Hardening: upper-case header copy.
        assert r.headers.get("PAYMENT-REQUIRED")
        # Hardening: base64 challenge mirrored into the body (the OKX validator
        # base64-decodes the body). Decode it to assert the challenge contents.
        challenge = json.loads(base64.b64decode(r.text).decode("utf-8"))
        assert challenge["x402Version"] == 2
        assert challenge["accepts"][0]["scheme"] == "exact"
        assert challenge["accepts"][0]["network"] == "eip155:196"
        assert challenge["accepts"][0]["asset"] == "0x779ded0c9e1022225f8e0630b35a9b54be713736"
        assert challenge["accepts"][0]["payTo"] == "0xf5fbbf435ecc12542992db5c9e14e117a90059c4"


def test_x402_paid_replay_returns_200(paid_app, monkeypatch):
    monkeypatch.setattr(paid_app, "scan_goplus", _safe_goplus)

    from fastapi.testclient import TestClient

    with TestClient(paid_app.app) as c:
        r = c.post(
            "/audit",
            json={"contract_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "chain": "ethereum"},
            headers={"payment-signature": "mock-payment-header"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["provider"] == "goplus"
        assert body["risk_level"] == "SAFE"
