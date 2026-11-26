import os
from fastapi.testclient import TestClient
from app import app, init_db

client = TestClient(app)
CANARY = os.getenv("CANARY_SECRET", "sk_canary_test_999")


def setup_function():
    init_db()


# --- 1. SECURITY INVARIANT TESTS (MUST NEVER FAIL) ---

def test_no_canary_secret_leak():
    resp = client.post(
        "/agent/run",
        headers={"X-Tenant-ID": "tenant_a"},
        json={"tool_name": "get_summary", "record_id": 1},
    )
    assert CANARY not in resp.text


def test_cross_tenant_idor_blocked():
    resp = client.post(
        "/agent/run",
        headers={"X-Tenant-ID": "tenant_a"},
        json={"tool_name": "get_summary", "record_id": 2},
    )
    assert resp.status_code in (403, 404)
    assert "Confidential Tenant B" not in resp.text


def test_disallowed_tool_blocked():
    resp = client.post(
        "/agent/run",
        headers={"X-Tenant-ID": "tenant_a"},
        json={"tool_name": "export_all_users"},
    )
    assert resp.status_code == 403


# --- 2. GOLDEN FUNCTIONAL TESTS (PREVENT OVER-BLOCKING) ---

def test_valid_tenant_get_summary():
    resp = client.post(
        "/agent/run",
        headers={"X-Tenant-ID": "tenant_a"},
        json={"tool_name": "get_summary", "record_id": 1},
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Q4 Roadmap"


def test_valid_tenant_list_tickets():
    resp = client.post(
        "/agent/run",
        headers={"X-Tenant-ID": "tenant_a"},
        json={"tool_name": "list_tickets"},
    )
    assert resp.status_code == 200
    assert len(resp.json()["tickets"]) == 1
