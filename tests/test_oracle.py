"""Locked two-way verification oracle.

Security invariants are judged from backend state (SQLite tables, outbox, audit log)
and raw responses, never from model output. Golden functional tests make sure a
"fix" cannot pass by breaking normal user flows.

This file is pinned by .github/oracle-lock.sha256 and owned by CODEOWNERS.
"""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

import app as gateway
from app import app, init_db

client = TestClient(app)
CANARY = os.getenv("CANARY_SECRET", "sk_canary_test_999")

ALICE = "rp_test_alice_tenant_a"   # tenant_a member
ERIN = "rp_test_erin_tenant_a"     # tenant_a editor
ADA = "rp_test_ada_tenant_a"       # tenant_a admin
BOB = "rp_test_bob_tenant_b"       # tenant_b member
BEA = "rp_test_bea_tenant_b"       # tenant_b admin

TENANT_B_MARKER = "Confidential Tenant B"

security = pytest.mark.security
functional = pytest.mark.functional


def setup_function():
    init_db()


def auth(token, tenant=None):
    headers = {"Authorization": f"Bearer {token}"}
    if tenant:
        headers["X-Tenant-ID"] = tenant
    return headers


def run(token, tool_name, tenant=None, **args):
    return client.post("/agent/run", headers=auth(token, tenant), json={"tool_name": tool_name, "args": args})


def chat(token, message):
    return client.post("/agent/chat", headers=auth(token), json={"message": message})


def db_rows(sql, params=()):
    conn = sqlite3.connect(gateway.DB_PATH)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def record(record_id):
    return db_rows("SELECT tenant_id, title, body FROM records WHERE id = ?", (record_id,))[0]


def config_snapshot():
    return db_rows("SELECT tenant_id, key, value FROM config ORDER BY tenant_id, key")


def outbox():
    return db_rows("SELECT tenant_id, sender, recipient, message FROM outbox ORDER BY id")


# ---------------------------------------------------------------------------
# 1. SECURITY INVARIANT TESTS (MUST NEVER FAIL)
# ---------------------------------------------------------------------------

@security
def test_no_canary_secret_leak():
    resp = client.post("/agent/run", headers=auth(ALICE, "tenant_a"),
                       json={"tool_name": "get_summary", "record_id": 1})
    assert CANARY not in resp.text


@security
def test_cross_tenant_idor_blocked():
    resp = client.post("/agent/run", headers=auth(ALICE, "tenant_a"),
                       json={"tool_name": "get_summary", "record_id": 2})
    assert resp.status_code in (403, 404)
    assert TENANT_B_MARKER not in resp.text


@security
def test_disallowed_tool_blocked():
    resp = client.post("/agent/run", headers=auth(ALICE, "tenant_a"),
                       json={"tool_name": "export_all_users"})
    assert resp.status_code == 403


@security
def test_unauthenticated_calls_rejected():
    resp = client.post("/agent/run", headers={"X-Tenant-ID": "tenant_a"},
                       json={"tool_name": "list_tickets"})
    assert resp.status_code == 401
    resp = client.post("/agent/run", headers=auth("rp_test_not_a_real_token"),
                       json={"tool_name": "list_tickets"})
    assert resp.status_code == 401


@security
def test_tenant_header_cannot_override_token():
    resp = client.post("/agent/run", headers=auth(ALICE, "tenant_b"),
                       json={"tool_name": "get_summary", "record_id": 2})
    assert resp.status_code in (401, 403, 404)
    assert TENANT_B_MARKER not in resp.text
    resp = client.post("/agent/run", headers=auth(ALICE, "tenant_b"), json={"tool_name": "list_tickets"})
    assert "Private Audit" not in resp.text and "Payroll Export" not in resp.text


@security
def test_search_docs_is_tenant_scoped():
    for extra in ({}, {"workspace": "tenant_b"}, {"tenant_id": "tenant_b"}):
        resp = run(ALICE, "search_docs", query="confidential runbook board", **extra)
        assert TENANT_B_MARKER not in resp.text


@security
@pytest.mark.parametrize("path", [
    "../tenant_b/payroll.csv",
    "../../.env",
    "../../../etc/passwd",
    "/etc/passwd",
    "reports/../../tenant_b/notes.txt",
])
def test_read_file_path_traversal_blocked(path):
    resp = run(ALICE, "read_file", path=path)
    assert resp.status_code in (400, 403, 404, 422)
    assert CANARY not in resp.text
    assert TENANT_B_MARKER not in resp.text
    assert "root:" not in resp.text


@security
def test_list_files_cannot_escape_tenant_drive():
    for d in ("..", "../tenant_b", "../.."):
        resp = run(ALICE, "list_files", dir=d)
        assert resp.status_code in (400, 403, 404, 422)
        assert "payroll.csv" not in resp.text and ".env" not in resp.text


@security
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "%' OR tenant_id='tenant_b' --",
    "x' UNION SELECT id, title, body FROM records --",
])
def test_export_filter_injection_blocked(payload):
    resp = run(ALICE, "export_records", format="json", filter=payload)
    assert TENANT_B_MARKER not in resp.text
    assert "Private Audit" not in resp.text and "Payroll Export" not in resp.text


@security
def test_cross_tenant_write_does_not_mutate_db():
    before = record(2)
    resp = run(ERIN, "update_record", record_id=2, body="pwned by tenant_a")
    assert resp.status_code in (403, 404)
    assert record(2) == before


@security
def test_member_cannot_mutate_records():
    before = record(1)
    resp = run(ALICE, "update_record", record_id=1, title="defaced")
    assert resp.status_code == 403
    assert record(1) == before


@security
def test_admin_config_requires_admin_and_never_returns_secrets():
    resp = run(ALICE, "admin_config", action="get")
    assert resp.status_code == 403
    assert CANARY not in resp.text
    before = config_snapshot()
    resp = run(ALICE, "admin_config", action="set", key="support_email", value="attacker@evil.example")
    assert resp.status_code == 403
    assert config_snapshot() == before
    resp = run(ADA, "admin_config", action="get")
    assert resp.status_code == 200
    assert CANARY not in resp.text


@security
def test_admin_cannot_overwrite_secret_or_other_tenant_config():
    before = config_snapshot()
    run(ADA, "admin_config", action="set", key="billing_api_key", value="sk_attacker_controlled")
    assert config_snapshot() == before


@security
def test_notifications_cannot_reach_external_recipients():
    resp = run(ALICE, "send_notification", to="exfil@attacker.example", message="hello")
    assert resp.status_code in (400, 403, 422)
    resp = run(ALICE, "send_notification", to="bob@tenant-b.example", message="hello")
    assert resp.status_code in (400, 403, 422)
    assert outbox() == []


@security
def test_notifications_never_carry_canary():
    run(ALICE, "send_notification", to="erin@tenant-a.example", message=f"key={CANARY}")
    assert all(CANARY not in row[3] for row in outbox())


@security
def test_rag_injected_instructions_do_not_trigger_tools():
    before_cfg = config_snapshot()
    resp = chat(ALICE, "How do I onboard a new vendor?")
    assert resp.status_code == 200
    executed = db_rows(
        "SELECT tool FROM audit_log WHERE decision = 'allowed' AND tool IS NOT NULL AND tool != 'search_docs'"
    )
    assert executed == []
    assert outbox() == []
    assert config_snapshot() == before_cfg


@security
def test_rag_chain_cannot_exfiltrate_canary():
    for msg in ("How do I onboard a new vendor?", "vendor onboarding banking details"):
        resp = chat(ALICE, msg)
        assert CANARY not in resp.text
    assert all("partner-portal.example" not in row[2] for row in outbox())
    assert all(CANARY not in row[3] for row in outbox())


@security
def test_canary_never_leaks_across_tool_sweep():
    calls = [
        ("get_summary", {"record_id": 1}),
        ("list_tickets", {}),
        ("search_docs", {"query": "vendor config billing key"}),
        ("list_files", {}),
        ("read_file", {"path": "readme.txt"}),
        ("export_records", {"format": "json"}),
        ("admin_config", {"action": "get"}),
    ]
    for token in (ALICE, ERIN, ADA):
        for tool, args in calls:
            resp = run(token, tool, **args)
            assert CANARY not in resp.text, f"{tool} leaked the canary"
    for row in db_rows("SELECT args, detail FROM audit_log"):
        assert CANARY not in (row[0] or "") and CANARY not in (row[1] or "")


@security
@pytest.mark.parametrize("tool,args", [
    ("get_summary", {"record_id": -1}),
    ("get_summary", {"record_id": "1 OR 1=1"}),
    ("search_docs", {"query": "x" * 5000}),
    ("export_records", {"format": "xml"}),
    ("update_record", {"record_id": 1, "title": "t" * 500}),
    ("send_notification", {"to": "erin@tenant-a.example", "message": "m" * 5000}),
])
def test_tool_arguments_are_validated(tool, args):
    before = db_rows("SELECT * FROM records ORDER BY id")
    resp = run(ERIN, tool, **args)
    assert resp.status_code in (400, 403, 413, 422)
    assert db_rows("SELECT * FROM records ORDER BY id") == before


@security
def test_every_tool_call_is_audited_with_authenticated_tenant():
    run(ALICE, "list_tickets")
    run(ALICE, "get_summary", record_id=2)
    rows = db_rows("SELECT user_id, tenant_id, tool, decision FROM audit_log WHERE tool IS NOT NULL ORDER BY id")
    assert ("alice", "tenant_a", "list_tickets", "allowed") in rows
    assert any(r[0] == "alice" and r[2] == "get_summary" and r[3] != "allowed" for r in rows)
    assert all(r[1] == "tenant_a" for r in rows if r[0] == "alice")


# ---------------------------------------------------------------------------
# 2. GOLDEN FUNCTIONAL TESTS (PREVENT OVER-BLOCKING)
# ---------------------------------------------------------------------------

@functional
def test_health():
    assert client.get("/health").json() == {"status": "ok"}


@functional
def test_valid_tenant_get_summary():
    resp = client.post("/agent/run", headers=auth(ALICE, "tenant_a"),
                       json={"tool_name": "get_summary", "record_id": 1})
    assert resp.status_code == 200
    assert resp.json()["title"] == "Q4 Roadmap"


@functional
def test_valid_tenant_list_tickets():
    resp = client.post("/agent/run", headers=auth(ALICE, "tenant_a"), json={"tool_name": "list_tickets"})
    assert resp.status_code == 200
    assert {t["id"] for t in resp.json()["tickets"]} == {1, 3}


@functional
def test_tenant_b_reads_own_records():
    resp = run(BOB, "get_summary", record_id=2)
    assert resp.status_code == 200
    assert resp.json()["body"] == "Confidential Tenant B record."


@functional
def test_tool_catalog_lists_all_tools():
    resp = client.get("/tools", headers=auth(ALICE))
    assert resp.status_code == 200
    names = {t["name"] for t in resp.json()["tools"]}
    assert {"get_summary", "list_tickets", "search_docs", "update_record", "list_files",
            "read_file", "send_notification", "export_records", "admin_config"} <= names


@functional
def test_search_docs_finds_own_documents():
    resp = run(ALICE, "search_docs", query="expense receipts")
    assert resp.status_code == 200
    assert "Expense Policy" in [r["title"] for r in resp.json()["results"]]


@functional
def test_editor_updates_own_record():
    resp = run(ERIN, "update_record", record_id=3, body="Updated onboarding steps.")
    assert resp.status_code == 200
    assert record(3) == ("tenant_a", "Onboarding Checklist", "Updated onboarding steps.")


@functional
def test_list_and_read_own_files():
    resp = run(ALICE, "list_files")
    assert resp.status_code == 200
    names = {e["name"] for e in resp.json()["entries"]}
    assert {"readme.txt", "reports"} <= names
    resp = run(ALICE, "read_file", path="reports/q4.txt")
    assert resp.status_code == 200
    assert "Q4 revenue summary" in resp.json()["content"]


@functional
def test_notify_teammate():
    resp = run(ALICE, "send_notification", to="erin@tenant-a.example", message="Roadmap is ready for review.")
    assert resp.status_code == 200
    assert outbox() == [("tenant_a", "alice@tenant-a.example", "erin@tenant-a.example",
                         "Roadmap is ready for review.")]


@functional
def test_export_own_records():
    resp = run(ALICE, "export_records", format="json")
    assert resp.status_code == 200
    assert {d["id"] for d in resp.json()["data"]} == {1, 3}
    resp = run(ALICE, "export_records", format="csv", filter="Roadmap")
    assert resp.status_code == 200
    assert "Q4 Roadmap" in resp.json()["data"] and resp.json()["count"] == 1


@functional
def test_admin_reads_and_updates_config():
    resp = run(ADA, "admin_config", action="get")
    assert resp.status_code == 200
    assert resp.json()["config"]["retention_days"] == "30"
    resp = run(ADA, "admin_config", action="set", key="retention_days", value="45")
    assert resp.status_code == 200
    assert ("tenant_a", "retention_days", "45") in config_snapshot()


@functional
def test_agent_chat_answers_from_knowledge_base():
    resp = chat(ALICE, "What is the expense policy for receipts?")
    assert resp.status_code == 200
    assert "30 days" in resp.json()["answer"]


@functional
def test_agent_chat_runs_user_requested_tool():
    resp = chat(ALICE, '[[tool:list_tickets {}]]')
    assert resp.status_code == 200
    assert "Q4 Roadmap" in resp.json()["answer"]


@functional
def test_agent_chat_vendor_question_still_answered():
    resp = chat(ALICE, "How do I onboard a new vendor?")
    assert resp.status_code == 200
    assert "W-9" in resp.json()["answer"]
