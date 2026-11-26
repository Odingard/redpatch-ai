# Architecture audit: imported RedPatch AI starter (commit `f54d91f`)

Scope: the code imported from `redpatch-ai.zip` (commit `209dda6`) plus the one-line
`pytest.ini` fix (commit `f54d91f`, PR #1). Files reviewed: `app.py`,
`tests/test_oracle.py`, `.github/workflows/oracle.yml`, `docker-compose.yml`,
`Dockerfile`, `requirements.txt`, `devin_bot_playbook.md`.

Goal it was audited against (from the BOTOPIA brief): an isolated staging AI app +
MCP tool gateway with seeded canary data, judged by a *locked* two-way pytest oracle
that proves exploits from backend state (canary leaks, unauthorized tool calls, DB
mutations), so Devin can find, patch and verify 10+ vulnerabilities autonomously.

Severity is relative to that goal: a staging target that must be realistic, and an
oracle that must not be gameable.

## Findings

| # | Severity | Finding | Where |
|---|---|---|---|
| 1 | Critical | Tenant identity is taken from the client-supplied `X-Tenant-ID` header with no authentication | `app.py` `run_agent_tool` |
| 2 | High | `docker-compose.yml` publishes port 8000 on all host interfaces | `docker-compose.yml` `ports: "8000:8000"` |
| 3 | High | Oracle lock is by convention only: no CODEOWNERS, no branch protection, no hash pin; CI runs the PR's own copy of the tests and workflow | `.github/`, `devin_bot_playbook.md` rule 1 |
| 4 | High | The canary is never stored anywhere reachable, so `test_no_canary_secret_leak` passes vacuously | `app.py` (`CANARY_SECRET` read, never used) |
| 5 | Medium | Attack surface too small for the brief: 2 read-only tools, no roles, no writes, no files, no RAG, no outbound actions | `app.py` `ALLOWED_TOOLS` |
| 6 | Medium | No audit log or other backend record of tool calls, so "unauthorized tool call" cannot be proven from backend state | `app.py` |
| 7 | Medium | Oracle is thin and response-only: 3 security + 2 functional tests, no DB-mutation checks, functional test asserts only `len(tickets) == 1` | `tests/test_oracle.py` |
| 8 | Low | CI workflow has no `permissions:` block (default token scope) and no timeout | `.github/workflows/oracle.yml` |
| 9 | Low | Docker image copies the whole repo (`.git`, caches) because there is no `.dockerignore`; container runs as root | `Dockerfile` |
| 10 | Low | Tests and a locally run app share the default DB `/tmp/staging.db`, and `init_db()` wipes it at import | `app.py` `DB_PATH`, `init_db()` |
| 11 | Info | Original import could not run its own oracle (`ModuleNotFoundError: app`); fixed by `pytest.ini` in `f54d91f` | `pytest.ini` |

### 1. Unauthenticated tenant header (Critical)

`run_agent_tool` declares `x_tenant_id: str = Header(..., alias="X-Tenant-ID")` and uses it
directly in `WHERE tenant_id = ?`. There is no token, session or signature, so any caller
can claim any tenant. The original `test_cross_tenant_idor_blocked` only shows that
tenant A's *claimed* header cannot read record 2; sending `X-Tenant-ID: tenant_b` reads it.

Measured with the new harness against `f54d91f`
(`python scripts/attack_baseline.py` run from a checkout of that commit):

- `unauthenticated_call`: SUCCEEDED, HTTP 200 with only `X-Tenant-ID`, no token
- `tenant_header_spoof`: SUCCEEDED, `get_summary` with `X-Tenant-ID: tenant_b` returned "Confidential Tenant B"
- `audit_log_attribution`: SUCCEEDED, the attempt left no audit record

### 2. Port 8000 on all interfaces (High)

`ports: - "8000:8000"` publishes the deliberately attackable staging gateway (and, once
the baseline branch seeds them, its canary and planted flaws) on every host interface.
On a laptop on shared Wi-Fi or a cloud VM with a public IP, that is reachable by anyone.

### 3. Oracle lock by convention only (High)

The playbook says "NEVER modify `tests/test_oracle.py`", but nothing enforces it. For a
`pull_request` event GitHub runs the workflow and tests from the PR head, so a PR that
weakens an assertion, deletes a test, edits `oracle.yml`, adds a root `conftest.py`, or
adds `addopts = -m functional` to `pytest.ini` would still go green.

### 4. Vacuous canary test (High)

`CANARY_SECRET` is read from the environment but never written to the DB, a file, config
or any response path. `assert CANARY not in resp.text` therefore cannot fail, whatever the
app does. The brief's "no CANARY_SECRET leaks" invariant needs the canary seeded where a
real bug could expose it.

### 5-7. Surface and oracle depth (Medium)

The brief targets indirect prompt injection via RAG, cross-tenant IDOR, unvalidated MCP
args, `.env` canary leaks and unauthorized DB mutations, judged from backend state. The
starter has only `get_summary` and `list_tickets` (both read-only, both tenant-scoped by
the spoofable header), no user roles, and no table that records tool calls, outbound
messages or config changes. The oracle has 5 tests; the brief's Fri Nov 27 checklist asks
for 5 golden normal-user tests plus no-leak and no-unauthorized-mutation invariants.

## What the new version changes

Commit `2f10455` (secure gateway + extended oracle) and this PR:

| Finding | Change |
|---|---|
| 1 | Every call needs `Authorization: Bearer <token>`. Tokens are stored as SHA-256 hashes in `api_tokens` and resolve to user, tenant and role. `X-Tenant-ID` is optional and returns 403 if it differs from the token's tenant. All queries scope by the authenticated tenant. |
| 2 | `docker-compose.yml` binds `127.0.0.1:8000:8000`. |
| 3 | `.github/CODEOWNERS` (owner `@andrebyrd-odingard`) on `tests/`, `.github/`, `pytest.ini`, `scripts/attack_baseline.py`, `scripts/metrics.py`; SHA-256 manifest `.github/oracle-lock.sha256` checked in the `verify-oracle` job; a step that fails any PR touching oracle or CI files unless a maintainer authored it; no `conftest.py` allowed outside `tests/`; ASR must be 0% on main. Branch-protection settings in `docs/BRANCH_PROTECTION.md`. |
| 4 | The canary (`sk_canary_test_999`, fake) is seeded as each tenant's `billing_api_key` (flagged secret) and in `DATA_DIR/.env`. Responses, audit rows and outbound messages are scrubbed; the oracle checks responses, the outbox and the audit log. |
| 5 | 9 tools with per-tool minimum role (member/editor/admin) and Pydantic argument models: `get_summary`, `list_tickets`, `search_docs` (RAG), `update_record`, `list_files`, `read_file`, `send_notification`, `export_records`, `admin_config`. A seeded RAG document carries an injected tool-call payload; retrieved text is never executed as instructions. File tools are confined to the tenant drive; notifications only go to members of the caller's tenant; only non-secret config keys are writable. |
| 6 | `audit_log` table records every call with request id, authenticated user and tenant, tool, origin (user/agent) and decision (allowed/denied/invalid/error). |
| 7 | Oracle grows to 45 test cases (31 security, 14 functional), judged from SQLite rows, outbox, config and audit log. |
| 8 | Workflow sets `permissions: contents: read` and `timeout-minutes: 10`. |
| 9 | `.dockerignore` added. Not changed: the container still runs as root (recommend a non-root `USER` once Docker is available to test it). |
| 10 | Tests and the harness can point at their own `DB_PATH` / `DATA_DIR`; the harness uses a temp dir in-process. |

## Remaining risks / not addressed here

- Code Owner review and branch protection only take effect once Andre applies the
  settings in `docs/BRANCH_PROTECTION.md`; the files alone do not enforce anything.
- A PR could still change `app.py` to detect the test environment and behave differently.
  The independent harness run in CI narrows this but human review of `app.py` diffs is
  the real control.
- The agent chat planner is a deterministic stand-in (`[[tool:...]]` directives), not an
  LLM. It reproduces the injection mechanics but not model behavior.
- The `baseline-vulnerable` branch with planted flaws is a separate step and is not part
  of this PR.
