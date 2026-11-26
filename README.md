# RedPatch AI

Autonomous, continuous boundary-verification and auto-patching Bot for AI apps, MCP
servers, and agent tool-chains. Built for Afore x Cognition BOTOPIA.

`main` is the **secure** reference: every oracle test passes and the Attack Success Rate
(ASR) is 0%. The planted-flaw target for the bot lives on the separate
`baseline-vulnerable` branch.

## Run everything (under 5 minutes)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt                    # FastAPI, uvicorn, pytest, httpx

pytest -q                                          # two-way oracle: 51 tests, all pass (own temp DB)
python scripts/attack_baseline.py --label secure   # ASR report -> reports/asr_secure.{json,md}
python scripts/metrics.py summary                  # attempts / blocked / PRs / human-message ratio
sha256sum -c .github/oracle-lock.sha256            # oracle files match the pinned hashes
```

Against the running container (bound to 127.0.0.1 only):

```bash
docker compose up --build -d
python scripts/attack_baseline.py --base-url http://127.0.0.1:8000 --label docker
```

Without `--db-path` the remote mode judges from HTTP evidence only and marks
backend-only checks as inconclusive; with `--max-asr` any inconclusive attack fails
the run. Run uvicorn locally with
`DB_PATH=/tmp/rp.db uvicorn app:app --host 127.0.0.1 --port 8000` and pass
`--db-path /tmp/rp.db` for full backend-state checks. Backend checks only count rows
written during each attack (per-attack `X-Request-ID` + id high-water marks), so a
long-lived gateway's old audit and outbox rows don't skew results.

## State: persistent by default, reset on request

The gateway keeps its SQLite DB (`DB_PATH`) and data dir (`DATA_DIR`) across restarts:
record edits, config, outbox and audit history survive. Seed data is written only on
first start (empty DB). To wipe and reseed at startup, opt in:

```bash
REDPATCH_RESET_ON_START=1 uvicorn app:app --host 127.0.0.1 --port 8000
# or in docker-compose.yml: - REDPATCH_RESET_ON_START=1
```

The oracle and the in-process harness never touch a running gateway's files: each
creates its own temp `DB_PATH`/`DATA_DIR` and calls `init_db(reset=True)` there.
`DATA_DIR` must be a real directory owned by the gateway user; startup refuses
symlinks and creates seeded files with `O_NOFOLLOW`, mode 0600.

Other guards: record edits use optimistic concurrency (`get_summary` returns
`version`; `update_record` accepts `expected_version` and returns 409 on a stale or
concurrent edit), CSV export uses Python's `csv` module, and audit fields are capped
at 1024 chars with the table pruned beyond `AUDIT_MAX_ROWS` (default 100000).

## Structure

- `app.py`: staging FastAPI multi-tenant MCP tool gateway. Bearer-token auth, SQLite,
  9 tools with per-tool roles and argument schemas, RAG search, audit log, seeded fake
  canary `sk_canary_test_999`.
- `tests/test_oracle.py`: locked two-way oracle (34 security cases judged from backend
  state + 17 golden functional tests).
- `scripts/attack_baseline.py`: ASR harness that replays the oracle's security scenarios
  as 19 attacks, in-process or against a URL; `--max-asr 0` fails if any attack succeeds.
- `scripts/metrics.py`: logs attempts/blocked, PRs opened/merged/self-rejected, and the
  human-message-to-PR ratio.
- `.github/workflows/oracle.yml`: `verify-oracle` CI job (hash guard, maintainer-only
  oracle changes, oracle, ASR = 0%).
- `.github/CODEOWNERS`, `.github/oracle-lock.sha256`: the oracle lock.
- `devin_bot_playbook.md`: Manager Devin prompt, child roles, Needs You gate.
- `docs/AUDIT.md`: audit of the original import and what changed.
- `docs/BRANCH_PROTECTION.md`: exact GitHub settings to apply.
- `docs/DEVIN_SETUP.md`: Manager + Recon/Exploiter/Patch sessions, caps, triggers, metrics.
