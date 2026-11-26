# Devin setup: Manager + Recon / Exploiter / Patch

How to wire the bot once Devin Bots access arrives. The full system prompt and role
rules are in [`devin_bot_playbook.md`](../devin_bot_playbook.md).

## 0. Day-one checks (Thu Nov 26 in the brief's checklist)

1. Confirm Devin Bots access and the $5,000 credit grant.
2. Connect the Devin GitHub App to `Odingard/redpatch-ai` only (see
   `docs/BRANCH_PROTECTION.md` §3) and apply the branch protection there.
3. In a Devin session: `pip install -r requirements.txt && pytest -q && python scripts/attack_baseline.py --label smoke`.
   Expect all oracle tests passing and ASR 0% on `main`.
4. Point the bot at the `baseline-vulnerable` branch (separate step) as its target.

## 1. Session layout

| Session | Job | Suggested caps (tune after the first run) |
|---|---|---|
| **Manager Devin** | Reads the latest ASR report, spawns children, enforces caps, decides what reaches "Needs You", logs metrics | 10 ACU, 60 min |
| **Recon Devin** (1) | Maps MCP tool schemas (`GET /tools`), RAG path (`/agent/chat`), auth and tenant handling; outputs candidate issues mapped to oracle tests | 5 ACU, 30 min |
| **Exploiter Devins** (1 per candidate, max 3 in parallel) | Reproduces one issue against the local container; writes a failing regression test in `tests/test_boundary_regressions.py`; logs an `attempt` | 5 ACU, 30 min each |
| **Patch Devins** (1 per confirmed issue) | Minimal fix, max 4 test-and-patch iterations; opens a PR or self-rejects | 8 ACU, 45 min each |

The ACU numbers are starting points, not measurements. Set them as `max_acu_limit` when
creating each session (Devin API `POST /v1/sessions` accepts `max_acu_limit`). Devin
stops at the limit and waits to be woken, so it is a hard stop on spend for that session.
Time caps are enforced by the Manager: it ends any child that passes its wall-clock budget
and logs it as a blocker.

Budget check before each sweep: (number of children × their ACU caps) must fit the
credits left. Stop spawning when it doesn't.

## 2. The "Needs You" gate

A child's PR reaches Andre only when **both** hold on the PR head:

1. **The issue is blocked 100%**: every oracle security test mapped to that issue passes,
   the new regression test passes, and `scripts/attack_baseline.py --only <attack_id>`
   reports `blocked`.
2. **All functional tests pass**: `pytest -m functional` shows 0 failed (no fix by
   over-blocking).

On `main` the `verify-oracle` CI job checks the whole oracle and ASR = 0%. Nothing else
pings Andre: no theoretical findings, no partial fixes, no questions the playbook answers.

Each Needs You PR body carries: issue and attack id, the failing-before / passing-after
pytest output, the ASR line before and after, the diff summary, and ACU/iterations used.

## 3. Self-rejected PRs are evidence

When a patch fails the gate after 4 iterations, the Patch Devin opens (or keeps) the PR
as a **draft**, labels it `self-rejected`, states which test failed, and does not request
review. Log it with `python scripts/metrics.py log pr_self_rejected --pr <n> --issue <id>`.
Keep 1-2 of these for the pitch as proof the oracle catches bad fixes.

## 4. Triggers

- **Nightly**: start one Manager sweep per night, e.g. a GitHub Actions `schedule:` job
  that calls the Devin API to create the Manager session with its `max_acu_limit` (or
  Devin's own scheduling, if Devin Bots offers it).
- **Every staging deployment / push to the target branch**: same call from CI.
- Each sweep starts with `python scripts/attack_baseline.py --label sweep-<date>` and ends
  with `--label after-<date>` so before/after ASR is recorded.
- Fix PRs target `baseline-vulnerable`. The full oracle is expected to fail there until
  every planted flaw is fixed, so the Manager applies the per-issue gate in §2 rather
  than waiting for the whole suite to go green.

## 5. Metrics to track (for the pitch)

```bash
python scripts/metrics.py log attempt --issue idor_get_summary --blocked
python scripts/metrics.py log pr_opened --pr 7 --issue idor_get_summary
python scripts/metrics.py log pr_merged --pr 7
python scripts/metrics.py log human_message --note "approved PR 7"
python scripts/metrics.py summary
```

`summary` reports attempts / blocked / ASR, PRs opened / merged / self-rejected, and the
human-message-to-PR ratio (messages per opened and per merged PR). The harness logs one
`attempt` per attack automatically. Log every message Andre sends the bot as
`human_message`.
