# RedPatch AI

Autonomous, continuous boundary-verification and auto-patching Bot for AI apps, MCP servers, and agent tool-chains.

## Quickstart

```bash
docker compose up --build -d
pytest -v tests/test_oracle.py
```

## Structure

- `app.py`: Staging FastAPI + multi-tenant MCP tool gateway.
- `tests/test_oracle.py`: Locked two-way verification oracle (security invariants + golden functional tests).
- `devin_bot_playbook.md`: Manager Devin Bot system prompt, parallel child roles, and anti-drift rules.
- `.github/workflows/oracle.yml`: CI check enforcing the verification oracle on every PR.
