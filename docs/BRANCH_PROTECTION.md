# Branch protection: lock the oracle so Devin cannot weaken it

The repo files (`.github/CODEOWNERS`, `.github/oracle-lock.sha256`, the hash-guard steps
in `.github/workflows/oracle.yml`) only bite once these GitHub settings are on. Andre
applies them; the bot's token deliberately has no Administration permission.

## 1. Protect `main`

GitHub: **Odingard/redpatch-ai → Settings → Branches → Add branch protection rule**
(or **Rules → Rulesets → New branch ruleset** targeting `main`; same options).

Branch name pattern: `main`

- [x] **Require a pull request before merging**
  - [x] Require approvals: **1**
  - [x] Dismiss stale pull request approvals when new commits are pushed
  - [x] **Require review from Code Owners**
  - [x] Require approval of the most recent reviewable push
- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging
  - Required check: **`verify-oracle`** (exact job name; it appears in the search box
    after the workflow has run once, which this PR does)
- [x] Require conversation resolution before merging
- [ ] Allow force pushes: **off** (blocks force pushes)
- [ ] Allow deletions: **off** (blocks deleting `main`)
- Bypass: **nobody except Andre**. Do not add the Devin GitHub App, its bot user, or
  any team containing it to a bypass list, to "Allow specified actors to bypass required
  pull requests", or to push restrictions. In a ruleset, the bypass list should contain
  only Repository admin (Andre).

Leave **"Do not allow bypassing the above settings" / "Include administrators" off** so
Andre (admin) can still merge his own PRs: GitHub does not let a PR author approve their
own PR, so a Code Owner review can never come from Andre on a PR Andre opened.
Devin is not an admin, so it gets no bypass either way.

Same settings via API (run by Andre, with a token that has Administration: write):

```bash
gh api -X PUT repos/Odingard/redpatch-ai/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {"strict": true, "contexts": ["verify-oracle"]},
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

## 2. Actions settings

**Settings → Actions → General**

- Workflow permissions: **Read repository contents** (the workflow also pins
  `permissions: contents: read`).
- [ ] **Allow GitHub Actions to create and approve pull requests: off.**
- Fork PR workflows: require approval for outside collaborators.

Optional repo variable **Settings → Secrets and variables → Actions → Variables**:
`ORACLE_MAINTAINERS` = comma-separated GitHub logins allowed to author PRs that touch the
oracle or CI. Default when unset: `andrebyrd-odingard`.

## 3. Devin's GitHub access

- Give the Devin GitHub App access to `redpatch-ai` only, with write on contents and
  pull requests so it can push branches and open PRs. No Administration permission.
- Devin works on feature branches and opens PRs; it never merges.

## What each layer stops

| Attempt by a bot PR | Stopped by |
|---|---|
| Edit or delete an oracle assertion in `tests/test_oracle.py` | Hash guard (manifest mismatch), maintainer-only step, Code Owner review |
| Edit the test **and** regenerate `.github/oracle-lock.sha256` | Maintainer-only step (any change under `.github/` or to a locked file fails for non-maintainer authors), Code Owner review |
| Edit `oracle.yml` to skip steps | Maintainer-only step runs from the PR copy, so this is the one a malicious workflow edit could remove; **Code Owner review on `.github/` is the backstop**, plus `verify-oracle` must report success |
| `addopts = -m functional` in `pytest.ini` | `pytest.ini` is in the manifest and CODEOWNERS |
| Root `conftest.py` that monkeypatches the app or tests | Hash guard rejects any `conftest.py` outside `tests/` (and `tests/` is code-owned) |
| Weaken `scripts/attack_baseline.py` or `scripts/metrics.py` so ASR reads 0% | Both in the manifest and CODEOWNERS |
| Push straight to `main`, force-push, delete `main` | Branch protection |
| Merge with a red or missing `verify-oracle` | Required status check |

## Changing the oracle on purpose (Andre only)

1. Branch, edit `tests/test_oracle.py` (or another locked file).
2. Run `.github/scripts/update-oracle-lock.sh` and commit the new manifest.
3. Open the PR; `verify-oracle` passes because you are a maintainer; merge as admin.
