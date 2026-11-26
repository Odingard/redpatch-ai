#!/usr/bin/env bash
# Regenerate the oracle hash manifest. Only a code owner should run this, in a
# PR that intentionally changes the oracle. CI fails if the manifest and the
# files disagree.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
sha256sum tests/test_oracle.py pytest.ini scripts/attack_baseline.py scripts/metrics.py > .github/oracle-lock.sha256
cat .github/oracle-lock.sha256
