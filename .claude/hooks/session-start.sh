#!/bin/bash
# SessionStart hook — provision a Claude Code on the web container so the
# repo's own verification commands actually work.
#
# Without this, a fresh remote container has the PQ crypto backends but not
# the dev extras, and the consequences are quiet rather than loud:
#
#   - `pytest tests/` aborts during *collection*, because ~25 modules import
#     fastapi / grpc / httpx / hypothesis / dnspython. Collection errors abort
#     the whole run, so the visible symptom is "0 tests ran", not "25 modules
#     skipped" — it looks like the suite is broken rather than the container.
#   - `scripts/verify.sh lint` prints "pre-commit not installed ... skipping"
#     and returns FAILED, so the lint lane never actually runs.
#   - `import ltp` fails (only `src.ltp` resolves), which is what a couple of
#     subprocess tests assert against.
#
# Everything installed here is already declared in pyproject.toml; this adds
# no dependency, it just installs the ones the repo says it needs. The command
# is exactly what `just setup` and docs/DEVELOPMENT.md already document, so
# there is one setup path rather than two that can drift apart.

set -euo pipefail

# Local machines are set up by `just setup`; this is for the remote container.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# Editable so `import ltp` resolves to this checkout, which is what the
# production-assertion tests exercise via a subprocess.
python3 -m pip install --quiet --disable-pip-version-check -e ".[production,dev]"

# Mandatory per CLAUDE.md — "No --no-verify or hook bypasses" only has teeth
# if the hooks are installed. Non-fatal: a container without a .git dir should
# still get a usable test environment.
pre-commit install --install-hooks >/dev/null 2>&1 || \
  echo "note: pre-commit install failed; the lint lane will be skipped" >&2

echo "session-start: dev environment ready"
