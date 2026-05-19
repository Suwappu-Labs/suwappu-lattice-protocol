#!/usr/bin/env bash
# Devcontainer first-run setup. Idempotent — re-running is safe.

set -euo pipefail

echo "▶ Installing foundryup (tracks contracts/foundry.toml at runtime)"
curl -L https://foundry.paradigm.xyz | bash
"${HOME}/.foundry/bin/foundryup"

echo "▶ Installing Python deps (production + dev)"
pip install --upgrade pip
pip install -e ".[production,dev]"

echo "▶ Installing solhint (matches CI pin in .github/workflows/contracts.yml)"
npm install -g solhint@5.0.3

echo "▶ Installing pre-commit git hook"
pre-commit install

echo "▶ Sanity check — can we import the production package?"
python -c "import ltp; print('ltp OK — production crypto loaded')"

echo
echo "✓ Devcontainer ready. Run \`just\` to see the command menu."
