#!/usr/bin/env bash
# Verify the LTP Lean proofs.
#
# Three gates, because "it compiled" is not the same as "it proved":
#   1. `lake build` succeeds.
#   2. No `sorry` / `admit` in the sources.
#   3. No theorem depends on `sorryAx` (the axiom a `sorry` introduces —
#      this catches a hole reached through any import, which a source
#      grep alone would miss).
#
# Usage: formal/lean/verify.sh
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v lake >/dev/null 2>&1; then
  if [ -x "$HOME/.elan/bin/lake" ]; then
    export PATH="$HOME/.elan/bin:$PATH"
  else
    echo "error: lake not found. Install Lean via elan:" >&2
    echo "  curl -sSfL https://elan.lean-lang.org/elan-init.sh | sh -s -- -y" >&2
    exit 127
  fi
fi

echo "==> lean toolchain: $(lean --version)"

echo "==> [1/3] lake build"
lake build

echo "==> [2/3] scanning sources for proof holes"
# Strip comments before scanning: `sorry` legitimately appears in prose
# (this repo's own Audit.lean explains what sorry does), and a naive grep
# flags that. Lean block comments nest, so track depth.
python3 - <<'PY'
import re, sys, pathlib

def strip(src: str) -> str:
    out, i, depth, n = [], 0, 0, len(src)
    while i < n:
        if src.startswith("/-", i):
            depth += 1; i += 2; continue
        if src.startswith("-/", i) and depth:
            depth -= 1; i += 2; continue
        if depth:
            i += 1; continue
        if src.startswith("--", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        out.append(src[i]); i += 1
    return "".join(out)

bad = []
for p in list(pathlib.Path("Ltp").rglob("*.lean")) + [pathlib.Path("Ltp.lean")]:
    if not p.exists():
        continue
    code = strip(p.read_text())
    for ln, line in enumerate(code.splitlines(), 1):
        if re.search(r"\b(sorry|admit)\b", line):
            bad.append(f"{p}:{ln}: {line.strip()}")

if bad:
    print("error: proof hole (sorry/admit) in code:", file=sys.stderr)
    print("\n".join(bad), file=sys.stderr)
    sys.exit(1)
print("    none found (comments excluded)")
PY

echo "==> [3/3] axiom audit"
AXIOMS="$(lake env lean Ltp/Audit.lean 2>&1)"
echo "$AXIOMS"
if echo "$AXIOMS" | grep -q "sorryAx"; then
  echo "error: a theorem depends on sorryAx — there is a hole in a proof" >&2
  exit 1
fi
# Every listed theorem must actually have been reported on; if Audit.lean
# stops printing (e.g. a theorem was renamed away) we want to know.
COUNT="$(echo "$AXIOMS" | grep -c "depends on axioms\|does not depend on any axioms" || true)"
if [ "$COUNT" -lt 73 ]; then
  echo "error: expected >=73 axiom reports, got $COUNT — did a theorem get renamed or dropped?" >&2
  exit 1
fi
echo "    $COUNT theorems audited, no sorryAx"

echo
echo "OK — LTP Lean proofs verified."
