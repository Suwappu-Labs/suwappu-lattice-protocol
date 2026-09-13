# src/ltp/ agent instructions

You are in the Python SDK of the Lattice Transfer Protocol (LTP). The full
guide is [`../../AGENTS.md`](../../AGENTS.md). This file adds only what is
specific to this package.

## Gate before merge

```bash
scripts/verify.sh fast       # fail-fast Python loop while iterating
make test-python             # ~4,000 tests; skips the live-anvil integration file
pre-commit run --all-files   # ruff, ruff-format, hygiene
semgrep scan --config .semgrep/ --metrics=off --error src/ scripts/
mypy                         # curated file list in pyproject [tool.mypy]
```

## Rules for this package

- `import ltp` asserts real post-quantum backends. Install with
  `pip install -e '.[production,dev]'` first.
- Use `logging`, never `print()`.
- Raise `ValueError` for input validation. Do not use `assert` for it.
- Type-annotate every public API. The package ships `py.typed`.
- Use SHA3-256 on every settlement and on-chain path.
- Keep classical and post-quantum crypto lanes separate.
  `.semgrep/crypto-lane-separation.yml` fails CI if you mix them.
- Never set `LTP_ENV=development` to make a test pass. Production fails
  closed on purpose (`bls.py`, `hsm.py`).
- Never alter `BLS_CORRIDOR_DST` in `corridor/constants.py`. Audit finding
  LTP-A-022.
- `corridor/`, `crypto`, and `anchor/` are CODEOWNERS-protected.

Full rules: [Working in src/ltp/](../../AGENTS.md#working-in-srcltp) and
[Boundaries](../../AGENTS.md#boundaries).
