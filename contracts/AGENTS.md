# contracts/ agent instructions

You are in the Solidity surface of the Lattice Transfer Protocol (LTP).
The full guide is [`../AGENTS.md`](../AGENTS.md). This file adds only what
is specific to this directory.

## Gate before merge

```bash
make test-contracts          # Foundry tests and invariants, ~340 functions
make contracts-secaudit      # Slither + Echidna + invariants; must be green
make abi                     # regenerate contracts/abi/ if the ABI changed
```

## Rules for this directory

- `docs/CORRIDOR_INTEGRATION.md` is the normative on-chain ABI.
- Bump `version()` in `src/LTPAnchorRegistry.sol` when you change it, and
  update the test assertions for it.
- Follow the upgrade pattern in `script/UpgradeV4.s.sol`.
- Never hand-edit `abi/`. Run `make abi`.
- Never change a deployed address in `docs/DEPLOYED_CONTRACTS.md` without a
  plan under `docs/plans/`.
- The BLS domain-separation tag must match `BLS_CORRIDOR_DST` in
  `src/ltp/corridor/constants.py` byte for byte. Audit finding LTP-A-022.
- `.github/CODEOWNERS` requires review on every file here.

Full rules: [Working in contracts/](../AGENTS.md#working-in-contracts) and
[Boundaries](../AGENTS.md#boundaries).
