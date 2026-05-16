# Contributor

You want to **send a PR**, **add an example**, **improve docs**, or **file a
high-quality bug**. This page is your fastest path to a green build.

## 30-second value prop

LTP is a Python + Solidity codebase with strict test coverage gates,
SHA-pinned CI actions, and a multi-tier review process for contract changes
(see CODEOWNERS). The path from clone to passing tests is about ten
minutes if you have Python 3.10+ and Foundry installed.

## Start here

1. **[CONTRIBUTING.md](../../CONTRIBUTING.md)** — prerequisites, clone,
   install, run tests, PR workflow, code style.
2. **[CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md)** — Contributor
   Covenant 2.1. Enforcement contact is `core@globalsettlement.dev`.
3. **[Makefile](../../Makefile)** — every command you need. Run
   `make help` to list targets. Notable: `make test-python`,
   `make test-contracts`, `make contracts-secaudit`, `make audit`.
4. **[examples/README.md](../../examples/README.md)** — runnable
   examples that double as tutorial content. Adding an example is one
   of the most welcome forms of contribution.
5. **[plans/](../plans/)** — every roadmap and design plan. If you're
   thinking about a non-trivial change, find or open a plan first.

## Workflow in one screen

```bash
# Clone + install
git clone https://github.com/GlobalSettlementNetwork/gsx-lattice-protocol.git
cd gsx-lattice-protocol
python3 -m pip install -e ".[dev]"

# Sanity check
make test-python           # ~1,200 Python tests
make test-contracts        # 84 Solidity tests via forge
make contracts-secaudit    # Slither + Echidna + invariants

# Iterate
git switch -c feat/your-thing
# ... edit ...
make test-python && make test-contracts

# Open PR
git push -u origin feat/your-thing
gh pr create
```

## Good first issues

- Adding a new runnable example under `examples/` that mirrors a
  doc-only walkthrough.
- Filling a TODO in `docs/api/` once the auto-generated pdoc reference
  is in place.
- Tightening type hints in `src/ltp/` modules that are still partially
  typed.
- Adding a Mermaid diagram for a design-decision doc that doesn't have
  one yet — see [docs/visuals/README.md](../visuals/README.md) for the
  Mermaid conventions used in the repo.

## What gets a PR rejected

- Changing a deployed-contract address without an accompanying upgrade
  plan in `plans/` — CODEOWNERS will catch this.
- Skipping `make contracts-secaudit` on a contract change — required
  before review.
- Adding a dependency without a bump-policy entry in
  [STABILITY_PROMISES.md](../STABILITY_PROMISES.md).
- Including a `Co-Authored-By` footer on a commit — repo convention
  forbids it.

If you're not sure, open a draft PR early. We'd rather give you feedback
mid-flight than reject a finished PR.
