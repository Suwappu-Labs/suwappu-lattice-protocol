# docs/ agent instructions

You are in the documentation tree of the Lattice Transfer Protocol (LTP).
The full guide is [`../AGENTS.md`](../AGENTS.md). This file adds only what
is specific to documentation.

## Gate before merge

Run from the repo root:

```bash
make docs-api                                   # pdoc build; gates docs CI
npx markdownlint-cli2 'docs/**/*.md' '*.md'     # one H1, no skipped levels
lychee --config lychee.toml 'docs/**/*.md' '*.md'   # every relative link must resolve
```

## Rules for this tree

- Start new readers at [README.md](README.md). Route by persona under
  [personas/](personas/README.md).
- Add every new page to [SUMMARY.md](SUMMARY.md) so GitBook and agents can
  find it.
- Mermaid diagrams follow [visuals/README.md](visuals/README.md).
- Never hand-edit `api/python/`. It is generated.
- Never change an address in [DEPLOYED_CONTRACTS.md](DEPLOYED_CONTRACTS.md)
  without a plan under [plans/](plans/).
- Audit finding IDs look like `LTP-A-025`. Cite them by ID.
- Use Python 3.10 to 3.13 for `make docs-api`. 3.14 has a pdoc bug.

Full rules: [Working in docs/](../AGENTS.md#working-in-docs).
