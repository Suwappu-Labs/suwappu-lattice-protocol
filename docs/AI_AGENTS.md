# Working with LTP from AI Coding Agents

This page tells AI coding agents (Claude Code, Cursor, Aider, Continue, ChatGPT
Code Interpreter / Plugins, GitHub Copilot Workspace) what to read, what to
avoid, and how to run the test suite from inside an agent session. Following
it gets you to a green build faster and keeps you out of the patterns that
will get a PR rejected.

Last updated: 2026-05-16. Pin against this date if behavior diverges.

## Always-read files

Before suggesting a non-trivial change, an agent should load:

1. **[../CONTRIBUTING.md](../CONTRIBUTING.md)** — prerequisites, test commands,
   PR workflow.
2. **[../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)** — enforcement contact
   `core@globalsettlement.dev`.
3. **[OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md) §13** — v7 deploy checklist.
   If a change touches deploy paths, this is the authoritative checklist.
4. **[SECURITY_AUDIT_2026-05-15.md](SECURITY_AUDIT_2026-05-15.md)** — every
   open finding and remediation status. Don't propose changes that would
   reopen a closed finding.
5. **[STABILITY_PROMISES.md](STABILITY_PROMISES.md)** — public-surface
   commitments and the cross-version compatibility matrix.
6. **[visuals/README.md](visuals/README.md)** — Mermaid conventions used
   across the repo (theme, layout, edge style).
7. **[CORRIDOR_INTEGRATION.md](CORRIDOR_INTEGRATION.md)** — wire format
   and on-chain ABI. Treat as normative.

The persona pages under [personas/](personas/README.md) tell you which of
these matter most for the task you're doing.

## Common gotchas surfaced during prior audits

These are real things the LTP audit caught that agents tend to get wrong:

- **BLS DST cross-language pinning** — the domain-separation tag string
  must be byte-identical between Python and Solidity. Don't "clean up" the
  string (no Unicode normalization, no trim). See audit finding
  LTP-A-022.
- **`LTP_ENV=production` gates** — several runtime paths fail-closed when
  `LTP_ENV=production` is set. Don't bypass these by setting
  `LTP_ENV=development` to make a test pass.
- **Deployed-contract addresses are immutable** — never change an address
  in [DEPLOYED_CONTRACTS.md](DEPLOYED_CONTRACTS.md) without an upgrade
  plan under `plans/`. CODEOWNERS will reject the PR.
- **No `Co-Authored-By` footers** — repo convention. Strip them from
  generated commit messages.
- **No `git rebase`** — use `git merge` or `git pull --no-rebase`. The
  consensus and audit tests are sensitive to commit topology.
- **Wire-format additions require a Linear ticket** — bumping
  `LTP-corridor-v1` to `v2` is not a refactor; it must be scoped in
  Linear under the LTP Dev Net project.
- **SHA-pinned GitHub Actions** — every new third-party action must be
  pinned by commit SHA, not tag. The LTP-A-025 audit finding made this
  mandatory.

## Running the test suite from an agent

The minimum-viable verification before saying "done":

```bash
make test-python           # ~1,200 Python tests
make test-contracts        # 84 Solidity tests via forge
make contracts-secaudit    # Slither + Echidna + invariants (slow)
```

For docs-only changes, the docs CI ([.github/workflows/docs.yml](../.github/workflows/docs.yml))
runs link-check, markdownlint, Mermaid validation, and the pdoc artifact
build. Reproducing locally:

```bash
make docs-api              # regenerates docs/api/python/
npx markdownlint-cli2 'docs/**/*.md' '*.md'
lychee --config lychee.toml 'docs/**/*.md' '*.md'
```

## Agent-specific notes

### Claude Code

A project-level [`CLAUDE.md`](../CLAUDE.md) lives at the repo root and is
loaded automatically. It captures the same gotchas as this page in the
format Claude Code expects.

### Cursor

A [`.cursorrules`](../.cursorrules) file at the repo root scopes Cursor's
suggestions. Same content, Cursor's format.

### Aider, Continue, Copilot Workspace

These tools don't have a single dotfile convention. Point them at this
document (`docs/AI_AGENTS.md`) and the always-read list above.

### ChatGPT Code Interpreter / Plugins

Upload the repo as a zip and ensure `CONTRIBUTING.md`,
`docs/AI_AGENTS.md`, and the file the user is asking about are all in
context. Avoid running the contract suite — forge isn't available in the
Code Interpreter sandbox.

## Reporting agent-introduced regressions

If an LLM-suggested change introduces a regression (test failure, audit
re-finding, deploy breakage), please file a Linear issue under the
**LTP Dev Net** project with the label `agent-regression` and link the
commit. That data improves future agent-targeted guidance here.
