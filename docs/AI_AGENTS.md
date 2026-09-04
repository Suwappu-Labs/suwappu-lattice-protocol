# Working with LTP from AI Coding Agents

This page tells you which file your agent reads and what is specific to
each tool. The rules, commands, and layout are not here. They live in one
place: [`AGENTS.md`](../AGENTS.md) at the repo root.

Last updated: 2026-09-04.

## One file, every tool

[`AGENTS.md`](../AGENTS.md) is the single source of truth. The other
entry files are symlinks to it, so no tool can drift from another:

| Your tool | File it reads | What it is |
|---|---|---|
| Codex and any other tool that reads `AGENTS.md` | `AGENTS.md` | The canonical file |
| Claude Code | `CLAUDE.md` | Symlink to `AGENTS.md` |
| Cursor | `AGENTS.md` (current) or `.cursorrules` (legacy) | `.cursorrules` is a symlink to `AGENTS.md` |
| Aider, Continue, Copilot Workspace | none automatic | Point the tool at `AGENTS.md` |
| ChatGPT Code Interpreter | none automatic | Upload the repo and read `AGENTS.md` first |

This mirrors how `vercel/next.js` and `apache/airflow` ship their agent
guidance: one `AGENTS.md`, with `CLAUDE.md` as a symlink to it.

To change any rule, edit `AGENTS.md`. Do not edit the symlinks.

## Tool-specific notes

### Claude Code

`CLAUDE.md` loads automatically. Nothing else to configure. The
`Find it fast` table at the top of `AGENTS.md` maps tasks to sections.

### Cursor

Recent Cursor versions read `AGENTS.md` directly. Older versions read
`.cursorrules`, which resolves to the same content.

### Aider, Continue, Copilot Workspace

These tools have no single dotfile convention. Add `AGENTS.md` to the
context at the start of each session. For a non-trivial change, also add
the files listed under **References** in `AGENTS.md`.

### ChatGPT Code Interpreter and plugins

Upload the repo as a zip. Make sure `AGENTS.md`, `CONTRIBUTING.md`, and
the file you are changing are all in context. Do not try to run the
Solidity suite there. `forge` is not available in that sandbox.

## Minimum verification before "done"

```bash
scripts/verify.sh          # all lanes; contracts lane only if forge is installed
```

Per-surface targets and the full command list are in the
**Commands** section of `AGENTS.md`.

## Reporting agent-introduced regressions

If an agent-suggested change breaks a test, reopens an audit finding, or
breaks a deploy, file a Linear issue under the **LTP Dev Net** project
with the label `agent-regression` and link the commit. That data improves
the guidance in `AGENTS.md`.
