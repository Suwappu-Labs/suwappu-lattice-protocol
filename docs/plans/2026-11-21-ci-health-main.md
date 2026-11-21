# CI health on main — 2026-11-21

A direct investigation of why `ETP CI` and `Docs CI` have been failing on
`main`, prompted by two merges in a row showing red checks. Two unrelated
problems, both diagnosed against primary evidence (job logs, run history),
not assumption. One is fixed in this change; the other needs a decision
only a maintainer can make.

## Finding 1 — two dead citation links (fixed here)

`Docs CI`'s Lychee link check has failed on every run since 2026-09-13,
on the same two URLs, in files this change doesn't touch:

- `docs/WHITEPAPER.md` cited `http://www.cacrnet.org.cn/`. Confirmed
  live from two networks: HTTP returns 444 (connection dropped, no
  response) and HTTPS fails the TLS handshake outright. This matches the
  pattern of several existing `lychee.toml` exclusions — a deliberate
  block of non-domestic bot traffic, not evidence the page is gone.
  Added to the exclude list.
- The threat-intel file for SCN-008 (Ronin) cited a Substack post that
  404s, while the Substack domain itself returns 200. The specific post
  was taken down. `web.archive.org` has a capture from 2023-04-01.
  Repointed the citation at that capture instead of suppressing the
  check — the source moved, the check was correct.

## Finding 2 — Python test matrix jobs are exposed to runner cancellation (not fixed, needs a decision)

Across three separate merge-triggered `ETP CI` runs in the last 24 hours
(the pushes for #80 and #82, plus a manual re-run during #82), 5 of 9
Python-matrix job attempts (3.10/3.11/3.12) were cancelled mid-run:

| Run | Job | Started → cancelled | Elapsed |
|---|---|---|---|
| push (merge #80), run 44818789189 | 3.10, 3.11, 3.12 | all ~22:31 | ~65-75s |
| PR #82 rerun, run 44829509184 | 3.12 (both attempts) | ~22:41 twice | ~35s and ~75s |
| PR #82 rerun, run 44829509184 | 3.10, 3.11 | both ended 23:25:31/32 | ~45 min |
| push (merge #82), run 44850064047 | 3.10, 3.11 | ~01:26 | ~34-38s |

Every GitHub-side log that was still retrievable shows the identical
signature: `The runner has received a shutdown signal... The operation
was canceled`, with zero test output — not a pytest assertion failure,
not an exit code from the test run. GitHub's own job metadata reports the
step itself as `cancelled`, which only happens when something outside the
running script terminates it.

**What this rules out:**

- Not a regression from any of these PRs' content (#79, #80, #82 are all
  `docs/`-only changes; none touch `src/ltp/`, `tests/`, or `contracts/`).
- Not a fleet-wide outage: in every affected run, `Forge Tests`, the
  Foundry invariant suite, `Slither + solhint`, and `pip-audit` — all on
  the same `ubuntu-latest` pool, running concurrently — completed clean.
- Not account-level concurrency contention: at the time of the clearest
  instance, this was the only workflow run in progress or queued on the
  repo.
- Not the `Install Foundry` flake documented in `contracts.yml`'s own
  comments (that failure mode is a 1-second `Install Foundry` step
  failure, last seen on `main` on 2026-08-26, already fixed by that
  file's retry-with-fresh-CDN-response loop — confirmed working clean on
  every run checked here).

**What's left standing:** the Python Tests job is the only one in this
workflow that normally runs 11-15 minutes. Every other job finishes in
under 6. A job's exposure to a transient hosted-runner reclamation event
scales with how long it's alive — which fits without requiring anything
specific to this job's content, and fits the self-contradictory timing
(sometimes cancelled at 35 seconds, once at 44 minutes) that a
content-driven bug wouldn't produce.

**Why this isn't fixed in this PR:** a retry loop *inside* the job's own
script (the pattern `contracts.yml` already uses for `Install Foundry`)
cannot help here — when the runner itself is torn down externally, the
script running the retry loop is torn down with it. The only mechanisms
that can recover from this are: a human/agent manually re-running the
failed jobs (what happened on #82 — it worked, twice), or a second
workflow that watches `workflow_run` completion and calls the re-run API
automatically. The second option is a real design decision — it needs a
cap on auto-retries so a genuine, reproducible failure doesn't get
silently retried forever, and it's the kind of CI-trust tradeoff a
maintainer should sign off on, not something to add unasked.

**Recommendation, not applied:** add a `workflow_run`-triggered workflow
that calls `rerun_failed_jobs` once when `ETP CI` concludes `failure` and
the failing jobs are exactly `python-test`, capped at one automatic retry
per run. Flagging for a maintainer decision rather than implementing it.

## Finding 3 — AGENTS.md's Linear references didn't match the real workspace (fixed here)

Checked `AGENTS.md`'s own "file a Linear issue" instructions against the
live workspace before relying on them: the team key `GLO` doesn't exist
(the real team is `Suwappu`, key `SUW`); the "LTP Dev Net" project
doesn't exist (this repo's work is scattered across unrelated projects,
e.g. `SUW-240` under SOC 2 Type II Readiness); and `GLO-785` / `GLO-786`
don't correspond to any issue found in this workspace by content search.

One real, currently-true bug was confirmed in the process of checking
this: `pyproject.toml` declares `license = "MIT"` while this repo's own
`LICENSE` file is Elastic License 2.0 — not a stale reference, an actual
live mismatch, which is presumably why `AGENTS.md`'s Boundaries section
gates it behind human sign-off rather than letting an agent touch it.
That gate was correct and is left untouched. Fixed only the citations:
`AGENTS.md`, `CHANGELOG.md` (still under `[Unreleased]`, so editable per
Keep a Changelog convention), and `docs/OPERATOR_RUNBOOK.md` now state
the real team key and note that no matching ticket could be confirmed,
instead of pointing at an issue that doesn't exist.

**Not fixed, flagged only:** the same wrong `GLO-` pattern recurs in
about a dozen other files (`docs/STABILITY_PROMISES.md`,
`SECURITY_TESTING.md`, several `docs/security/audits/` files). Those
weren't checked individually — fixing every one is a separate, larger
documentation pass, out of scope for a CI-health investigation.

## Sources

- Job logs and run history pulled live via the GitHub API on 2026-11-21.
- `web.archive.org`'s availability API for the Ronin post-mortem capture.
- Direct `curl` to `cacrnet.org.cn` from two independent networks.
- Linear API: `list_teams`, `list_projects`, `list_issue_labels`, and
  content search across the `SUW` team's issues.
