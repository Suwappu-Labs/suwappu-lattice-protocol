# Going-Public Gap Analysis — LTP vs. Tempo, Arc, Robinhood Chain

Date: 2026-07-03. Status: research complete; quick fixes landed on this
branch; owner decisions listed at the end.

> **Note before flipping the repo public:** this document itself references
> internal findings (leaked-credential history, internal hostnames). Review
> `docs/plans/` as a whole — including this file — as part of the P0
> checklist below.

## Purpose

We intend to make this repository public. This document benchmarks how
three comparable payments/settlement chains went public in 2025–2026 —
**Tempo** (Stripe/Paradigm), **Arc** (Circle), and **Robinhood Chain**
(Robinhood/Arbitrum) — plus the industry gold standard
(Optimism, go-ethereum, Uniswap v4), and turns the delta into a
prioritized checklist.

## How the comparators went public

### Tempo (tempo.xyz — Stripe/Paradigm)

- **Phased release:** announced Sept 2025 with a landing page and
  Paradigm's design essay only; code went public with the public testnet
  (Dec 2025); mainnet Mar 2026. Developed private, flipped public at
  testnet.
- **Licensing:** dual **Apache-2.0 OR MIT** for code (matches the
  Reth/Rust upstream ecosystem); the MPP wire-format spec is **CC0-1.0**
  (public domain) with tooling Apache/MIT — a deliberate split so a
  standard meant for competitors has zero adoption friction
  ([mpp-specs](https://github.com/tempoxyz/mpp-specs)).
- **Repo health:** org-level `.github` repo holds shared SECURITY.md
  (security@tempo.xyz, 5-day ack / 10-day follow-up) and CONTRIBUTING
  (no CLA/DCO; contributions dual-licensed). **No CODE_OF_CONDUCT file**
  (adopts Rust CoC by reference), **no published audits**, and — notably
  honest — an explicit "no bug bounty until audits conclude" statement.
- **Docs/spec:** specs are MDX pages in an open-source docs repo;
  versioning via numbered **TIPs** (Tempo Improvement Proposals) plus
  named hardforks; predeployed system contracts at fixed vanity
  addresses (same on testnet/mainnet), documented at
  [tempo.xyz/developers](https://tempo.xyz/developers).
- **Supply chain:** GPG + Sigstore release verification instructions in
  the README; per-crate semver tags.
- **Stayed closed:** validator set (permissioned), explorer, wallet,
  audit reports, tokenomics.

### Arc (arc.io / arc.network — Circle)

- **Phased release:** announced + litepaper Aug 2025; public testnet
  Oct 2025 (still closed source); **code drop Apr 2026** under
  Apache-2.0, launched simultaneously with a HackerOne bug bounty and
  run-your-own-node docs, framed explicitly as pre-mainnet security
  hardening.
- **Licensing:** Apache-2.0 across
  [arc-node](https://github.com/circlefin/arc-node) and
  [malachite](https://github.com/circlefin/malachite) (consensus engine,
  with Quint formal specs living in-repo).
- **Repo health:** LICENSE, COPYRIGHT, README, CONTRIBUTING, SECURITY,
  CHANGELOG, BREAKING_CHANGES at root. SECURITY.md is short and routes
  everything to Circle's existing HackerOne program. **No
  CODE_OF_CONDUCT, no in-repo audit reports** ("alpha software currently
  undergoing audits" stated plainly in the README).
- **Docs:** docs.arc.io ships an `llms.txt` machine-readable docs map and
  an agent skill; contract-address registry is **testnet-only**, every
  address links to the explorer, and known gotchas are documented
  per-address. Compliance is presented as a product feature (View Keys,
  Travel Rule support), not a legal appendix.
- **Stayed closed:** validator participation (permissioned), mainnet
  addresses, audit reports.

### Robinhood Chain (docs.robinhood.com/chain)

- **Effectively closed source at the chain level despite live mainnet**
  (July 2026): no first-party GitHub repo, no whitepaper, no spec, no
  chain bug bounty (a single `chain-developers-group@` email for
  everything). Protocol layer is Offchain Labs' Arbitrum Nitro run as a
  managed service; Robinhood publishes only docs, genesis configs, a
  docs-page address registry, and explorer-verified contract source.
- **Takeaway:** Robinhood is the anti-model for us — we are a protocol
  project, not a brokerage adding a chain feature. Tempo and Arc are the
  real benchmarks; the OSS baseline below is the bar.

### Industry baseline (Optimism monorepo, go-ethereum, Uniswap v4-core)

Universal across all three: root or org-level SECURITY.md with a
private-disclosure channel and a **funded external bug bounty**
(Immunefi $2M+ / bounty.ethereum.org with published PGP fingerprint /
Uniswap program); explicit license; CONTRIBUTING; CODEOWNERS; issue + PR
templates; visible CI; and **audit reports committed in-repo**
(`docs/security-reviews/`, `docs/audits/`, `docs/security/audits/`).
Divergent/optional: CODE_OF_CONDUCT (only Optimism ships one);
GOVERNANCE is always an external forum, never a file; changelog rigor
varies (Optimism per-component semver > geth release notes > Uniswap
none).

## Gap matrix

"Us" = this repo today, on this branch.

| Checklist item | Tempo | Arc | Baseline norm | Us |
|---|---|---|---|---|
| LICENSE | Apache-2.0/MIT dual | Apache-2.0 | Permissive or BUSL+MIT | ⚠️ **Contradictory** — Elastic-2.0 file vs MIT in `pyproject.toml`/README badge (GLO-785) |
| Spec license split | ✅ CC0 spec / Apache code | — (specs in-repo, Apache) | CC0 (OP specs) | ⚠️ CC BY-ND 4.0 (**NoDerivs blocks third-party corridor implementations' derived docs** — weakest-in-class for an interop wire format) |
| README | ✅ persona-split Getting Started | ✅ | ✅ | ✅ strong, but MIT badge wrong; fake static badges; ETP/LTP naming split |
| SECURITY.md | org-level, thin | routes to HackerOne | ✅ + funded bounty + PGP | ✅ thorough scope, but personal Gmail contact, no PGP, no bounty statement |
| Bug bounty | ❌ explicit "not yet" | ✅ HackerOne | ✅ funded | ❌ — adopt Tempo's honest "no bounty until audits conclude" line |
| CONTRIBUTING | ✅ org-level | ✅ | ✅ | ✅ (clone URL fixed on this branch); no DCO/CLA or inbound-license statement — needed for an Elastic-licensed project |
| CODE_OF_CONDUCT | ❌ | ❌ | Optimism only | ✅ **we beat both chains** |
| Audits published | ❌ | ❌ | ✅ in-repo | ✅ internal reports in `docs/security/audits/` — **we beat both chains** (pending publish decision) |
| Whitepaper | ❌ | ✅ litepaper | Uniswap in-repo | ✅ `docs/WHITEPAPER.md` — we beat Tempo |
| Formal verification | — | ✅ Quint specs in malachite | ✅ | ✅ `docs/FORMAL_VERIFICATION_STATUS.md` |
| Address registry | ✅ fixed predeploys | ✅ testnet-only, explorer-linked | dedicated repo/site | ✅ `docs/DEPLOYED_CONTRACTS.md`; add explorer links per address (Arc pattern) |
| Spec versioning | ✅ TIPs + hardforks | ADRs | ✅ EIPs/OP specs | ⚠️ `STABILITY_PROMISES.md` + CHANGELOG exist; no numbered improvement-proposal process (fine at this size; revisit post-launch) |
| Operator docs | ✅ | ✅ full-node only | ✅ | ✅ runbook + deployment guide |
| Issue/PR templates, CODEOWNERS, dependabot | ✅ | ✅ | ✅ | ✅ (+ `ISSUE_TEMPLATE/config.yml` added on this branch) |
| Release verification (GPG/Sigstore) | ✅ | — | ✅ | ⚠️ SBOM + release workflows exist; no signed-artifact verification instructions in README |
| `llms.txt` / agent docs | ✅ `.agents/` | ✅ llms.txt + skill | emerging | ✅ `CLAUDE.md`, `.cursorrules`, `docs/AI_AGENTS.md` — competitive |

Overall: **structurally we are at or above Tempo/Arc on repo health** —
the gaps are not missing files, they are (a) secrets/identity hygiene,
(b) the license contradiction, and (c) polish inconsistencies.

## P0 — blockers before flipping the repo public

1. **Purge and rotate the committed gateway keypair.**
   `deploy/gateway_keypair.json` (real ML-KEM decap + ML-DSA signing
   keys, label `gateway-vm-0`) was removed from tip in `7f0a9e1` but the
   blob is still recoverable from history (verified present in `d9841f7`
   and `d2542ff`). Making the repo public publishes those keys. Required:
   rotate the gateway keys, then rewrite history (`git filter-repo` /
   BFG) to drop the blob — also purging the historical
   `config/gsx-testnet.env.template` (internal AWS ELB hostname) in the
   same pass. History rewrite is owner-only: it breaks clones and
   conflicts with the no-rebase convention, so it must be a deliberate,
   announced cut — ideally done as a fresh squashed initial commit if the
   private history isn't meant to be public anyway (Tempo and Arc both
   developed private and flipped public with curated history).
2. **Resolve the license contradiction (GLO-785).** `LICENSE` says
   Elastic-2.0, `pyproject.toml` and the README badge say MIT. Shipping
   public with a self-contradictory license is a legal/PR problem.
   Comparator signal: both Tempo and Arc chose permissive (Apache/MIT)
   specifically to drive adoption; if the Elastic-2.0 posture is
   intentional (source-available, anti-hosted-competitor), say so
   explicitly in the README the way Uniswap explains BUSL. Also
   reconsider **CC BY-ND** for the spec — NoDerivs is hostile to the
   corridor format's stated goal of independent implementations
   (Tempo used CC0; Optimism specs are CC0).
3. **Replace the personal-Gmail security contact.** `SECURITY.md` routes
   reports to a personal Gmail, and the branded alias is marked
   non-functional. Minimum bar: working `security@` mailbox or GitHub
   private vulnerability reporting as the primary channel, plus a PGP
   key (geth publishes the fingerprint in-file). Add Tempo's explicit
   bounty status line ("undergoing audit; no active bug bounty yet").
4. **Pick one name.** README/CHANGELOG say "Entanglement Transfer
   Protocol (ETP)", the repo slug and CLAUDE.md say "Lattice Transfer
   Protocol (LTP)", history says GSX. Mid-rebrand reads unfinished and
   confuses every downstream mention. Decide, then sweep.
5. **Deliberate keep/drop review of internal-flavored trees:**
   `docs/plans/` (session roadmaps, gate closures — including this
   file), `docs/compliance/fedramp-high/` (references non-public sibling
   repos, POA&M items, team names), `docs/security/audits/internal/`
   (red-team report — publishing internal audits is actually
   ahead-of-market if intentional, see gap matrix), `docs/*.docx`
   binaries (carry author metadata; convert to Markdown/PDF or drop),
   `CODE_IMPROVEMENTS.md` and `run_trust_layer.py` at root (scratch;
   move to `examples/` or drop), `ETP-LTP-Dual.png` (841 KB at root).
6. **Git author identities.** History exposes personal emails and the
   pre-rebrand corporate domain. If history is rewritten per item 1,
   normalize authors in the same pass (or accept exposure explicitly).

## P1 — should fix before or at announcement

- **CONTRIBUTING: add an inbound-license/DCO statement.** Under
  Elastic-2.0 (or any relicense), state what license contributions are
  accepted under (Tempo: "contributions dual-licensed"; add DCO
  sign-off if no CLA).
- **README truthfulness pass:** replace static shields
  ("tests-2,800+ passing", MIT, version) with real CI/coverage badges
  wired to the workflows that already exist; fix the license badge to
  whatever GLO-785 decides.
- **DEPLOYED_CONTRACTS.md:** link every address to an explorer
  (Arc pattern), and state the verification story (source-verified on
  which explorer).
- **Release verification:** document checksum/signature verification for
  release artifacts (Tempo README pattern; SBOM workflow already
  exists, so most of the supply-chain story is done).
- **SECURITY.md additions:** safe-harbor language and explicit
  in-scope/out-of-scope assets (we have scope; add safe harbor).
- **`config/mainnet.env` → `mainnet.env.template`** so a real secrets
  file can never be committed over it.

## P2 — post-launch / differentiators

- **Phased-release playbook (adopt the Tempo/Arc sequence):** docs +
  whitepaper first, code public at testnet, bounty at code-drop,
  audits before mainnet. We already have the docs corpus — we can lead
  with it.
- **Publish the internal audit reports deliberately** — neither Tempo
  nor Arc has public audits; doing so is a trust differentiator for a
  PQ-crypto protocol (after redacting internal ticket/hostname refs).
- **Improvement-proposal process** (TIP/EIP-style numbered specs) once
  external contributors exist; `STABILITY_PROMISES.md` is the seed.
- **`llms.txt`** for the docs tree (Arc pattern) — cheap, on-brand given
  `docs/AI_AGENTS.md` already exists.
- **Bug bounty** once audits conclude (Arc's $5k critical cap drew
  public criticism — budget accordingly or stay with "no bounty yet"
  honesty).

## Fixed on this branch

- Internal AWS ELB hostname in `config/suwappu-testnet.env.template`
  replaced with a placeholder (P0 item 1's tip-of-tree half; history
  half still requires the rewrite).
- Broken clone URL in `CONTRIBUTING.md` (pointed at a nonexistent repo
  slug).
- `.superpowers/` agent scratch state untracked and gitignored.
- `.github/ISSUE_TEMPLATE/config.yml` added — routes vulnerability
  reports to private advisories instead of public issues (baseline
  norm).

## Decisions needed (owner)

| # | Decision | Options |
|---|---|---|
| 1 | License (GLO-785) | Keep Elastic-2.0 and fix pyproject/badge to match; or relicense Apache-2.0/MIT for adoption parity with Tempo/Arc |
| 2 | Spec license | Keep CC BY-ND; or CC0/CC-BY to permit independent implementations (recommended for the corridor format) |
| 3 | History | Rewrite in place vs. fresh squashed public history (recommended; also resolves author-email exposure) |
| 4 | Name | ETP vs LTP (single name everywhere) |
| 5 | Security contact | Set up `security@` mailbox + PGP, or GitHub private reporting as primary |
| 6 | Internal trees | Keep/redact/drop: `docs/plans/`, `docs/compliance/fedramp-high/`, internal audits, `.docx` files, root scratch files |
