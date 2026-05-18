# Security Testing Charter

This file authorizes and scopes the internal security-testing campaigns
run against LTP. It complements [`SECURITY.md`](SECURITY.md) (which
governs **external** vulnerability disclosure) by documenting how the
LTP team verifies its own defenses internally.

## Authorization

The Global Settlement Network project lead authorizes the LTP
engineering team and its tooling (including AI coding assistants
operating under direct human supervision) to conduct security tests
against systems **owned and operated by Global Settlement Network**.

Campaigns documented under this charter:

- [`docs/security/RED_TEAM_CAMPAIGN_2026-05.md`](docs/security/RED_TEAM_CAMPAIGN_2026-05.md)
  — May 2026, historical bridge-hack regression suite (33 scenarios). Closed.
- [`docs/security/RED_TEAM_CAMPAIGN_2026-06.md`](docs/security/RED_TEAM_CAMPAIGN_2026-06.md)
  — June 2026, economic / griefing attacks on the `OptimisticBridgeChallenge`
  bond mechanism (7 scenarios). R-1 in progress.

Authorization timestamp: 2026-05-16.
Authorization scope: until superseded by a new charter file in this
repository.

## Scope boundaries

Every security-testing campaign run under this charter operates under
these explicit rules:

1. **Owned systems only.** Tests target code and infrastructure owned
   by Global Settlement Network — primarily this repository
   (`gsx-lattice-protocol`) and its sibling repositories (`gsx-dag`,
   `gsx-db`, `ETP`). No third-party systems are probed.
2. **Isolated environments.** Contract-layer tests run in Foundry's
   local EVM, on `anvil`, or as Foundry mainnet-fork tests
   (`forge test --fork-url`). Mainnet-fork tests **never** broadcast
   transactions — they read state and simulate calls only.
3. **Testnet caveat.** A limited subset of campaign scenarios may run
   against GSX Testnet's deployed registry. Those tests use a
   dedicated test-only operator key with negligible balance, rotated
   after each phase closes.
4. **People-in-the-loop drills require consent.** Tabletop exercises
   that involve the operations team (e.g., social-engineering
   recognition drills) require prior written consent from the
   operations team lead. No external parties, no real phishing
   payloads, no surprise elements — these are scheduled, framed,
   debriefed paper walkthroughs.
5. **No malware, no exfil tooling.** Test artifacts are
   `forge` / `pytest` scripts that exercise documented input
   patterns and assert defensive behavior. They are not standalone
   exploits, attack frameworks, or red-team toolkits.
6. **Private until remediated.** When a campaign scenario uncovers
   an exploitable bug, the artifacts stay on a private branch and
   the corresponding Linear finding stays private until the
   remediation patch lands. Only the post-fix PR is public.

## How to file a new campaign

1. Open a Linear issue in the **LTP Dev Net** project (team
   "Global Settlement") with the label `security-campaign` describing
   the scenario set.
2. Create a campaign master document under `docs/security/` following
   the pattern of `RED_TEAM_CAMPAIGN_2026-05.md`.
3. Open a draft PR with the charter doc + directory skeleton for
   review. The project lead must approve the scope before any
   active testing begins.

## Prompt-care policy for AI-assisted testing

When AI coding assistants participate in security testing under this
charter, the human operator phrases requests as **defensive
verification**, not offensive generation. Example acceptable framings:

- "Write a Foundry test that verifies `LTPAnchorRegistry` rejects
  the input pattern that succeeded against Wormhole's `verifyVAA`."
- "Patch `submitChallenge` so the Poly-Network keeper-role
  privilege-escalation pattern is rejected at the access-control
  boundary."
- "Design a tabletop scenario where the on-call team walks through
  what they would do if a Ronin-style fake-recruiter DM reached an
  operator."

Out-of-scope requests:

- Generating standalone exploit binaries or attack frameworks
- Producing phishing payloads, social-engineering scripts, or
  pretexting content meant to deceive real people
- Producing malware, credential-stealing tooling, or persistence
  mechanisms

The distinction: we author **tests that confirm defenses hold**, not
**tools that bypass defenses**. Every artifact produced lives in
this repository as a regression test or a remediation patch.

## Relationship to other security documents

- [`SECURITY.md`](SECURITY.md) — external vulnerability disclosure
  policy (responsible-disclosure contact, in-scope assets,
  acknowledgement timeline).
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — protocol threat
  model (STRIDE + PQC-specific categories).
- [`docs/SECURITY_AUDIT_2026-05-15.md`](docs/SECURITY_AUDIT_2026-05-15.md)
  — most recent independent audit and the LTP-A-* finding registry.
- [`docs/FORMAL_VERIFICATION_STATUS.md`](docs/FORMAL_VERIFICATION_STATUS.md)
  — machine-checked vs. paper-proven boundary.
- This file — internal-testing authorization and scope.
