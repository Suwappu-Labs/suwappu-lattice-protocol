# SCN-033 — Sun-era operational hygiene (Heco) (tabletop)

**Status.** SCAFFOLDED. Live drill deferred to operator-team session.
**Layer.** 8 — Social engineering / OPSEC.
**Historical incident.** Heco Bridge / HTX, Nov 2023, ~\$86M + ~\$30M.

## What happened (the Sun-era pattern)

The Heco bridge + HTX (formerly Huobi) drains in November 2023
were not a single exploit — they were the gradual product of an
organizational culture that prioritized operational speed over
OPSEC discipline. Public reporting (Bloomberg, The Block,
CertiK) describes:

- Key material reportedly stored in unencrypted form on at
  least one developer machine.
- IAM credentials shared across team members via Slack DM.
- "Production access" granted broadly for convenience.
- No formal incident-response process at the time of the
  drain; the team learned of the loss via on-chain monitoring
  by external parties.

Root primitive: **OPSEC discipline is not a single control;
it's the integral of many small daily choices**. Once those
choices have drifted, no single contract or wallet feature can
substitute for the practice.

## Why this matters to LTP

LTP is in its early operational years. The patterns established
NOW determine what the operational culture looks like at
production scale. Sun-era Heco demonstrates what happens when
shortcuts accumulate; this tabletop drills against that drift.

## Tabletop drill design

Format: **60-90 minute SELF-AUDIT exercise** rather than a
scenario walkthrough. The team scores its current practices
against a baseline.

### Self-audit checklist (45 min — round-robin discussion)

For each item, the team scores: **OK / GAP / N/A / DEFERRED**.

#### Key custody (10 min)
- [ ] No production private keys exist on developer laptops
- [ ] Each operator has their own dedicated signing device
  (hardware wallet) for prod
- [ ] No screenshots / photos of seed phrases exist
- [ ] Seed-phrase backup procedure documented and rehearsed
- [ ] Key rotation cadence defined and met

#### IAM & cloud access (10 min)
- [ ] Each engineer has a personal IAM identity (no shared
  accounts)
- [ ] MFA enforced on every IAM identity
- [ ] Root credentials in break-glass procedure only (not
  used for day-to-day)
- [ ] Quarterly access review actually happens
- [ ] CloudTrail / Audit Logs streamed to isolated logging
  account

#### Communication & secrets (10 min)
- [ ] No production secrets shared via Slack / email / DM
- [ ] Secrets management tool in use (1Password / Vault / AWS
  Secrets Manager)
- [ ] Channel-level access controls on sensitive Slack
  channels
- [ ] No "shared" passwords (everything has individual access)

#### Incident response (10 min)
- [ ] On-call rotation defined and acknowledged by all
  participants
- [ ] Incident-commander role documented
- [ ] Comms tree exists (internal + external escalation)
- [ ] Post-mortem template exists and is used
- [ ] Tabletop drills happen at least quarterly

#### General hygiene (5 min)
- [ ] No "I'll fix it later" tickets older than 90 days for
  security-tagged work
- [ ] Audit findings closed within agreed SLA
- [ ] OPSEC training annual cadence in calendar

### Scoring & remediation (30 min)

After the self-audit, the team:

1. Tallies OK / GAP / N/A / DEFERRED.
2. For each GAP: owner + deadline + tracking issue.
3. For each DEFERRED: explicit risk-acceptance with sign-off.
4. Schedules the next self-audit (target: 90 days out).

### Debrief (15 min)

The note-taker reads back the gap list. The team confirms
owners + deadlines. Document the score in `transcript.md`.

## Deliverables (post-drill)

| Item | Owner | Target |
|------|-------|--------|
| Self-audit transcript with scores | facilitator | `transcript.md` |
| Gap-tracking Linear issues | each gap owner | private until remediated |
| OPSEC posture summary | team lead | `OPERATOR_RUNBOOK.md` §11 |
| Risk-accepted items list | team lead | (with sign-off) |
| Next self-audit date | team lead | calendar invite |

## Pre-drill checklist

- [ ] Team lead consent
- [ ] All operators given written consent
- [ ] Drill is announced as a self-audit, not an inspection
- [ ] No external auditor in the room (this is internal
  honesty)
- [ ] Time-box of 90 minutes hard
- [ ] Facilitator commits to NO blame in the readout — gaps
  are organizational, not personal

## Cross-references

- **SCN-011** (Lazarus HSM trust boundary) — the
  cryptographic complement
- **SCN-012** (Multichain single-custody) — the operational-
  distribution complement
- **SCN-027** (Mixin cloud-provider compromise) — the IAM
  hygiene complement
- **OPERATOR_RUNBOOK §11, §13** — where the OPSEC posture
  summary lands

## Findings opened

None at the documentation tier. Live self-audit will surface
specific gaps as private Linear issues.
