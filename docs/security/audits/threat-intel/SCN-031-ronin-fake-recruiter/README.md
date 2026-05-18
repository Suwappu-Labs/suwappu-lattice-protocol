# SCN-031 — Ronin fake-recruiter LinkedIn DM (tabletop)

**Status.** SCAFFOLDED. Live drill deferred to operator-team session.
**Layer.** 8 — Social engineering.
**Historical incident.** Ronin Bridge, 23 Mar 2022, \$625M
(initial-access vector).

## What happened (the initial-access vector)

The Ronin compromise (covered from the contract angle in SCN-008)
started with a single targeted social-engineering attack:

1. An attacker (Lazarus Group, per Chainalysis + OFAC) created a
   fake LinkedIn recruiter profile.
2. Reached out to a Sky Mavis senior engineer with a job offer.
3. The "interview" included a take-home PDF "job description."
4. The PDF exploited the engineer's machine and installed
   persistence.
5. From that one machine, the attacker pivoted to the validator
   keys and the rest is on-chain history.

Root primitive: **a single trusted operator's host is the
weakest link** between cryptographic protection and the
attacker. The defense is **operator awareness + recognition
training** combined with system-level isolation of high-trust
signing operations.

## Tabletop drill design

Format: **60-90 minute paper exercise** with the on-call team.
No surprises, no real phishing payload — purely a walkthrough
of "what would happen if this scenario showed up tomorrow?"

### Pre-drill setup (5 min)

- Team lead confirms written consent from each participant.
- Drill is announced as a drill at the start; no element of
  surprise.
- One facilitator (not a participant); one note-taker.

### Scenario 1: "The recruiter pings me on LinkedIn" (20 min)

The facilitator describes:
> One of our engineers receives a LinkedIn DM from a recruiter
> at "Genesis Crypto Partners" offering a Principal Bridge
> Engineer role at \$450k base + significant equity. The
> recruiter sends a calendar link for an initial screen and a
> "job description PDF" via Calendly.

Discussion questions:

1. What's the team's expected response BEFORE the engineer
   downloads the PDF?
2. Is there a documented "we'll always verify recruiter
   contacts via official company channel" policy? If not,
   where would such a policy live?
3. If the engineer DID download and open the PDF on their
   work machine, what's the detection path?
4. How would the team learn the machine had been
   compromised — and how quickly?
5. What's the time between (compromise) and (key access)?
   Is it minutes, hours, days?

### Scenario 2: "Discovery during routine signing" (20 min)

> Three days after the PDF, the engineer is asked to co-sign a
> routine multisig proposal. They notice their Ledger device
> shows a slightly different transaction summary than what the
> wallet UI shows.

Discussion:

1. What's the documented "if the Ledger and the UI disagree"
   policy? (Cross-references SCN-013 / O1-O5.)
2. Does the engineer have a way to ABORT mid-signing without
   disrupting the rest of the team?
3. If they abort: what's the next step? Quarantine the
   machine? Pause the multisig?

### Scenario 3: "Post-incident response" (20 min)

> The team confirms the machine is compromised. The engineer's
> keys have been used by an attacker for at least 12 hours.

Discussion:

1. What's the documented incident-response sequence?
2. Who's the IC (incident commander) on rotation?
3. What's the comms tree (internal Slack, ops team, audit
   partners, legal)?
4. Does the team have authority to rotate signer keys without
   board approval? If not, who does?
5. What's the post-mortem timeline target?

### Debrief (15 min)

- Note-taker reads back the gaps surfaced.
- Each gap is assigned: (a) immediate action, (b) runbook
  update, or (c) accepted-with-rationale.
- Schedule the runbook-update PRs.

## Deliverables (post-drill)

| Item | Owner | Target |
|------|-------|--------|
| Transcript / summary of the drill | facilitator | `docs/security/audits/threat-intel/SCN-031-ronin-fake-recruiter/transcript.md` |
| Updates to `OPERATOR_RUNBOOK.md` §11 (monitoring) and §13.x (incident response) | ops team | next operator-runbook PR |
| Decision on whether to add an external "phishing-recognition" annual training | team lead | tabletop debrief |

## Pre-drill checklist (must be true BEFORE scheduling)

- [ ] Operator-team lead has reviewed and signed off on this
  README
- [ ] All participants have given written consent
- [ ] Drill is announced as a drill at start; no surprise
- [ ] No real phishing payload, no live external party
- [ ] Facilitator is NOT a participant; note-taker is NOT a
  participant
- [ ] Time-box of 90 minutes hard
- [ ] Debrief discussion is captured in `transcript.md`

## Cross-references

- **SCN-008** (Ronin active-set collapse) — the contract-side
  defense
- **SCN-011** (Lazarus HSM) — the cryptographic-tier defense
- **SCN-013** (Radiant blind-signing) — the wallet-UX defense
  (Mandiant: same attacker, similar TTP)
- **OPERATOR_RUNBOOK §11, §13** — where post-drill updates land

## Findings opened

None at the documentation tier. Live drill will surface drill-
specific runbook gaps as Linear issues (filed privately per
charter).
