# SCN-032 — Inferno Drainer wallet-drainer kit (tabletop)

**Status.** SCAFFOLDED. Live drill deferred to operator-team session.
**Layer.** 8 — Social engineering.
**Historical pattern.** Inferno Drainer + similar wallet-drainer
toolkits, 2023-2024, cumulative ~\$80M+ extracted from
end-users across hundreds of phishing sites.

## What happens in this class

A wallet-drainer kit is a phishing-as-a-service product:

1. Attacker registers a typosquatted or look-alike domain
   for a popular dApp (`uniswop.org`, `0pensea.io`, etc.).
2. Loads the Inferno Drainer JS payload, paying the kit
   operators a 20-30% cut of stolen funds.
3. Drives traffic via paid Twitter / Discord ads, fake
   airdrop announcements, or compromised legitimate accounts.
4. Victims connect their wallet to the look-alike site.
5. The drainer's JS prompts a `setApprovalForAll` or
   `permit2` transaction. Confirming gives the attacker
   token-spending authority.
6. The attacker drains the wallet.

Inferno Drainer was the dominant kit operator until law
enforcement action in late 2023; the pattern persists with
successor kits (Monkey, Angel, Pink Drainer, etc.).

## Why this matters to LTP

LTP itself is not a drainer target — there's no LTP dApp today
for users to be phished onto (see SCN-023). BUT:

- **LTP's operator team** uses wallets to manage the multisig
  and gateway operator keys. If an operator falls for a
  drainer site while logged into a hot wallet that ALSO has
  LTP signing authority, the attacker drains the LTP-relevant
  keys.
- **LTP's integration partners** will deploy contracts that
  consume `LTPAnchorRegistry`. Their UI choices affect the
  end-user phishing surface.
- **Brand confusion** — if a future drainer kit imitates an
  LTP-branded UI, users may not have a clear way to tell.

## Tabletop drill design

Format: **60-90 minute paper exercise** with the on-call team.

### Scenario 1: "Operator sees a 'Claim your LTP airdrop' ad" (20 min)

The facilitator describes:
> An operator is scrolling X and sees a sponsored post:
> "Global Settlement Network launches LTP token airdrop —
> claim before Friday at ltp-airdrop.io." The site looks
> polished; the URL is not on our official domain list.

Discussion:

1. Does the operator KNOW that LTP has no token / no airdrop?
   Is this documented somewhere they'd see?
2. If they click the link out of curiosity, are they in a
   browser that can interact with their signing wallet? Is
   that browser isolated?
3. What's the response if a teammate forwards this link
   asking "is this real?"

### Scenario 2: "Wallet drainer prompts during a real LTP operation" (20 min)

> An operator is performing a legitimate LTP multisig
> confirmation in a Safe / wallet UI. A pop-up appears
> claiming to be a security warning: "Your wallet may be
> compromised. Click here to verify."

Discussion:

1. What's the documented policy for unexpected pop-ups
   during signing operations?
2. Is the operator's signing browser configured to block
   most pop-ups by default?
3. What's the abort path mid-signing? Does it require
   coordination with other co-signers?

### Scenario 3: "Phishing impersonates the LTP brand" (20 min)

> Trail of Bits reports to us that a phishing site has
> appeared at `ltp-bridge.network` impersonating an LTP
> integration UI. Users are losing funds.

Discussion:

1. Who owns the LTP brand-protection response? Legal? Comms?
2. What's the takedown procedure with the registrar / CDN?
3. Communication to the community — what channels, what
   messaging?
4. Long-term: should we proactively register defensive
   domains (typosquats, common misspellings)?

### Debrief (15 min)

- Note gaps; assign owners; schedule runbook PRs.

## Deliverables (post-drill)

| Item | Owner | Target |
|------|-------|--------|
| Transcript | facilitator | `transcript.md` in this directory |
| Brand-protection policy | comms / legal | future `docs/BRAND_PROTECTION.md` |
| Defensive-domain registration list | ops + legal | private list |
| Updates to operator runbook on "unexpected pop-up" handling | ops | runbook PR |

## Pre-drill checklist

Same prerequisites as SCN-031:

- [ ] Operator-team lead consent
- [ ] All participants given written consent
- [ ] Drill is announced as a drill
- [ ] No real phishing payload, no live external party
- [ ] Facilitator + note-taker are not participants

## Cross-references

- **SCN-013** (Radiant blind-signing) — adjacent operator-tier
  attack
- **SCN-023** (Curve DNS hijack) — sibling brand-protection
  scenario
- **SCN-025** (Badger Cloudflare) — sibling supply-chain
  scenario

## Findings opened

None. Live-drill findings filed privately at drill time.
