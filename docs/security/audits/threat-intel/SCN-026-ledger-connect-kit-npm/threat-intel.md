# SCN-026 — Threat intelligence sources

Historical incident: **Ledger Connect Kit npm supply-chain compromise, 14 December 2023, ~\$610k.**

## Primary sources

- **Ledger team statement** — published on company blog within
  hours; included rollback instructions and the malicious
  version-range.
- **npm security advisory** — package taken down and pinned in
  the npm registry's deprecated-and-malicious list.

## Secondary technical analyses

- **Blockaid** — drainer-payload analysis.
- **OpenZeppelin** — retrospective on npm publish-credential
  security.
- **CISA** — broader advisory on npm supply-chain risks for
  the crypto ecosystem.

## Root primitive

A trusted package on a widely-used registry was overwritten by
an attacker who compromised the publish credentials. The
distribution chain (npm → user dApp → user wallet) had no
integrity check between the original developer's intent and the
end-user's browser.

Generalized: any package-distribution layer (npm, PyPI, crates,
GitHub Packages, Docker Hub) is a privileged execution context
for downstream consumers. Defenses:

1. **Publisher-side**: hardware-token MFA, account audits,
   publish provenance signatures.
2. **Consumer-side**: exact-version pinning, hash verification,
   lockfile audits, SBOM (CycloneDX) verification.
3. **Ecosystem-side**: registry-level signature verification
   (npm provenance, Sigstore), known-malicious-version blocking.

Related incidents:
- event-stream npm package compromise (Nov 2018).
- ua-parser-js / colors.js npm vandalism (Oct 2021, Jan 2022).
- PyPI typosquatting campaigns (ongoing).
- xz-utils sshd backdoor (Mar 2024) — same primitive at the
  Linux distro layer.

## Mapping to LTP

LTP has zero npm/JS consumer surface today. The closest
equivalent surface is Docker base-image consumption, defended
by digest pinning (LTP-A-026 closed). Python dependencies are
pinned in `pyproject.toml`'s production extras. GitHub Actions
are SHA-pinned (LTP-A-025 closed). The toolchain-integrity
defense stack covers the categories that exist today.

If LTP ever publishes an npm client library, the publisher-side
defenses (LK6-LK9 in the README) must be in place before the
first release.

## Date of last verification

2026-05-17 — SCN-026 added under R-4.
