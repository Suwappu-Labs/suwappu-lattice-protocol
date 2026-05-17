# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Entanglement Transfer Protocol,
please report it responsibly.

**Email:** security@globalsettlement.network

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response
within 7 days.

## Scope

### In Scope

**Protocol & Cryptography:**
- **Cryptographic vulnerabilities** — weaknesses in ML-KEM-768, ML-DSA-65,
  XChaCha20-Poly1305, erasure coding, or dual-lane hashing
- **Key management flaws** — CEK leakage, lattice key exposure, inadequate
  key zeroization, sealed envelope bypass
- **Shard exposure** — any path that allows reconstruction of entity content
  without possessing the sealed lattice key
- **Commitment integrity** — attacks on the append-only Merkle log, tree
  manipulation, signature forgery, signed tree head spoofing
- **Access control bypass** — materializing entities without proper authorization
- **Replay attacks** — circumventing nonce-based replay protection in the bridge

**Smart Contracts:**
- **Contract vulnerabilities** — reentrancy, access control bypass, upgrade logic
  flaws, or storage collision in LTPAnchorRegistry or LTPMultiSig
- **Governance bypass** — circumventing MultiSig threshold requirements, timelock
  delay evasion, unauthorized admin transfer or proxy upgrade
- **Anchor integrity** — forging anchor digests, replaying anchor submissions
  across chains, sequence number manipulation
- **Cross-parity divergence** — Python and Solidity state machines accepting
  different transitions beyond the documented `UNKNOWN→ANCHORED` Solidity-only path

**Bridge:**
- **Bridge security** — relay packet forgery, sealed key tampering during relay,
  cross-chain replay, nonce tracker bypass

### Out of Scope

- **Known intentional divergences** — Solidity allows `UNKNOWN→ANCHORED`
  (documented in `CrossParityTest`); this is by design
- **Testnet timelock delay** — the 60-second delay on GSX Testnet is intentionally
  short for testing; production will use 24-48 hour delays
- **Denial of service on local instances** — the PoC runs in-memory with no
  network exposure
- **Dependencies** — vulnerabilities in Python stdlib modules should be reported
  to the Python Security Response Team; Solidity dependency issues to OpenZeppelin

## Contract Security Model

The on-chain governance chain enforces a multi-step authorization flow:

```
MultiSig (2-of-2) → TimelockController (60s testnet / 24-48h production) → LTPAnchorRegistry (UUPS)
```

- **LTPAnchorRegistry** — UUPS upgradeable proxy with `_authorizeUpgrade()` gated
  to the admin (Timelock). Includes emergency `pause()` / `unpause()`.
- **LTPMultiSig** — N-of-M multi-signature wallet controlling the Timelock.
- **TimelockController** — OpenZeppelin time-delayed governance between MultiSig and Registry.

### Deployed Contract Addresses (GSX Testnet — Chain ID `103115120`)

| Contract | Address |
|----------|---------|
| UUPS Proxy (registry) | `0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4` |
| Implementation v5 | `0xADf01df5B6Bef8e37d253571ab6e21177aCb7796` |
| MultiSig (2-of-2) | `0x0106A79e9236009a05742B3fB1e3B7a52F44373D` |
| Timelock (60s delay) | `0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8` |

## Security Documentation

For detailed security analysis and design decisions:

- [Internal Red-Team Report (May 2026)](docs/security/RED_TEAM_REPORT_2026-05.md)
  — consolidated audit-firm-style report covering 33 scenarios across 8
  attack layers and the LTP-A-031 finding surfaced + remediated by the campaign.
  Recommended starting point for external auditors.
- [Standing Audit Findings (2026-05-15)](docs/SECURITY_AUDIT_2026-05-15.md) — 31 LTP-A-* findings + strengths register
- [Internal Testing Charter](SECURITY_TESTING.md) — authorization and scope for red-team campaigns
- [Threat Model](docs/THREAT_MODEL.md)
- [Security Review (2026-02-24)](docs/design-decisions/Security/SECURITY_REVIEW-2-24-2026.md)
- [Lattice Key Shard Exposure Analysis](docs/design-decisions/Security/001-lattice-key-shard-exposure.md)
- [Architecture — Security Layers](docs/design-decisions/ARCHITECTURE.md#6-security-layers)
- [Formal Verification Tests](contracts/test/FormalVerification.t.sol) — 21 fuzz/invariant/parity tests

## ZK Mode Warning

ZK Transfer Mode uses Groth16 over BLS12-381, which is **not post-quantum safe**.
Deployments with a quantum-adversary threat model must use standard mode only.
See [ZK_TRANSFER_MODE.md](docs/design-decisions/ZK_TRANSFER_MODE.md) for details.

## Disclosure Policy

- We follow coordinated disclosure
- Security fixes will be released as patch versions
- Critical vulnerabilities will be disclosed publicly after a fix is available
