# Cryptographer

You're reviewing the cryptographic design, the security proofs, the audit
trail, or the formal-verification status. You want to understand the trust
assumptions and find the things that could break.

## 30-second value prop

LTP is built around post-quantum primitives (ML-KEM-768 for KEM, ML-DSA-65
for signatures, both FIPS-approved) layered with classical hybrids
(Ed25519, X25519) for transition-period assurance. The protocol has seven
formally proven security theorems, an independent third-party audit, and an
adversarial threat model that drives the implementation choices.

## Start here

1. **[WHITEPAPER.md](../WHITEPAPER.md)** — the full design. Three-phase
   protocol (COMMIT / LATTICE / MATERIALIZE), erasure coding, dual-lane
   hashing, post-quantum envelope encryption.
2. **[THREAT_MODEL.md](../THREAT_MODEL.md)** — the adversary, the
   capabilities granted, the invariants that must hold. Read this before
   reading the proofs.
3. **[FORMAL_VERIFICATION_STATUS.md](../FORMAL_VERIFICATION_STATUS.md)** —
   what is machine-checked, what is paper-proven, and the explicit gap
   between them.
4. **[SECURITY_AUDIT_2026-05-15.md](../security/audits/internal/SECURITY_AUDIT_2026-05-15.md)** —
   the most recent independent audit findings and remediation status.
5. **[CORRIDOR_INTEGRATION.md](../CORRIDOR_INTEGRATION.md)** — the wire
   format and the domain-separation tags that prevent cross-protocol
   signature reuse.

## Deeper dives

- **Shard exposure attack analysis** →
  [security/audits/internal/001-lattice-key-shard-exposure.md](../security/audits/internal/001-lattice-key-shard-exposure.md)
- **Formal protocol analysis (Tamarin / ProVerif outputs)** →
  [formal/ANALYSIS.md](../formal/ANALYSIS.md)
- **Cross-parity tests (Python ↔ Solidity state-machine validation)** →
  `tests/test_cross_parity.py` and `contracts/test/CrossParity.t.sol`
- **Mathematical review** →
  [security/audits/external/whitepaper-reviews/001/001-Mathematical-Review.md](../security/audits/external/whitepaper-reviews/001/001-Mathematical-Review.md)

## Things we want adversarial eyes on

- The hybrid signature scheme (ML-DSA-65 + Ed25519) — specifically the
  domain-separation tag derivation in `src/ltp/domain.py`.
- The BLS DST string pinning across Python and Solidity (cross-language
  string equality is easy to get wrong; see audit finding LTP-A-022).
- The Merkle-log consistency proof under registry upgrades — the proof
  must survive a UUPS implementation swap.
- The KEM-then-sign vs sign-then-encrypt ordering in the envelope.

If you find something, please follow [SECURITY.md](../../SECURITY.md) —
not the public issue tracker.
