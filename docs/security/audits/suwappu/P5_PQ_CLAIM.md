# P5 — Post-Quantum claim assessment

What Suwappu can and cannot truthfully claim about post-quantum (PQ) security today,
derived from the on-chain-vs-off-chain trust-boundary analysis (see `P5b_ONCHAIN_PQ.md`
for the engineering basis).

## On-chain vs off-chain PQ boundary

| Layer | Mechanism | PQ-safe? |
|---|---|---|
| Off-chain transport (KEM) | ML-KEM-768 (FIPS 203) | **Yes** — NIST PQC |
| Off-chain attestation (signature) | ML-DSA-65 (FIPS 204) | **Yes** — NIST PQC |
| On-chain anchor verification (today) | trusts off-chain relayer; **no on-chain ML-DSA** | **No** (LTP-A-001, by-design) |
| ZK finalization mode | Groth16 / BLS12-381 | **No** — broken by Shor |
| Custody contracts (Vault/MintAdapter/Wrapped/Escrow/Timelock) | plain Solidity, ECDSA/Safe, keccak | **No** — zero PQ crypto |
| Bridge security model in practice | authorized relayer/unlocker set + governance | classical (ECDSA/keccak) |

The custody contracts that hold user funds contain **no post-quantum cryptography**; their
safety rests on the trusted relayer set + governance, which is classical.

## Claim statement (the chosen "honest layered" posture)

**CAN say today:**
> "Suwappu's off-chain transport and attestation layer uses NIST-standardized
> post-quantum cryptography — ML-KEM-768 (FIPS 203) for confidentiality and
> ML-DSA-65 (FIPS 204) for operator attestation."

And, once the P5b precompile ships and is wired in (see below):
> "Settlement on the Suwappu DAG home chain is verified on-chain with FIPS-204 ML-DSA-65;
> EVM-destination bridges inherit post-quantum integrity transitively via Suwappu DAG
> consensus."

**CANNOT say (gate-blocked) until on-chain PQ ships + passes the audit gate:**
- "The bridge is post-quantum secure." (On-chain custody/finalization is not PQ.)
- Any wording implying the EVM-destination mint/unlock path is locally PQ-verified.
- That ZK mode is PQ (Groth16/BLS12-381 is Shor-broken — it must be replaced with the
  PQ-safe proof system from P5b or labelled non-PQ).

## Path to a true bridge-level claim (status)
P5b implements on-chain ML-DSA-65 verification. **Phase-1 core is built + locally verified**
(`suwappu-mldsa-precompile`, 8/8 tests against real FIPS-204 keys). The bold "bridge is
post-quantum" claim unlocks only when: on-chain ML-DSA gates every mint/unlock/finalize
path (INV-PQ-ONCHAIN green + revert-fails), the precompile + verifier pass P1-P3/P7, ZK
mode is PQ-safe or labelled, and the front end (P6) no longer shows mock proofs.

## Recommendation
Until then, all public/marketing material uses the **layered** statement above. A flat
"post-quantum bridge" claim on the EVM destinations would be materially misleading and a
reputational/regulatory risk if scrutinized.
