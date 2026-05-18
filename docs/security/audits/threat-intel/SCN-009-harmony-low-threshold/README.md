# SCN-009 — Harmony Horizon low-threshold compromise

**Status.** VERIFIED-GREEN expected.
**Layer.** 2 — Validator / consensus / signing.
**Historical incident.** Harmony Horizon bridge, 23 Jun 2022, ~$100M.
**LTP-A-* link.** [LTP-A-002](../../internal/SECURITY_AUDIT_2026-05-15.md)
(governance threshold) + [LTP-A-004](../../internal/SECURITY_AUDIT_2026-05-15.md)
(single-custody operator signing key).

## What happened (Harmony)

Harmony Horizon ran a 2-of-5 validator multisig. Lazarus Group
compromised 2 of the 5 keys — the bare minimum needed to reach
quorum. Public root-cause analysis points to phishing or hot-
wallet residence on developer machines; no formal post-mortem
identifies the precise compromise vector. $100M drained.

Root primitive: **threshold was chosen without regard to value-
at-risk.** A 2-of-5 is appropriate for a low-stakes admin wallet;
catastrophic for a $100M bridge. The contract enforced
`threshold ≤ owners` (which 2-of-5 satisfied) but it cannot
enforce "threshold reasonable for value-at-risk" — that's an
operational decision made at deploy time.

## LTP analogue

LTP has TWO layers of defense for this class:

| ID | Layer | Defense | Source |
|----|-------|---------|--------|
| H1 | Contract | `LTPMultiSig` constructor enforces `threshold > 0` and `threshold ≤ owners.length`. (No Byzantine floor at contract layer — that's by design, see H2.) | LTPMultiSig.sol:67-69 |
| H2 | **Deploy script** | **`DeployMainnet.s.sol` enforces `threshold >= ceil(N/2) + 1` on every mainnet deploy.** A Harmony-style 2-of-5 would be rejected at deploy time. | DeployMainnet.s.sol:43-47 |
| H3 | Operational | When threshold-many keys ARE compromised, the multisig correctly executes. The defense at that point is OFF-CHAIN: HSM custody, rotation, active-set monitoring. See LTP-A-004 and SCN-011. | OPERATOR_RUNBOOK.md |

The structural lesson: **the contract layer cannot defend against
"threshold too low" alone**. Solana, Cosmos, and EVM multisigs all
share this. The defense lives in the deploy policy (H2) — and LTP
has it.

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_009_Harmony_LowThreshold.t.sol` | H1 (contract accepts arbitrary basic-valid thresholds), H2 (Byzantine floor math + boundary cases + fuzz), H3 (under-quorum blocked, at-quorum executes by design, Byzantine floor blocks same compromise) |

The H3 "at-quorum executes" test is **explicitly documenting**
correct contract behavior — it is NOT a defense, it shows why H2
(deploy policy) is necessary.

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_009_*' -vvv
```

## Findings opened

None. Both contract bounds (H1) and deploy-script Byzantine floor
(H2) pre-exist. The "2-of-2 testnet" choice in
`DeployTestnet.s.sol` is INTENTIONAL (testnet) and not a finding
— the audit (LTP-A-002) flagged it for awareness rather than
remediation.

## Cross-references

- **SCN-004** (Orbit) — covers the M-effective < N collapse via
  key compromise; complementary to H3 here
- **SCN-008** (Ronin) — covers the proxy-signing collapse;
  different primitive
- **SCN-011** (Lazarus-tier sustained compromise) — covers the
  HSM/rotation operational defenses referenced in H3
