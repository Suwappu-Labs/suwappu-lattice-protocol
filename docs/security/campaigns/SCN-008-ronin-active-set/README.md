# SCN-008 — Ronin active-set collapse

**Status.** VERIFIED-GREEN expected (defenses pre-exist + structural absence).
**Layer.** 2 — Validator / consensus / signing.
**Historical incident.** Ronin Bridge, 23 Mar 2022, $625M.
**LTP-A-* link.** [LTP-A-002](../../../SECURITY_AUDIT_2026-05-15.md)
(governance threshold + production timelock).

## What happened (Ronin)

The Ronin (Axie Infinity) bridge ran a 5-of-9 validator multisig.
Sky Mavis directly controlled 4 of the 9 validator keys. The
remaining 5th "signature" needed for any cross-chain action was
historically provided by Axie DAO via a gas-relayer system —
an arrangement that was never revoked when the relationship
ended in November 2021.

When Lazarus Group compromised an engineer at Sky Mavis (via the
infamous fake-LinkedIn recruiter PDF that ran a payload), they
got 4 keys. Then they tricked the still-active Axie DAO gas-
relayer flow into signing on Axie DAO's behalf — providing the
5th signature without compromising the 5th key.

Result: advertised 5-of-9 → effective 5-of-5 (operator-only).
$625M withdrawn over 6 days before anyone noticed.

Root primitive: **"signer set" was not what it appeared to be**.
Two contributing factors:
1. **Inactive signers** in the nominal set inflated the threshold
   on paper but not in practice.
2. **A proxy/gas-relayer flow** let one party sign on behalf of
   another with no on-chain attestation distinguishing the two.

## LTP analogue

LTPMultiSig has structurally NO proxy-signing surface:

- No `permit(...)` / EIP-712 signature-recovery entrypoint
- No `executeWithSig(bytes)` flow
- No "gas relayer" / meta-transaction pattern
- No "delegate signer" registration

Every confirmation comes from `msg.sender == owner`. The defenses
pinned:

| ID | Defense | Source |
|----|---------|--------|
| R1 | `submitTransaction` credits ONLY `msg.sender` | LTPMultiSig.sol:113-130 |
| R2 | `confirmTransaction` credits ONLY `msg.sender`; no delegation | :134-141 |
| R3 | `executeTransaction` counts ONLY recorded per-owner confirmations from R1/R2 | :161-174 |
| R4 | No `permit`/`executeWithSig` entrypoint; unknown selectors revert (no fallback) | structural |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_008_Ronin_ActiveSetCollapse.t.sol` | R1, R2 (legit + attacker-relay attempt), R3, R4 (unknown selector reverts + fuzz over arbitrary selectors), plus "single compromised owner cannot execute" |

## Notes on the fork-test variant

The campaign plan suggested running SCN-008 as a Foundry fork
test against the GSX Testnet deployment. A fork test is feasible
without operator coordination (read-only) but doesn't add
defensive value beyond the local-deploy test pinned here — the
deployed instance runs the same bytecode. The fork variant is
deferred as a follow-up if FedRAMP evidence requires it.

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_008_*' -vvv
```

## Findings opened

None. Proxy-signing surface is structurally absent.
