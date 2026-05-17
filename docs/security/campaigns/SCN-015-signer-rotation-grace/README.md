# SCN-015 — Signer-rotation in-flight race

**Status.** REMEDIATED-GREEN. Test surfaced LTP-A-031 (companion finding); fix landed in same commit.
**Layer.** 2 — Validator / consensus / signing.
**Historical pattern.** Post-compromise key rotation across multiple
historical bridge incidents (Multichain post-detention, Ronin
post-fix, etc.). The general class is "rotated-out key continues to
hold authority after the operator believed it was revoked."
**LTP-A-* link.** [LTP-A-030](../../../SECURITY_AUDIT_2026-05-15.md)
(grace-period rotation safety) + [LTP-A-031](../../../SECURITY_AUDIT_2026-05-15.md)
(surfaced by this scenario — fix landed in same commit).

## What happened (the pattern)

When a key is rotated with a non-zero grace window:

- the OLD key must keep working for already-signed in-flight
  messages that arrive before the grace expires; and
- the OLD key must STOP working for new operations once the
  grace window elapses.

A real failure mode (seen in several bridge post-compromise
rotations): the implementation revokes the old key in ONE code
path but forgets to do so in a parallel path that uses the same
signer-authorization storage. The "rotated-out" key continues to
hold authority for the forgotten path.

## LTP analogue and the finding

LTP's grace-period rotation lives in `rotateSignerWithGrace`
(`LTPAnchorRegistry.sol:307`). It records
`signerExpiresAt[oldVkHash] = block.timestamp + gracePeriod` and
leaves `authorizedSigners[oldVkHash] = true`.

Two paths consume the signer authorization:

| Path | File:line | Checks `signerExpiresAt`? |
|---|---|---|
| `transitionState()` (state-machine path) | LTPAnchorRegistry.sol:234-242 | ✓ yes |
| `_anchor()` (anchor / batchAnchor path) | LTPAnchorRegistry.sol:535-538 (before fix) | **✗ no** |

**The bug:** `_anchor()` did NOT honor `signerExpiresAt`. After
the grace window elapsed, the old key still satisfied `anchor()`
indefinitely — the operator's "I rotated that key three days
ago, it shouldn't work anymore" mental model was wrong.

The contract doc-comment at line 305 explicitly claimed:

> `_anchor()` rejects the old key once expiry elapses.

…but the code didn't implement it.

**Fix landed in same commit.** Two-line addition to `_anchor()`
mirroring `transitionState()`:

```solidity
{
    uint64 expiresAt = signerExpiresAt[signerVkHash];
    if (expiresAt != 0 && block.timestamp > expiresAt) {
        revert UnauthorizedSigner(signerVkHash);
    }
}
```

The new finding is **LTP-A-031**, filed as private Linear issue
GLO-832 per the campaign charter, and now public (this scenario)
because the fix landed simultaneously.

## Defenses pinned (G1-G6)

| ID | Defense | Source |
|----|---------|--------|
| G1 | `rotateSignerWithGrace` records `signerExpiresAt` | LTPAnchorRegistry.sol:333 |
| G2 | `rotateSigner` (0 grace) revokes old key atomically | :326-329 |
| G3 | `transitionState` with old key inside grace succeeds | :234-242 (acceptance side) |
| G4 | `transitionState` with old key after grace reverts | :239-242 |
| G5 | `anchor` with old key inside grace succeeds | :536 + new :541-549 |
| **G6** | **`anchor` with old key AFTER grace reverts (LTP-A-031 fix)** | **new :541-549** |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit | `contracts/test/security/historical/SCN_015_SignerRotationGrace.t.sol` | G1-G6 explicit, plus an edge case (new key works both inside and outside grace) and the 7-day grace cap |

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_015_*' -vvv
```

## Findings opened

- **LTP-A-031** — `_anchor()` ignored `signerExpiresAt`. Linear
  GLO-832 (filed private, now public after fix). Fix at
  `LTPAnchorRegistry.sol:541-549`.

## Cross-references

- **SCN-008** (Ronin active-set) — orthogonal proxy-signing
  defense
- **SCN-009** (Harmony low-threshold) — Byzantine floor deploy
  policy
- **SCN-011** (Lazarus HSM) — key-management trust boundary
- **SCN-012** (Multichain single-custody) — threshold-signing
- **OPERATOR_RUNBOOK §13** — production deploy checklist
