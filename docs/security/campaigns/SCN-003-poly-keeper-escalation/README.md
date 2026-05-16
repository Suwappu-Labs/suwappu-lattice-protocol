# SCN-003 — Poly Network keeper-role escalation

**Status.** VERIFIED-GREEN (defenses hold; CI verifies).
**Layer.** 1 — Smart-contract input validation / access control.
**Historical incident.** Poly Network, 10 Aug 2021, $611M.
**LTP-A-* link.** [LTP-A-005](../../../SECURITY_AUDIT_2026-05-15.md)
("Entity-signer first-write bind-lock").

## What happened (Poly Network)

`EthCrossChainManager.verifyHeaderAndExecuteTx` consumed a cross-
chain message containing `(toContract, methodSig, args)` and
forwarded a call to that target on behalf of the cross-chain
sender. Caller-supplied data could direct the contract to call any
other contract.

The attacker crafted a message that targeted **the manager
contract itself** with method `putCurEpochConPubKeyBytes(bytes)` —
a privileged setter that rotated the trusted-keeper set. They
supplied attacker-controlled keys. Once the keeper set was theirs,
the attacker signed withdrawals freely.

Root primitive: **a generic-forwarder cross-chain handler accepted
caller-supplied (target, method, args) and executed without
checking the target was outside the privileged set.** The privilege
boundary was effectively in caller data, not in `msg.sender`.

## LTP analogue

LTP has **no generic-forwarder** in `LTPAnchorRegistry`. Every
privileged function gates on `msg.sender` against a concrete role:

| ID | Function | Gate | Source line | Revert error |
|----|----------|------|-------------|---------------|
| P1 | `registerSigner` | onlyAdmin | LTPAnchorRegistry.sol:281 | `NotAdmin(msg.sender)` |
| P2 | `revokeSigner` | onlyAdmin | :289 | `NotAdmin` |
| P3 | `rotateSigner` | onlyAdmin | :296 | `NotAdmin` |
| P4 | `rotateSignerWithGrace` | onlyAdmin | :311 | `NotAdmin` |
| P5 | `reassignEntitySigner` | onlyAdmin | :341 | `NotAdmin` |
| P6 | `setBindingDisputeVerifier` | onlyAdmin | :443 | `NotAdmin` |
| P7 | `disputeBinding` | bindingDisputeVerifier-only (NOT admin) | :416 | `NotBindingDisputeVerifier` |
| P8 | `transferAdmin` | onlyAdmin | :129 | `NotAdmin` |
| P9 | `pause` / `unpause` | onlyAdmin | :137, :143 | `NotAdmin` |
| P10 | `anchor()` does NOT register a signer as a side effect | structural | `_anchor` rejects unknown signer at :536 | `UnauthorizedSigner` |

The Poly-equivalent attack reduces to "can any non-admin caller
invoke a privileged function?" — and the answer must be no, on every
function and for every attacker address.

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_003_Poly_KeeperEscalation.t.sol` | P1-P10 explicit + 2 property fuzz tests (arbitrary caller × privileged function; arbitrary caller × disputeBinding) |
| Forge invariant | `contracts/test/security/historical/SCN_003_Poly_KeeperEscalation.invariant.t.sol` | K1 admin-monopoly-on-signers, K2 admin-never-silently-changes |
| Echidna properties | `contracts/test/echidna/SCN_003_PolyEchidna.sol` | R1 admin-never-moves, R2 only-seed-vk-authorized; inline `assert(false)` on every successful attacker path |

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_003_*' -vvv
cd contracts && echidna . --contract SCN_003_PolyEchidna --config echidna.yaml
```

## Findings opened

None expected. Privilege gates pre-exist on every function.
