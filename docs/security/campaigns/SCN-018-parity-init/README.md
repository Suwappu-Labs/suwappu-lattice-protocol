# SCN-018 — Parity multisig accidental kill (init-on-impl)

**Status.** CONFIRMED-OK. Defense pre-exists and is already pinned by existing audit test.
**Layer.** 4 — Governance.
**Historical incident.** Parity multisig library, Jul 2017 (~\$30M
frozen) + Nov 2017 (~\$280M permanently frozen via accidental
`selfdestruct`).
**LTP-A-* link.** None directly — covered by existing
`test_implementationCannotBeInitialized` in
`contracts/test/LTPAnchorRegistry.t.sol`.

## What happened (Parity)

Parity's wallet library was deployed once and shared by all
multisig instances via `delegatecall`. The library was
**uninitialized** — any caller could `initWallet(owner)` directly
on the library, becoming the owner of the library itself. The
attacker then called `kill()` on the library, triggering
`selfdestruct`. Because every Parity multisig instance pointed
its `delegatecall` at the now-destroyed library, all instances
permanently lost their `execute` path. ~\$280M permanently
frozen.

Two structural primitives were at fault:
1. **Uninitialized library / implementation contract** that
   anyone could claim.
2. **`selfdestruct` in upgradable code** — once destroyed, all
   downstream delegatecalls fail.

## LTP analogue

`LTPAnchorRegistry` is a UUPS proxy pattern. The implementation
is deployed once; the proxy delegate-calls into it. Both Parity
primitives are addressed:

| ID | Defense | Source |
|----|---------|--------|
| I1 | `constructor() { _disableInitializers(); }` on the implementation prevents anyone from calling `initialize()` directly on the impl | LTPAnchorRegistry.sol:96-98 |
| I2 | `initialize()` carries the OpenZeppelin `initializer` modifier — can only run once, on the proxy | :104 |
| I3 | No `selfdestruct` anywhere in the contract | structural (audit-verified absent) |
| I4 | No `delegatecall` to caller-supplied target | structural |

## Existing test coverage (no new test needed)

| Test | File:Line | What it pins |
|---|---|---|
| `test_implementationCannotBeInitialized` | `contracts/test/LTPAnchorRegistry.t.sol:843` | Calling `initialize()` directly on the implementation reverts |

This scenario is **purely a cross-reference / awareness doc**.
The defense is already in the codebase, already in the audit
test suite, and pre-dates the campaign. SCN-018's deliverable is
the campaign-directory entry that ties the historical incident
to LTP's defense for future reviewers / auditors.

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None new.** | _existing_ `contracts/test/LTPAnchorRegistry.t.sol:843` | Defense pre-pinned. |

## How to verify

```bash
cd contracts && forge test --match-test test_implementationCannotBeInitialized -vvv
```

## Cross-references

- **SCN-002** (Nomad init-bug) — Z6 already pins the
  initializer one-shot property via the SCN-002 unit test
- **SCN-016** (Cypher pause-upgrade) — sibling UUPS-upgrade
  defense
- **OPERATOR_RUNBOOK** — deploy procedures verify init runs
  ONCE on the proxy at deploy time

## Findings opened

None. Both primitives (`_disableInitializers` + no `selfdestruct`)
pre-exist and are audit-tested.
