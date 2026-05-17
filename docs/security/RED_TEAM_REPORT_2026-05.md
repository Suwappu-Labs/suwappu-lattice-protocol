# LTP Internal Red-Team Report — May 2026

> **Type.** Internal red-team self-assessment.
> **Not independent assurance.** This report is authored by the
> LTP engineering team against its own code. It does NOT
> substitute for a third-party audit. Intended use: preparatory
> material that lets an external audit firm scope the engagement
> in hours, not days.
>
> **Campaign window.** 2026-05-15 → 2026-05-17 (3-day intensive).
> **Repository.** `GlobalSettlementNetwork/gsx-lattice-protocol`.
> **Commit at close.** `698b894` (`main`, post PR #28 merge).
> **Authorization.** [`/SECURITY_TESTING.md`](../../SECURITY_TESTING.md), timestamp 2026-05-16.
> **Process record.** [`RED_TEAM_CAMPAIGN_2026-05.md`](RED_TEAM_CAMPAIGN_2026-05.md).

---

## 1. Disclaimer and self-assessment framing

This document compiles the artifacts of the LTP team's internal
red-team campaign against the Lattice Transfer Protocol. Three
properties distinguish it from a third-party audit:

1. **Authorship.** Authored by the same engineers who wrote the
   code. Findings reflect what the team could see; an
   independent reviewer will see surfaces we missed.
2. **Severity calls.** Self-assigned using the same scale that
   [`SECURITY_AUDIT_2026-05-15.md`](../SECURITY_AUDIT_2026-05-15.md)
   uses (Critical / High / Medium / Low / Informational). An
   independent assessor may reweight these.
3. **Scope.** Intentionally narrow — replaying historical bridge
   hack patterns. It does NOT cover economic-attack modeling,
   formal verification, or independent threat modeling. See
   §11 (Recommended External-Audit Focus Areas) for what is
   explicitly out of scope and recommended for a paid engagement.

Auditors reading this document should treat it as a coverage map
of what the team has already tested, not as a substitute for
their own review.

---

## 2. Executive summary

The May 2026 campaign converted the catalog of historical bridge
hacks documented in
[`SECURITY_AUDIT_2026-05-15.md` §28](../SECURITY_AUDIT_2026-05-15.md#real-world-bridge-hacks-cross-reference)
into 33 executable defensive regression tests, organized in 8
attack layers (Layer 1 contract input validation through Layer 8
social-engineering tabletops).

**Outcome at a glance.**

| Metric | Value |
|---|---|
| Total scenarios run | 33 |
| Attack layers covered | 8 (Layer 1-8) |
| Historical incidents mapped | 10+ (Wormhole, Ronin, Nomad, Poly, Orbit, Penpie, Euler, THORChain, Harmony, Multichain, Cypher, LayerZero, Parity, Curve, Badger, Ledger, Mixin, IBC class, plus Layer-8 cases) |
| New findings surfaced | **1** (LTP-A-031, HIGH, remediated same branch) |
| Defenses verified-green | 20 |
| Surfaces structurally absent from LTP | 5 |
| Policy-only / partial scenarios | 4 |
| Live tabletop drills scaffolded (consent gate) | 3 |
| Forge tests added (`contracts/test/security/historical/`) | ~70 across 18 files |
| Pytest tests added (`tests/security/historical/`) | ~50 across 5 files |
| Echidna harnesses added | 5 |
| Contract code changed | 5 LOC — `LTPAnchorRegistry.sol:541-549` (LTP-A-031 fix) |

**Headline finding (campaign-surfaced):**

> **LTP-A-031** — `LTPAnchorRegistry._anchor()` did not check
> `signerExpiresAt`, while the parallel `transitionState()` path
> did. A signer rotated out with a non-zero grace window
> continued to satisfy `anchor()` indefinitely after the grace
> expired. Self-rated HIGH severity. Surfaced by SCN-015 (Signer
> rotation in-flight race). Fix landed on the same branch in
> PR #26, commit `577e80f`. Status: **Fixed**.

No further exploitable findings were surfaced. 20 historical
attack classes were confirmed neutralized by pre-existing
defenses; 5 were structurally absent (no oracle, no flashloan,
no hot-wallet, etc.); 4 attack classes apply to surfaces LTP has
not deployed yet (frontend / CDN / IAM / hardware-wallet UX) and
are addressed by operator-policy documents pending activation.

---

## 3. Scope

### 3.1 In scope

| Surface | Path |
|---|---|
| Solidity registry + governance | `contracts/src/LTPAnchorRegistry.sol`, `LTPMultiSig.sol`, `OptimisticBridgeChallenge.sol`, `BridgeEmitter.sol`, `ZKBridgeVerifier.sol` |
| Deploy scripts | `contracts/script/DeployMainnet.s.sol` (timelock-floor policy) |
| Python SDK | `src/ltp/` (signing, threshold, HSM, BLS, sequencing) |
| Gateway | `src/ltp/gateway/` (HTTP bind, gRPC limits) |
| CI / supply chain | `.github/workflows/`, base-image digest pinning, action SHA pinning |

### 3.2 Out of scope for THIS campaign

- **gsx-dag BFT consensus.** Audited under a separate workstream
  (`GlobalSettlementNetwork/gsx-dag`). Cross-repo wire-format
  invariants are covered by SCN-030 (IBC replay class) but the
  consensus algorithm itself is not.
- **Economic / market-manipulation attacks.** No price-feed
  ingestion lives in LTP today (see §9 STRUCTURALLY-N/A).
- **Cryptographic primitives.** ML-KEM-768, ML-DSA-65, BLS12-381
  are treated as black-box trusted; their internal correctness
  is out of scope. Their *integration* (DST strings, key custody)
  is in scope.
- **Operator OPSEC.** Layer 8 scenarios (SCN-031..033) are
  scaffolded but live drills are deferred to operator-team
  consent per charter.
- **Formal verification.** See
  [`FORMAL_VERIFICATION_STATUS.md`](../FORMAL_VERIFICATION_STATUS.md)
  for the machine-checked surface; this campaign is empirical.

### 3.3 Repository state at campaign close

- Branch: `main`
- Commit: `698b894` (Merge PR #28)
- Date: 2026-05-17

---

## 4. Methodology

### 4.1 Process

Five-step pattern adapted from TIBER-EU and MITRE ATT&CK,
compressed to a single protocol:

1. **Threat intelligence input** — start from a documented
   post-mortem (Rekt News, SlowMist, Trail of Bits, project
   blog, court filing). No speculation.
2. **Pattern abstraction** — reduce the incident to its
   primitive (e.g., "signature-count check skipped", "validator
   key compromised", "frontend served by attacker CDN").
3. **LTP surface mapping** — find the analogous function call,
   RPC endpoint, signing path, or operator workflow.
4. **Defensive-test authoring** — write a `forge` / `pytest`
   test that replays the abstract pattern against the LTP
   surface and asserts the defense fires.
5. **Red-to-green loop** — test passes on first run → record
   evidence (VERIFIED-GREEN). Test fails → open finding,
   author patch on same branch, re-run until green
   (REMEDIATED-GREEN).

### 4.2 Tooling matrix

| Layer | Tool | Configuration |
|---|---|---|
| Solidity unit / property | Foundry `forge` | `contracts/foundry.toml` |
| Solidity invariants | Foundry `invariant` profile | `contracts/test/invariant/` |
| Solidity fuzz | Echidna | `contracts/echidna/*.yaml` |
| Solidity static analysis | Slither + solhint | `.slither.config.json`, `.solhint.json` |
| Python | `pytest` | `pyproject.toml` |
| Python security audit | `pip-audit` | `.github/workflows/etp.yml` |
| Documentation lint | `markdownlint-cli2`, `lychee`, `mmdc` | `.markdownlint-cli2.jsonc`, `lychee.toml`, `.github/workflows/docs.yml` |
| API docs gate | `pdoc` | `make docs-api` |

### 4.3 Standards referenced

- **NIST SP 800-115** — Technical Guide to Information Security
  Testing and Assessment (penetration-testing methodology).
- **OWASP SCSVS** — Smart Contract Security Verification
  Standard (control categories).
- **MITRE ATT&CK for Cloud** — Layer-7 infra scenarios mapped
  to ATT&CK tactic IDs in per-scenario READMEs.
- **TIBER-EU** — Threat Intelligence-Based Ethical
  Red-teaming (overall structure).
- **Trail of Bits TRAIL** threat model — codebase-maturity
  rubric in §10.

### 4.4 What was NOT done

Explicit list of techniques deliberately excluded:

- No standalone exploit binaries, no malware, no exfil tooling
  (charter prohibition).
- No probing of third-party systems (charter prohibition).
- No live mainnet broadcasts — fork tests read state only.
- No surprise social-engineering against the team (consent
  gate).
- No formal model checker run (Manticore, CBMC). Foundry
  invariants are the property-based proxy.

---

## 5. Threat model — historical incident mapping

Each row maps a documented historical bridge hack to its
abstract attack primitive, the corresponding LTP surface, the
scenario ID that exercises it, and the defense outcome.
Post-mortem citations live in each scenario's `threat-intel.md`.

### 5.1 Smart-contract input validation (Layer 1)

| Historical incident | Year | Loss | Attack primitive | LTP surface | SCN | Outcome |
|---|---|---|---|---|---|---|
| Wormhole | 2022 | $326M | Signature-count check skipped | `LTPAnchorRegistry.anchor` | [SCN-001](campaigns/SCN-001-wormhole-signature-skip/) | ✓ VERIFIED-GREEN |
| Nomad | 2022 | $190M | Initializer accepted any message hash as valid | UUPS proxy init guard | [SCN-002](campaigns/SCN-002-nomad-init-bug/) | ✓ VERIFIED-GREEN |
| Poly Network | 2021 | $611M | Keeper-role privilege escalation via crafted message | `onlyAdmin` gates | [SCN-003](campaigns/SCN-003-poly-keeper-escalation/) | ✓ VERIFIED-GREEN |
| Orbit Chain | 2024 | $82M | Multisig threshold subversion | `LTPMultiSig` threshold | [SCN-004](campaigns/SCN-004-orbit-multisig-subversion/) | ✓ VERIFIED-GREEN |
| Penpie | 2024 | $27M | Callback reentrancy through forgotten path | `OptimisticBridgeChallenge` | [SCN-005](campaigns/SCN-005-penpie-reentrancy/) | ✓ VERIFIED-GREEN |
| Euler | 2023 | $197M (recovered) | Donate-to-self account state confusion | Bond accounting | [SCN-006](campaigns/SCN-006-euler-donate-to-self/) | ✓ VERIFIED-GREEN |
| THORChain (ETH router) | 2021 | $5M | ABI-decode misinterpretation | `BridgeEmitter` + `ZKBridgeVerifier` | [SCN-007](campaigns/SCN-007-thorchain-decode/) | ✓ VERIFIED-GREEN |

### 5.2 Validator / consensus / signing (Layer 2)

| Historical incident | Year | Loss | Attack primitive | LTP surface | SCN | Outcome |
|---|---|---|---|---|---|---|
| Ronin | 2022 | $625M | 5-of-9 with only 4 active signers (proxy signing) | `LTPMultiSig` no-proxy-signing | [SCN-008](campaigns/SCN-008-ronin-active-set/) | ✓ VERIFIED-GREEN |
| Harmony | 2022 | $100M | 2-of-5 threshold + 2 key compromise | `DeployMainnet` Byzantine floor | [SCN-009](campaigns/SCN-009-harmony-low-threshold/) | ✓ VERIFIED-GREEN |
| THORChain (Bifrost) | 2021 | $140k | Mis-signed aggregate accepted | `BLS.aggregate_verify` | [SCN-010](campaigns/SCN-010-thorchain-bifrost/) | ✓ VERIFIED-GREEN |
| Lazarus-class | n/a | n/a | Sustained key compromise via OPSEC drift | `HSMBackend` / `SoftwareHSM` | [SCN-011](campaigns/SCN-011-lazarus-hsm/) | ✓ VERIFIED-GREEN |

### 5.3 Key management and rotation (Layer 3)

| Historical incident | Year | Loss | Attack primitive | LTP surface | SCN | Outcome |
|---|---|---|---|---|---|---|
| Multichain | 2023 | $125M | Single-custody collapse | `threshold_signing.py` | [SCN-012](campaigns/SCN-012-multichain-single-custody/) | ✓ VERIFIED-GREEN |
| Radiant Capital | 2024 | $58M | Blind-signing on hardware wallet | Operator policy O1-O5 | [SCN-013](campaigns/SCN-013-radiant-blind-signing/) | 📝 DOCUMENTATION-COMPLETE |
| Mt Gox | 2011-14 | $480M | Hot-wallet drain | (no on-chain hot wallet) | [SCN-014](campaigns/SCN-014-mt-gox-hot-wallet/) | — STRUCTURALLY-N/A |
| **(campaign-surfaced)** | 2026 | — | Signer-rotation grace race | `_anchor` `signerExpiresAt` | [SCN-015](campaigns/SCN-015-signer-rotation-grace/) | ⚠ **REMEDIATED-GREEN (LTP-A-031)** |

### 5.4 Governance (Layer 4)

| Historical incident | Year | Loss | Attack primitive | LTP surface | SCN | Outcome |
|---|---|---|---|---|---|---|
| Cypher | 2023 | $1M | Pause bypass via upgrade | pause + upgrade co-control | [SCN-016](campaigns/SCN-016-cypher-pause-bypass/) | ✓ VERIFIED-GREEN |
| LayerZero DVN debate | 2024 | n/a | DVN-count downgrade | `setArbiter` separation | [SCN-017](campaigns/SCN-017-layerzero-dvn/) | ✓ VERIFIED-GREEN |
| Parity multisig | 2017 | $280M frozen | `initialize` callable on impl | `_disableInitializers` | [SCN-018](campaigns/SCN-018-parity-init/) | ✓ VERIFIED-GREEN (cross-ref) |
| Timelock-floor class | n/a | n/a | Sub-grace timelock delay deployed | `DeployMainnet` 24h floor | [SCN-019](campaigns/SCN-019-timelock-floor/) | ✓ VERIFIED-GREEN |

### 5.5 Oracle / data feed (Layer 5)

| Historical incident | Year | Loss | Attack primitive | LTP surface | SCN | Outcome |
|---|---|---|---|---|---|---|
| Mango | 2022 | $116M | Oracle price manipulation | (no on-chain oracle) | [SCN-020](campaigns/SCN-020-mango-oracle-manipulation/) | — STRUCTURALLY-N/A |
| Cream | 2021 | $130M | Flashloan + oracle | (no flashloan, no oracle) | [SCN-021](campaigns/SCN-021-cream-flashloan-oracle/) | — STRUCTURALLY-N/A |
| bZx (three-incident) | 2020-21 | $8M+ | Leverage / margin / borrow | (no leverage / margin) | [SCN-022](campaigns/SCN-022-bzx-three-incident/) | — STRUCTURALLY-N/A |

### 5.6 Frontend / supply chain (Layer 6)

| Historical incident | Year | Loss | Attack primitive | LTP surface | SCN | Outcome |
|---|---|---|---|---|---|---|
| Curve DNS hijack | 2022 | $610k | Registrar DNS hijack | (no LTP dApp domain today) | [SCN-023](campaigns/SCN-023-curve-dns-hijack/) | 📝 PARTIAL — C1-C6 policy drafted |
| Curve Vyper compiler | 2023 | $73M | Compiler reentrancy bug | Solidity pragma + SHA-pinned actions | [SCN-024](campaigns/SCN-024-curve-vyper-compiler/) | ✓ VERIFIED-GREEN |
| Badger Cloudflare | 2021 | $120M | CDN worker injection | (no LTP CDN today) | [SCN-025](campaigns/SCN-025-badger-cloudflare/) | 📝 PARTIAL — B1-B6 policy drafted |
| Ledger Connect Kit | 2023 | $610k | npm package compromise | Docker digest-pin + pip-audit | [SCN-026](campaigns/SCN-026-ledger-connect-kit-npm/) | ✓ VERIFIED-GREEN |

### 5.7 Off-chain infrastructure (Layer 7)

| Historical incident | Year | Loss | Attack primitive | LTP surface | SCN | Outcome |
|---|---|---|---|---|---|---|
| Mixin | 2023 | $200M | Cloud-provider compromise | multi-account KMS distribution | [SCN-027](campaigns/SCN-027-mixin-cloud-compromise/) | 📝 DOCUMENTATION-COMPLETE — IAM audit deferred |
| Gateway bind class | n/a | n/a | 0.0.0.0 default exposure | `__main__.py` loopback default | [SCN-028](campaigns/SCN-028-gateway-bind/) | ✓ VERIFIED-GREEN |
| gRPC exhaustion class | n/a | n/a | Resource exhaustion | `server.py` 4 MB / 100-stream limits | [SCN-029](campaigns/SCN-029-grpc-resource-exhaustion/) | ✓ VERIFIED-GREEN |
| Cosmos IBC | theoretical | n/a | Packet replay across chains | replay + chain-id + sequence | [SCN-030](campaigns/SCN-030-ibc-packet-replay/) | ✓ VERIFIED-GREEN (via SCN-001) |

### 5.8 Social engineering (Layer 8, tabletop only)

| Historical incident | Year | Loss | Attack primitive | LTP surface | SCN | Outcome |
|---|---|---|---|---|---|---|
| Ronin fake-recruiter | 2022 | $625M | LinkedIn DM with malicious PDF | Operator awareness | [SCN-031](campaigns/SCN-031-ronin-fake-recruiter/) | 🧑‍✈️ SCAFFOLDED — drill pending consent |
| Inferno Drainer | 2023-24 | $90M+ | Wallet-drainer kit + phishing | End-user dApp posture | [SCN-032](campaigns/SCN-032-inferno-drainer/) | 🧑‍✈️ SCAFFOLDED — drill pending consent |
| Heco / HTX Sun-era OPSEC | 2023 | $86M + $30M | Gradual OPSEC drift | Self-audit | [SCN-033](campaigns/SCN-033-heco-opsec-hygiene/) | 🧑‍✈️ SCAFFOLDED — drill pending consent |

---

## 6. Findings summary

### 6.1 Aggregate severity table

Pulled from
[`SECURITY_AUDIT_2026-05-15.md` § Summary by severity](../SECURITY_AUDIT_2026-05-15.md#summary-by-severity)
with the campaign-surfaced finding folded in.

| Severity | Total | Closed (audit + campaign) | Deferred to follow-up |
|---|---|---|---|
| CRITICAL | 6 | 4 (LTP-A-004, -006, -007, -009) | 2 (LTP-A-001 by-design, -002 needs v7 deploy) |
| HIGH | 10 | 7 (incl. LTP-A-031 from this campaign) | 3 (LTP-A-005, -014, -022) |
| MEDIUM | 7 | 6 | 1 (LTP-A-024) |
| LOW | 6 | 1 (LTP-A-027) | 5 |
| INFO | 2 | 2 | 0 |
| **Strengths register** | 20 | n/a | n/a |
| **Total findings** | **31** | **20 closed** | **11 deferred** |

### 6.2 Severity scale (self-applied)

| Severity | Definition |
|---|---|
| CRITICAL | Direct loss of user funds or anchor authenticity exploitable by an unprivileged attacker with no preconditions. |
| HIGH | Loss-of-funds or anchor-authenticity bug requiring a precondition (e.g., compromised operator key, specific governance state). LTP-A-031 falls here: requires a rotation-grace window to be open. |
| MEDIUM | Defense in depth violation, non-fund-loss correctness bug, or denial-of-service requiring privileged position. |
| LOW | Hardening / cleanup; no exploit path observed under current operator model. |
| INFORMATIONAL | Documentation, code-quality, or property assertion that closes a hypothetical class but is not currently exploitable. |

Scale matches
[`SECURITY_AUDIT_2026-05-15.md`](../SECURITY_AUDIT_2026-05-15.md);
this report does not introduce a new scale.

---

## 7. Detailed finding — campaign-surfaced

Only one finding was surfaced by this campaign. The 30 pre-
existing findings (LTP-A-001..030) are documented in
[`SECURITY_AUDIT_2026-05-15.md`](../SECURITY_AUDIT_2026-05-15.md)
and are not duplicated here.

### LTP-A-031 — `_anchor()` ignored `signerExpiresAt`

| Field | Value |
|---|---|
| **Title** | `_anchor()` ignored `signerExpiresAt` (companion to LTP-A-030) |
| **Severity** | HIGH (self-assigned) |
| **Type** | Access Control / Time-Based Authorization |
| **Difficulty (ToB-style)** | Low — single missing check, deterministic to exploit once a rotation grace window is open |
| **Surfaced by** | SCN-015 authoring (Signer rotation in-flight race) |
| **Target** | `contracts/src/LTPAnchorRegistry.sol:535-549` |
| **Linear** | [GLO-832](https://linear.app/globalsettlement/issue/GLO-832) |
| **Remediation PR** | [#26](https://github.com/GlobalSettlementNetwork/gsx-lattice-protocol/pull/26), commit `577e80f` |
| **Status** | ✓ Fixed |
| **Regression test** | `test_G6_old_key_rejected_after_grace_via_anchor` in `contracts/test/security/historical/SCN_015_SignerRotationGrace.t.sol` |

#### Description

`rotateSignerWithGrace(oldVk, newVk, gracePeriod)` records
`signerExpiresAt[oldVk] = block.timestamp + gracePeriod` and
leaves `authorizedSigners[oldVk] = true` so in-flight messages
signed by the old key complete during the grace window.

Two paths consume signer authorization:

| Path | Location | Honored `signerExpiresAt` before fix? |
|---|---|---|
| `transitionState()` (state-machine path) | `LTPAnchorRegistry.sol:234-242` | ✓ yes |
| `_anchor()` (anchor / batchAnchor path) | `LTPAnchorRegistry.sol:535-538` | ✗ **no** |

`_anchor()` only checked `authorizedSigners`. The two paths
diverged.

The doc-comment at `LTPAnchorRegistry.sol:305` explicitly
claimed that `_anchor()` rejects the old key once expiry
elapses. The code did not implement that claim.

#### Impact

An operator who rotated a compromised key with a 7-day grace
window believed the old key would stop working post-grace. In
fact, `anchor()` continued to accept the rotated-out key
indefinitely (`authorizedSigners[oldVk]` stayed `true`; no
expiry check fired on the `_anchor` path).

A bridge attacker who had previously compromised the rotated-
out key could continue to anchor entities under that key past
the operator's intended revocation horizon — defeating the
purpose of the grace-window rotation primitive.

#### Exploit scenario

1. Operator detects compromise of signer key `oldVk` at time `T`.
2. Operator calls `rotateSignerWithGrace(oldVk, newVk, 7 days)`
   to give in-flight messages time to drain.
3. At `T + 7 days + 1`, operator believes `oldVk` is fully
   revoked.
4. Attacker (still in possession of `oldVk`'s private material)
   calls `anchor(...)` signed by `oldVk` at `T + 30 days`.
5. **Before fix:** call succeeds. `signerExpiresAt` check is
   absent on the `_anchor` path; `authorizedSigners[oldVk]` is
   still `true`. Attacker anchors arbitrary entities under the
   compromised identity.
6. **After fix:** call reverts with `UnauthorizedSigner(oldVk)`.

#### Recommendation

**Short term (done).** Mirror the `transitionState()` expiry
check in `_anchor()`. Two-line block immediately after the
`authorizedSigners` check:

```solidity
{
    uint64 expiresAt = signerExpiresAt[signerVkHash];
    if (expiresAt != 0 && block.timestamp > expiresAt) {
        revert UnauthorizedSigner(signerVkHash);
    }
}
```

**Long term.** Refactor the two signer-authorization sites
into a single internal `_authorizeSigner(bytes32 vkHash)`
helper called from both `transitionState()` and `_anchor()`.
The two paths drifted because the check was duplicated rather
than centralized; centralization removes the future-divergence
risk class. Tracked separately; not blocking on this finding.

#### Remediation evidence

- Fix commit: `577e80f` (PR [#26](https://github.com/GlobalSettlementNetwork/gsx-lattice-protocol/pull/26))
- Regression test (added same PR): `test_G6_old_key_rejected_after_grace_via_anchor`
- Pre-fix verification: before the fix landed, the G6 test
  failed on the exact input the operator believed was now safe.
  Post-fix, G6 passes.
- Companion finding: [LTP-A-030](../SECURITY_AUDIT_2026-05-15.md#ltp-a-030)
  (grace-period rotation safety) — LTP-A-031 is the
  forgotten-second-path bug introduced when LTP-A-030's
  rotation primitive was added.

#### Auditor's note

This finding is the exact failure mode the campaign methodology
was designed to catch: a single missing line in the second of
two parallel authorization paths. An auditor reviewing the
remediation should confirm (a) the two-line check is byte-
identical to the `transitionState()` block, (b) no third
authorization path exists in the contract (search for
`authorizedSigners[`), (c) the G6 test correctly fails when
the new check is mutated out.

---

## 8. Defenses verified (negative results)

The following 20 historical attack classes were confirmed to be
neutralized by pre-existing LTP defenses. Each row identifies
the attack primitive, where the defense lives, and the test
file that pins it. **These surfaces are unlikely to repay
re-testing in an external engagement** — auditor effort is
better spent on §11.

| SCN | Attack class | Defense location | Test file |
|---|---|---|---|
| 001 | Signature-count check skipped (Wormhole) | `LTPAnchorRegistry.anchor` BLS aggregate verify path | `SCN_001_Wormhole_AnchorRegistry.t.sol` + `.invariant.t.sol` |
| 002 | Init callable as message (Nomad) | UUPS proxy `_disableInitializers` + zero-input guards in `_anchor` | `SCN_002_Nomad_InitBug.t.sol` + `.invariant.t.sol` |
| 003 | Keeper-role escalation (Poly) | `onlyAdmin` gates on privileged functions | `SCN_003_Poly_KeeperEscalation.t.sol` + `.invariant.t.sol` |
| 004 | Multisig subversion (Orbit) | `LTPMultiSig` threshold enforcement | `SCN_004_Orbit_MultisigSubversion.t.sol` + `.invariant.t.sol` |
| 005 | Callback reentrancy (Penpie) | `OptimisticBridgeChallenge` ReentrancyGuard + CEI ordering | `SCN_005_Penpie_Reentrancy.t.sol` + `.invariant.t.sol` |
| 006 | Donate-to-self (Euler) | No `receive()` / `fallback()` on bond-bearing contract; bond accounting | `SCN_006_Euler_DonateToSelf.t.sol` |
| 007 | ABI-decode misinterpretation (THORChain) | Strict `(admin, challengeContract, mode)` decode + bounds | `SCN_007_THORChain_DecodeBug.t.sol` |
| 008 | Proxy-signing past active set (Ronin) | `LTPMultiSig` no-proxy semantics; per-call signer enumeration | `SCN_008_Ronin_ActiveSetCollapse.t.sol` |
| 009 | Low threshold deployed (Harmony) | Byzantine floor in `DeployMainnet.s.sol`; deploy-time `require` | `SCN_009_Harmony_LowThreshold.t.sol` |
| 010 | BLS mis-signed aggregate (THORChain Bifrost) | `BLS.aggregate_verify` (blst + py_ecc parity) | `test_scn_010_thorchain_bifrost.py` |
| 011 | Sustained key compromise (Lazarus class) | `HSMBackend` trust boundary + sentinel dk/sk | `test_scn_011_lazarus_hsm.py` |
| 012 | Single-custody collapse (Multichain) | `threshold_signing.py` Shamir share + DKG | `test_scn_012_multichain.py` |
| 015 | Signer-rotation grace race | **NEW** `_anchor` `signerExpiresAt` check (LTP-A-031 fix) | `SCN_015_SignerRotationGrace.t.sol` |
| 016 | Pause bypass via upgrade (Cypher) | Pause + upgrade both `onlyAdmin`; same Timelock | `SCN_016_PauseUpgradeBypass.t.sol` |
| 017 | DVN-count downgrade (LayerZero) | `setArbiter` rejects `arbiter == admin`; structural separation | `SCN_017_LayerZero_DVN.t.sol` |
| 018 | Init-on-implementation (Parity) | `_disableInitializers()` (already pinned by existing `test_implementationCannotBeInitialized`) | (cross-ref) |
| 019 | Timelock-delay floor | `DeployMainnet.s.sol:48` 24h require | `SCN_019_TimelockFloor.t.sol` |
| 024 | Compiler reentrancy (Curve Vyper) | Solidity pragma fixed; GitHub Actions SHA-pinned | (CI policy + docs) |
| 026 | npm supply-chain (Ledger Connect Kit) | Docker base-image digest-pin; `pip-audit` in CI | (CI policy + docs) |
| 028 | Gateway 0.0.0.0 default exposure | `__main__.py` loopback default + explicit opt-in | `test_scn_028_gateway_bind.py` |
| 029 | gRPC resource exhaustion | `server.py` 4 MB / 100-stream / thread-pool limits | `test_scn_029_grpc_limits.py` |
| 030 | IBC packet replay (theoretical class) | Replay + chain-id + sequence (via SCN-001 defense) | (cross-ref) |

---

## 9. Surfaces confirmed absent (structurally N/A)

The following attack classes apply to surfaces LTP does not
expose today. An auditor should distinguish "missing feature"
(deliberate scope choice) from "missing defense" (gap) when
reviewing.

| SCN | Class | Why N/A in LTP |
|---|---|---|
| 014 | Hot-wallet drain (Mt Gox) | LTP holds no on-chain custody; `OptimisticBridgeChallenge` is the only ETH-bearing contract, and only as bond escrow — no hot wallet |
| 020 | Oracle price manipulation (Mango) | No on-chain oracle; no price feed ingested |
| 021 | Flashloan + oracle (Cream) | No flashloan primitive; no oracle |
| 022 | Leverage / margin / borrow (bZx) | No lending, no margin, no leverage |
| 018 | Init-on-implementation (Parity) | `_disableInitializers()` in constructor; verified separately by existing test |

If LTP later adds any of these surfaces (e.g., an oracle for
fee pricing, or any on-chain custody), the corresponding SCN
graduates from N/A to active and the test pack must follow.

---

## 10. Codebase maturity self-assessment (Trail of Bits TRAIL style)

Self-rated. Categories from ToB TRAIL methodology; ratings
{Strong / Satisfactory / Moderate / Weak / Missing / N/A}.

| Category | Rating | Justification |
|---|---|---|
| **Access Controls** | Satisfactory | `onlyAdmin` gates uniform; Timelock-mediated; LTP-A-031 surfaced the only known omission (now fixed). |
| **Arithmetic** | Strong | Solidity 0.8.24 checked arithmetic; no inline assembly arithmetic in registry. |
| **Centralization** | Moderate | Admin role concentrated at Timelock; mitigated by `LTPMultiSig` 2-of-2 + Timelock 24-48h delay. Documented in operator runbook. |
| **Cryptography** | Strong | ML-KEM-768 + ML-DSA-65 + BLS12-381 with Python↔Solidity DST byte-identical; HSM-backed key custody; `assert_real_crypto()` import-time gate. |
| **Data Validation** | Satisfactory | Zero-input guards; sequence monotonicity; replay rejection at `_anchor`. Covered by SCN-001..007. |
| **Documentation** | Satisfactory | Docs for every public function; threat model published; operator runbook; FedRAMP-High SSP narratives. One drift caught (LTP-A-031: doc-comment claimed expiry check that wasn't in code) — fixed. |
| **Front-Running Resistance** | Moderate | Anchors are commit-only — no MEV-extractable orderings on the public surface. No internal AMM. |
| **Key Management** | Satisfactory | HSM abstraction; threshold-signing via DKG; rotation primitive (`rotateSignerWithGrace`) tested by SCN-015 + LTP-A-031 fix. Hardware-wallet UX policy drafted (SCN-013) pending operator rollout. |
| **Memory Safety** | Strong | Python + Solidity stack; no `unsafe` blocks; no FFI to C without HSM boundary. |
| **Monitoring** | Moderate | Anchor events emitted; off-chain monitor not yet productionized — SCN-027 IAM audit deferred. |
| **Specification** | Satisfactory | Wire format specified in `LTP-corridor-v1`; STABILITY_PROMISES contract; THREAT_MODEL.md published. |
| **Testing & Verification** | Strong | ~1,200 Python tests + 84+ Solidity tests + 70 new historical tests (this campaign) + 8 invariants + 5 Echidna harnesses + cross-parity test. CI runs all on every push. |
| **Transaction Ordering** | Satisfactory | Sequence per signer enforced (`signerSequences`); replay rejection by digest; cross-chain replay covered by SCN-030. |
| **Trusted Computing Base** | Satisfactory | TCB enumerated: Solidity compiler 0.8.24, Foundry pinned, Python 3.10-3.13, OpenZeppelin (digest-pinned), HSM vendor, gsx-dag consensus (out-of-scope here). |
| **Upgradeability** | Satisfactory | UUPS with `_disableInitializers()`; `_authorizeUpgrade` gated to Timelock; upgrade plan template under `plans/`; CODEOWNERS routes contract changes. |

Two categories deserve auditor attention based on the self-
rating: **Centralization** and **Monitoring**. The campaign did
not specifically exercise either — they are operational rather
than code-level.

---

## 11. Recommended external-audit focus areas

Where THIS campaign did not have time or expertise to provide
high confidence. An external audit firm landing on the repo
should prioritize the following:

1. **Formal verification of the `_anchor` state machine.** The
   campaign caught LTP-A-031 by writing a regression test
   AFTER spotting the divergence between two paths. A formal
   model (TLA+, Coq, or symbolic execution with hevm /
   Halmos) would surface this class of bug pre-emptively.
   Highest priority.

2. **Economic-attack modeling.** No price-feed today, but
   `OptimisticBridgeChallenge` has a bond mechanism. Adversarial
   bond pricing under EIP-1559 fee spikes, or griefing the
   challenge window, was not exercised. Recommended: pen-test
   the challenge contract's economic equilibrium with a fork-
   simulation harness.

3. **Cross-chain finality assumptions.** LTP anchors cross-chain
   commitments. Reorg behavior at the source chain (L1 reorg,
   uncle blocks, finality delay) was not exercised against the
   anchor-acceptance path. SCN-030 covers replay; reorg is a
   sibling class.

4. **Gas-griefing under EIP-1559.** No tests for malicious gas
   consumption inside `_anchor` (storage-heavy operations,
   loops bounded by attacker input). Static review desirable.

5. **Cryptographic primitive integration.** ML-KEM and ML-DSA
   are trusted as black boxes; their *integration boundary*
   (parameter passing, error handling, side-channel resistance
   of the wrappers) deserves dedicated crypto review.

6. **`LTPMultiSig` cross-implementation parity.** The contract
   is bespoke; cross-check against `safe-contracts` semantics
   for replay protection, nonce ordering, and signature
   malleability under EIP-2098 compact signatures.

7. **Operator IAM and cloud-account boundary (SCN-027 deferral).**
   Out-of-scope for THIS campaign by charter; the next paid
   engagement should include an IAM review of the operator's
   AWS account.

8. **R-5 live tabletop drills (SCN-031..033).** Scaffolded but
   not executed. An external red-team firm with social-
   engineering scope authorized by the operator team would be
   the appropriate executor.

---

## 12. Appendices

### Appendix A — Scenario index

Condensed from
[`campaigns/README.md`](campaigns/README.md). See that index for
the full per-scenario directory list and links.

```
Layer 1 (Contract input)       : SCN-001..007  →  7 verified-green
Layer 2 (Validator/signing)    : SCN-008..011  →  4 verified-green
Layer 3 (Key management)       : SCN-012..015  →  2 verified-green
                                                  1 doc-only (SCN-013)
                                                  1 N/A (SCN-014)
                                                  1 REMEDIATED (SCN-015 / LTP-A-031)
Layer 4 (Governance)           : SCN-016..019  →  4 verified-green
Layer 5 (Oracle)               : SCN-020..022  →  3 N/A
Layer 6 (Frontend/supply)      : SCN-023..026  →  2 verified-green, 2 partial
Layer 7 (Off-chain infra)      : SCN-027..030  →  3 verified-green, 1 doc-only
Layer 8 (Social engineering)   : SCN-031..033  →  3 scaffolded (consent gate)
                                                ──────────────────────
                                                  33 total
```

### Appendix B — Test suite inventory

Counts at commit `698b894`.

| Suite | Path | Files | Approx. tests |
|---|---|---|---|
| Forge historical units | `contracts/test/security/historical/SCN_*.t.sol` | 12 | ~60 |
| Forge historical invariants | `contracts/test/security/historical/SCN_*.invariant.t.sol` | 5 | 8 invariants |
| Forge pre-existing | `contracts/test/*.t.sol` (excluding historical) | 14 | 84 |
| Echidna harnesses | `contracts/echidna/*.yaml` | 5 (SCN-001..005) | property-based |
| pytest historical | `tests/security/historical/test_scn_*.py` | 5 | ~50 |
| pytest pre-existing | `tests/` (excluding historical) | (full suite) | ~1,200 |

CI runtime (campaign close):

- ETP CI / Forge Tests: ~8 min
- ETP CI / Foundry invariant suite: ~12 min
- ETP CI / Python Tests (with real PQ crypto): ~10 min
- ETP CI / Slither + solhint: ~3 min
- ETP CI / Contract Integration (Python + Anvil): ~6 min
- ETP CI / Dependency vulnerability audit (pip-audit): ~1 min
- Docs CI / Lychee + Markdownlint + Mermaid + pdoc: ~5 min

### Appendix C — Tooling configuration

| Tool | Config path |
|---|---|
| Foundry | `contracts/foundry.toml` |
| Slither | `contracts/.slither.config.json` |
| solhint | `contracts/.solhint.json` |
| Echidna | `contracts/echidna/*.yaml` |
| Lychee | `lychee.toml` |
| Markdownlint | `.markdownlint-cli2.jsonc` |
| pip-audit | `.github/workflows/etp.yml` |
| GitHub Actions (SHA-pinned per LTP-A-025) | `.github/workflows/*.yml` |

### Appendix D — References

**Standards.**

- NIST SP 800-115 — Technical Guide to Information Security Testing.
- OWASP SCSVS — Smart Contract Security Verification Standard.
- TIBER-EU — Threat Intelligence-Based Ethical Red-teaming.
- Trail of Bits TRAIL threat model — `blog.trailofbits.com/2025/02/28/threat-modeling-the-trail-of-bits-way/`

**Post-mortems** — per-scenario `threat-intel.md` files cite
primary sources. Summary by incident:

| Incident | Primary citation class |
|---|---|
| Wormhole (2022) | Certus One post-mortem; Rekt News analysis |
| Nomad (2022) | Nomad team disclosure; SlowMist tracking |
| Poly Network (2021) | Poly team disclosure; Mudit Gupta technical analysis |
| Orbit Chain (2024) | Project disclosure; SlowMist |
| Penpie (2024) | Penpie team disclosure; Rekt News |
| Euler (2023) | Euler Labs post-mortem (recovered) |
| THORChain (2021 x2) | THORChain blog; technical analyses |
| Ronin (2022) | Sky Mavis disclosure; Chainalysis |
| Harmony (2022) | Harmony team disclosure |
| Multichain (2023) | Project disclosure; on-chain forensics |
| Radiant (2024) | Project disclosure; technical analyses |
| Mt Gox (2011-14) | Court filings; historical analyses |
| Cypher (2023) | Project disclosure |
| LayerZero (2024 debate) | LayerZero team; community analysis |
| Parity (2017) | Parity post-mortem |
| Mango (2022) | DOJ filings; Mango DAO governance |
| Cream (2021) | Cream team post-mortem |
| bZx (2020-21) | Three separate project disclosures |
| Curve DNS (2022) | Curve team disclosure |
| Curve Vyper (2023) | Vyper team disclosure; Curve emergency response |
| Badger (2021) | Badger team disclosure |
| Ledger Connect Kit (2023) | Ledger team disclosure |
| Mixin (2023) | Mixin team disclosure |
| Heco / HTX (2023) | HTX / Justin Sun statements; Bloomberg |

**Audit-firm reference materials consulted** for the structure
of THIS report (NOT for the LTP code itself):

- Trail of Bits Publications repository.
- ConsenSys Diligence — Linea Rollup Update (2024-12).
- OpenZeppelin Audit Reports — Compound III, others.
- Spearbit audit-template repository.
- Cantina audit-structure blog.
- Zellic Publications repository.
- Red Team Guide report template.

### Appendix E — Authorization trail

- Charter file: [`/SECURITY_TESTING.md`](../../SECURITY_TESTING.md), authorization timestamp 2026-05-16.
- External vulnerability disclosure: [`/SECURITY.md`](../../SECURITY.md).
- Campaign master document (process record): [`RED_TEAM_CAMPAIGN_2026-05.md`](RED_TEAM_CAMPAIGN_2026-05.md).
- Scenario index: [`campaigns/README.md`](campaigns/README.md).
- Standing audit findings register: [`/docs/SECURITY_AUDIT_2026-05-15.md`](../SECURITY_AUDIT_2026-05-15.md).
- Threat model: [`/docs/THREAT_MODEL.md`](../THREAT_MODEL.md).
- Formal verification status: [`/docs/FORMAL_VERIFICATION_STATUS.md`](../FORMAL_VERIFICATION_STATUS.md).
- Operator runbook: [`/docs/OPERATOR_RUNBOOK.md`](../OPERATOR_RUNBOOK.md).
- FedRAMP-High compliance package: [`/docs/compliance/fedramp-high/`](../compliance/fedramp-high/).

**Repeated disclaimer.** This report is an internal red-team
self-assessment. It is not third-party assurance. It is
preparatory material for an external audit engagement.

---

*End of report.*
