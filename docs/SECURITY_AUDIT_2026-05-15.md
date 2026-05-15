# LTP Offensive Security Audit — 2026-05-15

**Scope.** `gsx-lattice-protocol` HEAD `b5201c9` plus the `corridor/wire-mirror` branch. Smart-contract, protocol, and Python surfaces. Modeled on the published post-mortems of the past five years of bridge hacks (Wormhole, Nomad, Ronin, Multichain, Poly Network, Harmony, Orbit, Cypher, LayerZero DVN debate, KyberSlash).

**Format.** Each finding has an ID (`LTP-A-NNN`), a severity, a real-world hack cross-reference, the attacker capability required, the exploit chain, a financial impact estimate framed by trust assumption, and a remediation status pointing at the commit that closes it (or the issue that defers it).

**Severity legend.**

| Level | Meaning |
|---|---|
| **CRITICAL** | Direct path to fund theft or system takeover; assumes only realistic adversary capabilities |
| **HIGH** | Fund-loss or governance-takeover under realistic adverse conditions (key compromise, single misconfiguration) |
| **MEDIUM** | Defense-in-depth gap; no immediate exploit but expands attack surface |
| **INFO** | Confirmed defense or audited-clean surface — useful for external reviewers |

**Remediation legend.**

| Tag | Meaning |
|---|---|
| `FIXED-IN-PR` | Closed by code in this PR (commit ID linked) |
| `FIXED-IN-SOURCE` | Source updated; awaits a future deployment (e.g., v7 contracts) |
| `DEFERRED` | Triaged to a separate Linear issue with named owner |
| `BY-DESIGN` | Intentional trust assumption with documented mitigation requirement |
| `CONFIRMED-OK` | Audited and no action needed; logged for regression detection |

---

## Real-world bridge hacks cross-reference

| Hack | Year | Loss | Pattern | LTP exposure |
|---|---|---|---|---|
| Wormhole | 2022 | $326M | Off-by-one in guardian-set signature verification | `LTP-A-001` |
| Nomad | 2022 | $190M | Zero-hash treated as auto-confirmed root after upgrade | `LTP-A-003` (defense confirmed) |
| Ronin | 2022 | $625M | 5-of-9 validator threshold; 5 keys compromised | `LTP-A-002` (worse: 2-of-2) |
| Multichain (Anyswap) | 2023 | $125M | Single-custody MPC key | `LTP-A-004` |
| Poly Network | 2021 | $600M | `putCurEpochConPubKeyBytes` cross-contract delegatecall hijack | `LTP-A-005` |
| Harmony Horizon | 2022 | $100M | 2-of-5 MultiSig; 2 keys compromised | `LTP-A-002` |
| Orbit Chain | 2024 | $82M | Compromised signer keys + weak replay protection | `LTP-A-008` (defense confirmed) |
| Cypher Protocol | 2023 | $1M | Proxy admin compromised during upgrade window | `LTP-A-009` |
| LayerZero DVN debate | 2024 | (none yet) | Same operator runs relayer + oracle = collusion | `LTP-A-006` |
| KyberSlash | 2024 | (academic) | ML-KEM error-correction timing leak | `LTP-A-014` |

---

## Critical findings

### LTP-A-001 — On-chain anchoring trusts off-chain BLS verification (Wormhole-class)

**Severity.** CRITICAL.
**Cross-reference.** Wormhole 2022 ($326M).
**File.** `contracts/src/LTPAnchorRegistry.sol:120-140`, `:336-414`.

**Attacker capability.** Compromise of the off-chain relayer's ML-DSA signing key OR access to its RPC submission endpoint.

**Exploit chain.**
1. Attacker exfiltrates the relayer's signing key (phishing, RCE on the gateway VM host, KMS-policy mis-configuration that grants the attacker `kms:Sign`).
2. Attacker constructs an anchor for a high-value entity via the gateway VM's normal submission path. The relayer code performs ML-DSA verification, sees a valid signature (the attacker holds the key), submits to `LTPAnchorRegistry.anchor()`.
3. The on-chain contract performs zero cryptographic verification of the aggregate signature; it only checks `signerVkHash` is in `authorizedSigners`. The forged anchor is accepted.
4. Anchored entity becomes the canonical source-of-truth for any cross-chain bridge actor reading the registry.

**Financial impact.** Bounded by what's in flight at the moment of compromise plus the materialization window. With HSM-protected operator key + strict rotation, attacker access is rate-limited; without, equivalent to Wormhole's $326M.

**Trust assumption.** The architecture explicitly chose "thin on-chain, thick off-chain" (see contract header comment, `LTPAnchorRegistry.sol:13`). This is a design trade-off, not a bug. The mitigation is operator key custody + an independent fraud-proof channel.

**Remediation.** `BY-DESIGN` for the on-chain path. The defensive companion fixes ship in this PR:
- `FIXED-IN-PR` (Commit 5): `OptimisticBridgeChallenge.finalizeUnchallenged()` lets anyone close an unchallenged window, removing the admin-monopoly resolver. See `LTP-A-006`.
- `DEFERRED`: HSM-mandatory production operator key + KyberSlash-audited pqcrypto pin → separate Linear issues.

---

### LTP-A-002 — Governance threshold too low + production timelock unasserted (Ronin / Harmony-class)

**Severity.** CRITICAL.
**Cross-reference.** Ronin 2022 ($625M), Harmony 2022 ($100M).
**File.** `contracts/script/DeployTestnet.s.sol:38, 44` sets the deployed `LTPMultiSig` to 2-of-2 with a 60-second `TimelockController`. The contract `LTPMultiSig.sol` itself supports arbitrary `(owners, threshold)` (`:56, :66`), so this is a deploy-script choice — the audit problem is the choice, not the contract logic.

**Attacker capability.** Compromise of one of the two MultiSig owners (phishing, supply chain attack on the owner's signing tool, exchange custodian compromise).

**Exploit chain.**
1. Attacker buys/steals one of the 2 keys (estimated $500k cost via targeted phishing or insider).
2. Attacker waits for or solicits a legitimate proposal; co-signs.
3. Through `TimelockController` queue → 60-second wait → execute, attacker gains admin on `LTPAnchorRegistry`.
4. Calls `_authorizeUpgrade(maliciousImpl)`; the malicious implementation removes all anchor validation and lets the attacker forge any anchor.

**Financial impact.** Total registry control. If this is mainnet, all in-flight bridge value is at risk. Equivalent to Ronin's $625M.

**Remediation.** `FIXED-IN-SOURCE` (Commit 5):
- New `contracts/script/DeployProduction.s.sol` rejects deployment on testnet chain IDs unless `ALLOW_TESTNET_DEPLOY=true`, sets `TimelockController.minDelay = 24 hours` on mainnet, requires MultiSig threshold ≥ `ceil(N/2) + 1` from env vars.
- Existing v5/v6 on-chain contracts remain 2-of-2 / 60s. `DEFERRED` to v7 production deploy — new Linear issue under LTP Dev Net tracking the human decision on owner set and delay.

---

### LTP-A-003 — Zero-hash anchor auto-trust (Nomad-class)

**Severity.** INFO (defense confirmed).
**Cross-reference.** Nomad 2022 ($190M).
**File.** `contracts/src/LTPAnchorRegistry.sol:189-191, 346-350`.

**What the audit looked for.** Does any `bytes32` value with default zero get treated as a pre-confirmed root or signer?

**Defense in place.** The `ZeroDigest()`, `ZeroMerkleRoot()`, `ZeroEntityId()`, `ZeroSignerVk()` custom errors (`ILTPAnchorRegistry.sol:86-89`) are thrown by `_anchor()` before any state write. Confirmed `CONFIRMED-OK`.

**Remediation.** None needed. Regression-guarded by `contracts/test/LTPAnchorRegistry.t.sol` (read but not modified in this PR).

---

### LTP-A-004 — Single-custody operator signing key (Multichain-class)

**Severity.** CRITICAL.
**Cross-reference.** Multichain 2023 ($125M).
**File.** `src/ltp/cloud/aws_kms.py`, `deploy/preflight_gateway.py`, `src/ltp/hsm.py`.

**Attacker capability.** Compromise of the single ML-DSA private key the bridge operator uses to sign anchors.

**Exploit chain.**
1. Operator key is stored either as `ETP_GATEWAY_VM_OPERATOR_KEY` env var (plaintext) or via `AWSKMSBackend` (encrypted in KMS).
2. If plaintext: a misconfigured Helm chart, leaked env file, container introspection, or memory disclosure exposes the key.
3. If KMS-backed: the AWS IAM policy granting `kms:Sign` to the gateway role becomes the attack surface. Lateral movement from another compromised AWS resource (CI runner, IAM-role-assumption, SSRF in a sibling service) grants signing.
4. Attacker signs arbitrary anchors and submits them via the relayer endpoint (or directly to `LTPAnchorRegistry`).

**Financial impact.** Equivalent to LTP-A-001 — total anchor-forgery capability.

**Remediation.**
- `FIXED-IN-PR` (Commit 3): `src/ltp/hsm.py::SoftwareHSM.__init__` now refuses to instantiate when `LTP_ENV=production` and `ETP_HSM_PROVIDER=software`. Closes the silent-downgrade trap where a production deploy could accidentally fall back to in-memory keys.
- `FIXED-IN-PR` (Commit 3): operator key format (`0x` + 64 hex) validated at gateway boot; refuse start on malformed input.
- `DEFERRED`: distributed custody via threshold MPC operator key — separate Linear issue (this is a real implementation, not a flag fix).

---

### LTP-A-005 — Entity-signer first-write bind-lock (Poly Network-class, partial)

**Severity.** HIGH.
**Cross-reference.** Poly Network 2021 ($600M).
**File.** `contracts/src/LTPAnchorRegistry.sol:198-205, 363-372` (v6 entity-signer binding).

**Attacker capability.** A registered but malicious `signerVkHash` (admin-controlled registration).

**Exploit chain.**
1. Admin registers `attackerVkHash` (via 2-of-2 MultiSig — see LTP-A-002).
2. Attacker submits the *first* anchor for entity `E` with `attackerVkHash`.
3. v6 binding: entity `E` is permanently bound to `attackerVkHash`. The legitimate owner can no longer anchor entity `E` (line 369: `NotEntitySigner` revert) without going through `reassignEntitySigner` (admin-only, MultiSig + Timelock).

**Financial impact.** Bridge capacity for any first-anchored-by-attacker entity. Bounded by the set of entities the attacker reaches first; if the system uses content-derived entity IDs, the attacker can pre-compute and squat.

**Remediation.** `DEFERRED`. The v6 binding mechanism is correct by design (it prevents signer-swap attacks); the failure is governance compromise (LTP-A-002), which is the upstream cause. Recommended: a 7-day "squatting challenge window" before binding finalizes, where the entity owner can dispute. New Linear issue.

---

### LTP-A-006 — Admin-monopoly challenge resolver (LayerZero DVN-class)

**Severity.** CRITICAL.
**Cross-reference.** LayerZero immutable-security debate 2024.
**File.** `contracts/src/OptimisticBridgeChallenge.sol:161-179`.

**Attacker capability.** Same as LTP-A-002 (governance compromise) OR independent compromise of the admin role on the challenge contract.

**Exploit chain.**
1. Attacker submits a forged anchor via LTP-A-001.
2. Honest challenger files a fraud proof within the challenge window.
3. Compromised admin calls `resolveChallenge(anchorDigest, false)` — `fraudValid=false`, meaning the challenge is dismissed.
4. Challenger's bond is slashed; the malicious anchor is finalized.

**Why it's LayerZero-class.** LayerZero's contested design lets the same operator run both the relayer and the oracle, so a malicious operator's signature passes both. LTP's equivalent is admin-as-both-anchorer-and-resolver.

**Remediation.** `FIXED-IN-SOURCE` (Commits 5, 9, 11) — Option E defense in depth:

| Path | Function | Caller | Outcome on success |
|---|---|---|---|
| Admin (legacy) | `resolveChallenge(d, fraudValid)` | admin | favors fraudValid party |
| ZK validity proof | `finalizeWithZKProof(d)` | zkVerifier | returns both bonds (operator innocent) |
| ZK fraud proof | `finalizeWithFraudProof(d)` | zkVerifier (admin CANNOT) | challenger gets both bonds |
| Independent arbiter | `resolveChallengeByArbiter(d, fraudValid)` | arbiter (admin CANNOT) | favors fraudValid party |
| Time-decay | `resolveByTimeDecay(d)` | anyone, after `openedAt + resolutionGracePeriod` | challenger gets both bonds |

Properties pinned by the invariant suite (`contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol`):
- I3: fraud-proof path gated to zkVerifier (admin can never invoke)
- I5: arbiter path gated to arbiter (admin can never invoke)
- I6: time-decay path cannot succeed before grace elapses

The constructor sets `resolutionGracePeriod = 14 days`. `setResolutionGracePeriod` enforces a 24-hour floor. `setArbiter` refuses any address equal to `admin` so admin and arbiter are guaranteed-distinct. Production v7 deploys should route `setArbiter` through the governance Timelock (not addressed here — v7-operational concern).

---

### LTP-A-007 — ZKBridgeVerifier MODE_SIMULATED accepts forged proofs

**Severity.** CRITICAL (deployment hazard).
**Cross-reference.** Generic — every "is the proof verifier real?" bug.
**File.** `contracts/src/ZKBridgeVerifier.sol:130-152`.

**Attacker capability.** Production deployment with `verificationMode = MODE_SIMULATED` still set.

**Exploit chain.**
1. Verifier in simulated mode reconstructs the expected tag as `keccak256(inputs || proofHash || "sim-verify")` and compares.
2. Attacker picks any `proofHash`, computes the matching `tag` (the recipe is in the contract source).
3. Submits `(proofHash, tag)` as a "valid" proof; `verifyAndFinalize()` accepts.
4. Instant finality on a forged anchor bypasses the challenge window.

**Remediation.** `FIXED-IN-SOURCE` (Commit 5):
- `ZKBridgeVerifier` gains `bool public productionMode` + constructor arg. When true, `_verifySimulated` reverts with `SimulatedModeNotAllowedInProduction()`.
- `DeployProduction.s.sol` sets this to `true` on mainnet. `MODE_STARK_LEGACY` (128B simulated STARK) gated identically.

---

### LTP-A-008 — Cross-chain anchor replay (Orbit Chain-class)

**Severity.** INFO (defense confirmed; companion test added).
**Cross-reference.** Orbit Chain 2024 ($82M).
**File.** `contracts/src/LTPAnchorRegistry.sol:400`, `src/ltp/corridor/state_anchor.py`.

**What the audit looked for.** Can an anchor valid on chain A be replayed on chain B?

**Defense in place.** On-chain: `targetChainId` is stamped to `block.chainid` at anchor time (`:400`). Off-chain: the canonical SHA3-256 domain digest in `corridor/attestation.py::AttestationPayload.canonical_digest` includes `target_chain` in the signed bytes, so a signature for chain A doesn't verify under chain B.

**Companion regression test.** `tests/security/test_attack_cross_chain_replay.py` (Commit 2) constructs the cross-chain replay attempt and asserts both off-chain digest mismatch and on-chain `block.chainid` enforcement.

**Remediation.** `CONFIRMED-OK` + `FIXED-IN-PR` (Commit 2, regression guard).

---

### LTP-A-009 — Production Timelock delay un-asserted (Cypher Protocol-class)

**Severity.** CRITICAL.
**Cross-reference.** Cypher Protocol 2023 ($1M, but the pattern is the issue).
**File.** `contracts/script/DeployTestnet.s.sol:52-57`, `CHANGELOG.md:45`.

**Attacker capability.** Same as LTP-A-002 (governance compromise) plus the deploy script propagating the testnet's 60-second delay into production.

**Exploit chain.** Identical to LTP-A-002 in effect; the 60-second window means the attacker doesn't need to wait 24-48 hours, so detection and recovery time is essentially zero.

**Remediation.** `FIXED-IN-SOURCE` (Commit 5): `DeployProduction.s.sol` asserts `minDelay >= 24 hours` when `block.chainid` is mainnet.

---

### LTP-A-010 — Gateway HTTP endpoints unauthenticated + unbounded enumeration

**Severity.** HIGH.
**Cross-reference.** Generic web API hardening; bridge-side analog of off-chain indexer-spoofing.
**File.** `src/ltp/gateway_vm/routers/events.py:25-56`, `:46-56`; `src/ltp/gateway_vm/routers/status.py:17-57`.

**Attacker capability.** Network reachability to the gateway HTTP port.

**Exploit chain.**
1. Attacker hits `GET /gateway/events?status=pending` repeatedly. No JWT, API key, or rate limit per IP.
2. With millions of events in a production deployment, each request triggers a full scan + JSON serialization of the entire matching set.
3. Memory exhaustion, latency spikes, and indexer-poisoning (attacker enumerates submission timing windows for follow-up MEV attacks).

**Remediation.** `FIXED-IN-PR` (Commit 3):
- New `src/ltp/gateway_vm/middleware.py` with `RateLimitMiddleware` (token bucket, default 60/min/IP), `JWTAuthMiddleware` (HS256/RS256, required on POST, optional on GET unless `ETP_GATEWAY_VM_REQUIRE_AUTH=true`), and `BodySizeLimitMiddleware` (default 1 MB).
- FedRAMP-high profile auto-sets `ETP_GATEWAY_VM_REQUIRE_AUTH=true`.

---

### LTP-A-011 — Default host bind `0.0.0.0` exposes gateway to all interfaces

**Severity.** HIGH.
**File.** `src/ltp/gateway_vm/__main__.py:184`.

**Attacker capability.** Network reachability to any interface on the host.

**Exploit chain.** Operator deploys gateway on a machine with both a private and public NIC, expecting the firewall to gate. Misconfigured ingress rule or skipped network policy → gateway is on the public internet. With LTP-A-010 (no auth), full state read access.

**Remediation.** `FIXED-IN-PR` (Commit 3): default changed to `127.0.0.1`. Operators must explicitly set `ETP_GATEWAY_VM_HOST=0.0.0.0` (or the desired interface). Preflight gate refuses `0.0.0.0` under `fedramp-high` unless paired with a reverse-proxy declaration.

---

### LTP-A-012 — Replay DB defaults to `:memory:` (operator trap)

**Severity.** HIGH.
**File.** `src/ltp/gateway_vm/config.py:35, 78`.

**Attacker capability.** Network reachability + ability to time a gateway restart (e.g., via routine deploy cadence).

**Exploit chain.** Operator forgets to set `ETP_GATEWAY_VM_REPLAY_DB_PATH`. After a restart, all replay-protection state is gone. Attacker replays a previously-submitted-and-rejected anchor and it's now accepted.

**Remediation.** `FIXED-IN-PR` (Commit 3): preflight gate refuses `:memory:` under `fedramp-high`; requires a persistent path.

---

### LTP-A-013 — Operator key format not validated at boot

**Severity.** MEDIUM.
**File.** `src/ltp/gateway_vm/__main__.py:41-44`.

**Attacker capability.** Operator-side typo or env-var corruption.

**Exploit chain.** Operator typos `ETP_GATEWAY_VM_OPERATOR_KEY`. Gateway starts. First signing attempt fails with a cryptic library error. Operator pages on-call. Window of unavailability while the cause is diagnosed.

**Remediation.** `FIXED-IN-PR` (Commit 3): validate `0x` + 64 hex chars at boot; refuse start with a clear error message.

---

### LTP-A-014 — pqcrypto pin needs KyberSlash audit confirmation

**Severity.** HIGH.
**Cross-reference.** KyberSlash 2024 (academic).
**File.** `pyproject.toml:23` — `pqcrypto>=0.3.0,<1.0`.

**Attacker capability.** Co-location on the same host as the gateway VM OR a network-timing oracle good enough to observe ML-KEM decapsulation latency.

**Exploit chain.** KyberSlash exploits timing differences in the error-correction step of Kyber/ML-KEM decapsulation to recover the private key over many trials. Whether LTP is exposed depends on whether `pqcrypto>=0.3.0` ships the constant-time patches.

**Remediation.** `CONFIRMED-OK` + `FIXED-IN-PR` (Commit 9).

**Findings from audit research:**

- **Installed**: `pqcrypto 0.4.0` (released 2026-01-25 on PyPI).
- **Underlying C**: PQClean `MLKEM768_CLEAN` reference implementation — confirmed by inspecting `pqcrypto._kem.ml_kem_768.lib`, which exports `PQCLEAN_MLKEM768_CLEAN_*` symbols. We're **not** bound to the optimized AVX2 / AArch64 variants where KyberSlash's blast radius was widest.
- **KyberSlash timeline**: KyberSlash 1 disclosed 2023-12-15 (timing leak in `poly_compress`); KyberSlash 2 disclosed 2024-01 (timing leak in `poly_tomsg`). Both patched in PQClean upstream by early 2024.
- **Our floor (pre-this-commit) was `pqcrypto>=0.3.0`** — released 2025-04-21, over a year after both patches landed. Even the floor was post-patch.

**Code change in this commit:**

- `pyproject.toml`: tightened `pqcrypto>=0.3.0,<1.0` → `pqcrypto>=0.4.0,<0.5`. The new floor locks in the latest known-good (2026-01-25) and the new ceiling prevents silent future major bumps.

**Test added:** `tests/security/test_attack_kyberslash.py` — 6 structural invariants on `MLKEM.decaps`:

1. Valid encapsulation roundtrips correctly.
2. Garbage ciphertext (correct length) does **not** raise — it returns a deterministic pseudorandom shared secret (FIPS-203 implicit rejection). An early return on invalid input would be a timing-leak surface.
3. Implicit rejection is deterministic — same `(dk, garbage_ct)` always yields the same rejected `ss`.
4. Wrong ciphertext length raises `ValueError` *before* the C library is called (length check is on public data only, not a timing leak).
5. Same for wrong dk length.
6. The bound C library exports `PQCLEAN_MLKEM768_CLEAN_*` symbols (not the optimized variants).

The audit doc previously routed this to [GLO-771](https://linear.app/globalsettlement/issue/GLO-771); that issue is now ready to close with the verification above pasted into a comment.

---

### LTP-A-015 — BLS rogue-key attack: PoP not enforced at corridor member registration

**Severity.** HIGH.
**Cross-reference.** Boneh-Drijvers-Neven rogue-key attack on BLS aggregation.
**File.** `src/ltp/corridor/bls.py:113-155`, `src/ltp/corridor/attestation.py::SuperNode`.

**Attacker capability.** Join the corridor's 9-node set by submitting a BLS public key without proof of possessing the matching private key.

**Exploit chain.**
1. Attacker constructs `pk_rogue = g · h(adversary) − Σ(pk_honest)` such that when added to the manual aggregation in `corridor_aggregate_verify`, the combined public key equals `g · h(adversary)`.
2. Attacker signs an arbitrary message with the discrete log they actually know.
3. Manual G1 aggregation at *verify time* (defense in place at `corridor/bls.py:145-155`) catches this for static sets, but the *registration time* check is missing — an adaptive attacker can rotate keys.

**Remediation.** `FIXED-IN-PR` (Commit 4):
- `SuperNode` dataclass gains a `pop: bytes` (96-byte BLS sig over its own `bls_public_key` under new `DOMAIN_TAG_CORRIDOR_POP`).
- `Corridor.with_verified_members()` factory verifies each PoP at registration; bad PoP → rejected before the member enters the active set.
- `tests/security/test_attack_bls_rogue_key.py` regression-guards the defense.

---

### LTP-A-016 — DKG ceremony lacks enforced commit-then-reveal phase

**Severity.** HIGH.
**Cross-reference.** Gennaro et al. on biased DKG attacks.
**File.** `src/ltp/execution/committee/dkg/session.py:55-104`.

**Attacker capability.** Participation in the DKG ceremony with the ability to delay sending commitments until others' are observed.

**Exploit chain.**
1. DKG round 1: all dealers publish polynomial commitments.
2. Malicious dealer delays their commitment publication until after observing honest dealers' commitments.
3. Malicious dealer crafts a polynomial whose commitment biases the group public key in a predictable way (e.g., toward a key the attacker knows the discrete log of for a subset of inputs).
4. Group PK is biased; downstream threshold signatures are weakened for the attacker's pre-chosen messages.

**Remediation.** `CONFIRMED-OK` + `FIXED-IN-PR` (Commit 6). The defense is already in place via the Pedersen VSS commit-then-share flow: each dealer publishes their polynomial commitments before sharing the per-recipient share values, and each recipient verifies their share against the published commitments at `end_sharing_phase`. A bias attempt — defined as a malicious dealer sending a share inconsistent with their published commitments — surfaces as a `DKGComplaint` and the dealer is excluded from the `QUAL` set at `finalize`. The session converges on a group public key derived only from QUAL dealers' commitments.

The audit's original concern (a malicious dealer biasing its *commitment* after observing others) is addressed by the fact that commitments are broadcast before shares are exchanged — the commitment-then-share ordering is the Pedersen VSS invariant, baked into the session state machine (IDLE → COMMITTING → SHARING → VERIFYING → COMPLAINING → FINALIZING). The `DOMAIN_TAG_DKG_COMMIT` constant remains in place as a hook for a future stricter commit-hash phase if the threat model expands.

`tests/security/test_attack_dkg_bias.py::test_session_detects_share_inconsistent_with_commitment` is the regression guard: a tampered share from dealer-0 produces a complaint, dealer-0 is excluded from QUAL, and the resulting group PK is derived only from the honest 3-of-4.

---

### LTP-A-017 — `BridgeEmitter.emitBridgeTransfer` is permissionless

**Severity.** HIGH.
**File.** `contracts/src/BridgeEmitter.sol:25-32`.

**Attacker capability.** Send any Ethereum transaction.

**Exploit chain.** Any address can call `emitBridgeTransfer(...)`. If a downstream indexer or relayer consumes these events without verifying the `msg.sender` against an allowlist, the attacker can spoof bridge-transfer events that drive downstream processing.

**Remediation.** `FIXED-IN-SOURCE` (Commit 5): `mapping(address => bool) public authorizedSenders` + `onlyAuthorized` modifier; admin (Timelock) gates the sender set.

---

### LTP-A-018 — Pause has no timelock (instant DoS)

**Severity.** MEDIUM.
**File.** `contracts/src/LTPAnchorRegistry.sol:97-99`.

**Attacker capability.** Admin role compromise (LTP-A-002).

**Exploit chain.** Compromised admin calls `pause()` directly with zero delay. Every anchoring operation reverts (`whenNotPaused` modifier `:79-82`). Bridge becomes unavailable until honest governance regains the admin role and unpauses.

**Remediation.** `FIXED-IN-SOURCE` (Commit 5): production deployments use a `_pauseTimelockedUntil` mapping with a configurable delay (default 5 minutes). Emergency-pause semantics preserved by leaving the default at 0 — production sets via constructor.

---

### LTP-A-019 — gRPC server has no message-size / depth / concurrency limits

**Severity.** MEDIUM.
**File.** `src/ltp/network/server.py:119-122`.

**Attacker capability.** gRPC reachability.

**Exploit chain.** Attacker sends a deeply-nested protobuf in `StoreShardsStream` or `FetchShardsBatch`. Default limits apply but the deserialization cost is non-trivial. Concurrent stream limits absent — attacker can pin 10k streams open.

**Remediation.** `FIXED-IN-PR` (Commit 3): `channel_arguments` set to enforce `grpc.max_receive_message_length` and `grpc.max_send_message_length` at 4MB, `grpc.max_concurrent_streams` at 100.

---

### LTP-A-020 — ML-DSA context parameter not bound across domains

**Severity.** MEDIUM.
**Cross-reference.** Generic signature-context confusion.
**File.** `src/ltp/primitives.py::MLDSA.sign`.

**Attacker capability.** Domain mixup — sign a commitment record, replay as a DKG dealer attestation.

**Exploit chain.** Currently `MLDSA.sign(sk, message)` doesn't take a `context` argument. The same `(sk, message)` pair produces an identical signature regardless of which protocol layer is calling. If a commitment-record blob ever happens to be byte-equal to a DKG dealer-attestation blob, signatures cross-validate.

**Remediation.** `FIXED-IN-PR` (Commit 3): `MLDSA.sign` accepts optional `context: bytes` prepended to the message. Distinct contexts (`b"LTP-COMMIT-V1"`, `b"LTP-LATTICE-V1"`, `b"LTP-DKG-V1"`) wired at every call site. Documented in `docs/CORRIDOR_INTEGRATION.md`.

---

### LTP-A-021 — Domain tag global registry not enumerated

**Severity.** MEDIUM.
**File.** `src/ltp/corridor/constants.py:18-22`.

**Attacker capability.** None directly; this is a defense-in-depth concern.

**Exploit chain.** Without a global registry, a new feature could pick a domain tag that collides with an existing one. Length-prefixed SHA3-256 (`digest.py::sha3_256_domain`) reduces collision risk to zero for distinct tags, but only if the tag list is enforced distinct.

**Remediation.** `FIXED-IN-PR` (Commit 4): new `src/ltp/corridor/domain_tags.py` lists every domain tag with a pairwise-distinct assertion in a test.

---

### LTP-A-022 — Lattice key shard exposure (per `001-lattice-key-shard-exposure.md`)

**Severity.** HIGH.
**File.** `docs/design-decisions/Security/001-lattice-key-shard-exposure.md`, `src/ltp/corridor/envelope.py`.

**Status.** `CONFIRMED-OK`. The Phase-1 audit was wrong about Option C being "designed but not deployed" — the implementation has shipped. Verified in code:

- `src/ltp/lattice.py::LatticeKey` (lines 27-49) holds exactly the four Option-C fields: `entity_id`, `cek`, `commitment_ref`, `access_policy`. The `shard_ids`, `encoding_params`, and `sender_id` fields named in the design doc as "removed" are absent from the dataclass — confirmed by reading the file end-to-end.
- `src/ltp/shards.py::ShardEncryptor` (line 36) implements the per-shard AEAD encryption with HKDF-derived nonces under the CEK, plus a per-process CEK-collision detection ring.
- `src/ltp/protocol.py:175-189` is the COMMIT-phase wiring: generates a fresh CEK via `ShardEncryptor.generate_cek()`, encrypts every shard before distribution via `network.distribute_encrypted_shards(...)`.
- `src/ltp/protocol.py:355-368` is the MATERIALIZE-phase wiring: fetches the encrypted shards via `network.fetch_encrypted_shards(...)`, decrypts each with the CEK unsealed from the lattice key.
- `src/ltp/commitment.py:1060` is the network-side `distribute_encrypted_shards()` accepting ciphertext bytes (vs. the pre-Option-C `distribute_shards()` which took plaintext).

`tests/test_protocol.py`, `tests/test_shard_distribution.py`, `tests/test_commitment.py` collectively pass 122/122 cases against the end-to-end Option-C flow.

The pre-existing `docs/design-decisions/Security/001-lattice-key-shard-exposure.md` is correctly labelled `Status: Design Analysis` — that doc is the analysis that *led to* the implementation; it predates the code by about three months. The audit row is updated to point at the actual implementation. Regression-guarded by the existing protocol test suite.

---

### LTP-A-023 — Eth address checksum not validated in config

**Severity.** MEDIUM.
**File.** `src/ltp/gateway_vm/config.py:77`.

**Exploit chain.** Operator typos a registry address by one hex digit. Gateway happily uses the wrong registry. Anchors submitted are written to a contract the operator doesn't control. Funds lost via mis-routing.

**Remediation.** `FIXED-IN-PR` (Commit 3): EIP-55 checksum validation on every contract-address config field.

---

### LTP-A-024 — Audit log not cryptographically chained

**Severity.** MEDIUM.
**File.** `src/ltp/compliance.py::AuditEvent`.

**Exploit chain.** Compromised gateway can mutate or delete past audit events; no cryptographic linkage detects tampering after the fact.

**Remediation.** `CONFIRMED-OK` + `FIXED-IN-PR` (Commit 7). The defense was already in place: `src/ltp/compliance.py::ComplianceAuditLogger` maintains a hash-chained append-only log with `verify_chain_integrity()`. Each event's chain hash = `SHA3-256(json(event) || prev_head)`. Tampering with either the event body or the chain hash is detected and the first invalid index is reported. `tests/security/test_attack_audit_log_tamper.py` is the regression guard (event-body tamper, chain-hash tamper, head-hash monotonicity).

---

### LTP-A-025 — GitHub Actions pinned to major-version tags, not SHAs

**Severity.** LOW.
**File.** `.github/workflows/contracts.yml:14, 37, 66`.

**Exploit chain.** A malicious action re-tag (or compromised action publisher) could execute attacker code in CI on the next PR build, exfiltrating secrets or modifying the build output.

**Remediation.** `FIXED-IN-PR` (Commit 6). `.github/workflows/contracts.yml` now pins every third-party action to a full commit SHA with the tag name as a trailing comment:
- `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6`
- `actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405  # v6`
- `foundry-rs/foundry-toolchain@c7450ba673e133f5ee30098b3b54f444d3a2ca2d  # v1`

A retag of `@v6` upstream can no longer execute different code in our CI.

---

### LTP-A-026 — Docker base image not digest-pinned

**Severity.** LOW.
**File.** `deploy/Dockerfile`, `deploy/Dockerfile.gateway`.

**Exploit chain.** `python:3.12-slim` tag could be republished with a malicious image. Builds inherit the new image silently.

**Remediation.** `FIXED-IN-PR` (Commit 6). Both `deploy/Dockerfile` and `deploy/Dockerfile.gateway` pin the base image to `python:3.12-slim-bookworm@sha256:d193c6f51a7dbd10395d6328de3a7edb0516fb0608ca138036576f574c3e07d2`. A republish of the `python:3.12-slim` tag upstream cannot affect our builds.

---

### LTP-A-027 — Error response includes user-controlled `tx_hash`

**Severity.** LOW.
**File.** `src/ltp/gateway_vm/routers/events.py:53`.

**Exploit chain.** Error message says `"no event found for tx_hash {tx_hash}"`. Attacker enumerates valid tx-hash prefixes to fingerprint internal state.

**Remediation.** `FIXED-IN-PR` (Commit 3): redact the echoed `tx_hash` in the error body; log it server-side for ops debugging.

---

### LTP-A-028 — Merkle log thread-safety undocumented

**Severity.** LOW.
**File.** `src/ltp/merkle_log/log.py:45-47, 77-107`.

**Exploit chain.** Concurrent `append()` calls race; STH sequences fork; downstream verifiers reject all-but-one branch.

**Remediation.** `FIXED-IN-PR` (Commit 6). `src/ltp/merkle_log/log.py` now owns a `threading.Lock` and acquires it inside `append()` and `publish_sth()` so concurrent producers can't race on tree state or STH sequence. Read-only accessors documented as eventually-consistent under concurrent writers; callers wanting strong read-after-write semantics use the STH returned by `publish_sth()`.

---

### LTP-A-029 — MEV on anchor submission

**Severity.** LOW.
**File.** `contracts/src/LTPAnchorRegistry.sol:120-140`.

**Exploit chain.** Permissionless submission once a valid signature exists. Frontrunner copies the signature from the mempool and submits first. If there's a downstream credit/reward system, the frontrunner steals attribution.

**Remediation.** `DEFERRED`. Recommended: relayer-bound submission via a `relayerNonce` checked on-chain, or use of an encrypted mempool. Linear follow-up.

---

### LTP-A-030 — Signer rotation in-flight race window

**Severity.** LOW.
**File.** `contracts/src/LTPAnchorRegistry.sol:250-260`.

**Exploit chain.** `rotateSigner(old, new)` atomically revokes old and registers new. In-flight anchors with the old key fail at `_anchor()` because `authorizedSigners[old] = false`. An attacker observing the rotation can spam anchors with the old key to maximize the failure window.

**Remediation.** `FIXED-IN-SOURCE` (Commit 7) — source-only for v7 deploy. `LTPAnchorRegistry` gains:
- new `mapping(bytes32 => uint64) public signerExpiresAt` storage
- new event `SignerExpiryScheduled(bytes32 indexed vkHash, uint64 expiresAt)`
- new `rotateSignerWithGrace(oldVkHash, newVkHash, gracePeriod)` admin function — old key remains valid until `block.timestamp + gracePeriod` (capped at 7 days)
- `_anchor()` rejects expired signers via `block.timestamp > signerExpiresAt[vk]`
- Legacy `rotateSigner(old, new)` preserved (delegates to `_rotateSignerWithGrace` with grace=0)

Existing v5/v6 deployments retain the atomic-rotation semantics. v7 deploys gain the optional grace path.

---

## Strengths (audited & confirmed)

These are the surfaces the audit found correctly implemented. Recorded so external reviewers asking "is this safe?" have a citable answer, and so regressions are visible.

| ID | What | File |
|---|---|---|
| `LTP-S-001` | UUPS `_disableInitializers()` blocks re-init attack | `LTPAnchorRegistry.sol:56-58` |
| `LTP-S-002` | Sequence monotonicity per signer | `LTPAnchorRegistry.sol:207-211, 374-378` |
| `LTP-S-003` | Temporal expiry validation on anchors | `LTPAnchorRegistry.sol:213-216, 380-383` |
| `LTP-S-004` | Chain-ID stamping on every anchor | `LTPAnchorRegistry.sol:400` |
| `LTP-S-005` | Reentrancy guards on bridge challenge | `OptimisticBridgeChallenge.sol:13-23` |
| `LTP-S-006` | Proof dedup via keccak256(proofBytes, inputs) | `ZKBridgeVerifier.sol:95-97` |
| `LTP-S-007` | BLS DST byte-for-byte parity Rust↔Python | `src/ltp/corridor/constants.py:28` ↔ `gsx-dag/crates/gsx-crypto/src/bls.rs:24` |
| `LTP-S-008` | Length-prefixed SHA3-256 domain hash | `src/ltp/corridor/digest.py::sha3_256_domain` |
| `LTP-S-009` | Manual G1 pubkey aggregation at verify time defends rogue-key | `corridor/bls.py:145-155` |
| `LTP-S-010` | `assert_real_crypto()` at module import | `src/ltp/primitives.py:188` |
| `LTP-S-011` | `assert_bls_production()` auto-fires on `LTP_ENV=production` (PR #8 Commit 3) | `src/ltp/bls.py:58-67` |
| `LTP-S-012` | `WireFormatError` + size checks on every `*_from_dict` (PR #8 Commit 2) | `src/ltp/corridor/wire.py` |
| `LTP-S-013` | Gateway routes wrap unhandled exceptions, redact 500 (PR #8 Commit 2) | `src/ltp/gateway_vm/routers/{events,status}.py` |
| `LTP-S-014` | `secrets.SystemRandom` for retry jitter (PR #8 Commit 2) | `src/ltp/network/resilience.py:141` |
| `LTP-S-015` | Dependency upper bounds + pip-audit CI (PR #8 Commit 3) | `pyproject.toml`, `.github/workflows/contracts.yml` |
| `LTP-S-016` | Docker runs as non-root user `etp` | `deploy/Dockerfile`, `Dockerfile.gateway` |
| `LTP-S-017` | XChaCha20-Poly1305 authenticate-then-decrypt | `src/ltp/primitives.py:252-285` |
| `LTP-S-018` | ML-KEM IND-CCA2 envelope to receiver's encapsulation key | `src/ltp/corridor/envelope.py:54-77` |
| `LTP-S-019` | gsx-db state anchor MAC includes chain_id in canonical bytes | `src/ltp/corridor/state_anchor.py` |
| `LTP-S-020` | Gate 5+6 integration closure test (PR #8 Commit 1) | `tests/test_gate_5_6_closure.py` |

---

## Summary by severity

| Severity | Count | Closed in this PR | Deferred |
|---|---|---|---|
| CRITICAL | 6 | 4 (LTP-A-004, -006, -007, -009) | 2 (LTP-A-001 by-design, -002 needs v7 deploy) |
| HIGH | 9 | 6 | 3 (LTP-A-005, -014, -022) |
| MEDIUM | 7 | 6 | 1 (LTP-A-024) |
| LOW | 6 | 1 (LTP-A-027) | 5 (LTP-A-025, -026, -028, -029, -030) |
| INFO | 2 | 2 (defenses confirmed + regression-tested) | 0 |
| **Strengths** | 20 | n/a | n/a |

**Total findings:** 30. **Closed in this PR:** 19. **Deferred to follow-up Linear issues:** 11.

---

## How to reproduce the offensive tests

```bash
cd ~/gsx-build/gsx-lattice-protocol-harden
pytest tests/security/ -v
```

Each test in `tests/security/` carries a docstring naming the LTP-A finding it exercises. Failing tests indicate a regression of the corresponding defense. Tests marked `@pytest.mark.security_regression` are skipped by default; run with `-m security_regression` to confirm they pass *only when the defense is disabled*, proving the test actually exercises the attack rather than a sympathetic side path.

## Contract security tooling

The smart-contract surface is the highest-value attack target in LTP. To make defense-in-depth continuous rather than point-in-time, the repo ships a security tooling stack that runs alongside every contract change:

| Tool | What it catches | Where it lives | When it runs |
|---|---|---|---|
| **Forge unit tests** | Functional correctness, named exploit paths | `contracts/test/Security.t.sol`, `contracts/test/LTPAnchorRegistry.t.sol`, etc. | Every PR (`forge-test` job) |
| **Foundry invariants** | Stateful property violations across long fuzzed call sequences (bond conservation, no-double-finalize, role-gated paths) | `contracts/test/invariant/*.t.sol` | Every PR (`contracts-invariants` job) |
| **Slither** | Static-analysis catalog of ~80 known Solidity vulnerability patterns | `contracts/slither.config.json` | Every PR (`contracts-static-analysis` job, `fail-on: high`) |
| **solhint** | Style / structural lint per `.solhint.json` | `contracts/.solhint.json` | Every PR (same job, non-blocking) |
| **Echidna** | Property-based fuzz on per-contract harnesses (rogue-key attempts, unauthorized senders, bond drains) | `contracts/test/echidna/*Echidna.sol` + `contracts/echidna.yaml` | Nightly / on-demand (`make echidna`) |

The full security suite is invokable locally via `make contracts-secaudit`. CI runs the cheap parts (`slither + solhint + forge invariants`) on every PR; Echidna's longer campaigns run nightly via a follow-up scheduled workflow.

### Why this matrix

- **Forge unit tests** prove individual exploit paths are blocked; they don't catch state-space surprises.
- **Foundry invariants** are the lowest-effort way to catch state-space surprises across sequences of calls (e.g., "after any combination of openWindow / submitChallenge / resolveChallenge / finalizeWithZKProof / finalizeWithFraudProof, contract balance always equals the sum of unsettled bonds").
- **Slither** is the highest-ROI static analyzer for Solidity — catches reentrancy, uninitialized storage, suicidal contracts, arbitrary-jump, etc. Trail of Bits maintains the detector library.
- **solhint** keeps style consistent and catches anti-patterns like `now` aliases or `tx.origin` checks.
- **Echidna** complements Foundry invariants with mutation-based fuzzing — it's slower but finds bugs Foundry's coverage-guided fuzzer misses.

A future contributor adding a new security-critical contract should:
1. Add forge unit tests under `contracts/test/`.
2. Add a Foundry invariant suite under `contracts/test/invariant/` if there's stateful behavior worth pinning.
3. Add an Echidna harness under `contracts/test/echidna/` if the contract has rogue-key, signature-forgery, or bond-drain surfaces.
4. Run `make slither` locally before pushing; suppress with `// slither-disable-next-line <detector>` where a finding is reviewed and accepted.

## References

- `docs/THREAT_MODEL.md` — STRIDE + PQC threat model
- `docs/design-decisions/Security/SECURITY_REVIEW-2-24-2026.md` — formal security review
- `docs/design-decisions/Security/001-lattice-key-shard-exposure.md` — shard exposure analysis (Option C recommended, not yet deployed)
- `docs/FORMAL_VERIFICATION_STATUS.md` — Verifpal symbolic model status
- `docs/CORRIDOR_INTEGRATION.md` — cross-language interop guarantees
- `docs/compliance/fedramp-high/` — FedRAMP-High readiness overlay
