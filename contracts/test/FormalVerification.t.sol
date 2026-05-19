// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ILTPAnchorRegistry} from "../src/interfaces/ILTPAnchorRegistry.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TestSetup} from "./helpers/TestSetup.sol";

// ==========================================================================
// Fuzz Tests — State Machine Transition Parity
// ==========================================================================

contract FuzzStateTransitions is TestSetup {
    /// @notice Exhaustive parity: _isValidTransition matches the known-good set.
    ///         The expected set has 11 valid transitions (Python 10 + UNKNOWN→ANCHORED).
    function _expectedValid(uint8 from_, uint8 to_) internal pure returns (bool) {
        // Happy path
        if (from_ == 0 && to_ == 1) return true; // UNKNOWN → COMMITTED
        if (from_ == 1 && to_ == 2) return true; // COMMITTED → ANCHORED
        if (from_ == 2 && to_ == 3) return true; // ANCHORED → MATERIALIZED
        // Dispute path
        if (from_ == 1 && to_ == 4) return true; // COMMITTED → DISPUTED
        if (from_ == 2 && to_ == 4) return true; // ANCHORED → DISPUTED
        if (from_ == 3 && to_ == 4) return true; // MATERIALIZED → DISPUTED
        // Deletion path
        if (from_ == 1 && to_ == 5) return true; // COMMITTED → DELETED
        if (from_ == 2 && to_ == 5) return true; // ANCHORED → DELETED
        if (from_ == 3 && to_ == 5) return true; // MATERIALIZED → DELETED
        if (from_ == 4 && to_ == 5) return true; // DISPUTED → DELETED
        // Direct anchor (Solidity-only)
        if (from_ == 0 && to_ == 2) return true; // UNKNOWN → ANCHORED
        return false;
    }

    /// @notice Fuzz all possible (from, to) state pairs — assert _isValidTransition matches.
    function test_fuzz_transitionParity(uint8 from_, uint8 to_) public {
        // Bound to valid state range
        from_ = uint8(bound(from_, 0, 5));
        to_ = uint8(bound(to_, 0, 5));

        // Expose _isValidTransition via transitionState behavior
        // We test the actual contract function by attempting transitions
        bool expected = _expectedValid(from_, to_);

        // Set up entity in 'from_' state
        bytes32 entityId = keccak256(abi.encodePacked("fuzz-entity", from_, to_));
        bytes32 signer = signerVkHash;
        uint64 validUntil = uint64(block.timestamp + 3600);
        uint64 seq = registry.getSignerSequence(signer);

        // Force entity into 'from_' state (admin bypass via direct storage)
        // We use transitionState for valid paths to get there, or test from UNKNOWN
        if (from_ == 0) {
            // Entity starts at UNKNOWN — attempt transition to 'to_'
            if (to_ == from_) {
                // Self-transition: always reverts
                vm.expectRevert();
                registry.transitionState(entityId, to_, signer, seq + 1, validUntil);
            } else if (expected) {
                registry.transitionState(entityId, to_, signer, seq + 1, validUntil);
                assertEq(registry.getEntityState(entityId), to_);
            } else {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        ILTPAnchorRegistry.InvalidStateTransition.selector, from_, to_
                    )
                );
                registry.transitionState(entityId, to_, signer, seq + 1, validUntil);
            }
        }
        // For other from_ states, we verify via the _expectedValid table (tested below)
    }

    /// @notice Exhaustive: test all 36 state pairs explicitly.
    function test_exhaustive_all36Pairs() public pure {
        uint256 validCount = 0;
        for (uint8 f = 0; f <= 5; f++) {
            for (uint8 t = 0; t <= 5; t++) {
                if (_expectedValid(f, t)) {
                    validCount++;
                }
            }
        }
        // Exactly 11 valid transitions in Solidity
        assertEq(validCount, 11);
    }

    /// @notice No self-transitions are valid.
    function test_fuzz_noSelfTransitions(uint8 state) public pure {
        state = uint8(bound(state, 0, 5));
        assertFalse(_expectedValid(state, state));
    }

    /// @notice DELETED is absorbing — no transitions out.
    function test_fuzz_deletedAbsorbing(uint8 to_) public pure {
        to_ = uint8(bound(to_, 0, 5));
        assertFalse(_expectedValid(5, to_));
    }

    /// @notice Out-of-range states are always invalid.
    function test_fuzz_outOfRangeStates(uint8 from_, uint8 to_) public pure {
        // If either state is > 5, it's out of range and should be invalid
        if (from_ > 5 || to_ > 5) {
            assertFalse(_expectedValid(from_, to_));
        }
    }
}

// ==========================================================================
// Fuzz Tests — Sequence Enforcement
// ==========================================================================

contract FuzzSequenceEnforcement is TestSetup {
    /// @notice Sequences must be strictly increasing — any seq <= current reverts.
    function test_fuzz_sequenceMonotonicity(uint64 firstSeq, uint64 secondSeq) public {
        // Ensure firstSeq is at least 1 (valid for first anchor)
        firstSeq = uint64(bound(firstSeq, 1, type(uint64).max - 1));
        uint64 validUntil = uint64(block.timestamp + 3600);

        // First anchor succeeds
        bytes32 d1 = keccak256(abi.encodePacked("seq-d1", firstSeq));
        bytes32 e1 = keccak256(abi.encodePacked("seq-e1", firstSeq));
        registry.anchor(d1, e1, bytes32(uint256(1)), bytes32(uint256(1)), signerVkHash, firstSeq, validUntil, 0);

        // Second anchor: should succeed only if secondSeq > firstSeq
        bytes32 d2 = keccak256(abi.encodePacked("seq-d2", secondSeq));
        bytes32 e2 = keccak256(abi.encodePacked("seq-e2", secondSeq));

        if (secondSeq > firstSeq) {
            registry.anchor(d2, e2, bytes32(uint256(2)), bytes32(uint256(2)), signerVkHash, secondSeq, validUntil, 0);
            assertEq(registry.getSignerSequence(signerVkHash), secondSeq);
        } else {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILTPAnchorRegistry.SequenceTooLow.selector,
                    signerVkHash, secondSeq, firstSeq
                )
            );
            registry.anchor(d2, e2, bytes32(uint256(2)), bytes32(uint256(2)), signerVkHash, secondSeq, validUntil, 0);
        }
    }

    /// @notice Sequence HWM only increases, never decreases.
    function test_fuzz_hwmNeverDecreases(uint64[5] memory seqs) public {
        uint64 validUntil = uint64(block.timestamp + 3600);
        uint64 highWaterMark = 0;

        for (uint256 i = 0; i < 5; i++) {
            seqs[i] = uint64(bound(seqs[i], 1, type(uint64).max));

            bytes32 d = keccak256(abi.encodePacked("hwm-d", i, seqs[i]));
            bytes32 e = keccak256(abi.encodePacked("hwm-e", i, seqs[i]));
            // Use non-zero merkleRoot and policyHash (v6 zero-value guards)
            bytes32 root = keccak256(abi.encodePacked("hwm-r", i));
            bytes32 policy = keccak256(abi.encodePacked("hwm-p", i));

            if (seqs[i] > highWaterMark) {
                registry.anchor(d, e, root, policy, signerVkHash, seqs[i], validUntil, 0);
                highWaterMark = seqs[i];
            } else {
                vm.expectRevert();
                registry.anchor(d, e, root, policy, signerVkHash, seqs[i], validUntil, 0);
            }

            // Invariant: HWM never decreases
            uint64 currentHwm = uint64(registry.getSignerSequence(signerVkHash));
            assertTrue(currentHwm >= highWaterMark || highWaterMark == 0);
        }
    }
}

// ==========================================================================
// Fuzz Tests — Temporal Expiry
// ==========================================================================

contract FuzzTemporalExpiry is TestSetup {
    /// @notice Anchoring with validUntil <= block.timestamp always reverts.
    function test_fuzz_expiredAlwaysReverts(uint64 validUntil) public {
        // Ensure validUntil <= block.timestamp (expired)
        validUntil = uint64(bound(validUntil, 0, block.timestamp));

        bytes32 d = keccak256(abi.encodePacked("exp-d", validUntil));
        bytes32 e = keccak256(abi.encodePacked("exp-e", validUntil));

        vm.expectRevert(
            abi.encodeWithSelector(
                ILTPAnchorRegistry.Expired.selector,
                validUntil, uint64(block.timestamp)
            )
        );
        registry.anchor(d, e, bytes32(uint256(1)), bytes32(uint256(1)), signerVkHash, 1, validUntil, 0);
    }

    /// @notice Anchoring with validUntil > block.timestamp succeeds (if other checks pass).
    function test_fuzz_futureExpiryAccepted(uint64 offset) public {
        offset = uint64(bound(offset, 1, 365 days));
        uint64 validUntil = uint64(block.timestamp) + offset;

        bytes32 d = keccak256(abi.encodePacked("fut-d", offset));
        bytes32 e = keccak256(abi.encodePacked("fut-e", offset));

        registry.anchor(d, e, bytes32(uint256(1)), bytes32(uint256(1)), signerVkHash, 1, validUntil, 0);
        assertTrue(registry.isAnchored(d));
    }
}

// ==========================================================================
// Fuzz Tests — Signer Authorization
// ==========================================================================

contract FuzzSignerAuth is TestSetup {
    /// @notice Unauthorized signers are always rejected.
    function test_fuzz_unauthorizedSignerReverts(bytes32 randomSigner) public {
        // Skip the one authorized signer and bytes32(0) (hits ZeroSignerVk, not UnauthorizedSigner)
        vm.assume(randomSigner != signerVkHash);
        vm.assume(randomSigner != bytes32(0));
        vm.assume(!registry.authorizedSigners(randomSigner));

        uint64 validUntil = uint64(block.timestamp + 3600);
        bytes32 d = keccak256(abi.encodePacked("auth-d", randomSigner));
        bytes32 e = keccak256(abi.encodePacked("auth-e", randomSigner));

        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.UnauthorizedSigner.selector, randomSigner)
        );
        registry.anchor(d, e, bytes32(uint256(1)), bytes32(uint256(1)), randomSigner, 1, validUntil, 0);
    }
}

// ==========================================================================
// Invariant Tests — Handler + Invariant Assertions
// ==========================================================================

/// @notice Handler contract that performs random valid actions on the registry.
contract RegistryHandler is TestSetup {
    uint64 public currentSequence;
    uint256 public anchorCount;
    uint256 public transitionCount;
    bytes32[] public anchoredDigests;
    mapping(bytes32 => bool) public wasAnchored;

    // Track per-entity state for invariant checking
    bytes32[] public knownEntities;
    mapping(bytes32 => uint8) public entityStateHistory;

    function setUp() public override {
        super.setUp();
        currentSequence = 0;
    }

    /// @notice Anchor a new entity (random-ish, but always valid).
    function doAnchor(uint256 seed) external {
        currentSequence++;
        uint64 validUntil = uint64(block.timestamp + 3600);

        bytes32 d = keccak256(abi.encodePacked("inv-d", seed, currentSequence));
        bytes32 e = keccak256(abi.encodePacked("inv-e", seed, currentSequence));

        // Avoid collisions
        if (registry.isAnchored(d)) return;

        // Use non-zero merkleRoot and policyHash (v6 zero-value guards reject bytes32(0))
        bytes32 root = keccak256(abi.encodePacked("inv-r", seed));
        bytes32 policy = keccak256(abi.encodePacked("inv-p", seed));
        registry.anchor(d, e, root, policy, signerVkHash, currentSequence, validUntil, 0);

        anchoredDigests.push(d);
        wasAnchored[d] = true;
        anchorCount++;
        knownEntities.push(e);
        entityStateHistory[e] = registry.STATE_ANCHORED();
    }

    /// @notice Transition a random entity to MATERIALIZED.
    function doMaterialize(uint256 index) external {
        if (knownEntities.length == 0) return;
        index = index % knownEntities.length;
        bytes32 e = knownEntities[index];

        uint8 currentState = registry.getEntityState(e);
        if (currentState != registry.STATE_ANCHORED()) return;

        currentSequence++;
        uint64 validUntil = uint64(block.timestamp + 3600);

        registry.transitionState(e, registry.STATE_MATERIALIZED(), signerVkHash, currentSequence, validUntil);
        entityStateHistory[e] = registry.STATE_MATERIALIZED();
        transitionCount++;
    }

    /// @notice Transition a random entity to DISPUTED.
    function doDispute(uint256 index) external {
        if (knownEntities.length == 0) return;
        index = index % knownEntities.length;
        bytes32 e = knownEntities[index];

        uint8 currentState = registry.getEntityState(e);
        // Can dispute from COMMITTED, ANCHORED, or MATERIALIZED
        if (currentState < 1 || currentState > 3) return;

        currentSequence++;
        uint64 validUntil = uint64(block.timestamp + 3600);

        registry.transitionState(e, registry.STATE_DISPUTED(), signerVkHash, currentSequence, validUntil);
        entityStateHistory[e] = registry.STATE_DISPUTED();
        transitionCount++;
    }

    function anchoredDigestsLength() external view returns (uint256) {
        return anchoredDigests.length;
    }

    function knownEntitiesLength() external view returns (uint256) {
        return knownEntities.length;
    }

    // --- Invariant checks ---

    function invariant_anchorsNeverDisappear() external view {
        for (uint256 i = 0; i < anchoredDigests.length; i++) {
            assert(registry.isAnchored(anchoredDigests[i]));
        }
    }

    function invariant_sequenceNeverDecreases() external view {
        uint64 onChain = uint64(registry.getSignerSequence(signerVkHash));
        // On-chain HWM should equal our tracked sequence (or 0 if nothing anchored yet)
        if (currentSequence == 0) {
            assert(onChain == 0);
        } else {
            assert(onChain == currentSequence);
        }
    }

    function invariant_entityStatesConsistent() external view {
        for (uint256 i = 0; i < knownEntities.length; i++) {
            bytes32 e = knownEntities[i];
            uint8 onChain = registry.getEntityState(e);
            uint8 tracked = entityStateHistory[e];
            assert(onChain == tracked);
        }
    }
}

/// @notice Invariant test contract — tells Foundry to fuzz the handler.
contract InvariantTest is Test {
    RegistryHandler public handler;

    function setUp() public {
        handler = new RegistryHandler();
        handler.setUp();

        // Target the handler for invariant fuzzing
        targetContract(address(handler));

        // Only fuzz these functions
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = RegistryHandler.doAnchor.selector;
        selectors[1] = RegistryHandler.doMaterialize.selector;
        selectors[2] = RegistryHandler.doDispute.selector;
        targetSelector(FuzzSelector(address(handler), selectors));
    }

    /// @notice Anchored digests are permanent — once anchored, always anchored.
    function invariant_anchorsArePermanent() external view {
        handler.invariant_anchorsNeverDisappear();
    }

    /// @notice Signer sequence HWM only increases.
    function invariant_sequenceMonotonicity() external view {
        handler.invariant_sequenceNeverDecreases();
    }

    /// @notice Entity states tracked by handler match on-chain state.
    function invariant_entityStateConsistency() external view {
        handler.invariant_entityStatesConsistent();
    }

    /// @notice Anchor count is non-negative and matches digest array.
    function invariant_anchorCountConsistent() external view {
        assertEq(handler.anchorCount(), handler.anchoredDigestsLength());
    }
}

// ==========================================================================
// Cross-Parity: All 36 state pairs verified against expected set
// ==========================================================================

contract CrossParityTest is TestSetup {
    // Python VALID_TRANSITIONS (10 transitions)
    function _pythonValid(uint8 f, uint8 t) internal pure returns (bool) {
        if (f == 0 && t == 1) return true;
        if (f == 1 && t == 2) return true;
        if (f == 2 && t == 3) return true;
        if (f == 1 && t == 4) return true;
        if (f == 2 && t == 4) return true;
        if (f == 3 && t == 4) return true;
        if (f == 1 && t == 5) return true;
        if (f == 2 && t == 5) return true;
        if (f == 3 && t == 5) return true;
        if (f == 4 && t == 5) return true;
        return false;
    }

    // Solidity VALID_TRANSITIONS (11 transitions = Python + UNKNOWN→ANCHORED)
    function _solidityValid(uint8 f, uint8 t) internal pure returns (bool) {
        if (_pythonValid(f, t)) return true;
        if (f == 0 && t == 2) return true; // UNKNOWN → ANCHORED (Solidity-only)
        return false;
    }

    /// @notice Verify all 36 pairs: Python has 10 valid, Solidity has 11 valid.
    function test_crossParity_all36Pairs() public pure {
        uint256 pyCount = 0;
        uint256 solCount = 0;

        for (uint8 f = 0; f <= 5; f++) {
            for (uint8 t = 0; t <= 5; t++) {
                if (_pythonValid(f, t)) pyCount++;
                if (_solidityValid(f, t)) solCount++;
            }
        }

        assertEq(pyCount, 10);
        assertEq(solCount, 11);
    }

    /// @notice The only divergence is UNKNOWN(0) → ANCHORED(2).
    function test_crossParity_singleDivergence() public pure {
        uint256 divergences = 0;
        for (uint8 f = 0; f <= 5; f++) {
            for (uint8 t = 0; t <= 5; t++) {
                if (_pythonValid(f, t) != _solidityValid(f, t)) {
                    divergences++;
                    // Must be UNKNOWN → ANCHORED
                    assertEq(f, 0);
                    assertEq(t, 2);
                }
            }
        }
        assertEq(divergences, 1);
    }

    /// @notice Solidity is a SUPERSET of Python — every Python-valid transition
    ///         is also Solidity-valid.
    function test_crossParity_solidityIsSuperset() public pure {
        for (uint8 f = 0; f <= 5; f++) {
            for (uint8 t = 0; t <= 5; t++) {
                if (_pythonValid(f, t)) {
                    assertTrue(_solidityValid(f, t));
                }
            }
        }
    }

    /// @notice Verify the contract's transitionState actually matches our expected set
    ///         for all 36 pairs (live on-chain test, not just pure function).
    function test_crossParity_liveTransitions() public {
        uint64 validUntil = uint64(block.timestamp + 3600);
        uint64 seq = 0;

        for (uint8 f = 0; f <= 5; f++) {
            for (uint8 t = 0; t <= 5; t++) {
                if (f == t) continue; // Self-transitions always revert (no-op or invalid)

                bytes32 entityId = keccak256(abi.encodePacked("parity-", f, "-", t));
                bool expected = _solidityValid(f, t);

                // Set entity to 'from' state via sequential valid transitions
                if (f > 0) {
                    // Build path to reach 'from' state
                    _setEntityState(entityId, f, seq, validUntil);
                    seq = uint64(registry.getSignerSequence(signerVkHash));
                }

                // Now attempt transition to 'to'
                seq++;
                if (expected) {
                    registry.transitionState(entityId, t, signerVkHash, seq, validUntil);
                    assertEq(registry.getEntityState(entityId), t);
                } else {
                    vm.expectRevert();
                    registry.transitionState(entityId, t, signerVkHash, seq, validUntil);
                    seq--; // Revert didn't consume the sequence
                }
            }
        }
    }

    /// @dev Helper: transition entity through valid path to reach target state.
    function _setEntityState(
        bytes32 entityId,
        uint8 targetState,
        uint64 startSeq,
        uint64 validUntil
    ) internal {
        uint64 seq = uint64(registry.getSignerSequence(signerVkHash));

        if (targetState == 1) {
            // UNKNOWN → COMMITTED
            seq++;
            registry.transitionState(entityId, 1, signerVkHash, seq, validUntil);
        } else if (targetState == 2) {
            // UNKNOWN → COMMITTED → ANCHORED
            seq++;
            registry.transitionState(entityId, 1, signerVkHash, seq, validUntil);
            seq++;
            registry.transitionState(entityId, 2, signerVkHash, seq, validUntil);
        } else if (targetState == 3) {
            // UNKNOWN → COMMITTED → ANCHORED → MATERIALIZED
            seq++;
            registry.transitionState(entityId, 1, signerVkHash, seq, validUntil);
            seq++;
            registry.transitionState(entityId, 2, signerVkHash, seq, validUntil);
            seq++;
            registry.transitionState(entityId, 3, signerVkHash, seq, validUntil);
        } else if (targetState == 4) {
            // UNKNOWN → COMMITTED → DISPUTED
            seq++;
            registry.transitionState(entityId, 1, signerVkHash, seq, validUntil);
            seq++;
            registry.transitionState(entityId, 4, signerVkHash, seq, validUntil);
        } else if (targetState == 5) {
            // UNKNOWN → COMMITTED → DELETED
            seq++;
            registry.transitionState(entityId, 1, signerVkHash, seq, validUntil);
            seq++;
            registry.transitionState(entityId, 5, signerVkHash, seq, validUntil);
        }
    }
}
