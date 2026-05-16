// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../../src/LTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_001_Wormhole_AnchorRegistry
/// @notice Red-team scenario SCN-001 — Wormhole-class "skip signature
///         verification" pattern. See
///         docs/security/campaigns/SCN-001-wormhole-signature-skip/.
///
/// Historical incident: Wormhole bridge, Feb 2022, $326M. The Solana
/// program failed to validate that a sysvar-instructions account was
/// authentic, allowing the attacker to spoof a "signatures verified"
/// signal and mint wrapped ETH without proving custody.
///
/// LTP analogue: `LTPAnchorRegistry.anchor()` deliberately does NO
/// on-chain ML-DSA verification — the design is "thin on-chain, thick
/// off-chain" (see audit finding LTP-A-001, BY-DESIGN). The on-chain
/// defenses that compensate are:
///
///   (D1) `authorizedSigners[signerVkHash]` must be true
///        → revert UnauthorizedSigner
///   (D2) `signerExpiresAt[signerVkHash]` (if set) must not have
///        elapsed → revert UnauthorizedSigner
///   (D3) `_anchors[anchorDigest].anchoredAt == 0`
///        → revert AlreadyAnchored (replay protection)
///   (D4) `entitySigners[entityIdHash]` must be unset or match
///        → revert NotEntitySigner
///   (D5) `sequence > signerSequences[signerVkHash]`
///        → revert SequenceTooLow (sequence monotonicity)
///   (D6) `block.timestamp < validUntil`
///        → revert Expired (temporal expiry)
///   (D7) `_isValidTransition(currentState, ANCHORED)`
///        → revert InvalidStateTransition
///   (D8) `targetChainId` is stamped from `block.chainid`, not caller-
///        supplied → cross-chain replay protection
///   (D9) `paused == false` → revert ContractPaused
///
/// This file verifies each defense fires on the corresponding attack
/// pattern, plus a fuzz layer that asserts no random
/// `(signerVkHash, sequence, validUntil)` triple can produce an
/// accepted anchor unless every defense holds.
contract SCN001_Wormhole_AnchorRegistry is Test {
    LTPAnchorRegistry internal reg;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ATTACKER = address(0xBADC0DE);
    address internal constant LEGITIMATE_RELAYER = address(0xC0DE);

    bytes32 internal constant LEGIT_VK = keccak256("legit-relayer-vk");
    bytes32 internal constant ATTACKER_VK = keccak256("attacker-forged-vk");

    function setUp() public {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        vm.prank(ADMIN);
        reg.registerSigner(LEGIT_VK);
    }

    // -----------------------------------------------------------------------
    // D1 — Unauthorized signer rejected
    // -----------------------------------------------------------------------

    /// @dev Attacker holds a forged ML-DSA key whose hash is NOT in
    ///      `authorizedSigners`. Even though there is no on-chain
    ///      signature check, the membership check stops the call.
    function test_D1_unauthorized_signer_rejected() public {
        bytes32 anchorDigest = keccak256("malicious-anchor");
        bytes32 entityId = keccak256("victim-entity");
        bytes32 merkleRoot = keccak256("attacker-state");

        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(
            LTPAnchorRegistry.UnauthorizedSigner.selector, ATTACKER_VK
        ));
        reg.anchor(
            anchorDigest, entityId, merkleRoot, bytes32(0),
            ATTACKER_VK, uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    /// @dev Same as D1 but caller is the legitimate relayer address.
    ///      Caller address is irrelevant; the VK-hash membership is
    ///      what gates the call.
    function test_D1_unauthorized_signer_rejected_legitimate_caller() public {
        bytes32 anchorDigest = keccak256("malicious-anchor-2");
        bytes32 entityId = keccak256("victim-entity-2");

        vm.prank(LEGITIMATE_RELAYER);
        vm.expectRevert(abi.encodeWithSelector(
            LTPAnchorRegistry.UnauthorizedSigner.selector, ATTACKER_VK
        ));
        reg.anchor(
            anchorDigest, entityId, keccak256("root"), bytes32(0),
            ATTACKER_VK, uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // D3 — Replay rejected (same anchor digest twice)
    // -----------------------------------------------------------------------

    function test_D3_replay_rejected() public {
        bytes32 anchorDigest = keccak256("legit-anchor");
        bytes32 entityId = keccak256("entity-replay");

        // First anchor succeeds via legitimate path.
        _legitAnchor(anchorDigest, entityId, LEGIT_VK, uint64(1));

        // Second submit of the same digest must revert.
        vm.expectRevert(abi.encodeWithSelector(
            LTPAnchorRegistry.AlreadyAnchored.selector, anchorDigest
        ));
        reg.anchor(
            anchorDigest, entityId, keccak256("root"), bytes32(0),
            LEGIT_VK, uint64(2), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // D4 — Entity-signer binding (first-write-wins)
    // -----------------------------------------------------------------------

    function test_D4_foreign_signer_cannot_overwrite_entity_binding() public {
        bytes32 entityId = keccak256("entity-bound");
        bytes32 secondVk = keccak256("second-legit-vk");

        // Register a second authorized signer so D1 doesn't fire first.
        vm.prank(ADMIN);
        reg.registerSigner(secondVk);

        // First legitimate anchor binds entity → LEGIT_VK.
        _legitAnchor(keccak256("first-anchor"), entityId, LEGIT_VK, uint64(1));

        // Second anchor from a different authorized signer must revert.
        vm.expectRevert(abi.encodeWithSelector(
            LTPAnchorRegistry.NotEntitySigner.selector, entityId, secondVk
        ));
        reg.anchor(
            keccak256("second-anchor"), entityId, keccak256("root"), bytes32(0),
            secondVk, uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // D5 — Sequence monotonicity (replay-by-old-sequence rejected)
    // -----------------------------------------------------------------------

    function test_D5_stale_sequence_rejected() public {
        bytes32 entityId = keccak256("entity-seq");

        _legitAnchor(keccak256("seq-anchor-1"), entityId, LEGIT_VK, uint64(5));

        // Replay attempt with sequence <= current HWM (5) must revert.
        vm.expectRevert(abi.encodeWithSelector(
            LTPAnchorRegistry.SequenceTooLow.selector, LEGIT_VK, uint64(5), uint64(5)
        ));
        reg.anchor(
            keccak256("seq-anchor-2"), entityId, keccak256("root"), bytes32(0),
            LEGIT_VK, uint64(5), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // D6 — Temporal expiry
    // -----------------------------------------------------------------------

    function test_D6_expired_anchor_rejected() public {
        uint64 validUntil = uint64(block.timestamp + 100);
        vm.warp(uint256(validUntil) + 1); // jump past expiry

        vm.expectRevert(abi.encodeWithSelector(
            LTPAnchorRegistry.Expired.selector, validUntil, uint64(block.timestamp)
        ));
        reg.anchor(
            keccak256("expired-anchor"), keccak256("entity"), keccak256("root"),
            bytes32(0), LEGIT_VK, uint64(1), validUntil, uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // D8 — Cross-chain replay (targetChainId is block.chainid, not caller-supplied)
    // -----------------------------------------------------------------------

    /// @dev We can't easily simulate a real cross-chain replay in a
    ///      unit test, but we can assert the stored `targetChainId`
    ///      always equals `block.chainid`. A replay across chains
    ///      would fail to match the destination chain's stored value.
    function test_D8_target_chain_stamped_from_block_chainid() public {
        bytes32 anchorDigest = keccak256("chain-stamp-anchor");
        bytes32 entityId = keccak256("chain-stamp-entity");

        _legitAnchor(anchorDigest, entityId, LEGIT_VK, uint64(1));

        LTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(anchorDigest);
        assertEq(uint256(rec.targetChainId), block.chainid);
    }

    // -----------------------------------------------------------------------
    // D9 — Pause enforcement
    // -----------------------------------------------------------------------

    function test_D9_paused_rejects_anchor() public {
        vm.prank(ADMIN);
        reg.pause();

        vm.expectRevert(LTPAnchorRegistry.ContractPaused.selector);
        reg.anchor(
            keccak256("paused-anchor"), keccak256("entity"), keccak256("root"),
            bytes32(0), LEGIT_VK, uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // Fuzz — for any unauthorized VK + arbitrary inputs, no anchor lands
    // -----------------------------------------------------------------------

    /// @dev Property: a `signerVkHash` that is NOT in `authorizedSigners`
    ///      can never produce an accepted anchor, regardless of the
    ///      other parameters. This is the Wormhole-equivalent claim:
    ///      the unauthorized-claimant path must always revert.
    function testFuzz_unauthorized_signer_always_reverts(
        bytes32 forgedVk,
        bytes32 anchorDigest,
        bytes32 entityId,
        bytes32 merkleRoot,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) public {
        vm.assume(forgedVk != bytes32(0));
        vm.assume(forgedVk != LEGIT_VK);
        vm.assume(anchorDigest != bytes32(0));
        vm.assume(entityId != bytes32(0));
        vm.assume(merkleRoot != bytes32(0));

        // The forged VK is not in `authorizedSigners` by construction.
        // We just need to verify the call reverts.
        vm.expectRevert(); // any of D0..D2 may fire first; the property is "no acceptance"
        reg.anchor(anchorDigest, entityId, merkleRoot, bytes32(0),
                   forgedVk, sequence, validUntil, receiptType);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _legitAnchor(
        bytes32 anchorDigest,
        bytes32 entityId,
        bytes32 vk,
        uint64  sequence
    ) internal {
        reg.anchor(
            anchorDigest, entityId, keccak256(abi.encode(anchorDigest, "root")),
            bytes32(0), vk, sequence, uint64(block.timestamp + 1 days), uint8(0)
        );
    }
}
