// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_015_SignerRotationGrace
/// @notice Red-team scenario SCN-015 — signer-rotation in-flight race.
///         Maps to LTP-A-030 (grace-period rotation safety) and the
///         companion LTP-A-031 surfaced during SCN-015 authoring (the
///         `_anchor` did not honor `signerExpiresAt`; fixed in the
///         same commit).
///
/// Historical pattern: when a compromised key is rotated with a
/// non-zero grace window, the rotated-out key must be accepted for
/// already-signed in-flight messages but REJECTED for new operations
/// after the grace window elapses. Real bridge incidents (Multichain,
/// Ronin's post-compromise rotation) have shipped with the
/// post-grace-acceptance failure mode. The defenses pinned here:
///
///   (G1) `rotateSignerWithGrace` records `signerExpiresAt` for the
///        old key, leaving it temporarily authorized.
///   (G2) `rotateSigner(old, new)` (0 grace) revokes the old key
///        atomically — `authorizedSigners[old]` becomes false.
///   (G3) `transitionState()` with the old key INSIDE the grace
///        window succeeds.
///   (G4) `transitionState()` with the old key AFTER the grace
///        window expires reverts with UnauthorizedSigner. (Already
///        pinned by existing audit tests; included here for
///        completeness.)
///   (G5) **LTP-A-031**: `_anchor()` (via `anchor()`) with the old
///        key INSIDE the grace window succeeds.
///   (G6) **LTP-A-031**: `_anchor()` with the old key AFTER the
///        grace window expires reverts with UnauthorizedSigner.
///        Before the fix, this test would have FAILED, exposing the
///        bug. The fix is the new expiresAt check at
///        `LTPAnchorRegistry.sol:541-549`.
contract SCN015_SignerRotationGrace is Test {
    LTPAnchorRegistry internal reg;

    address internal constant ADMIN = address(0xA11CE);
    bytes32 internal constant OLD_VK = keccak256("scn015-old-vk");
    bytes32 internal constant NEW_VK = keccak256("scn015-new-vk");

    function setUp() public {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        vm.prank(ADMIN);
        reg.registerSigner(OLD_VK);
    }

    // -----------------------------------------------------------------------
    // G1 — rotateSignerWithGrace records expiry; old key stays authorized
    // -----------------------------------------------------------------------

    function test_G1_grace_rotation_records_expiry() public {
        uint64 grace = uint64(1 days);
        uint64 t0 = uint64(block.timestamp);

        vm.prank(ADMIN);
        reg.rotateSignerWithGrace(OLD_VK, NEW_VK, grace);

        assertTrue(reg.authorizedSigners(OLD_VK), "OLD_VK must stay authorized during grace");
        assertTrue(reg.authorizedSigners(NEW_VK), "NEW_VK must be authorized immediately");
        assertEq(reg.signerExpiresAt(OLD_VK), t0 + grace, "OLD_VK expiry must be t0+grace");
        assertEq(reg.signerExpiresAt(NEW_VK), 0, "NEW_VK must have no expiry");
    }

    // -----------------------------------------------------------------------
    // G2 — atomic rotation revokes old key immediately
    // -----------------------------------------------------------------------

    function test_G2_atomic_rotation_revokes_old_key() public {
        vm.prank(ADMIN);
        reg.rotateSigner(OLD_VK, NEW_VK);

        assertFalse(reg.authorizedSigners(OLD_VK), "atomic rotation must revoke OLD_VK");
        assertTrue(reg.authorizedSigners(NEW_VK));
        assertEq(reg.signerExpiresAt(OLD_VK), 0, "no expiry written on atomic path");
    }

    // -----------------------------------------------------------------------
    // G3 — old key still works inside grace window (transitionState path)
    // -----------------------------------------------------------------------

    function test_G3_old_key_works_inside_grace_via_transitionState() public {
        uint64 grace = uint64(1 days);

        vm.prank(ADMIN);
        reg.rotateSignerWithGrace(OLD_VK, NEW_VK, grace);

        // Warp HALFWAY through grace.
        vm.warp(block.timestamp + uint256(grace) / 2);

        // transitionState() with OLD_VK should still succeed.
        bytes32 entityId = keccak256("g3-entity");
        reg.transitionState(
            entityId,
            uint8(2), // STATE_ANCHORED
            OLD_VK,
            uint64(1),
            uint64(block.timestamp + 30 days)
        );
        assertEq(reg.entityStates(entityId), uint8(2));
    }

    // -----------------------------------------------------------------------
    // G4 — old key rejected after grace expires (transitionState path)
    // -----------------------------------------------------------------------

    function test_G4_old_key_rejected_after_grace_via_transitionState() public {
        uint64 grace = uint64(1 days);

        vm.prank(ADMIN);
        reg.rotateSignerWithGrace(OLD_VK, NEW_VK, grace);

        // Warp PAST grace.
        vm.warp(block.timestamp + uint256(grace) + 1);

        bytes32 entityId = keccak256("g4-entity");
        vm.expectRevert(abi.encodeWithSelector(
            ILTPAnchorRegistry.UnauthorizedSigner.selector, OLD_VK
        ));
        reg.transitionState(
            entityId,
            uint8(2), // STATE_ANCHORED
            OLD_VK,
            uint64(1),
            uint64(block.timestamp + 30 days)
        );
    }

    // -----------------------------------------------------------------------
    // G5 — LTP-A-031: old key still works inside grace via anchor()
    // -----------------------------------------------------------------------

    function test_G5_old_key_works_inside_grace_via_anchor() public {
        uint64 grace = uint64(1 days);

        vm.prank(ADMIN);
        reg.rotateSignerWithGrace(OLD_VK, NEW_VK, grace);

        vm.warp(block.timestamp + uint256(grace) / 2);

        // anchor() with OLD_VK should still succeed during grace.
        reg.anchor(
            keccak256("g5-digest"),
            keccak256("g5-entity"),
            keccak256("g5-root"),
            bytes32(0),
            OLD_VK,
            uint64(1),
            uint64(block.timestamp + 30 days),
            uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // G6 — LTP-A-031: old key REJECTED after grace via anchor() (THE FIX)
    // -----------------------------------------------------------------------

    /// @dev This is the regression test for LTP-A-031. Before the fix
    ///      at LTPAnchorRegistry.sol:541-549, this test would have
    ///      FAILED because `_anchor()` only checked
    ///      `authorizedSigners[signerVkHash]` and ignored
    ///      `signerExpiresAt`. The fix adds the expiry check matching
    ///      `transitionState()`.
    function test_G6_old_key_rejected_after_grace_via_anchor() public {
        uint64 grace = uint64(1 days);

        vm.prank(ADMIN);
        reg.rotateSignerWithGrace(OLD_VK, NEW_VK, grace);

        // Warp past grace.
        vm.warp(block.timestamp + uint256(grace) + 1);

        vm.expectRevert(abi.encodeWithSelector(
            ILTPAnchorRegistry.UnauthorizedSigner.selector, OLD_VK
        ));
        reg.anchor(
            keccak256("g6-digest"),
            keccak256("g6-entity"),
            keccak256("g6-root"),
            bytes32(0),
            OLD_VK,
            uint64(1),
            uint64(block.timestamp + 30 days),
            uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // Edge case: new key works at all times (no expiry recorded)
    // -----------------------------------------------------------------------

    function test_G_new_key_works_inside_and_outside_grace() public {
        uint64 grace = uint64(1 days);

        vm.prank(ADMIN);
        reg.rotateSignerWithGrace(OLD_VK, NEW_VK, grace);

        // Inside grace.
        reg.anchor(
            keccak256("new-inside-digest"),
            keccak256("new-inside-entity"),
            keccak256("root"),
            bytes32(0), NEW_VK,
            uint64(1), uint64(block.timestamp + 30 days), uint8(0)
        );

        // Outside grace.
        vm.warp(block.timestamp + uint256(grace) + 1);
        reg.anchor(
            keccak256("new-outside-digest"),
            keccak256("new-outside-entity"),
            keccak256("root"),
            bytes32(0), NEW_VK,
            uint64(2), uint64(block.timestamp + 30 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // rotateSignerWithGrace argument bounds (already enforced)
    // -----------------------------------------------------------------------

    function test_G_grace_cap_at_7_days() public {
        vm.prank(ADMIN);
        vm.expectRevert(bytes("grace > 7d"));
        reg.rotateSignerWithGrace(OLD_VK, NEW_VK, uint64(8 days));
    }
}
