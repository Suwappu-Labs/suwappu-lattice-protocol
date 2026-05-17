// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_016_PauseUpgradeBypass
/// @notice Red-team scenario SCN-016 — Cypher Protocol-class
///         "pause bypassed by an upgrade to a malicious implementation
///         that doesn't honor the paused flag."
///
/// Historical incident: Cypher Protocol, Aug 2023, ~$1M. The team
/// paused the program after an exploit was detected. The attacker
/// then triggered an upgrade path that the team had not anticipated
/// would survive a pause — and continued draining post-pause.
///
/// LTP analogue: `LTPAnchorRegistry.pause()` sets `paused = true`
/// and the `whenNotPaused` modifier blocks `anchor`, `batchAnchor`,
/// `transitionState`, and `anchorWithBinding`. Upgrade authorization
/// is via `_authorizeUpgrade(newImpl) internal override onlyAdmin`.
///
/// The defenses pinned in this scenario:
///
///   (U1) `pause()` is `onlyAdmin`. Non-admin cannot pause OR
///        unpause.
///   (U2) `unpause()` is `onlyAdmin` — even if the contract is
///        paused, a non-admin cannot lift the pause.
///   (U3) `_authorizeUpgrade()` is `onlyAdmin`. The SAME gate as
///        pause. Pause + upgrade are co-controlled.
///   (U4) After an upgrade to a new (benign) implementation, the
///        `paused` storage slot survives. Anchoring stays blocked
///        until `unpause()` is explicitly called.
///   (U5) Combined: a non-admin attacker cannot use the upgrade
///        path to bypass the pause, because both require admin.
///
/// LTP-A-* link: LTP-A-018 (pause has no timelock) + LTP-A-009
/// (production-Timelock delay floor). In a production deploy, the
/// TimelockController controls both pause and upgrade, adding a
/// 24h delay — covered by SCN-019.
contract SCN016_PauseUpgradeBypass is Test {
    LTPAnchorRegistry internal reg;
    LTPAnchorRegistry internal implv1;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ATTACKER = address(0xBADC0DE);
    bytes32 internal constant LEGIT_VK = keccak256("scn016-vk");

    function setUp() public {
        implv1 = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implv1), initData);
        reg = LTPAnchorRegistry(address(proxy));

        vm.prank(ADMIN);
        reg.registerSigner(LEGIT_VK);
    }

    // -----------------------------------------------------------------------
    // U1 — non-admin cannot pause
    // -----------------------------------------------------------------------

    function test_U1_non_admin_cannot_pause() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(
            ILTPAnchorRegistry.NotAdmin.selector, ATTACKER
        ));
        reg.pause();
    }

    // -----------------------------------------------------------------------
    // U2 — non-admin cannot unpause (even when paused)
    // -----------------------------------------------------------------------

    function test_U2_non_admin_cannot_unpause() public {
        vm.prank(ADMIN);
        reg.pause();
        assertTrue(reg.paused());

        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(
            ILTPAnchorRegistry.NotAdmin.selector, ATTACKER
        ));
        reg.unpause();
        assertTrue(reg.paused(), "attacker must not lift pause");
    }

    // -----------------------------------------------------------------------
    // U3 — non-admin cannot upgrade (same gate as pause)
    // -----------------------------------------------------------------------

    function test_U3_non_admin_cannot_upgrade() public {
        LTPAnchorRegistry implv2 = new LTPAnchorRegistry();

        vm.prank(ATTACKER);
        // The OpenZeppelin UUPSUpgradeable wrapper for upgradeToAndCall
        // bubbles up the `_authorizeUpgrade` revert; we accept ANY
        // revert here because the exact selector depends on the OZ
        // version (NotAdmin vs UUPSUnauthorizedCallContext).
        vm.expectRevert();
        reg.upgradeToAndCall(address(implv2), "");
    }

    // -----------------------------------------------------------------------
    // U4 — paused flag survives a benign upgrade
    // -----------------------------------------------------------------------

    function test_U4_paused_state_survives_upgrade() public {
        // Pause.
        vm.prank(ADMIN);
        reg.pause();
        assertTrue(reg.paused());

        // Deploy a fresh v2 impl (identical code, same storage layout).
        LTPAnchorRegistry implv2 = new LTPAnchorRegistry();

        // Upgrade.
        vm.prank(ADMIN);
        reg.upgradeToAndCall(address(implv2), "");

        // Paused state must still be true — storage is preserved
        // across UUPS upgrades.
        assertTrue(reg.paused(), "upgrade must not silently unpause");

        // Anchoring must STILL fail because of the pause, not because
        // of a missing-function or upgrade-induced loss of state.
        vm.expectRevert(ILTPAnchorRegistry.ContractPaused.selector);
        reg.anchor(
            keccak256("u4-digest"),
            keccak256("u4-entity"),
            keccak256("u4-root"),
            bytes32(0),
            LEGIT_VK,
            uint64(1),
            uint64(block.timestamp + 1 days),
            uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // U5 — combined: attacker has neither pause nor upgrade authority
    // -----------------------------------------------------------------------

    function test_U5_attacker_cannot_use_upgrade_to_bypass_pause() public {
        // Admin pauses.
        vm.prank(ADMIN);
        reg.pause();

        // Attacker tries to upgrade — fails.
        LTPAnchorRegistry implv2 = new LTPAnchorRegistry();
        vm.prank(ATTACKER);
        vm.expectRevert();
        reg.upgradeToAndCall(address(implv2), "");

        // Attacker tries to unpause directly — fails.
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(
            ILTPAnchorRegistry.NotAdmin.selector, ATTACKER
        ));
        reg.unpause();

        // State unchanged.
        assertTrue(reg.paused(), "neither path lifted the pause");
    }
}
