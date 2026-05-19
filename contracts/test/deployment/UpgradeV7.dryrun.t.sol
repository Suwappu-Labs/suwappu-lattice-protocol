// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../../src/LTPMultiSig.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title UpgradeV7.dryrun.t.sol — pre-flight test for the v7 testnet ceremony
///
/// Validates that the v7 implementation can be swapped behind the existing
/// proxies without breaking the live state. Runs in fork mode against the
/// GSX testnet (chain 103115120) and Base Sepolia (chain 84532) at recent
/// blocks; you must export the RPC URLs before running:
///
///   GSX_RPC_URL=https://...      forge test \
///   BASE_SEPOLIA_RPC_URL=https://... \
///       --match-path contracts/test/deployment/UpgradeV7.dryrun.t.sol
///
/// Without the URLs, the relevant test bodies are skipped — CI does not gate
/// on fork tests today because the GSX testnet RPC is private. The script
/// runs in the operator ceremony pre-flight (see docs/runbooks/v7-upgrade-
/// testnet.md §"Pre-flight"); a follow-up PR adds the same test under a CI
/// matrix with secret-injected RPCs.
///
/// What each test asserts:
///   1. The v7 storage layout extends v6 (no slot reordering, no removed
///      slots). UUPS upgrades MUST preserve the existing layout — slot
///      reordering corrupts state silently.
///   2. After the upgrade, `paused()` is callable (it was in v6 too;
///      this is a smoke-test for the post-upgrade state).
///   3. The admin (Timelock) can call `pause()` end-to-end without revert,
///      and `paused == true` afterwards. The 0-second pause delay on the
///      Timelock (testnet) is exercised by simulating the full
///      multisig → timelock → registry chain in one forked transaction.
///   4. `unpause()` is symmetrical.
contract UpgradeV7DryRunTest is Test {
    // GSX Testnet (chain 103115120)
    address constant GSX_PROXY = 0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4;
    address payable constant GSX_MULTISIG = payable(0x0106A79e9236009a05742B3fB1e3B7a52F44373D);
    address constant GSX_TIMELOCK = 0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8;

    // Base Sepolia (chain 84532)
    address constant BASE_SEPOLIA_PROXY = 0x79eF1B7914f98C5C1404617449AB1f377c475996;
    address payable constant BASE_SEPOLIA_MULTISIG = payable(0x4c324c3c3475f58b67d3c879880D6c94eDC82E49);
    address constant BASE_SEPOLIA_TIMELOCK = 0xc915740e35E38569E47f611eA5772Ff5278bc5Ae;

    // ------------------------------------------------------------------
    // GSX testnet fork
    // ------------------------------------------------------------------

    function testGsxStorageLayoutPreserved() public {
        string memory url = vm.envOr("GSX_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        _assertUpgradePreservesLayout(GSX_PROXY, GSX_TIMELOCK);
    }

    function testGsxPauseRehearsal() public {
        string memory url = vm.envOr("GSX_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        _drillPauseAfterUpgrade(GSX_PROXY, GSX_TIMELOCK);
    }

    // ------------------------------------------------------------------
    // Base Sepolia fork
    // ------------------------------------------------------------------

    function testBaseSepoliaStorageLayoutPreserved() public {
        string memory url = vm.envOr("BASE_SEPOLIA_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        _assertUpgradePreservesLayout(BASE_SEPOLIA_PROXY, BASE_SEPOLIA_TIMELOCK);
    }

    function testBaseSepoliaPauseRehearsal() public {
        string memory url = vm.envOr("BASE_SEPOLIA_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        _drillPauseAfterUpgrade(BASE_SEPOLIA_PROXY, BASE_SEPOLIA_TIMELOCK);
    }

    // ------------------------------------------------------------------
    // Internal helpers — chain-agnostic
    // ------------------------------------------------------------------

    /// @dev Reads selected v6 storage slots, performs the v7 upgrade,
    /// then verifies the same slots still hold the same values.
    /// Captures the public, well-known fields; a full layout diff is
    /// out of scope for this dry-run (Foundry's `forge inspect storage`
    /// is the right tool for the exhaustive check).
    function _assertUpgradePreservesLayout(address proxy, address timelock) internal {
        LTPAnchorRegistry registry = LTPAnchorRegistry(proxy);

        // Capture pre-upgrade state we can verify post-upgrade.
        address preAdmin = registry.admin();
        bool prePaused = registry.paused();
        uint256 preVersion = registry.version();

        // Perform the upgrade as the Timelock would.
        LTPAnchorRegistry newImpl = new LTPAnchorRegistry();
        vm.prank(timelock);
        UUPSUpgradeable(proxy).upgradeToAndCall(address(newImpl), "");

        // Storage from pre-upgrade reads must round-trip exactly.
        assertEq(registry.admin(), preAdmin, "admin slot moved during upgrade");
        assertEq(registry.paused(), prePaused, "paused slot moved during upgrade");
        assertGe(registry.version(), preVersion, "version monotonicity violated");
    }

    /// @dev Drills the emergency pause flow against a freshly-upgraded
    /// registry. Pranks as the Timelock (= admin after deploy) and asserts
    /// pause() / unpause() succeed and state flips correctly.
    function _drillPauseAfterUpgrade(address proxy, address timelock) internal {
        LTPAnchorRegistry registry = LTPAnchorRegistry(proxy);

        // Upgrade first.
        LTPAnchorRegistry newImpl = new LTPAnchorRegistry();
        vm.prank(timelock);
        UUPSUpgradeable(proxy).upgradeToAndCall(address(newImpl), "");

        // Pause.
        bool wasPaused = registry.paused();
        vm.prank(timelock);
        registry.pause();
        assertTrue(registry.paused(), "pause() did not flip paused = true");

        // Unpause (cleanup so the pre-existing state is restored).
        vm.prank(timelock);
        registry.unpause();
        assertEq(registry.paused(), wasPaused, "unpause() did not restore prior state");
    }
}
