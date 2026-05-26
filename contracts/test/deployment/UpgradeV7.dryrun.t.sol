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
        _drillPauseAfterUpgrade(GSX_PROXY, GSX_TIMELOCK, GSX_MULTISIG);
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
        _drillPauseAfterUpgrade(BASE_SEPOLIA_PROXY, BASE_SEPOLIA_TIMELOCK, BASE_SEPOLIA_MULTISIG);
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

        // The v7 ceremony's invariant is a real version bump — equality
        // here would silently green-light a no-op or wrong-impl deploy.
        assertGt(
            registry.version(),
            preVersion,
            "version did not advance — implementation not actually upgraded"
        );
    }

    /// @dev Drills the emergency pause flow against a freshly-upgraded
    /// registry by exercising the full governance path that the runbook
    /// uses in production:
    ///   multisig.submitTransaction(timelock, schedule(...))
    ///     → multisig.confirmTransaction
    ///     → multisig.executeTransaction (fires timelock.schedule)
    ///     → vm.warp past timelock delay
    ///     → multisig.submitTransaction(timelock, execute(...))
    ///     → multisig.confirmTransaction
    ///     → multisig.executeTransaction (fires timelock.execute → registry.pause)
    ///
    /// This catches governance-wiring regressions (proposer/executor
    /// role assignments, multisig owner set, threshold) that a direct
    /// `vm.prank(timelock); registry.pause()` would silently pass.
    ///
    /// Branches on the live fork's starting pause state — OZ Pausable
    /// reverts `pause()` when already paused (and `unpause()` when not).
    /// End state is always restored to the pre-drill value.
    function _drillPauseAfterUpgrade(address proxy, address timelock, address payable multisig) internal {
        LTPAnchorRegistry registry = LTPAnchorRegistry(proxy);
        TimelockController tl = TimelockController(payable(timelock));
        LTPMultiSig ms = LTPMultiSig(multisig);

        // Governance wiring invariants — the multisig must hold both
        // proposer and executor roles on the timelock for the ceremony
        // to clear in production.
        assertTrue(
            tl.hasRole(tl.PROPOSER_ROLE(), multisig),
            "multisig does not hold PROPOSER_ROLE on timelock"
        );
        assertTrue(
            tl.hasRole(tl.EXECUTOR_ROLE(), multisig),
            "multisig does not hold EXECUTOR_ROLE on timelock"
        );

        // Upgrade first.
        LTPAnchorRegistry newImpl = new LTPAnchorRegistry();
        vm.prank(timelock);
        UUPSUpgradeable(proxy).upgradeToAndCall(address(newImpl), "");

        bool wasPaused = registry.paused();
        bytes memory pauseCall = abi.encodeCall(LTPAnchorRegistry.pause, ());
        bytes memory unpauseCall = abi.encodeCall(LTPAnchorRegistry.unpause, ());

        if (wasPaused) {
            _routeAdminCallThroughGovernance(registry, tl, ms, unpauseCall);
            assertFalse(registry.paused(), "governance path did not unpause registry");

            _routeAdminCallThroughGovernance(registry, tl, ms, pauseCall);
            assertTrue(registry.paused(), "governance path did not re-pause registry");
        } else {
            _routeAdminCallThroughGovernance(registry, tl, ms, pauseCall);
            assertTrue(registry.paused(), "governance path did not pause registry");

            _routeAdminCallThroughGovernance(registry, tl, ms, unpauseCall);
            assertFalse(registry.paused(), "governance path did not unpause registry");
        }

        assertEq(registry.paused(), wasPaused, "drill did not restore prior pause state");
    }

    /// @dev Drives an `onlyAdmin` registry call through the live
    /// multisig + timelock the way the runbook prescribes: two
    /// multisig txs (schedule then execute) bracketing the timelock
    /// delay. Assumes a 2-of-N multisig where the first two owners
    /// are both able to sign — true for the 2-of-2 testnet deployments.
    ///
    /// Salt is derived per-call so consecutive rehearsals (and forks
    /// where the same op was already executed in a prior drill) get
    /// distinct Timelock operation ids — otherwise `schedule(...)`
    /// reverts because the op id is no longer `Unset`.
    function _routeAdminCallThroughGovernance(
        LTPAnchorRegistry registry,
        TimelockController tl,
        LTPMultiSig ms,
        bytes memory adminCall
    ) internal {
        address[] memory owners = ms.getOwners();
        require(owners.length >= 2, "test requires >= 2 multisig owners");

        uint256 delay = tl.getMinDelay();
        bytes32 salt = keccak256(
            abi.encode(block.timestamp, block.prevrandao, address(registry), adminCall)
        );

        // STEP A-C: submit + confirm + execute the timelock.schedule(...)
        bytes memory scheduleCall = abi.encodeCall(
            TimelockController.schedule,
            (address(registry), 0, adminCall, bytes32(0), salt, delay)
        );
        vm.prank(owners[0]);
        uint256 scheduleTxId = ms.submitTransaction(address(tl), 0, scheduleCall);
        vm.prank(owners[1]);
        ms.confirmTransaction(scheduleTxId);
        vm.prank(owners[0]);
        ms.executeTransaction(scheduleTxId);

        // STEP D: advance past the timelock delay.
        vm.warp(block.timestamp + delay + 1);

        // STEP E-G: submit + confirm + execute the timelock.execute(...)
        // The salt MUST match the schedule call so the Timelock
        // resolves the same op id.
        bytes memory executeCall = abi.encodeCall(
            TimelockController.execute,
            (address(registry), 0, adminCall, bytes32(0), salt)
        );
        vm.prank(owners[0]);
        uint256 executeTxId = ms.submitTransaction(address(tl), 0, executeCall);
        vm.prank(owners[1]);
        ms.confirmTransaction(executeTxId);
        vm.prank(owners[0]);
        ms.executeTransaction(executeTxId);
    }
}
