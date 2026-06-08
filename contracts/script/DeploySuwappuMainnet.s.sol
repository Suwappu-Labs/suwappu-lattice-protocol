// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SuwappuTimelockController} from "../src/SuwappuTimelockController.sol";
import {SuwappuWrappedToken} from "../src/SuwappuWrappedToken.sol";
import {SuwappuEcdsaMintVerifier} from "../src/verifiers/SuwappuEcdsaMintVerifier.sol";
import {SuwappuMintAdapter} from "../src/SuwappuMintAdapter.sol";
import {SuwappuVault} from "../src/SuwappuVault.sol";

/// @title DeploySuwappuMainnet
/// @notice Production custody deploy with the SAFE wiring the P9 fix-verification
///         pass requires (blocker #1):
///           - `minterManager` is the SuwappuTimelockController (real per-selector
///             delays), NEVER an EOA, and is DISTINCT from the token admin Safe
///             (the SuwappuWrappedToken constructor now hard-reverts on
///             admin_ == minterManager_).
///           - The vault ships with a daily RELEASE cap configured for every
///             lockable asset (P3-4 is inert at cap==0), plus a refund verifier.
///           - All admin-gated config is done by the deployer as a TEMPORARY
///             admin, then `transferAdmin` hands each contract to the Safe (the
///             Safe must `acceptAdmin` — two-step, no accidental lock-out).
///
/// @dev Some final steps MUST be performed by governance after this script and
///      are logged, not executed here:
///        1. Safe calls `acceptAdmin()` on vault / adapter / verifier.
///        2. Safe (the timelock PROPOSER) schedules then, after the delay,
///           executes the MINTER_ROLE/BURNER_ROLE grant to the adapter — minting
///           authority is intentionally a timelocked governance action (P3-3).
///        3. Safe grants the token's DEFAULT_ADMIN_ROLE to itself and the
///           deployer renounces it (handled below if DEPLOYER_RENOUNCE=true).
///
///   Env: SAFE (admin), GUARDIAN (pause), OPERATOR (attestation signer),
///        RELAYER, ETH_DAILY_RELEASE_CAP, FEE_BPS.
contract DeploySuwappuMainnet is Script {
    struct Deployed {
        SuwappuTimelockController timelock;
        SuwappuWrappedToken token;
        SuwappuEcdsaMintVerifier verifier;
        SuwappuMintAdapter adapter;
        SuwappuVault vault;
    }

    function run() external returns (Deployed memory d) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address safe = vm.envAddress("SAFE");
        address guardian = vm.envAddress("GUARDIAN");
        address operator = vm.envAddress("OPERATOR");
        address relayer = vm.envAddress("RELAYER");
        uint256 ethReleaseCap = vm.envUint("ETH_DAILY_RELEASE_CAP");
        uint256 feeBps = vm.envOr("FEE_BPS", uint256(0));

        vm.startBroadcast(pk);
        d = _deploy(deployer, safe, guardian, operator, relayer, ethReleaseCap, feeBps);
        vm.stopBroadcast();

        console2.log("Timelock (minterManager):", address(d.timelock));
        console2.log("WrappedToken (swETH):    ", address(d.token));
        console2.log("EcdsaMintVerifier:       ", address(d.verifier));
        console2.log("MintAdapter:             ", address(d.adapter));
        console2.log("SuwappuVault:            ", address(d.vault));
        console2.log("admin (Safe, pending):   ", safe);
        console2.log(
            "NEXT: Safe.acceptAdmin() on vault/adapter/verifier; timelock-schedule MINTER/BURNER grant to adapter."
        );
    }

    /// @dev Wiring logic, shared by run() and the deployment test. `admin` is the
    ///      TEMP admin that every config call is authorized against, so it MUST be
    ///      whatever address the config calls will carry as msg.sender:
    ///        - run(): the deployer EOA (calls broadcast as the EOA);
    ///        - test: the test contract itself (it inherits this script, so _deploy
    ///                executes in the test's frame and config calls come from it).
    function _deploy(
        address admin,
        address safe,
        address guardian,
        address operator,
        address relayer,
        uint256 ethReleaseCap,
        uint256 feeBps
    ) public returns (Deployed memory d) {
        require(safe != address(0) && safe != admin, "SAFE must be set and != deployer");
        require(ethReleaseCap > 0, "ETH release cap must be > 0 (P3-4)");

        // 1. Governance timelock: Safe is the sole proposer/canceller; guardian
        //    gets GUARDIAN_ROLE; executors open; no post-deploy admin.
        address[] memory proposers = new address[](1);
        proposers[0] = safe;
        address[] memory guardians = new address[](1);
        guardians[0] = guardian;
        d.timelock = new SuwappuTimelockController(proposers, guardians);

        // 2. Wrapped token: admin = admin (temp, handed to Safe below),
        //    minterManager = timelock (DISTINCT — the P3-3 guard enforces this).
        d.token = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether",
            "swETH",
            18,
            block.chainid,
            address(0),
            admin,
            address(d.timelock)
        );

        // 3. Attestation verifier (ECDSA interim on EVM; ML-DSA on Suwappu DAG).
        d.verifier = new SuwappuEcdsaMintVerifier(admin);
        d.verifier.setOperator(operator, true);

        // 4. Mint adapter wired to the verifier + relayer.
        d.adapter = new SuwappuMintAdapter(admin, address(d.token));
        d.adapter.setVerifier(address(d.verifier));
        d.adapter.addRelayer(relayer);

        // 5. Vault with a daily RELEASE cap on ETH (P3-4 safe-by-default) and the
        //    refund verifier wired (C2 refund gate). Lock-side caps/allowlists are
        //    set the same way per asset by governance.
        d.vault = new SuwappuVault(admin, safe, feeBps);
        d.vault.setDailyReleaseCap(address(0), ethReleaseCap);
        d.vault.setRefundVerifier(address(d.verifier));
        d.vault.setGuardian(guardian);
        // C2: the timelock is the emergency rescuer, so emergencyRefund is
        // timelock-delayed (a public objection window), never instant.
        d.vault.setEmergencyRescuer(address(d.timelock));
        d.vault.addUnlocker(relayer);

        // 6. Hand control to the Safe (two-step: Safe must acceptAdmin()).
        d.verifier.transferAdmin(safe);
        d.adapter.transferAdmin(safe);
        d.vault.transferAdmin(safe);
        // Token DEFAULT_ADMIN_ROLE → Safe; admin renounces its temp admin.
        d.token.grantRole(d.token.DEFAULT_ADMIN_ROLE(), safe);
        d.token.renounceRole(d.token.DEFAULT_ADMIN_ROLE(), admin);
    }
}
