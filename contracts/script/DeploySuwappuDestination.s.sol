// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {SuwappuWrappedToken} from "../src/SuwappuWrappedToken.sol";
import {SuwappuEcdsaMintVerifier} from "../src/verifiers/SuwappuEcdsaMintVerifier.sol";
import {SuwappuMintAdapter} from "../src/SuwappuMintAdapter.sol";

/// @notice Deploys the destination-chain mint side of the bridge for the testnet
///         demo: WrappedToken(swETH) + EcdsaMintVerifier + MintAdapter.
///
///   The P3-3 constructor guard forbids admin_ == minterManager_, so even on
///   testnet the minter-manager must be a distinct principal. We deploy a
///   ZERO-DELAY TimelockController as the minter-manager — structurally
///   identical to production (where a real-delay SuwappuTimelockController holds
///   MINTER_ADMIN_ROLE), but with minDelay=0 so the demo can grant the adapter's
///   MINTER/BURNER roles in the same script. Mainnet uses DeploySuwappuMainnet.
///
///   PRIVATE_KEY=0x... forge script script/DeploySuwappuDestination.s.sol \
///     --rpc-url <DEST_RPC> --broadcast
contract DeploySuwappuDestination is Script {
    uint256 constant SOURCE_CHAIN_ID = 84532; // Base Sepolia

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address me = vm.addr(pk);

        vm.startBroadcast(pk);

        // 0. Zero-delay timelock as the minter-manager (distinct from admin=me).
        //    proposer=executor=admin=me for the testnet demo.
        address[] memory proposers = new address[](1);
        proposers[0] = me;
        address[] memory executors = new address[](1);
        executors[0] = me;
        TimelockController minterManager = new TimelockController(0, proposers, executors, me);

        // 1. Wrapped token. admin=me, minterManager=the timelock (P3-3 separation).
        SuwappuWrappedToken token = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether",
            "swETH",
            18,
            SOURCE_CHAIN_ID,
            address(0),
            me,
            address(minterManager)
        );

        // 2. ECDSA attestation verifier; authorize the operator (me).
        SuwappuEcdsaMintVerifier verifier = new SuwappuEcdsaMintVerifier(me);
        verifier.setOperator(me, true);

        // 3. Mint adapter; wire verifier + relayer.
        SuwappuMintAdapter adapter = new SuwappuMintAdapter(me, address(token));
        adapter.setVerifier(address(verifier));
        adapter.addRelayer(me);

        // 4. Grant MINTER/BURNER to the adapter THROUGH the timelock (the only
        //    MINTER_ADMIN_ROLE holder). Zero delay => schedule+execute inline.
        _timelockGrant(minterManager, token, token.MINTER_ROLE(), address(adapter));
        _timelockGrant(minterManager, token, token.BURNER_ROLE(), address(adapter));

        vm.stopBroadcast();

        console2.log("WrappedToken (swETH):", address(token));
        console2.log("MinterManager (TL):  ", address(minterManager));
        console2.log("EcdsaMintVerifier:   ", address(verifier));
        console2.log("MintAdapter:         ", address(adapter));
        console2.log("operator/relayer:    ", me);
    }

    function _timelockGrant(
        TimelockController tl,
        SuwappuWrappedToken token,
        bytes32 role,
        address grantee
    ) internal {
        bytes memory data = abi.encodeWithSignature("grantRole(bytes32,address)", role, grantee);
        tl.schedule(address(token), 0, data, bytes32(0), bytes32(0), 0);
        tl.execute(address(token), 0, data, bytes32(0), bytes32(0));
    }
}
