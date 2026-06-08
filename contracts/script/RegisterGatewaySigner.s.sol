// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

interface IMultiSig {
    function submit(address to, uint256 value, bytes calldata data) external returns (uint256);
    function confirm(uint256 txId) external;
    function execute(uint256 txId) external;
    function transactions(uint256 txId) external view returns (
        address to, uint256 value, bytes memory data, bool executed, uint256 confirmations
    );
    function transactionCount() external view returns (uint256);
}

interface ITimelock {
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) external;
    function execute(
        address target,
        uint256 value,
        bytes calldata payload,
        bytes32 predecessor,
        bytes32 salt
    ) external payable;
    function getMinDelay() external view returns (uint256);
    function isOperationReady(bytes32 id) external view returns (bool);
    function hashOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external pure returns (bytes32);
}

/// @title RegisterGatewaySigner
/// @notice Registers the gateway VM's ML-DSA-65 vkHash on the SUWAPPU devnet LTPAnchorRegistry.
///         Runs the full governance flow: MultiSig -> Timelock -> Registry.
///
/// Usage (3 steps):
///   Step 1 — Submit + confirm (deployer):
///     forge script script/RegisterGatewaySigner.s.sol:RegisterGatewaySigner \
///         --sig "step1_submit()" --rpc-url "$SUWAPPU_RPC_URL" \
///         --private-key "$SUWAPPU_DEPLOYER_KEY" --broadcast -vvvv
///
///   Step 2 — Confirm (operator):
///     forge script script/RegisterGatewaySigner.s.sol:RegisterGatewaySigner \
///         --sig "step2_confirm(uint256)" <TX_ID> --rpc-url "$SUWAPPU_RPC_URL" \
///         --private-key "$SUWAPPU_OPERATOR_KEY" --broadcast -vvvv
///
///   Step 3 — Execute MultiSig + wait + execute Timelock:
///     forge script script/RegisterGatewaySigner.s.sol:RegisterGatewaySigner \
///         --sig "step3_execute(uint256)" <TX_ID> --rpc-url "$SUWAPPU_RPC_URL" \
///         --private-key "$SUWAPPU_DEPLOYER_KEY" --broadcast -vvvv
contract RegisterGatewaySigner is Script {
    // SUWAPPU Testnet addresses
    address constant MULTISIG = 0x0106A79e9236009a05742B3fB1e3B7a52F44373D;
    address constant TIMELOCK = 0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8;
    address constant REGISTRY = 0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4;

    // Gateway VM's ML-DSA-65 vkHash (from deploy/gateway_keypair.json)
    bytes32 constant VK_HASH = 0xf87bb5fbcb2ebd25ed6b13072dff3d7daa1cebdae952d641111110361ab5d415;

    bytes32 constant SALT = keccak256("etp-gateway-vm-signer-registration-v1");

    /// @notice Step 1: Deployer submits the registerSigner proposal to MultiSig
    ///         and auto-confirms (deployer is first signer).
    function step1_submit() external {
        // Build the inner call: Registry.registerSigner(vkHash)
        bytes memory registryCall = abi.encodeWithSignature("registerSigner(bytes32)", VK_HASH);

        // Build the Timelock.schedule call
        uint256 minDelay = ITimelock(TIMELOCK).getMinDelay();
        bytes memory timelockCall = abi.encodeWithSignature(
            "schedule(address,uint256,bytes,bytes32,bytes32,uint256)",
            REGISTRY, 0, registryCall, bytes32(0), SALT, minDelay
        );

        vm.startBroadcast();

        // Submit to MultiSig (auto-confirms for msg.sender)
        IMultiSig ms = IMultiSig(MULTISIG);
        uint256 txId = ms.submit(TIMELOCK, 0, timelockCall);

        vm.stopBroadcast();

        console.log("=== Step 1: Submitted ===");
        console.log("MultiSig TX ID:", txId);
        console.log("vkHash:", vm.toString(VK_HASH));
        console.log("Timelock delay:", minDelay, "seconds");
        console.log("Next: Run step2_confirm with the operator key");
    }

    /// @notice Step 2: Operator confirms the MultiSig transaction.
    function step2_confirm(uint256 txId) external {
        vm.startBroadcast();
        IMultiSig(MULTISIG).confirm(txId);
        vm.stopBroadcast();

        console.log("=== Step 2: Confirmed ===");
        console.log("MultiSig TX ID:", txId);
        console.log("Next: Run step3_execute to execute the MultiSig tx");
    }

    /// @notice Step 3: Execute the MultiSig tx (calls Timelock.schedule),
    ///         then after the delay, execute the Timelock operation.
    function step3_execute(uint256 txId) external {
        IMultiSig ms = IMultiSig(MULTISIG);

        // Check if already executed
        (, , , bool executed, uint256 confirmations) = ms.transactions(txId);
        console.log("Confirmations:", confirmations);

        bytes memory registryCall = abi.encodeWithSignature("registerSigner(bytes32)", VK_HASH);

        if (!executed) {
            console.log("Executing MultiSig tx (schedules Timelock)...");
            vm.startBroadcast();
            ms.execute(txId);
            vm.stopBroadcast();
            console.log("Timelock operation scheduled. Wait for delay, then run step4_finalize.");
        } else {
            console.log("MultiSig tx already executed.");
        }

        // Check if Timelock operation is ready
        bytes32 opId = ITimelock(TIMELOCK).hashOperation(
            REGISTRY, 0, registryCall, bytes32(0), SALT
        );
        bool ready = ITimelock(TIMELOCK).isOperationReady(opId);
        console.log("Timelock operation ready:", ready);

        if (ready) {
            console.log("Executing Timelock operation (registers signer)...");
            vm.startBroadcast();
            ITimelock(TIMELOCK).execute(REGISTRY, 0, registryCall, bytes32(0), SALT);
            vm.stopBroadcast();
            console.log("=== DONE: Gateway signer registered! ===");
            console.log("vkHash:", vm.toString(VK_HASH));
        } else {
            console.log("Timelock not ready yet. Wait and re-run step3_execute.");
        }
    }
}
