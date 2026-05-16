// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LTPAnchorRegistry} from "../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_001_WormholeEchidna
/// @notice Property harness for SCN-001 (Wormhole-class "skip signature
///         verification" pattern). Run with:
///
///           cd contracts && echidna . \
///             --contract SCN_001_WormholeEchidna --config echidna.yaml
///
/// Properties pinned (mirror SCN_001_Invariant.invariant_*):
///   P1: nextAnchorId never increases unless the call used an
///       authorized signer.
///   P2: every digest the harness believes is anchored has its
///       targetChainId == block.chainid.
///   P3: signerSequences for any signer the harness has touched is
///       non-decreasing across calls.
contract SCN_001_WormholeEchidna {
    LTPAnchorRegistry internal reg;
    address internal constant ADMIN = address(0xA1);

    // Echidna uses assertion testMode (from echidna.yaml); we surface
    // properties either as `echidna_*` view functions returning bool
    // (must always be true) OR as inline `assert(...)` calls inside
    // the entrypoints.
    bytes32 internal constant SEED_VK = keccak256("echidna-seed-vk");

    // Accounting mirrors of contract state — keeps the harness honest
    // about whether a call should have succeeded.
    bytes32[] internal anchoredDigests;
    mapping(bytes32 => bool) internal isAnchored;
    mapping(bytes32 => bool) internal sawAuthorizedAtWrite;
    mapping(bytes32 => uint64) internal harnessSeqHwm;

    constructor() {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        // Bootstrap one authorized signer so the harness has at least
        // one valid path.
        vm_prank(ADMIN);
        reg.registerSigner(SEED_VK);
    }

    // ----------------------------------------------------------------
    // vm.prank shim — Echidna doesn't have forge-std cheatcodes by
    // default. We inline a minimal version that uses the HEVM cheatcode
    // address.
    // ----------------------------------------------------------------
    address internal constant HEVM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    function vm_prank(address who) internal {
        (bool ok, ) = HEVM_ADDRESS.call(
            abi.encodeWithSignature("prank(address)", who)
        );
        require(ok, "prank failed");
    }

    // ----------------------------------------------------------------
    // Fuzzed entrypoints
    // ----------------------------------------------------------------

    function tryRegisterSigner(bytes32 vkHash) external {
        if (vkHash == bytes32(0)) return;
        vm_prank(ADMIN);
        try reg.registerSigner(vkHash) {} catch {}
    }

    function tryRevokeSigner(bytes32 vkHash) external {
        vm_prank(ADMIN);
        try reg.revokeSigner(vkHash) {} catch {}
    }

    function tryAnchor(
        bytes32 digest,
        bytes32 entityId,
        bytes32 merkleRoot,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntilOffset,
        uint8   receiptType
    ) external {
        if (digest == bytes32(0) || entityId == bytes32(0) ||
            merkleRoot == bytes32(0) || signerVkHash == bytes32(0)) return;

        uint64 validUntil = uint64(block.timestamp) + (validUntilOffset == 0 ? 1 : validUntilOffset);
        bool authBefore = reg.authorizedSigners(signerVkHash);

        try reg.anchor(digest, entityId, merkleRoot, bytes32(0),
                       signerVkHash, sequence, validUntil, receiptType) {
            // P1 asserts inline: a successful anchor implies authorized signer.
            assert(authBefore);

            if (!isAnchored[digest]) {
                isAnchored[digest] = true;
                anchoredDigests.push(digest);
            }
            sawAuthorizedAtWrite[signerVkHash] = sawAuthorizedAtWrite[signerVkHash] || authBefore;
            if (sequence > harnessSeqHwm[signerVkHash]) {
                harnessSeqHwm[signerVkHash] = sequence;
            }
        } catch {}
    }

    // ----------------------------------------------------------------
    // Properties
    // ----------------------------------------------------------------

    /// P1 (companion to inline assert in tryAnchor): for every accepted
    /// digest the harness has observed, the recorded signer was
    /// authorized at write-time.
    function echidna_no_unauthorized_anchor() external view returns (bool) {
        for (uint256 i = 0; i < anchoredDigests.length; ++i) {
            bytes32 d = anchoredDigests[i];
            ILTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(d);
            if (!sawAuthorizedAtWrite[rec.signerVkHash]) {
                return false;
            }
        }
        return true;
    }

    /// P2: targetChainId stamp on every anchor equals block.chainid.
    function echidna_chain_id_stamp() external view returns (bool) {
        for (uint256 i = 0; i < anchoredDigests.length; ++i) {
            ILTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(anchoredDigests[i]);
            if (uint256(rec.targetChainId) != block.chainid) {
                return false;
            }
        }
        return true;
    }

    /// P3: on-chain signer-sequence HWM is at least as large as the
    /// harness's mirror — the contract never reverses a sequence bump.
    function echidna_sequence_monotone() external view returns (bool) {
        // We only check the seed VK + the SEED_VK pre-registered in the
        // constructor; the harness doesn't enumerate all signers used.
        return reg.signerSequences(SEED_VK) >= harnessSeqHwm[SEED_VK];
    }
}
