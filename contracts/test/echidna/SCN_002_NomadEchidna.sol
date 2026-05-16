// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LTPAnchorRegistry} from "../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_002_NomadEchidna
/// @notice Property harness for SCN-002 (Nomad-class init-bug pattern).
///
///   cd contracts && echidna . --contract SCN_002_NomadEchidna --config echidna.yaml
///
/// Properties pinned:
///   Q1: _anchors[bytes32(0)].anchoredAt is always 0 (sentinel never written).
///   Q2: every digest the harness believes is anchored has non-zero
///       digest + entity + merkle + signer.
contract SCN_002_NomadEchidna {
    LTPAnchorRegistry internal reg;
    address internal constant ADMIN = address(0xA1);
    bytes32 internal constant SEED_VK = keccak256("scn002-echidna-vk");

    bytes32[] internal anchoredDigests;
    mapping(bytes32 => bool) internal isAnchored;

    constructor() {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        vm_prank(ADMIN);
        reg.registerSigner(SEED_VK);
    }

    address internal constant HEVM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    function vm_prank(address who) internal {
        (bool ok, ) = HEVM_ADDRESS.call(abi.encodeWithSignature("prank(address)", who));
        require(ok, "prank failed");
    }

    function tryAnchor(
        bytes32 digest,
        bytes32 entityId,
        bytes32 merkleRoot,
        bytes32 signerVkHash,
        bytes32 policyHash,
        uint64  sequence,
        uint64  validUntilOffset,
        uint8   receiptType
    ) external {
        uint64 validUntil = uint64(block.timestamp) + (validUntilOffset == 0 ? 1 : validUntilOffset);
        try reg.anchor(digest, entityId, merkleRoot, policyHash,
                       signerVkHash, sequence, validUntil, receiptType) {
            // Q2 inline: any successful anchor has non-zero primary inputs.
            assert(digest != bytes32(0));
            assert(entityId != bytes32(0));
            assert(merkleRoot != bytes32(0));
            assert(signerVkHash != bytes32(0));

            if (!isAnchored[digest]) {
                isAnchored[digest] = true;
                anchoredDigests.push(digest);
            }
        } catch {}
    }

    /// Q1: zero-digest sentinel slot stays empty for the lifetime of the run.
    function echidna_zero_digest_never_anchored() external view returns (bool) {
        ILTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(bytes32(0));
        return rec.anchoredAt == 0;
    }

    /// Q2 (view-side companion to inline assert).
    function echidna_no_zero_primary_input_accepted() external view returns (bool) {
        for (uint256 i = 0; i < anchoredDigests.length; ++i) {
            if (anchoredDigests[i] == bytes32(0)) return false;
            ILTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(anchoredDigests[i]);
            if (rec.entityIdHash == bytes32(0)) return false;
            if (rec.merkleRoot == bytes32(0)) return false;
            if (rec.signerVkHash == bytes32(0)) return false;
        }
        return true;
    }
}
