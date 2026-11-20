// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ZKNOX_dilithium65} from "../src/ZKNOX_dilithium65.sol";
import {F1600Helper} from "./F1600Helper.sol";
import {SSTORE2} from "sstore2/SSTORE2.sol";

/// Prototype only: a 7-of-9 ML-DSA-65 quorum check with keys stored once as
/// contract code, so the per-epoch transaction carries only signatures.
contract QuorumProto {
    uint256 internal constant N = 9;
    uint256 internal constant T = 7;
    uint256 internal constant SPLIT = 24000;
    bytes internal constant CTX = "LTP-corridor-v1";

    ZKNOX_dilithium65 public immutable verifier;
    address[2][N] internal keyChunks;
    bytes32[N] public keyHash;

    constructor(ZKNOX_dilithium65 v) {
        verifier = v;
    }

    /// The 38,112-byte expanded key exceeds the 24,576-byte code limit, so it
    /// is stored as two data contracts.
    function registerKey(uint256 i, bytes calldata blob) external {
        require(i < N && blob.length == 38112, "bad key");
        keyChunks[i][0] = SSTORE2.write(blob[:SPLIT]);
        keyChunks[i][1] = SSTORE2.write(blob[SPLIT:]);
        keyHash[i] = keccak256(blob);
    }

    function _key(uint256 i) internal view returns (bytes memory) {
        return bytes.concat(SSTORE2.read(keyChunks[i][0]), SSTORE2.read(keyChunks[i][1]));
    }

    /// sigs holds one signature per set bit of bitmap, in ascending signer order.
    function verifyQuorum(bytes32 root, uint256 bitmap, bytes[] calldata sigs, bool useCtx)
        external
        view
        returns (bool)
    {
        require(bitmap < (1 << N), "bad bitmap");
        bytes memory m = abi.encodePacked(root);
        uint256 used;
        for (uint256 i = 0; i < N; i++) {
            if (bitmap & (1 << i) == 0) continue;
            if (!verifier.verify(_key(i), m, sigs[used], useCtx ? CTX : bytes(""))) return false;
            used++;
        }
        return used >= T && used == sigs.length;
    }
}

contract LTPQuorumTest is Test {
    ZKNOX_dilithium65 v;
    QuorumProto q;
    string j;

    function _k(string memory a, uint256 i) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, string.concat(".", a, "[", vm.toString(i), "]"));
    }

    function setUp() public {
        v = new ZKNOX_dilithium65(F1600Helper.deploy(vm));
        q = new QuorumProto(v);
        j = vm.readFile("test/KAT/ltp65.json");
        uint256 regGas;
        for (uint256 i = 0; i < 9; i++) {
            bytes memory blob = _k("blobs", i);
            uint256 g = gasleft();
            q.registerKey(i, blob);
            regGas += g - gasleft();
        }
        console.log("register 9 keys, execution total:", regGas);
    }

    function _calldataGas(bytes memory cd) internal pure returns (uint256 standard, uint256 floor) {
        uint256 nz;
        for (uint256 i = 0; i < cd.length; i++) {
            if (cd[i] != 0) nz++;
        }
        uint256 z = cd.length - nz;
        standard = 4 * z + 16 * nz;
        floor = 10 * (z + 4 * nz);
    }

    function testQuorum7of9Stored() public view {
        bytes32 root = bytes32(vm.parseJsonBytes(j, ".root"));
        bytes[] memory sigs = new bytes[](7);
        uint256 bitmap;
        // signers 0,1,3,4,5,7,8
        uint8[7] memory who = [0, 1, 3, 4, 5, 7, 8];
        for (uint256 n = 0; n < 7; n++) {
            sigs[n] = _k("sigRoot", who[n]);
            bitmap |= 1 << who[n];
        }
        bytes memory cd = abi.encodeCall(QuorumProto.verifyQuorum, (root, bitmap, sigs, false));
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = address(q).staticcall(cd);
        uint256 used = g - gasleft();
        assertTrue(ok && abi.decode(ret, (bool)));
        (uint256 std, uint256 floor) = _calldataGas(cd);
        console.log("verifyQuorum execution gas:", used);
        console.log("calldata bytes:", cd.length);
        console.log("calldata gas (standard 4/16):", std);
        console.log("calldata gas (EIP-7623 floor):", floor);
        console.log("estimated tx total (21000 + std + exec):", 21000 + std + used);
    }

    function testQuorumRejects() public view {
        bytes32 root = bytes32(vm.parseJsonBytes(j, ".root"));
        bytes[] memory six = new bytes[](6);
        uint256 bitmap;
        for (uint256 n = 0; n < 6; n++) {
            six[n] = _k("sigRoot", n);
            bitmap |= 1 << n;
        }
        // six valid signatures are below threshold
        assertFalse(q.verifyQuorum(root, bitmap, six, false));
        // seven signatures, one attributed to the wrong signer
        bytes[] memory seven = new bytes[](7);
        for (uint256 n = 0; n < 7; n++) {
            seven[n] = _k("sigRoot", n);
        }
        assertTrue(q.verifyQuorum(root, 0x7f, seven, false));
        assertFalse(q.verifyQuorum(root, 0xbf, seven, false));
        // empty-context signatures must fail once a context is required
        assertFalse(q.verifyQuorum(root, 0x7f, seven, true));
    }
}
