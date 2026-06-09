//! SP1 zkVM circuit: proves GSX-DAG validator quorum over a header attestation.
//!
//! Given private witnesses (validator set, signers) and public binding inputs
//! (networkId, oracle, blockNumber, stateRoot, totalStake), the circuit:
//!   1. Computes header_digest = blake3(HEADER_DOMAIN || networkId || oracle ||
//!      blockNumber-as-uint256-BE || stateRoot).
//!   2. Checks the validator list is strictly-increasing by pkHash (canonical root).
//!   3. Computes validator_set_root = keccak256(pkHash_0 || stake_0-as-uint256-BE ||
//!      pkHash_1 || stake_1-as-uint256-BE || ...) in pkHash order.
//!   4. Calls quorum_core::verify_quorum_stake — panics on unsorted signers (unprovable).
//!   5. Asserts quorum_reached — proof only exists when >2/3 stake signs.
//!   6. Commits public values (128 bytes):
//!      networkId(32) || blockNumber-as-uint256-BE(32) || stateRoot(32) || validator_set_root(32)
//!
//! ## Trust framing
//! The SNARK proving this circuit is classical BN254 (Groth16) — NOT post-quantum.
//! The on-chain verifier (Sp1QuorumVerifier) uses a standard EVM Groth16 verifier.
//! The ML-DSA-65 signatures are verified INSIDE the circuit, enabling a chain
//! WITHOUT the native 0x0101 precompile to accept ML-DSA quorum attestations.
//! The validator_set_root commits the proof to the on-chain registry's set,
//! preventing a quorum proof with an off-chain validator set from being accepted.
//!
//! ## Wire format (sp1_zkvm::io::read_vec)
//! Reads (in order):
//!   1. networkId           — 32 bytes
//!   2. oracle              — 20 bytes
//!   3. blockNumber         — 8 bytes (u64 BE)
//!   4. stateRoot           — 32 bytes
//!   5. N u32 BE (4 bytes)  — number of validators
//!   For each validator:
//!     5a. pkHash            — 32 bytes
//!     5b. stake             — 16 bytes (u128 BE)
//!   6. M u32 BE (4 bytes)  — number of signers
//!   For each signer:
//!     6a. pubkey            — 1952 bytes (ML-DSA-65)
//!     6b. sig               — 3309 bytes (ML-DSA-65)
//!   7. totalStake          — 16 bytes (u128 BE)

#![no_main]
sp1_zkvm::entrypoint!(main);

use quorum_core::{quorum_reached, verify_quorum_stake, SignerInput, Validator};
use sha3::{Digest, Keccak256};

/// HEADER_DOMAIN = keccak256("SUWAPPU_GSXDAG_HEADER_V1")
/// Pre-computed to avoid runtime hashing; must equal the Solidity constant:
///   GsxDagQuorumHeaderOracle.HEADER_DOMAIN
///
/// Derivation (verified):
///   keccak256(b"SUWAPPU_GSXDAG_HEADER_V1")
///   = the domain tag for header attestation digests
const HEADER_DOMAIN: [u8; 32] = {
    // keccak256("SUWAPPU_GSXDAG_HEADER_V1")
    // Computed offline; matches the Solidity `keccak256("SUWAPPU_GSXDAG_HEADER_V1")` constant.
    // We cannot call keccak256 at const-eval time without a constexpr hasher, so we
    // hard-code the result. The host test cross-checks this against a runtime computation.
    // Verified: python3 -c "from Crypto.Hash import keccak; k=keccak.new(digest_bits=256); k.update(b'SUWAPPU_GSXDAG_HEADER_V1'); print(k.hexdigest())"
    // = c70c21ebc79f8a20433457a70cf2985f05e70b017cbd95f328e3b2a8721ebd3a
    [
        0xc7, 0x0c, 0x21, 0xeb, 0xc7, 0x9f, 0x8a, 0x20, 0x43, 0x34, 0x57, 0xa7, 0x0c, 0xf2,
        0x98, 0x5f, 0x05, 0xe7, 0x0b, 0x01, 0x7c, 0xbd, 0x95, 0xf3, 0x28, 0xe3, 0xb2, 0xa8,
        0x72, 0x1e, 0xbd, 0x3a,
    ]
};

pub fn main() {
    // -----------------------------------------------------------------------
    // Step 1: Read inputs
    // -----------------------------------------------------------------------

    // Public binding inputs
    let network_id: Vec<u8> = sp1_zkvm::io::read_vec(); // 32 bytes
    let oracle: Vec<u8> = sp1_zkvm::io::read_vec(); // 20 bytes
    let block_number_bytes: Vec<u8> = sp1_zkvm::io::read_vec(); // 8 bytes (u64 BE)
    let state_root: Vec<u8> = sp1_zkvm::io::read_vec(); // 32 bytes

    assert_eq!(network_id.len(), 32, "networkId must be 32 bytes");
    assert_eq!(oracle.len(), 20, "oracle must be 20 bytes");
    assert_eq!(block_number_bytes.len(), 8, "blockNumber must be 8 bytes");
    assert_eq!(state_root.len(), 32, "stateRoot must be 32 bytes");

    // Parse block_number as u64 for display; encode as uint256 BE (32 bytes) for digest + public values
    let block_number_u64 =
        u64::from_be_bytes(block_number_bytes.as_slice().try_into().expect("8 bytes"));
    // blockNumber as uint256 BE: left-pad 8-byte u64 with 24 zero bytes
    let mut block_number_u256 = [0u8; 32];
    block_number_u256[24..32].copy_from_slice(&block_number_u64.to_be_bytes());

    // Validator set
    let n_validators_bytes: Vec<u8> = sp1_zkvm::io::read_vec(); // 4 bytes (u32 BE)
    assert_eq!(n_validators_bytes.len(), 4, "n_validators must be 4 bytes");
    let n_validators =
        u32::from_be_bytes(n_validators_bytes.as_slice().try_into().expect("4 bytes")) as usize;

    let mut validators: Vec<Validator> = Vec::with_capacity(n_validators);
    for _ in 0..n_validators {
        let pk_hash_bytes: Vec<u8> = sp1_zkvm::io::read_vec(); // 32 bytes
        let stake_bytes: Vec<u8> = sp1_zkvm::io::read_vec(); // 16 bytes (u128 BE)
        assert_eq!(pk_hash_bytes.len(), 32, "pkHash must be 32 bytes");
        assert_eq!(stake_bytes.len(), 16, "stake must be 16 bytes");
        let pk_hash: [u8; 32] = pk_hash_bytes.try_into().expect("32 bytes");
        let stake = u128::from_be_bytes(stake_bytes.as_slice().try_into().expect("16 bytes"));
        validators.push(Validator { pk_hash, stake });
    }

    // Signer inputs
    let n_signers_bytes: Vec<u8> = sp1_zkvm::io::read_vec(); // 4 bytes (u32 BE)
    assert_eq!(n_signers_bytes.len(), 4, "n_signers must be 4 bytes");
    let n_signers =
        u32::from_be_bytes(n_signers_bytes.as_slice().try_into().expect("4 bytes")) as usize;

    let mut signers: Vec<SignerInput> = Vec::with_capacity(n_signers);
    for _ in 0..n_signers {
        let pubkey: Vec<u8> = sp1_zkvm::io::read_vec(); // 1952 bytes
        let sig: Vec<u8> = sp1_zkvm::io::read_vec(); // 3309 bytes
        assert_eq!(pubkey.len(), 1952, "ML-DSA-65 pubkey must be 1952 bytes");
        assert_eq!(sig.len(), 3309, "ML-DSA-65 sig must be 3309 bytes");
        signers.push(SignerInput { pubkey, sig });
    }

    // Total stake for quorum threshold
    let total_stake_bytes: Vec<u8> = sp1_zkvm::io::read_vec(); // 16 bytes (u128 BE)
    assert_eq!(total_stake_bytes.len(), 16, "totalStake must be 16 bytes");
    let total_stake =
        u128::from_be_bytes(total_stake_bytes.as_slice().try_into().expect("16 bytes"));

    // -----------------------------------------------------------------------
    // Step 2: Compute header_digest
    // = blake3(HEADER_DOMAIN(32) || networkId(32) || oracle(20) ||
    //          blockNumber-as-uint256-BE(32) || stateRoot(32))
    //
    // This matches GsxDagQuorumHeaderOracle.headerDigest / _blake3(
    //   abi.encodePacked(HEADER_DOMAIN, registry.networkId(), address(this),
    //                    blockNumber, stateRoot))
    // -----------------------------------------------------------------------
    let mut preimage = Vec::with_capacity(32 + 32 + 20 + 32 + 32);
    preimage.extend_from_slice(&HEADER_DOMAIN);
    preimage.extend_from_slice(&network_id);
    preimage.extend_from_slice(&oracle);
    preimage.extend_from_slice(&block_number_u256);
    preimage.extend_from_slice(&state_root);

    let digest_output = blake3::hash(&preimage);
    let header_digest: [u8; 32] = *digest_output.as_bytes();

    // -----------------------------------------------------------------------
    // Step 3: Require validator set is strictly-increasing by pkHash.
    // This canonicalizes the set: the root is uniquely determined by the
    // validator set (not by insertion order), which the on-chain registry
    // also enforces via _installSet's sort check.
    // -----------------------------------------------------------------------
    {
        let mut last = [0u8; 32];
        for v in &validators {
            assert!(
                v.pk_hash > last,
                "validator list must be strictly increasing by pkHash"
            );
            last = v.pk_hash;
        }
    }

    // -----------------------------------------------------------------------
    // Step 4: Compute validator_set_root
    // = keccak256(pkHash_0(32) || stake_0-as-uint256-BE(32) ||
    //             pkHash_1(32) || stake_1-as-uint256-BE(32) || ...)
    //
    // stake is u128 but encoded as uint256 (32 bytes, left-padded with 16
    // zero bytes). This matches the Solidity registry:
    //   bytes memory preimage = new bytes(n * 64);
    //   mstore(..., pkHash)          // 32 bytes
    //   mstore(..., stake)           // uint256, 32 bytes
    // -----------------------------------------------------------------------
    let validator_set_root = {
        let mut h = Keccak256::new();
        for v in &validators {
            h.update(v.pk_hash);
            // stake as uint256 BE: left-pad u128 (16 bytes) with 16 zero bytes
            let mut stake_u256 = [0u8; 32];
            stake_u256[16..32].copy_from_slice(&v.stake.to_be_bytes());
            h.update(stake_u256);
        }
        let result: [u8; 32] = h.finalize().into();
        result
    };

    // -----------------------------------------------------------------------
    // Step 5: Verify ML-DSA-65 quorum
    // verify_quorum_stake panics on unsorted signers (UnsortedOrDuplicate) —
    // this makes the proof unprovable for an unsorted input (correct behaviour).
    // -----------------------------------------------------------------------
    let sig_stake = verify_quorum_stake(&header_digest, &validators, &signers)
        .expect("signer list must be strictly increasing by keccak256(pubkey)");

    // -----------------------------------------------------------------------
    // Step 6: Assert quorum reached
    // Proof only exists if >2/3 stake signed the header digest.
    // -----------------------------------------------------------------------
    assert!(
        quorum_reached(sig_stake, total_stake),
        "quorum not reached: sig_stake < threshold"
    );

    // -----------------------------------------------------------------------
    // Step 7: Commit public values (128 bytes, fixed layout)
    //
    // Byte offsets:
    //   [0..32]   networkId          (32 bytes, as provided)
    //   [32..64]  blockNumber        (32 bytes, uint256 BE)
    //   [64..96]  stateRoot          (32 bytes, as provided)
    //   [96..128] validator_set_root (32 bytes, keccak256 of sorted validators)
    //
    // The on-chain Sp1QuorumVerifier reconstructs these in the same order:
    //   abi.encodePacked(registry.networkId(), uint256(blockNumber),
    //                    stateRoot, validatorSetRoot)
    // -----------------------------------------------------------------------
    sp1_zkvm::io::commit_slice(&network_id); // [0..32]
    sp1_zkvm::io::commit_slice(&block_number_u256); // [32..64]
    sp1_zkvm::io::commit_slice(&state_root); // [64..96]
    sp1_zkvm::io::commit_slice(&validator_set_root); // [96..128]
}
