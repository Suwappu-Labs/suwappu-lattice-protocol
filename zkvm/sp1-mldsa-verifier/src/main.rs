//! SP1 zkVM circuit: proves ML-DSA-65 (FIPS 204) signature validity.
//!
//! Given private witnesses (operator_vk, signature, signable_payload) and public
//! binding inputs (anchor_digest, chain_id, verifier_addr), the circuit asserts
//! that ML-DSA-65 verification succeeds, then commits the public inputs
//! (anchor_digest, sth_root_hash, operator_vk_hash, tree_size, sth_sequence,
//! chain_id, verifier_addr) in the exact order ZKBridgeVerifier expects.
//!
//! This is the core proof obligation for the ETP cross-chain bridge:
//! "The operator's STH signature is valid" — proved in zero knowledge.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha3::{Digest, Sha3_256};

pub fn main() {
    // -----------------------------------------------------------------------
    // Step 1: Read private witnesses from SP1 stdin
    // -----------------------------------------------------------------------
    let operator_vk: Vec<u8> = sp1_zkvm::io::read_vec(); // 1952 bytes (ML-DSA-65 VK)
    let signature: Vec<u8> = sp1_zkvm::io::read_vec(); // 3309 bytes (ML-DSA-65 sig)
    let signable_payload: Vec<u8> = sp1_zkvm::io::read_vec(); // 56 bytes

    // Public binding inputs: echoed into the committed public values so the proof
    // is bound to the exact anchor digest AND the destination chain + verifier
    // instance it finalizes on. The host MUST provide these in this order; they
    // must equal the on-chain ZKBridgeVerifier publicValues (P9 / C3 binding).
    let anchor_digest: Vec<u8> = sp1_zkvm::io::read_vec(); // 32 bytes
    let chain_id: Vec<u8> = sp1_zkvm::io::read_vec(); // 32 bytes (uint256 BE)
    let verifier_addr: Vec<u8> = sp1_zkvm::io::read_vec(); // 20 bytes

    // Validate witness sizes
    assert_eq!(operator_vk.len(), 1952, "Invalid VK size");
    assert_eq!(signature.len(), 3309, "Invalid signature size");
    assert_eq!(signable_payload.len(), 56, "Invalid payload size");
    assert_eq!(anchor_digest.len(), 32, "Invalid anchor digest size");
    assert_eq!(chain_id.len(), 32, "Invalid chain id size");
    assert_eq!(verifier_addr.len(), 20, "Invalid verifier address size");

    // -----------------------------------------------------------------------
    // Step 2: Verify ML-DSA-65 signature (FIPS 204)
    //
    // This is the proof obligation. If verification fails, the SP1 prover
    // will abort and no proof is generated (soundness guarantee).
    // -----------------------------------------------------------------------
    use ml_dsa::signature::Verifier;
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

    // Parse verification key from raw bytes
    let vk_encoded = EncodedVerifyingKey::<MlDsa65>::try_from(operator_vk.as_slice())
        .expect("Failed to create EncodedVerifyingKey (wrong size)");
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_encoded);

    // Parse signature from raw bytes
    let sig_encoded = EncodedSignature::<MlDsa65>::try_from(signature.as_slice())
        .expect("Failed to create EncodedSignature (wrong size)");
    let sig =
        Signature::<MlDsa65>::decode(&sig_encoded).expect("Failed to decode ML-DSA-65 signature");

    // Verify — this is the proof obligation
    vk.verify(&signable_payload, &sig)
        .expect("ML-DSA-65 signature verification FAILED — proof is unsound");

    // -----------------------------------------------------------------------
    // Step 3: Extract public inputs from signable_payload
    //
    // Layout: sequence(8B BE) || tree_size(8B BE) || timestamp(8B BE) || root_hash(32B)
    // -----------------------------------------------------------------------
    let sth_sequence = u64::from_be_bytes(signable_payload[0..8].try_into().unwrap());
    let tree_size = u64::from_be_bytes(signable_payload[8..16].try_into().unwrap());
    // timestamp at [16..24] is not part of public inputs (private)
    let sth_root_hash = &signable_payload[24..56]; // 32 bytes

    // -----------------------------------------------------------------------
    // Step 4: Compute operator_vk_hash = SHA3-256(operator_vk)
    // -----------------------------------------------------------------------
    let mut hasher = Sha3_256::new();
    hasher.update(&operator_vk);
    let operator_vk_hash = hasher.finalize();

    // -----------------------------------------------------------------------
    // Step 5: Commit public inputs (verifiable by anyone with the proof)
    //
    // These values become the "public statement" of the ZK proof:
    // "There exists a valid ML-DSA-65 signature by operator_vk_hash
    //  on an STH with root_hash, tree_size, and sequence, bound to anchor_digest
    //  on chain_id at verifier_addr."
    //
    // Commit order MUST match ZKBridgeVerifier._verifySP1 publicValues exactly:
    //   anchor_digest(32) || sth_root_hash(32) || operator_vk_hash(32)
    //     || tree_size(8 BE) || sth_sequence(8 BE) || chain_id(32) || verifier_addr(20)
    //   = 164 bytes
    // -----------------------------------------------------------------------
    sp1_zkvm::io::commit_slice(&anchor_digest); // 32 bytes (C3 binding)
    sp1_zkvm::io::commit_slice(sth_root_hash); // 32 bytes
    sp1_zkvm::io::commit_slice(&operator_vk_hash); // 32 bytes
    sp1_zkvm::io::commit_slice(&tree_size.to_be_bytes()); // 8 bytes
    sp1_zkvm::io::commit_slice(&sth_sequence.to_be_bytes()); // 8 bytes
    sp1_zkvm::io::commit_slice(&chain_id); // 32 bytes (P9: chain binding)
    sp1_zkvm::io::commit_slice(&verifier_addr); // 20 bytes (P9: instance binding)
}
