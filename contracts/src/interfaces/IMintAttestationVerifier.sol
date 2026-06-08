// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IMintAttestationVerifier
/// @notice Pluggable on-chain verification gate for SuwappuMintAdapter.mint.
///         The adapter computes a domain-bound digest over the exact mint
///         parameters (commitId, recipient, amount, sourceChainId) plus
///         block.chainid and the adapter address, and requires this verifier
///         to confirm an AUTHORIZED operator attested to it.
///
/// @dev Two implementations:
///   - SuwappuEcdsaMintVerifier  — EVM-interim, ECDSA operator signatures.
///   - SuwappuMlDsaMintVerifier   — Suwappu DAG, calls the native ML-DSA-65
///                                  (FIPS 204) precompile. This is the
///                                  post-quantum path; its message encoding
///                                  matches the `suwappu-mldsa-precompile`
///                                  crate (pubkey || sig || message).
///
/// Fixes (vs. the audit findings):
///   - C1:   mint params are now bound into a signed digest — a relayer can no
///           longer mint with an arbitrary unbacked commitId.
///   - P3-1: operator authorization is enforced inside the verifier — a
///           self-signed key is rejected.
///   - P3-5: block.chainid + adapter address are in the digest — the same
///           attestation cannot replay onto another instance or chain.
interface IMintAttestationVerifier {
    /// @param digest       keccak256 of the domain-separated mint commitment.
    /// @param attestation  Opaque operator attestation (ECDSA sig, or
    ///                     abi.encode(pubkey, mldsaSig) for the PQ verifier).
    /// @return ok          True iff `attestation` is a valid signature over
    ///                     `digest` by a currently-authorized operator.
    function verifyMintAttestation(bytes32 digest, bytes calldata attestation)
        external
        view
        returns (bool ok);
}
