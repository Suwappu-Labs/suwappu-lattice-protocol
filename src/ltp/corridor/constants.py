"""Cross-repo constants that bind LTP to gsx-dag/crates/gsx-ltp.

These constants must match `gsx-dag/crates/gsx-ltp/src/lib.rs` byte-for-byte.
Any drift here will break wire compatibility with the DAG L1 corridor surface.
"""

from __future__ import annotations

# Paper §10.2 — constant on-chain commitment size.
# ML-KEM-768 ciphertext (~1,568 B) + BLS12-381 aggregate signature (~96 B) +
# SHA3-256 payload root (32 B) ≈ 1,600 B.
ON_CHAIN_COMMITMENT_BYTES = 1_600

# Paper §10 — 7-of-9 corridor super-node attestation quorum.
LTP_ATTESTATION_QUORUM_THRESHOLD = 7
LTP_ATTESTATION_QUORUM_SIZE = 9

# Domain tags. These are passed to `sha3_256_domain(tag, data)` exactly as
# encoded here so the resulting digests match the Rust crate.
DOMAIN_TAG_ATTEST = b"GSX-LTP-ATTEST-V1"
DOMAIN_TAG_CID = b"GSX-LTP-CID-V1"
DOMAIN_TAG_DID_STARK = b"GSX-DID-STARK-V1"

# Proof-of-possession domain for corridor SuperNode registration. Closes
# LTP-A-015 (Boneh-Drijvers-Neven rogue-key attack on aggregate BLS) by
# requiring each member to prove they hold the secret key for the
# advertised BLS public key. The signature is over the public key bytes
# under this DST.
DOMAIN_TAG_CORRIDOR_POP = b"LTP-CORRIDOR-POP-V1"

# DKG commit-then-reveal phase. Closes LTP-A-016 by binding each dealer
# to a hash-commitment of their polynomial commitments before any
# commitment payload is revealed to peers.
DOMAIN_TAG_DKG_COMMIT = b"LTP-DKG-COMMIT-V1"

# BLS hash-to-curve domain separation tag for the corridor signing surface.
# Matches `gsx-dag/crates/gsx-crypto/src/bls.rs::BLS_DST`. LTP's default BLS
# helper signs under py_ecc's `G2ProofOfPossession` DST instead, so the
# corridor surface uses this constant explicitly when calling into blst.
BLS_CORRIDOR_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
