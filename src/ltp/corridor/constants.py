"""Cross-repo constants that bind LTP to suwappu-dag/crates/suwappu-ltp.

These constants must match `suwappu-dag/crates/suwappu-ltp/src/lib.rs` byte-for-byte.
Any drift here will break wire compatibility with the DAG L1 corridor surface.
"""

from __future__ import annotations

# Paper §10.2 — constant on-chain commitment size.
#
# CAUTION: this figure is a paper-level approximation and matches NO actual
# field layout. The real envelope totals are:
#     ML-KEM-768:   1088 + 96 + 32 = 1216 B
#     ML-KEM-1024:  1568 + 96 + 32 = 1696 B
# Neither is 1,600. The 1,600 figure is the ML-KEM-**1024** ciphertext
# (1,568 B) plus the SHA3-256 root (32 B), i.e. it drops the 96-byte
# aggregate signature — and an earlier version of this comment additionally
# mislabeled that 1,568 B as the "ML-KEM-768 ciphertext". ML-KEM-768's
# ciphertext is 1,088 B (see `src/ltp/primitives.py::_REAL_KEM_CT`);
# 1,568 B is ML-KEM-1024 (Level 5).
#
# Consequences, both already documented in `envelope.py`:
#   - `OnChainCommitment.assert_strict_total()` is unsatisfiable for every
#     well-formed envelope; it is a forward-compat stub, not a live check.
#   - The invariant that actually holds is payload INDEPENDENCE, not this
#     specific number. That is machine-checked in `formal/lean/` (see
#     `Ltp/Commitment.lean`: `commitment_size_payload_independent` and
#     `strict_total_unsatisfiable`).
#
# Do not "fix" a field width to make this arithmetic work — the Lean proofs
# pin the widths and will fail. Changing the constant is a cross-repo wire
# decision shared with suwappu-dag/crates/suwappu-ltp.
ON_CHAIN_COMMITMENT_BYTES = 1_600

# Paper §10 — 7-of-9 corridor super-node attestation quorum.
LTP_ATTESTATION_QUORUM_THRESHOLD = 7
LTP_ATTESTATION_QUORUM_SIZE = 9

# Domain tags. These are passed to `sha3_256_domain(tag, data)` exactly as
# encoded here so the resulting digests match the Rust crate.
DOMAIN_TAG_ATTEST = b"SUWAPPU-LTP-ATTEST-V1"
DOMAIN_TAG_CID = b"SUWAPPU-LTP-CID-V1"
DOMAIN_TAG_DID_STARK = b"SUWAPPU-DID-STARK-V1"

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
# Matches `suwappu-dag/crates/suwappu-crypto/src/bls.rs::BLS_DST`. LTP's default BLS
# helper signs under py_ecc's `G2ProofOfPossession` DST instead, so the
# corridor surface uses this constant explicitly when calling into blst.
BLS_CORRIDOR_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

# Canonical corridor roster digest — see `membership.py`. Unlike the tags
# above this one has NO counterpart in `suwappu-dag/crates/suwappu-ltp` yet:
# roster assembly is currently a Python-side concern, and the digest is used
# for operators to confirm agreement out-of-band rather than on the wire. It
# lives here so `domain_tags.py` keeps its single-source-of-truth claim
# (LTP-A-021). If roster assembly ever moves onto the wire, this tag is the
# one the Rust side must adopt verbatim.
DOMAIN_TAG_CORRIDOR_ROSTER = b"LTP-CORRIDOR-ROSTER-V1"

# Corridor enrollment binding. The Proof-of-Possession above signs the
# public key ALONE, so it proves key ownership but says nothing about
# which corridor, which seat, or which roster epoch the holder intends to
# join — a PoP observed on the wire can be rebroadcast under any
# (authority, corridor) pair. The enrollment binding closes that by
# signing (corridor || epoch || authority || pk). Python-side only, on
# the same terms as DOMAIN_TAG_CORRIDOR_ROSTER above: no Rust counterpart
# yet, and this is the tag the Rust side must adopt verbatim if enrollment
# ever moves onto the cross-repo wire.
DOMAIN_TAG_CORRIDOR_ENROLL = b"LTP-CORRIDOR-ENROLL-V1"

# Seat-allowlist digest — see `policy.py`. Lets nine operators confirm they
# were configured with the same permitted seat set *before* enrollment
# starts, so a misconfiguration surfaces as one mismatched digest rather
# than as an unexplained storm of rejected announcements. Python-side only,
# on the same terms as the two tags above.
DOMAIN_TAG_CORRIDOR_ALLOWLIST = b"LTP-CORRIDOR-ALLOWLIST-V1"
