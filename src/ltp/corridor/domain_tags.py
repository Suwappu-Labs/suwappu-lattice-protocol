"""Single source-of-truth registry of every domain tag in LTP corridor flows.

LTP-A-021 in ``docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md`` flagged the lack of a
global enumeration of domain tags. Tags MUST be pairwise distinct so that
``sha3_256_domain(tag_a, payload)`` and ``sha3_256_domain(tag_b, payload)``
never collide for any payload — the length-prefixed hash guarantees this
*for distinct tags*; this module guarantees the tags themselves are
distinct.

Pairwise distinctness is enforced by ``tests/test_domain_tags_unique.py``.
"""

from __future__ import annotations

from .constants import (
    BLS_CORRIDOR_DST,
    DOMAIN_TAG_ATTEST,
    DOMAIN_TAG_CID,
    DOMAIN_TAG_CORRIDOR_POP,
    DOMAIN_TAG_DID_STARK,
    DOMAIN_TAG_DKG_COMMIT,
)

__all__ = ["ALL_DOMAIN_TAGS"]


# Every byte string in this tuple is passed to a hash-function-as-MAC
# helper somewhere in the codebase. Adding a new domain tag without
# registering it here will not break correctness, but the audit doc
# (LTP-A-021) commits to keeping this list complete; the matching test
# uses it to assert pairwise distinctness.
ALL_DOMAIN_TAGS: tuple[bytes, ...] = (
    DOMAIN_TAG_ATTEST,
    DOMAIN_TAG_CID,
    DOMAIN_TAG_DID_STARK,
    DOMAIN_TAG_CORRIDOR_POP,
    DOMAIN_TAG_DKG_COMMIT,
    # BLS_CORRIDOR_DST is a hash-to-curve DST, not a SHA3 domain tag, so
    # technically a different namespace — but we include it here so the
    # distinctness test catches any accidental collision with a future
    # SHA3 tag.
    BLS_CORRIDOR_DST,
)
