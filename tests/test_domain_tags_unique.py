"""LTP-A-021: every domain tag in the corridor flow must be pairwise distinct.

``sha3_256_domain(tag, payload)`` is collision-resistant across distinct
tags only if the tag set itself is distinct. This test pins that invariant
so a future contributor adding a domain tag is forced to register it in
``src/ltp/corridor/domain_tags.py``.
"""

from __future__ import annotations

from src.ltp.corridor.domain_tags import ALL_DOMAIN_TAGS


def test_every_domain_tag_is_unique():
    """No two domain tags share a byte string."""
    seen: set[bytes] = set()
    for tag in ALL_DOMAIN_TAGS:
        assert isinstance(tag, bytes), f"tag {tag!r} is not bytes"
        assert tag not in seen, (
            f"domain tag {tag!r} is duplicated in ALL_DOMAIN_TAGS — "
            "every protocol surface that uses sha3_256_domain MUST use a "
            "distinct tag"
        )
        seen.add(tag)


def test_no_domain_tag_is_prefix_of_another():
    """Length-prefixing makes prefix-collisions impossible *inside the hash*,
    but a tag-prefix collision is still a code smell: two different
    subsystems would format very similarly in logs and audit trails.
    """
    for i, a in enumerate(ALL_DOMAIN_TAGS):
        for j, b in enumerate(ALL_DOMAIN_TAGS):
            if i == j:
                continue
            assert not a.startswith(b), f"domain tag {a!r} starts with {b!r}; rename for clarity"


def test_every_domain_tag_is_nontrivial():
    """No empty tags, no whitespace-only tags."""
    for tag in ALL_DOMAIN_TAGS:
        assert len(tag) >= 4, f"tag {tag!r} too short to be meaningful"
        assert tag.strip(), f"tag {tag!r} is whitespace-only"
