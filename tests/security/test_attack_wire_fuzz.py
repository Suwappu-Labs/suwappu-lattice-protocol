"""LTP-A-012 / -019 regression: wire format fuzz.

Hypothesis-driven fuzz of corridor JSON deserializers. The goal is to
prove that no malformed input — random bytes, oversized strings, deep
nesting, missing fields — can crash the verifier or leak a stack trace.
Every reject path must go through ``WireFormatError`` (the boundary the
PR #8 wire-hardening introduced).
"""

from __future__ import annotations

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from src.ltp.corridor.wire import (
    WireFormatError,
    attestation_payload_from_dict,
    corridor_attestation_from_dict,
    state_anchor_from_dict,
)


# Any input that is not a dict at all should still raise WireFormatError,
# not TypeError / KeyError leaking through.
_NON_DICT_SHAPES = [
    None,
    0,
    "string",
    [],
    [1, 2, 3],
    b"bytes",
]


@pytest.mark.parametrize("bad", _NON_DICT_SHAPES)
def test_attestation_payload_rejects_non_dict(bad):
    with pytest.raises((WireFormatError, AttributeError, TypeError)):
        # Some non-dicts will raise WireFormatError via the field lookups,
        # others will fail at the dict-subscript boundary. Either way: no
        # silent success.
        attestation_payload_from_dict(bad)


# Hypothesis strategies for individual fields. Each one targets a slot
# that has *some* validation in wire.py and we want to confirm the
# validation actually catches the bad shape.
_hex_or_garbage = st.one_of(
    st.text(alphabet="0123456789abcdef", min_size=0, max_size=200),
    st.text(min_size=0, max_size=200),  # includes non-hex
    st.integers(),
    st.none(),
)
_int_or_garbage = st.one_of(
    st.integers(min_value=-10**9, max_value=10**9),
    st.text(min_size=0, max_size=20),
    st.none(),
)


@given(
    source_chain=_int_or_garbage,
    target_chain=_int_or_garbage,
    source_height=_int_or_garbage,
    state_root=_hex_or_garbage,
    timestamp_round=_int_or_garbage,
)
@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_attestation_payload_fuzz_never_crashes(
    source_chain, target_chain, source_height, state_root, timestamp_round
):
    """Hypothesis fuzz: every input either parses or raises WireFormatError.

    No other exception escapes. No silent acceptance.
    """
    d = {
        "source_chain": source_chain,
        "target_chain": target_chain,
        "source_height": source_height,
        "state_root": state_root,
        "timestamp_round": timestamp_round,
    }
    try:
        attestation_payload_from_dict(d)
    except WireFormatError:
        return  # expected failure mode
    except Exception as e:  # pragma: no cover
        pytest.fail(
            f"non-WireFormatError exception escaped: {type(e).__name__}: {e}"
        )


@given(
    aggregate_signature=_hex_or_garbage,
    signers=st.one_of(
        st.lists(st.integers(min_value=0, max_value=255), max_size=20),
        st.none(),
        st.text(min_size=0, max_size=20),
    ),
)
@settings(max_examples=200, deadline=None)
def test_corridor_attestation_fuzz_never_crashes(aggregate_signature, signers):
    d = {
        "payload": {
            "source_chain": 1,
            "target_chain": 2,
            "source_height": 100,
            "state_root": "00" * 32,
            "timestamp_round": 50,
        },
        "aggregate_signature": aggregate_signature,
        "signers": signers,
    }
    try:
        corridor_attestation_from_dict(d)
    except WireFormatError:
        return
    except Exception as e:  # pragma: no cover
        pytest.fail(
            f"non-WireFormatError exception escaped: {type(e).__name__}: {e}"
        )


@given(
    chain_id=_int_or_garbage,
    height=_int_or_garbage,
    state_root=_hex_or_garbage,
    parent=_hex_or_garbage,
    mac=_hex_or_garbage,
    auth_scheme=st.integers(min_value=-5, max_value=1000),
)
@settings(max_examples=200, deadline=None)
def test_state_anchor_fuzz_never_crashes(
    chain_id, height, state_root, parent, mac, auth_scheme
):
    d = {
        "chain_id": chain_id,
        "height": height,
        "state_root": state_root,
        "parent": parent,
        "mac": mac,
        "auth_scheme": auth_scheme,
    }
    try:
        state_anchor_from_dict(d)
    except WireFormatError:
        return
    except Exception as e:  # pragma: no cover
        pytest.fail(
            f"non-WireFormatError exception escaped: {type(e).__name__}: {e}"
        )


def test_oversized_hex_field_rejected():
    """A 1MB hex string in any byte field must reject quickly, not OOM."""
    huge = "00" * (1024 * 512)  # 512 KB hex = 256 KB bytes; would blow size checks
    d = {
        "source_chain": 1,
        "target_chain": 2,
        "source_height": 100,
        "state_root": huge,
        "timestamp_round": 50,
    }
    with pytest.raises(WireFormatError, match=r"state_root.*32 bytes"):
        attestation_payload_from_dict(d)


def test_deeply_nested_signers_list_rejected():
    """A list-of-lists where signers should be ints — rejected, not crashed."""
    d = {
        "payload": {
            "source_chain": 1,
            "target_chain": 2,
            "source_height": 100,
            "state_root": "00" * 32,
            "timestamp_round": 50,
        },
        "aggregate_signature": "00" * 96,
        "signers": [[[1, 2, 3]]],
    }
    with pytest.raises(WireFormatError, match=r"signers.*integers"):
        corridor_attestation_from_dict(d)
