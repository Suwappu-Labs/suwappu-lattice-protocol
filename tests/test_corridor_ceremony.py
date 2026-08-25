"""The corridor ceremony CLI — `scripts/corridor_ceremony.py`.

Drives `main()` with argv rather than shelling out, so failures surface as
readable assertions. The nine-keypair setup is module-scoped because keygen
dominates the runtime of this file by an order of magnitude.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.corridor_ceremony import main

try:
    from src.ltp.corridor.bls import _blst_available, _py_ecc_available

    _HAS_BLS_BACKEND = _blst_available or _py_ecc_available
except (ImportError, AttributeError):  # pragma: no cover — backend detection
    _HAS_BLS_BACKEND = False

pytestmark = pytest.mark.skipif(
    not _HAS_BLS_BACKEND, reason="no BLS backend (blst or py_ecc) installed"
)

CORRIDOR = 7
STATE_ROOT = "ab" * 32


def _pubkey(path: Path) -> str:
    return json.loads(path.read_text())["bls_public_key"]


@pytest.fixture(scope="module")
def ceremony(tmp_path_factory):
    """Nine keys, an allowlist, nine announcements, a finalized corridor."""
    root = tmp_path_factory.mktemp("ceremony")
    (root / "anns").mkdir()
    (root / "partials").mkdir()

    keys = [root / f"op-{i}.key.json" for i in range(9)]
    for key in keys:
        assert main(["keygen", "--out", str(key)]) == 0

    seat_args = []
    for i, key in enumerate(keys):
        seat_args += ["--seat", f"{i}={_pubkey(key)}"]
    allowlist = root / "allowlist.json"
    assert (
        main(["allowlist", "--corridor", str(CORRIDOR), *seat_args, "--out", str(allowlist)]) == 0
    )

    for i, key in enumerate(keys):
        assert (
            main(
                [
                    "announce",
                    "--key",
                    str(key),
                    "--allowlist",
                    str(allowlist),
                    "--authority",
                    str(i),
                    "--out",
                    str(root / "anns" / f"ann-{i}.json"),
                ]
            )
            == 0
        )

    corridor = root / "corridor.json"
    assert (
        main(
            [
                "roster",
                "--allowlist",
                str(allowlist),
                "--announcements",
                str(root / "anns"),
                "--out",
                str(corridor),
            ]
        )
        == 0
    )

    return {"root": root, "keys": keys, "allowlist": allowlist, "corridor": corridor}


def _payload(root: Path, name: str, state_root: str = STATE_ROOT, height: int = 100) -> Path:
    out = root / name
    assert (
        main(
            [
                "payload",
                "--source-chain",
                "1",
                "--target-chain",
                "2",
                "--height",
                str(height),
                "--state-root",
                state_root,
                "--round",
                "42",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    return out


# -- the whole ceremony -----------------------------------------------------


def test_a_full_round_attests_and_verifies(ceremony):
    root, keys = ceremony["root"], ceremony["keys"]
    payload = _payload(root, "payload.json")

    for i in range(7):
        assert (
            main(
                [
                    "sign",
                    "--key",
                    str(keys[i]),
                    "--authority",
                    str(i),
                    "--payload",
                    str(payload),
                    "--history",
                    str(root / f"h-{i}.json"),
                    "--out",
                    str(root / "partials" / f"p-{i}.json"),
                ]
            )
            == 0
        )

    attestation = root / "attestation.json"
    assert (
        main(
            [
                "aggregate",
                "--corridor",
                str(ceremony["corridor"]),
                "--payload",
                str(payload),
                "--partials",
                str(root / "partials"),
                "--out",
                str(attestation),
            ]
        )
        == 0
    )
    assert (
        main(["verify", "--corridor", str(ceremony["corridor"]), "--attestation", str(attestation)])
        == 0
    )

    signers = json.loads(attestation.read_text())["signers"]
    assert signers == sorted(signers) == list(range(7))


def test_the_roster_digest_is_reported(ceremony, capsys):
    assert (
        main(
            [
                "roster",
                "--allowlist",
                str(ceremony["allowlist"]),
                "--announcements",
                str(ceremony["root"] / "anns"),
                "--out",
                str(ceremony["root"] / "corridor-again.json"),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "roster digest:" in out
    assert "9 of 9" in out


# -- key handling -----------------------------------------------------------


def test_keygen_writes_the_secret_key_unreadable_by_others(tmp_path):
    key = tmp_path / "op.key.json"
    assert main(["keygen", "--out", str(key)]) == 0
    assert key.stat().st_mode & 0o777 == 0o600


def test_keygen_refuses_to_clobber_an_existing_key(tmp_path, capsys):
    key = tmp_path / "op.key.json"
    assert main(["keygen", "--out", str(key)]) == 0
    before = key.read_text()

    assert main(["keygen", "--out", str(key)]) == 1
    assert "refusing to overwrite" in capsys.readouterr().err
    assert key.read_text() == before

    assert main(["keygen", "--out", str(key), "--force"]) == 0
    assert key.read_text() != before


# -- the guard that stops a node slashing itself ----------------------------


def test_a_restart_does_not_let_a_node_equivocate(ceremony, tmp_path, capsys):
    """The history file is the whole point: each `sign` is a fresh process, so
    without it a node that restarts has forgotten what it signed."""
    root, keys = ceremony["root"], ceremony["keys"]
    history = tmp_path / "history.json"
    first = _payload(tmp_path, "first.json", state_root="11" * 32, height=500)
    conflicting = _payload(tmp_path, "conflicting.json", state_root="22" * 32, height=500)

    assert (
        main(
            [
                "sign",
                "--key",
                str(keys[0]),
                "--authority",
                "0",
                "--payload",
                str(first),
                "--history",
                str(history),
                "--out",
                str(tmp_path / "p.json"),
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert (
        main(
            [
                "sign",
                "--key",
                str(keys[0]),
                "--authority",
                "0",
                "--payload",
                str(conflicting),
                "--history",
                str(history),
                "--out",
                str(tmp_path / "p2.json"),
            ]
        )
        == 1
    )
    assert "refusing to sign" in capsys.readouterr().err
    assert not (tmp_path / "p2.json").exists()
    assert root  # fixture ordering guard


def test_re_signing_the_same_payload_is_a_retry(ceremony, tmp_path):
    keys = ceremony["keys"]
    history = tmp_path / "history.json"
    payload = _payload(tmp_path, "same.json", state_root="33" * 32, height=600)

    for name in ("p1.json", "p2.json"):
        assert (
            main(
                [
                    "sign",
                    "--key",
                    str(keys[1]),
                    "--authority",
                    "1",
                    "--payload",
                    str(payload),
                    "--history",
                    str(history),
                    "--out",
                    str(tmp_path / name),
                ]
            )
            == 0
        )
    assert (tmp_path / "p1.json").read_text() == (tmp_path / "p2.json").read_text()


def test_the_history_file_is_not_world_readable(ceremony, tmp_path):
    keys = ceremony["keys"]
    history = tmp_path / "history.json"
    payload = _payload(tmp_path, "hist.json", state_root="44" * 32, height=700)
    assert (
        main(
            [
                "sign",
                "--key",
                str(keys[2]),
                "--authority",
                "2",
                "--payload",
                str(payload),
                "--history",
                str(history),
                "--out",
                str(tmp_path / "p.json"),
            ]
        )
        == 0
    )
    assert history.stat().st_mode & 0o777 == 0o600


# -- the mistakes an operator actually makes --------------------------------


def test_claiming_a_seat_your_key_was_not_published_for(ceremony, capsys):
    assert (
        main(
            [
                "announce",
                "--key",
                str(ceremony["keys"][0]),
                "--allowlist",
                str(ceremony["allowlist"]),
                "--authority",
                "5",
                "--out",
                str(ceremony["root"] / "wrong.json"),
            ]
        )
        == 1
    )
    assert "different key for seat 5" in capsys.readouterr().err


def test_claiming_a_seat_that_is_not_on_the_allowlist(ceremony, capsys):
    assert (
        main(
            [
                "announce",
                "--key",
                str(ceremony["keys"][0]),
                "--allowlist",
                str(ceremony["allowlist"]),
                "--authority",
                "99",
                "--out",
                str(ceremony["root"] / "wrong.json"),
            ]
        )
        == 1
    )
    assert "not on this allowlist" in capsys.readouterr().err


def test_a_short_roster_names_the_missing_seats(ceremony, tmp_path, capsys):
    partial = tmp_path / "anns"
    partial.mkdir()
    for i in (0, 1, 2):
        src = ceremony["root"] / "anns" / f"ann-{i}.json"
        (partial / src.name).write_text(src.read_text())

    assert (
        main(
            [
                "roster",
                "--allowlist",
                str(ceremony["allowlist"]),
                "--announcements",
                str(partial),
                "--out",
                str(tmp_path / "c.json"),
            ]
        )
        == 1
    )
    err = capsys.readouterr().err
    assert "short by 6" in err
    assert "3, 4, 5" in err  # names who is still missing
    assert not (tmp_path / "c.json").exists()


def test_below_quorum_names_the_outstanding_seats(ceremony, tmp_path, capsys):
    root, keys = ceremony["root"], ceremony["keys"]
    payload = _payload(tmp_path, "short.json", state_root="55" * 32, height=800)
    partials = tmp_path / "partials"
    partials.mkdir()
    for i in range(3):
        assert (
            main(
                [
                    "sign",
                    "--key",
                    str(keys[i]),
                    "--authority",
                    str(i),
                    "--payload",
                    str(payload),
                    "--history",
                    str(tmp_path / f"h{i}.json"),
                    "--out",
                    str(partials / f"p{i}.json"),
                ]
            )
            == 0
        )
    capsys.readouterr()

    assert (
        main(
            [
                "aggregate",
                "--corridor",
                str(ceremony["corridor"]),
                "--payload",
                str(payload),
                "--partials",
                str(partials),
                "--out",
                str(tmp_path / "a.json"),
            ]
        )
        == 1
    )
    err = capsys.readouterr().err
    assert "below quorum by 4" in err
    assert "outstanding" in err or "waiting on seats" in err
    assert root


def test_a_partial_for_a_different_round_is_rejected(ceremony, tmp_path, capsys):
    """The commonest real failure: a signer a round behind."""
    keys = ceremony["keys"]
    signed = _payload(tmp_path, "round-a.json", state_root="66" * 32, height=900)
    aggregated = _payload(tmp_path, "round-b.json", state_root="77" * 32, height=901)
    partials = tmp_path / "partials"
    partials.mkdir()
    for i in range(7):
        assert (
            main(
                [
                    "sign",
                    "--key",
                    str(keys[i]),
                    "--authority",
                    str(i),
                    "--payload",
                    str(signed),
                    "--history",
                    str(tmp_path / f"h{i}.json"),
                    "--out",
                    str(partials / f"p{i}.json"),
                ]
            )
            == 0
        )
    capsys.readouterr()

    assert (
        main(
            [
                "aggregate",
                "--corridor",
                str(ceremony["corridor"]),
                "--payload",
                str(aggregated),
                "--partials",
                str(partials),
                "--out",
                str(tmp_path / "a.json"),
            ]
        )
        == 1
    )
    assert "rejected" in capsys.readouterr().err


# -- malformed input --------------------------------------------------------


@pytest.mark.parametrize("blob", ["not json", "[]", '{"seats": "nope"}'])
def test_a_malformed_allowlist_is_a_clean_error(tmp_path, capsys, blob):
    bad = tmp_path / "allowlist.json"
    bad.write_text(blob)
    key = tmp_path / "op.key.json"
    assert main(["keygen", "--out", str(key)]) == 0

    assert (
        main(
            [
                "announce",
                "--key",
                str(key),
                "--allowlist",
                str(bad),
                "--authority",
                "0",
                "--out",
                str(tmp_path / "a.json"),
            ]
        )
        == 1
    )
    assert "error:" in capsys.readouterr().err


def test_a_missing_file_is_a_clean_error(tmp_path, capsys):
    assert (
        main(
            [
                "verify",
                "--corridor",
                str(tmp_path / "nope.json"),
                "--attestation",
                str(tmp_path / "also-nope.json"),
            ]
        )
        == 1
    )
    assert "cannot read" in capsys.readouterr().err


def test_a_bad_state_root_is_rejected(tmp_path, capsys):
    assert (
        main(
            [
                "payload",
                "--source-chain",
                "1",
                "--target-chain",
                "2",
                "--height",
                "1",
                "--state-root",
                "abcd",
                "--round",
                "1",
                "--out",
                str(tmp_path / "p.json"),
            ]
        )
        == 1
    )
    assert "32 bytes" in capsys.readouterr().err
