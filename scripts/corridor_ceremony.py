#!/usr/bin/env python3
"""Run a corridor ceremony from the command line, one file at a time.

`src/ltp/corridor/` has everything a nine-operator corridor needs and nothing
an operator can actually *run*. This script is that missing part: the whole
ceremony — generate a key, claim a seat, agree on who is in, sign a round,
aggregate to 7-of-9 — as commands that read and write plain JSON.

Files rather than sockets, deliberately. Every corridor step is asynchronous
and human-paced (nine operators, different timezones, out-of-band digest
comparison), and a file is a transport every operator already has: email it,
commit it, paste it in a channel. It also means this whole thing is testable
with no network and no new dependencies, and that a real daemon can be built
later without any of the protocol below changing.

The ceremony, in order:

    # Each operator, once, on their own machine:
    corridor_ceremony.py keygen --out operator-3.key.json
    # ... then publishes the bls_public_key line from that file.

    # Whoever coordinates, from the nine published keys:
    corridor_ceremony.py allowlist --corridor 7 \\
        --seat 0=<pubkey-hex> ... --seat 8=<pubkey-hex> --out allowlist.json
    # ... then publishes allowlist.json AND its digest. Every operator
    # checks the digest matches before going further.

    # Each operator, claiming their seat:
    corridor_ceremony.py announce --key operator-3.key.json \\
        --allowlist allowlist.json --authority 3 --out ann-3.json

    # Anyone, from the nine announcements:
    corridor_ceremony.py roster --allowlist allowlist.json \\
        --announcements ./anns --out corridor.json

    # A round:
    corridor_ceremony.py payload --source-chain 1 --target-chain 2 \\
        --height 100 --state-root <32-byte-hex> --round 42 --out payload.json
    corridor_ceremony.py sign --key operator-3.key.json --authority 3 \\
        --payload payload.json --history operator-3.history.json --out partial-3.json
    corridor_ceremony.py aggregate --corridor corridor.json \\
        --payload payload.json --partials ./partials --out attestation.json
    corridor_ceremony.py verify --corridor corridor.json --attestation attestation.json

Every command exits non-zero and prints one line to stderr on failure, so the
whole thing composes in a shell script.

TESTNET TOOLING. `keygen` writes a BLS secret key to disk in plaintext,
mode 0600. That is appropriate for a testnet corridor and is not a key
custody solution: a corridor holding value wants the secret in an HSM or in
Turnkey, with this script reading a handle rather than the bytes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ltp.corridor.attestation import (  # noqa: E402
    AttestationPayload,
    LtpError,
    verify_attestation,
)
from src.ltp.corridor.bls import keygen  # noqa: E402
from src.ltp.corridor.enrollment import announce  # noqa: E402
from src.ltp.corridor.membership import CorridorRegistry  # noqa: E402
from src.ltp.corridor.policy import SeatAllowlist  # noqa: E402
from src.ltp.corridor.session import CorridorSigner, SessionKey, SigningSession  # noqa: E402
from src.ltp.corridor.wire import (  # noqa: E402
    WireFormatError,
    attestation_payload_from_dict,
    attestation_payload_to_dict,
    corridor_attestation_from_dict,
    corridor_attestation_to_dict,
    corridor_from_dict,
    corridor_to_dict,
    enrollment_announcement_from_dict,
    enrollment_announcement_to_dict,
    seat_allowlist_from_dict,
    seat_allowlist_to_dict,
    witness_signature_from_dict,
    witness_signature_to_dict,
)

KEY_FILE_MODE = 0o600


class CeremonyError(Exception):
    """Anything the operator can fix by changing an argument or a file."""


# -- file helpers -----------------------------------------------------------


def _read_json(path: Path, what: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise CeremonyError(f"cannot read {what} at {path}: {e}") from e
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CeremonyError(f"{what} at {path} is not valid JSON: {e}") from e
    if not isinstance(parsed, dict):
        raise CeremonyError(f"{what} at {path} must be a JSON object")
    return parsed


def _write_json(path: Path, payload: dict[str, Any], *, secret: bool = False) -> None:
    blob = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if secret:
        # Create with the restrictive mode rather than chmod-ing after: a
        # world-readable window, however brief, is a window.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, KEY_FILE_MODE)
        with os.fdopen(fd, "w") as fh:
            fh.write(blob)
    else:
        path.write_text(blob)


def _read_dir(path: Path, what: str) -> list[tuple[Path, dict[str, Any]]]:
    if not path.is_dir():
        raise CeremonyError(f"{what} directory {path} does not exist")
    # Sorted so a run is reproducible and any error names a predictable file.
    files = sorted(p for p in path.iterdir() if p.suffix == ".json")
    if not files:
        raise CeremonyError(f"no .json files in {what} directory {path}")
    return [(p, _read_json(p, what)) for p in files]


def _hex32(value: str, what: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as e:
        raise CeremonyError(f"{what} is not valid hex: {e}") from e
    if len(raw) != 32:
        raise CeremonyError(f"{what} must be 32 bytes, got {len(raw)}")
    return raw


def _load_key(path: Path) -> tuple[bytes, bytes]:
    d = _read_json(path, "key file")
    for field in ("bls_public_key", "bls_secret_key"):
        if field not in d or not isinstance(d[field], str):
            raise CeremonyError(f"key file {path} is missing a string {field!r}")
    try:
        return bytes.fromhex(d["bls_public_key"]), bytes.fromhex(d["bls_secret_key"])
    except ValueError as e:
        raise CeremonyError(f"key file {path} contains invalid hex: {e}") from e


# -- commands ---------------------------------------------------------------


def cmd_keygen(args) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        raise CeremonyError(
            f"{out} already exists; refusing to overwrite a key file. "
            "Pass --force only if you are certain that key is not in a roster."
        )
    pk, sk = keygen()
    _write_json(
        out,
        {
            "bls_public_key": pk.hex(),
            "bls_secret_key": sk.hex(),
            "_warning": (
                "Plaintext BLS secret key, testnet only. A corridor holding "
                "value wants this in an HSM or Turnkey, not on disk."
            ),
        },
        secret=True,
    )
    print(f"wrote {out} (mode {KEY_FILE_MODE:o})")
    print(f"bls_public_key: {pk.hex()}")
    print("Publish the public key only. The secret key never leaves this machine.")
    return 0


def cmd_allowlist(args) -> int:
    seats: dict[int, bytes] = {}
    for spec in args.seat:
        if "=" not in spec:
            raise CeremonyError(f"--seat expects AUTHORITY=PUBKEYHEX, got {spec!r}")
        left, _, right = spec.partition("=")
        try:
            authority = int(left)
        except ValueError as e:
            raise CeremonyError(f"seat id {left!r} is not an integer") from e
        if authority in seats:
            raise CeremonyError(f"seat {authority} given twice")
        try:
            seats[authority] = bytes.fromhex(right)
        except ValueError as e:
            raise CeremonyError(f"public key for seat {authority} is not valid hex: {e}") from e

    try:
        allowlist = SeatAllowlist(corridor_id=args.corridor, seats=seats)
    except ValueError as e:
        raise CeremonyError(str(e)) from e

    _write_json(Path(args.out), seat_allowlist_to_dict(allowlist))
    print(f"wrote {args.out} — {len(seats)} seat(s) on corridor {args.corridor}")
    print(f"allowlist digest: {allowlist.digest().hex()}")
    print("Every operator must see this same digest before enrolling.")
    return 0


def _load_allowlist(path: Path) -> SeatAllowlist:
    try:
        return seat_allowlist_from_dict(_read_json(path, "allowlist"))
    except WireFormatError as e:
        raise CeremonyError(f"allowlist at {path} is invalid: {e}") from e


def cmd_announce(args) -> int:
    allowlist = _load_allowlist(Path(args.allowlist))
    pk, sk = _load_key(Path(args.key))

    expected = allowlist.seats.get(args.authority)
    if expected is None:
        raise CeremonyError(
            f"seat {args.authority} is not on this allowlist (seats: {sorted(allowlist.seats)})"
        )
    if bytes(expected) != pk:
        raise CeremonyError(
            f"the allowlist publishes a different key for seat {args.authority} than "
            f"the one in {args.key}. Either you are claiming the wrong seat or the "
            "allowlist is not the one your key was published for."
        )

    ann = announce(sk, pk, allowlist.corridor_id, args.authority, epoch=args.epoch)
    _write_json(Path(args.out), enrollment_announcement_to_dict(ann))
    print(
        f"wrote {args.out} — seat {args.authority}, corridor "
        f"{allowlist.corridor_id}, epoch {args.epoch}"
    )
    print(f"allowlist digest: {allowlist.digest().hex()}")
    return 0


def cmd_roster(args) -> int:
    allowlist = _load_allowlist(Path(args.allowlist))
    registry = CorridorRegistry(
        corridor_id=allowlist.corridor_id, epoch=args.epoch, policy=allowlist
    )

    for path, raw in _read_dir(Path(args.announcements), "announcements"):
        try:
            ann = enrollment_announcement_from_dict(raw)
        except WireFormatError as e:
            raise CeremonyError(f"{path}: malformed announcement: {e}") from e
        try:
            registry.enroll_announcement(ann)
        except LtpError as e:
            raise CeremonyError(f"{path}: rejected — {e}") from e
        print(f"  admitted seat {ann.super_node.authority} from {path.name}")

    print(f"roster: {registry.size} of {registry.quorum_size}")
    print(f"roster digest: {registry.roster_digest().hex()}")

    if not registry.is_ready:
        raise CeremonyError(
            f"roster is short by {registry.missing()}; missing seats "
            f"{sorted(set(allowlist.seats) - {m.authority for m in registry.ordered_members()})}"
        )

    corridor = registry.finalize()
    _write_json(Path(args.out), corridor_to_dict(corridor))
    print(f"wrote {args.out}")
    print("Compare the roster digest with every peer before signing anything.")
    return 0


def cmd_payload(args) -> int:
    try:
        payload = AttestationPayload(
            source_chain=args.source_chain,
            target_chain=args.target_chain,
            source_height=args.height,
            state_root=_hex32(args.state_root, "--state-root"),
            timestamp_round=args.round,
        )
    except ValueError as e:
        raise CeremonyError(str(e)) from e

    _write_json(Path(args.out), attestation_payload_to_dict(payload))
    print(f"wrote {args.out}")
    print(f"canonical digest: {payload.canonical_digest().hex()}")
    print("Every signer must produce this same digest, or they are not signing this round.")
    return 0


def _load_payload(path: Path) -> AttestationPayload:
    try:
        return attestation_payload_from_dict(_read_json(path, "payload"))
    except (WireFormatError, ValueError) as e:
        raise CeremonyError(f"payload at {path} is invalid: {e}") from e


def cmd_sign(args) -> int:
    payload = _load_payload(Path(args.payload))
    pk, sk = _load_key(Path(args.key))
    del pk

    signer = CorridorSigner(args.authority, sk)

    # The double-sign guard is only as durable as the file behind it. Paper
    # §6.4 makes equivocation a 100%-slashing offence, and the usual way to
    # commit one is a restart that forgot what was already signed.
    history_path = Path(args.history)
    if history_path.exists():
        raw = _read_json(history_path, "signing history")
        restored = {}
        for entry in raw.get("rounds", []):
            key = SessionKey(
                source_chain=entry["source_chain"],
                target_chain=entry["target_chain"],
                source_height=entry["source_height"],
            )
            restored[key] = bytes.fromhex(entry["digest"])
        try:
            signer.restore(restored)
        except (ValueError, LtpError) as e:
            raise CeremonyError(f"signing history at {history_path} is unusable: {e}") from e

    try:
        ws = signer.sign(payload)
    except LtpError as e:
        raise CeremonyError(
            f"refusing to sign: {e}. This node already signed a different payload "
            "for this round; signing again is the equivocation that forfeits the bond."
        ) from e

    _write_json(
        history_path,
        {
            "rounds": [
                {
                    "source_chain": k.source_chain,
                    "target_chain": k.target_chain,
                    "source_height": k.source_height,
                    "digest": v.hex(),
                }
                for k, v in sorted(signer.signed_rounds().items())
            ]
        },
        secret=True,
    )
    _write_json(Path(args.out), witness_signature_to_dict(ws))
    print(f"wrote {args.out} — seat {args.authority}, round {SessionKey.of(payload)}")
    print(f"history: {history_path} (keep this; losing it is how nodes equivocate)")
    return 0


def _load_corridor(path: Path):
    try:
        return corridor_from_dict(_read_json(path, "corridor"))
    except WireFormatError as e:
        raise CeremonyError(f"corridor at {path} is invalid: {e}") from e


def cmd_aggregate(args) -> int:
    corridor = _load_corridor(Path(args.corridor))
    payload = _load_payload(Path(args.payload))

    try:
        session = SigningSession(corridor, payload)
    except LtpError as e:
        raise CeremonyError(str(e)) from e

    for path, raw in _read_dir(Path(args.partials), "partials"):
        try:
            ws = witness_signature_from_dict(raw)
        except WireFormatError as e:
            raise CeremonyError(f"{path}: malformed partial: {e}") from e
        try:
            fresh = session.submit(ws)
        except LtpError as e:
            raise CeremonyError(f"{path}: rejected — {e}") from e
        print(f"  {'accepted' if fresh else 'duplicate'} seat {ws.witness} from {path.name}")

    print(f"quorum: {session.have} of {session.threshold} required")
    if not session.has_quorum:
        raise CeremonyError(
            f"below quorum by {session.missing()}; still waiting on seats "
            f"{list(session.outstanding())}"
        )

    try:
        attestation = session.finalize()
    except LtpError as e:
        raise CeremonyError(str(e)) from e

    _write_json(Path(args.out), corridor_attestation_to_dict(attestation))
    print(f"wrote {args.out} — signers {sorted(attestation.signers)}")
    return 0


def cmd_verify(args) -> int:
    corridor = _load_corridor(Path(args.corridor))
    try:
        attestation = corridor_attestation_from_dict(
            _read_json(Path(args.attestation), "attestation")
        )
    except WireFormatError as e:
        raise CeremonyError(f"attestation is invalid: {e}") from e

    try:
        verify_attestation(corridor, attestation)
    except LtpError as e:
        raise CeremonyError(f"attestation does NOT verify: {e}") from e

    print("attestation verifies")
    print(f"  corridor:  {corridor.id}")
    print(f"  signers:   {sorted(attestation.signers)}")
    print(f"  round:     {SessionKey.of(attestation.payload)}")
    print(f"  digest:    {attestation.payload.canonical_digest().hex()}")
    return 0


# -- wiring -----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corridor_ceremony.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate this operator's BLS keypair")
    p.add_argument("--out", required=True)
    p.add_argument("--force", action="store_true", help="overwrite an existing key file")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("allowlist", help="build the published seat allowlist")
    p.add_argument("--corridor", type=int, required=True)
    p.add_argument("--seat", action="append", required=True, metavar="AUTHORITY=PUBKEYHEX")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_allowlist)

    p = sub.add_parser("announce", help="claim your seat")
    p.add_argument("--key", required=True)
    p.add_argument("--allowlist", required=True)
    p.add_argument("--authority", type=int, required=True)
    p.add_argument("--epoch", type=int, default=0)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_announce)

    p = sub.add_parser("roster", help="assemble announcements into a corridor")
    p.add_argument("--allowlist", required=True)
    p.add_argument("--announcements", required=True, metavar="DIR")
    p.add_argument("--epoch", type=int, default=0)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_roster)

    p = sub.add_parser("payload", help="describe the round to be attested")
    p.add_argument("--source-chain", type=int, required=True)
    p.add_argument("--target-chain", type=int, required=True)
    p.add_argument("--height", type=int, required=True)
    p.add_argument("--state-root", required=True, metavar="HEX32")
    p.add_argument("--round", type=int, required=True, dest="round")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_payload)

    p = sub.add_parser("sign", help="produce this seat's partial signature")
    p.add_argument("--key", required=True)
    p.add_argument("--authority", type=int, required=True)
    p.add_argument("--payload", required=True)
    p.add_argument("--history", required=True, help="durable double-sign guard state")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("aggregate", help="collect partials into a 7-of-9 attestation")
    p.add_argument("--corridor", required=True)
    p.add_argument("--payload", required=True)
    p.add_argument("--partials", required=True, metavar="DIR")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_aggregate)

    p = sub.add_parser("verify", help="check an attestation against the roster")
    p.add_argument("--corridor", required=True)
    p.add_argument("--attestation", required=True)
    p.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CeremonyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
