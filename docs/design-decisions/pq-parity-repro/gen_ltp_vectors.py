"""Generate ML-DSA-65 test vectors with LTP's own signing path.

Writes nine keypairs, each signing a 32-byte SHA3-256 state root and a
225-byte message, using ``ltp.primitives.MLDSA`` (empty FIPS 204 context).
The output feeds ``ltp_expand.mjs``. See README.md in this directory.

Usage: python gen_ltp_vectors.py <out.json>
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from pathlib import Path

from ltp.primitives import MLDSA

logger = logging.getLogger(__name__)

SIGNERS = 9


def main(out_path: str) -> None:
    root = hashlib.sha3_256(b"LTP parity test state root").digest()
    long_msg = b"LTP structured statement " + os.urandom(200)
    signers = []
    for _ in range(SIGNERS):
        vk, sk = MLDSA.keygen()
        sig_root = MLDSA.sign(sk, root)
        sig_long = MLDSA.sign(sk, long_msg)
        if not (MLDSA.verify(vk, root, sig_root) and MLDSA.verify(vk, long_msg, sig_long)):
            raise RuntimeError("self-verification failed")
        signers.append({"pk": vk.hex(), "sigRoot": sig_root.hex(), "sigLong": sig_long.hex()})
    doc = {"root": "0x" + root.hex(), "long": "0x" + long_msg.hex(), "signers": signers}
    Path(out_path).write_text(json.dumps(doc))
    logger.info("wrote %d signers to %s", SIGNERS, out_path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
