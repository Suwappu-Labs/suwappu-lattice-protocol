# Reproducing the ML-DSA-65 On-Chain Verification Measurements

These files reproduce the measurements in
[`PQ_ZK_PARITY_LANDSCAPE.md`](../PQ_ZK_PARITY_LANDSCAPE.md) section 5.6:
signatures produced by LTP's own `ltp.primitives.MLDSA` verified by an
open-source Solidity ML-DSA-65 verifier, and a 7-of-9 quorum prototype.

They are a measurement harness, not protocol code. Nothing here is
imported by `src/ltp/` or `contracts/`, and `QuorumProto` is a prototype
that has had no review.

## What is here

| File | Purpose |
|---|---|
| `gen_ltp_vectors.py` | Nine ML-DSA-65 keypairs and signatures from `ltp.primitives.MLDSA` |
| `ltp_expand.mjs` | Converts each 1,952-byte public key to the verifier's 38,112-byte expanded form, using the verifier repository's own helper |
| `LTPCompat.t.sol` | Verifies LTP signatures; checks four rejection cases |
| `LTPQuorum.t.sol` | `QuorumProto`: 7-of-9 with keys stored as contract code |

## Steps

Pinned to [ZKNoxHQ/ETHDILITHIUM](https://github.com/ZKNoxHQ/ETHDILITHIUM)
branch `mldsa87` at commit `d46aa70004de4ef9cd39c37a14154189d258495a`.
That code is unaudited by its authors' own statement.

```bash
git clone https://github.com/ZKNoxHQ/ETHDILITHIUM
```

```bash
cd ETHDILITHIUM && git checkout d46aa70004de4ef9cd39c37a14154189d258495a && git submodule update --init
```

From an environment where `import ltp` works (see the root `AGENTS.md`),
with `$REPRO` pointing at this directory:

```bash
python $REPRO/gen_ltp_vectors.py /tmp/ltp65_raw.json
```

```bash
cp $REPRO/ltp_expand.mjs js/ && (cd js && npm ci --ignore-scripts && node ltp_expand.mjs /tmp/ltp65_raw.json ../test/KAT/ltp65.json)
```

```bash
cp $REPRO/LTPCompat.t.sol $REPRO/LTPQuorum.t.sol test/
```

```bash
forge test --match-path "test/LTP*.t.sol" -vv
```

The verifier repository enables FFI in its `foundry.toml`, and its test
helper uses it to `cat` the Keccak helper bytecode (`test/f1600_170.hex`).
These tests therefore run with FFI on. That one `cat` is the only FFI
call they reach.

## Environment of the recorded run

| Item | Value |
|---|---|
| Date | 2026-11-20 |
| forge | 1.7.1 |
| solc | 0.8.30, IR pipeline, 1,000,000 optimizer runs, EVM version `osaka` (the verifier repository's default profile) |
| Signer | `pqcrypto` 0.4.0 through `ltp.primitives.MLDSA`, Python 3.13 |

Keys and the long message are random per run, so gas varies by a few
thousand between runs.
