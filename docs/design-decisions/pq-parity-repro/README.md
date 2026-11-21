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
| `LTPQuorumAnchor.sol` | State-changing version: verifies seven signatures, records the signer bitmap for the root, emits an event |
| `DeployLTPQuorum.s.sol` | Deploys the Keccak helper, the verifier and the anchor, registers nine keys, anchors one root |

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

## Deploying to a testnet

Not yet broadcast to any public network. The script below was run on
2026-11-21 against a local fork of Base Sepolia (chain 84532), where all
14 transactions succeeded:

| Transaction | Gas used |
|---|---|
| Deploy Keccak helper | 4,716,322 |
| Deploy ML-DSA-65 verifier | 5,094,537 |
| Deploy `LTPQuorumAnchor` | 852,376 |
| `registerKey`, nine times | about 8,357,000 each |
| `sealKeys` | 43,385 |
| `anchorQuorum`, seven of nine | 9,620,050 |
| Total | 95,537,903 |

From the verifier checkout, after the steps above:

```bash
cp $REPRO/LTPQuorumAnchor.sol src/ && cp $REPRO/DeployLTPQuorum.s.sol script/
```

```bash
python3 -c "d=open('test/f1600_170.hex').read().strip(); open('test/KAT/f1600_170.hex','w').write(d if d.startswith('0x') else '0x'+d)"
```

```bash
FOUNDRY_FFI=false forge script script/DeployLTPQuorum.s.sol:DeployLTPQuorum --rpc-url "$BASE_SEPOLIA_RPC_URL" --private-key "$DEPLOYER_KEY" --broadcast --slow
```

The deploy script reads its inputs with `vm.readFile` and does not use
FFI. The deployer needs about 0.003 testnet ETH. `LTPQuorumAnchor` is
unreviewed test code: do not point anything of value at it.
