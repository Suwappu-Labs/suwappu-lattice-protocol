# Phase 0 Benchmark Notes
# Run on: 2026-06-09 (macOS 25.5.0, Apple Silicon)
# Forge version: 1.7.1 (commit 4072e48705af9d93e3c0f6e29e93b5e9a40caed8, 2026-05-08)

## Repos cloned to /Users/toma/gsx/pq-research/

  sol-spartan-whir  — https://github.com/privacy-ethereum/sol-spartan-whir (depth=1)
  sol-whir          — https://github.com/privacy-scaling-explorations/sol-whir (depth=1)
  leanMultisig      — https://github.com/leanEthereum/leanMultisig (depth=1)

## sol-spartan-whir: forge test run

### Setup

  forge install foundry-rs/forge-std   (installed v1.16.1)
  forge install Vectorized/solady       (installed v0.1.26)

### Command

  cd /Users/toma/gsx/pq-research/sol-spartan-whir
  forge test --match-test "testGasWhirVerifyBlobNativeFixed"

### Raw output (edited to key lines)

  [PASS] WhirBlobVerifierNative4_lir11_ff5_rsv3 :: testGasWhirVerifyBlobNativeFixed()  gas: 899,906
  [PASS] WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1 :: testGasWhirVerifyBlobNativeFixed()  gas: 6,085,570
  [PASS] WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 :: testGasWhirVerifyBlobNativeFixed()  gas: 5,454,992
  [PASS] WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv4 :: testGasWhirVerifyBlobNativeFixed()  gas: 6,317,780
  [PASS] WhirBlobVerifierNativeLir11Test :: testGasWhirVerifyBlobNativeFixed()  gas: 911,958

  Ran 29 test suites: 303 passed, 0 failed

### What each verifier is

  WhirBlobVerifierNative4 (lir11_ff5_rsv3):
    - Field: KoalaBear + quartic (ext4) — ~80-bit SNARK security
    - num_variables: see schedule lir11 (lower than 22)
    - Foundry gas: 899,906
    - Transaction gas (from README): 975,202  (includes 159,640 calldata gas)
    - Calldata bytes: 10,276
    - EIP-170 status: FITS (21,877 bytes runtime bytecode)

  WhirBlobVerifierNative5 k22_jb100_ext5_lir4_ff4_rsv3_pow28 (CURRENT HIGH-SECURITY TARGET):
    - Field: KoalaBear + quintic (ext5), X^5 + X^2 - 1
    - num_variables: 22, JohnsonBound 100-bit
    - Achieved security: 100.0145 bits SNARK, 160 bits Merkle
    - Foundry gas (MEASURED): 5,454,992
    - Transaction gas (from README Anvil measurement): 5,646,080
    - Execution gas: 4,768,744
    - Calldata bytes: 54,436
    - EIP-170 status: DOES NOT FIT — 31,856 bytes (7,280 over EIP-170 limit)

  WhirBlobVerifierNative8 k22_jb100_lir6_ff4_rsv1 (octic):
    - Field: KoalaBear + octic (ext8)
    - Foundry gas (MEASURED): 6,085,570
    - Transaction gas: 6,367,262

## leanMultisig: EVM verifier status

  No Solidity or Yul EVM verifier found.
  Only verifier in repo: crates/lean_prover/python-verifier/verifier.py (Python)
  Proof sizes (from README, measured on M4 Max):
    - XMSS aggregation: 127–344 KiB depending on rate/regime
    - Recursive (single epoch): 98–285 KiB
  There is NO path from leanMultisig output directly to an EVM call today.

## sol-whir: status

  Runnable via: forge test --via-ir
  Proof fixture at: test/data/whir/
  Transaction gas from broadcast artifact (README): 1,135,052 (BN254, 80-bit, 28,740 calldata bytes)
  Calldata gas: 414,876; execution remainder: 699,176
  Note: uses BN254 field (not KoalaBear) — not post-quantum at the hash level
        and has worse calldata than sol-spartan-whir's KoalaBear quartic path.

## Key discriminator: proof size gap

  leanMultisig outputs proofs of 98–344 KiB.
  sol-spartan-whir's EVM verifier accepts proofs of ~10 KB (quartic) or ~54 KB (quintic).
  To use the EVM verifier for leanMultisig output, a wrapping/recursion step
  is needed that compresses a 100–300 KiB leanMultisig WHIR proof into a
  Spartan-WHIR blob the Solidity verifier can consume.
  This step does NOT exist today (as of 2026-06-09).
