// SPDX-License-Identifier: MIT
//
// Verify an LTP anchor from JavaScript using ethers v6.
//
// Usage:
//   node examples/verify_anchor_from_js.mjs <rpcUrl> <registry> <entityIdHash>
//
// Example (Base Sepolia):
//   node examples/verify_anchor_from_js.mjs \
//     https://sepolia.base.org \
//     0x79eF...                 \
//     0xabc1...                  # 32-byte hex
//
// Requires:
//   npm install ethers@6
//
// ABI is checked into contracts/abi/LTPAnchorRegistry.json so this script
// works against the deployed registry without any local Solidity build.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { ethers } from "ethers";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ABI_PATH = resolve(__dirname, "..", "contracts", "abi", "LTPAnchorRegistry.json");

async function main() {
  const [rpcUrl, registryAddress, entityIdHash] = process.argv.slice(2);
  if (!rpcUrl || !registryAddress || !entityIdHash) {
    console.error(
      "usage: node examples/verify_anchor_from_js.mjs <rpcUrl> <registry> <entityIdHash>"
    );
    process.exit(1);
  }
  if (!entityIdHash.startsWith("0x") || entityIdHash.length !== 66) {
    console.error("entityIdHash must be 0x-prefixed 32-byte hex (66 chars total)");
    process.exit(1);
  }

  const abi = JSON.parse(readFileSync(ABI_PATH, "utf8"));
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const registry = new ethers.Contract(registryAddress, abi, provider);

  // The on-chain entity state is one of:
  //   0 = NotIssued, 1 = Committed, 2 = LatticeIssued, 3 = Materialized, 4 = Expired
  const STATE_NAMES = ["NotIssued", "Committed", "LatticeIssued", "Materialized", "Expired"];

  console.log(`Looking up entity ${entityIdHash} on ${rpcUrl} via ${registryAddress}`);

  const state = await registry.getEntityState(entityIdHash);
  console.log(`Entity state: ${state} (${STATE_NAMES[Number(state)] ?? "Unknown"})`);

  if (Number(state) === 0) {
    console.log("Entity has no anchor on this registry.");
    return;
  }

  // For end-to-end verification, fetch the AnchorRecord by anchor digest.
  // Most callers will already know the anchorDigest from the corridor
  // attestation. This snippet demonstrates that getAnchorRecord round-trips
  // the AnchorRecord struct correctly through ethers' decoder.
  const exampleDigest = process.env.LTP_ANCHOR_DIGEST;
  if (exampleDigest) {
    const rec = await registry.getAnchorRecord(exampleDigest);
    console.log("Anchor record:");
    console.log(`  merkleRoot:    ${rec.merkleRoot}`);
    console.log(`  policyHash:    ${rec.policyHash}`);
    console.log(`  signerVkHash:  ${rec.signerVkHash}`);
    console.log(`  entityIdHash:  ${rec.entityIdHash}`);
    console.log(`  sequence:      ${rec.sequence}`);
    console.log(`  validUntil:    ${rec.validUntil}`);
    console.log(`  targetChainId: ${rec.targetChainId}`);
    console.log(`  receiptType:   ${rec.receiptType}`);
    console.log(`  entityState:   ${rec.entityState}`);
    console.log(`  anchoredAt:    ${rec.anchoredAt}`);
  } else {
    console.log("(set LTP_ANCHOR_DIGEST=0x... to also fetch the full anchor record)");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
