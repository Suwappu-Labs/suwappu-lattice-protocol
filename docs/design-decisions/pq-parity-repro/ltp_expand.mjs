// Expands LTP-generated ML-DSA-65 public keys into the verifier's key format.
// Usage: node ltp_expand.mjs <raw.json> <out.json>
import fs from 'fs';
import { publicKeyToBlob65, hexToBytes } from './mldsa65.js';

const [, , rawPath, outPath] = process.argv;
const d = JSON.parse(fs.readFileSync(rawPath));
const out = { root: d.root, long: d.long, blobs: [], sigRoot: [], sigLong: [] };
for (const s of d.signers) {
  out.blobs.push(publicKeyToBlob65(hexToBytes(s.pk)));
  out.sigRoot.push('0x' + s.sigRoot);
  out.sigLong.push('0x' + s.sigLong);
}
fs.writeFileSync(outPath, JSON.stringify(out));
console.log('keys', out.blobs.length, 'blob bytes', (out.blobs[0].length - 2) / 2);
