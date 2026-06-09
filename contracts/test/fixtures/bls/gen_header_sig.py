#!/usr/bin/env python3
import sys
from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
from py_ecc.optimized_bls12_381 import G1, normalize, add, multiply
from py_ecc.bls.g2_primitives import signature_to_G2
def fp_to_eip2537(fp_n):
    return b'\x00'*16 + fp_n.to_bytes(48, 'big')
def g2_to_eip2537(pt):
    n = normalize(pt)
    xc0, xc1 = n[0].coeffs
    yc0, yc1 = n[1].coeffs
    return fp_to_eip2537(xc0)+fp_to_eip2537(xc1)+fp_to_eip2537(yc0)+fp_to_eip2537(yc1)
digest_hex = sys.argv[1]
if digest_hex.startswith('0x'): digest_hex = digest_hex[2:]
digest = bytes.fromhex(digest_hex)
sks = [1, 2, 3]
sigs = [bytes(bls.Sign(sk, digest)) for sk in sks]
agg = bytes(bls.Aggregate(sigs))
from py_ecc.bls.g2_primitives import signature_to_G2
enc = g2_to_eip2537(signature_to_G2(agg))
print('0x' + enc.hex())
