# SCN-011 — Lazarus-tier sustained key compromise

**Status.** VERIFIED-GREEN expected.
**Layer.** 3 — Key management.
**Historical incidents.** Ronin (Mar 2022, \$625M), Harmony
(Jun 2022, \$100M), Atomic Wallet (Jun 2023, \$100M), DMM Bitcoin
(May 2024, \$305M), WazirX (Jul 2024, \$230M) — all DPRK / Lazarus-
attributed by Chainalysis, OFAC, and FBI public statements.
**LTP-A-* link.** [LTP-A-004](../../../SECURITY_AUDIT_2026-05-15.md)
(single-custody operator signing key) + [LTP-A-013](../../../SECURITY_AUDIT_2026-05-15.md)
(operator key format validated at boot).

## What happened (the pattern)

Lazarus operations against crypto-bridge / exchange targets share
a sustained-pressure shape:

1. **Initial access** via spearphishing, fake-recruiter PDFs, or
   supply-chain compromise of operator-team laptops.
2. **Lateral movement** to signing infrastructure: HSM access,
   exchange hot-wallet operator stations, or developer machines
   that keep signing keys in memory or on disk.
3. **Persistence** over weeks: minimize detection by signing only
   a few transactions per session at low volume.
4. **Drain** when an opportunity to take the full balance arises —
   typically synchronized with a low-staff window (weekend, holiday).

Defense is not "make compromise impossible" — that's beyond any
cryptographic boundary. Defense is **bound the blast radius**: when
N operators are compromised, what can the attacker do?

## LTP analogue

`src/ltp/hsm.py` is the HSM abstraction. `SoftwareHSM` is the PoC
backend; `HSMBackend` is the abstract interface that PKCS#11 and
cloud-KMS production backends will implement.

The defenses pinned in this scenario:

| ID | Defense | Source |
|----|---------|--------|
| L1 | `SoftwareHSM.__init__` fails closed when `LTP_ENV=production` and `ETP_HSM_PROVIDER=software` (the documented prod-software trap) | `hsm.py:115-129` |
| L2 | `HSMBackend` abstract API has no export-private-key method. Private key material never leaves the HSM via the public interface | `hsm.py:33-103` |
| L3 | `sign(key_id, message)` requires the key to exist; raises `KeyError` on miss | `hsm.py:159-163` |
| L4 | `sign` requires the key type to match; raises `TypeError` if used with a KEM key (and symmetric for `kem_decaps` against a DSA key) | `hsm.py:159-175` |
| L5 | `destroy_key` zeroizes the in-memory private material; signing after destroy raises | `hsm.py:177-188` |
| L7 | `generate_dsa_keypair` / `generate_kem_keypair` REJECT duplicate `key_id`. Defends against stealth-rotation: an attacker with HSM-operator access cannot silently overwrite a legit key with one they control while keeping the same `key_id` | `hsm.py:135-136, 148-149` |
| L8 | `has_key` is a safe pre-check — distinguishes present vs absent without leaking key material | `hsm.py:190` |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| pytest | `tests/security/historical/test_scn_011_lazarus_hsm.py` | L1×3 (prod-refuse, dev-allow, mixed-env-allow), L2 (no export method), L3 (sign missing key), L4×2 (DSA-as-KEM + KEM-as-DSA), L5×2 (destroy-then-sign + idempotent), L7×3 (DSA-dup, KEM-dup, cross-type-dup), L8 (has_key) |

## Cross-references

- **SCN-008** (Ronin) — proxy-signing surface (Layer 2 defense)
- **SCN-009** (Harmony) — threshold-vs-VaR (deploy-policy defense)
- **OPERATOR_RUNBOOK.md** — operational defenses: HSM rotation
  policy, active-set monitoring, alerting on signing-cadence
  anomalies
- **LTP-A-004** — single-custody trap
- **LTP-A-013** — operator key format validated at boot
- Future work: PKCS#11 / Cloud-KMS backends implementing
  `HSMBackend` — when those land, SCN-011 should be extended

## How to run

```bash
pip install -e '.[dev]'
pytest tests/security/historical/test_scn_011_lazarus_hsm.py -v
```

## Findings opened

None expected. HSM-tier defenses pre-exist as part of LTP-A-004.
