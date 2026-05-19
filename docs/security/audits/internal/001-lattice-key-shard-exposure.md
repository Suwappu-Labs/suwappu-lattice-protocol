# LTP Security Fix #1: Lattice Key Shard ID Exposure

**Date:** 2026-02-24  
**Issue:** CRITICAL — Lattice key leaks shard IDs, enabling unauthorized reconstruction  
**Status:** Design Analysis → **Option C implemented** (verified 2026-05-15)

> **Implementation note (2026-05-15):** Option C is the production design and is shipped.
> See [`SECURITY_AUDIT_2026-05-15.md`](SECURITY_AUDIT_2026-05-15.md) LTP-A-022 for the
> code-anchor verification: `src/ltp/lattice.py::LatticeKey` carries only
> `entity_id` / `cek` / `commitment_ref` / `access_policy`; shards are encrypted
> via `src/ltp/shards.py::ShardEncryptor` before distribution at
> `src/ltp/protocol.py:175-189`; receivers fetch encrypted shards and decrypt
> with the CEK at `src/ltp/protocol.py:355-368`. The 122-test protocol + shard
> + commitment suite is the regression guard.
> 
> This doc remains the design-rationale source. The implementation diverges
> in two minor ways: (1) the access-policy field is a dict rather than a
> fixed-length blob, and (2) the encrypted-shard nonce is HKDF-derived
> from the CEK + entity_id + shard index rather than the literal shard
> index, providing an extra layer of protection against CEK-reuse-across-
> entities accidents.

---

## The Exact Attack Chain

The problem is actually **deeper than the lattice key itself**. There are THREE
information leakage points that form a kill chain:

```mermaid
flowchart TD
    subgraph Leaks["CURRENT DESIGN — ATTACK CHAIN"]
        L1["LEAK 1: Lattice Key\n(plaintext, in transit)\nContains: entity_id, shard_ids,\nencoding_params, sender_id"]
        L2["LEAK 2: Commitment Log\n(public, at rest)\nContains: entity_id, shard_ids,\nencoding_params, shard_map_root"]
        L3["LEAK 3: Commitment Nodes\n(no access control, no encryption)\nServe shards to anyone, plaintext"]
    end

    L1 --> ATK1["Intercept key → extract shard_ids\n→ compute locations → fetch → decode"]
    L2 --> ATK2["Know entity_id → query log\n→ get shard_ids → fetch → decode"]
    L3 --> ATK1
    L3 --> ATK2
```

**Key insight:** Fixing only the lattice key isn't enough. If shards are stored in
plaintext and the commitment log is public, an attacker who knows the entity_id can
reconstruct the entity without ever seeing the lattice key.

This means any fix must address at least two of the three leaks to be meaningful.

---

## Design Options

### Option A: Envelope Encryption Only

**What changes:** Encrypt the entire lattice key to the receiver's public key using
X25519 + XChaCha20-Poly1305 (NaCl sealed box).

```
BEFORE:  Key = { entity_id, shard_ids, params, ... }              ← plaintext JSON
AFTER:   Key = SealedBox(receiver_pubkey, { entity_id, shard_ids, params, ... })  ← ciphertext
```

**What breaks:**
```
Interceptor captures encrypted key  →  can't read shard_ids  →  ✓ blocked
Attacker queries public commit log  →  reads shard_ids there  →  ✗ STILL EXPOSED
Compromised node reads its shards   →  plaintext data          →  ✗ STILL EXPOSED
```

| Pros | Cons |
|------|------|
| Simple to implement (~20 lines of code) | Doesn't fix leak 2 (public log has shard_ids) |
| Protects against passive interception | Doesn't fix leak 3 (nodes store plaintext) |
| Minimal changes to architecture | False sense of security — 2 of 3 leaks remain |
| No performance impact | Any attacker who knows entity_id bypasses this entirely |

**Verdict: Insufficient. Band-aid, not a fix.**

---

### Option B: Encrypted Shards (Content Encryption Key)

**What changes:** Before distributing shards to commitment nodes, encrypt each shard with
a random Content Encryption Key (CEK). Nodes store ciphertext. The CEK is included in the
(encrypted) lattice key.

```
COMMIT PHASE:
  1. Erasure encode entity → plaintext shards
  2. Generate random CEK (256-bit)
  3. For each shard: encrypted_shard = AEAD_Encrypt(CEK, shard, nonce=shard_index)
  4. Distribute encrypted_shards to nodes
  5. ShardID = H(encrypted_shard || entity_id || index)
  6. Commitment record stores encrypted shard IDs

LATTICE KEY:
  SealedBox(receiver_pubkey, {
    entity_id,
    content_encryption_key,   ← NEW: the CEK
    shard_ids,                ← still here, but now they reference ciphertext
    encoding_params,
    access_policy
  })

MATERIALIZE PHASE:
  1. Decrypt lattice key → get entity_id, CEK, shard_ids
  2. Fetch encrypted shards from nodes
  3. Verify: H(encrypted_shard) matches shard_id ← proves node didn't tamper
  4. Decrypt each shard with CEK
  5. Erasure decode → entity
  6. Verify entity_id
```

**What breaks:**
```
Interceptor captures encrypted key  →  can't decrypt key        →  ✓ blocked
Attacker queries public commit log  →  gets encrypted shard IDs →  fetches ciphertext → ✓ blocked (no CEK)
Compromised node reads its shards   →  sees ciphertext only     →  ✓ blocked (no CEK)
Attacker has receiver's private key →  decrypts key → gets CEK  →  ✗ game over (inherent limit)
```

| Pros | Cons |
|------|------|
| Fixes all 3 leakage points | Shard_ids still in the key (bloats key size to ~900 bytes) |
| Nodes become untrusted storage (can't read data) | CEK is a single point of compromise |
| AEAD provides authenticated encryption (tamper detection) | ~16-28 bytes overhead per shard (AEAD tag) |
| Commitment log metadata is useless without CEK | Key is still larger than necessary |
| Works with current node architecture (no access control needed) | Doesn't reduce the key to its theoretical minimum |

**Verdict: Solid security fix. Addresses the real problem. But the key is still bloated.**

---

### Option C: Encrypted Shards + Derivable Metadata (Remove Shard IDs From Key)

**What changes:** Everything from Option B, PLUS: remove shard_ids from the latticement
key entirely. The receiver can derive everything they need from entity_id alone.

**Key realization:** Shard IDs don't need to be transmitted because:
- Shard **locations** (which nodes store them) are derivable: `ConsistentHash(entity_id || index)`
- Shard **IDs** (for integrity) are in the commitment record on the public log
- The receiver already fetches the commitment record to verify it — they get shard_ids there

So the lattice key shrinks to its **theoretical minimum**:

```
LATTICE KEY (new):
  SealedBox(receiver_pubkey, {
    entity_id,                  ← 32 bytes (hash)
    content_encryption_key,     ← 32 bytes (symmetric key)
    commitment_ref,             ← 32 bytes (log reference hash)
    access_policy               ← ~20-50 bytes (policy metadata)
  })

  TOTAL: ~140-180 bytes sealed (vs. ~869 bytes currently)
```

**The full flow:**
```
COMMIT:
  1. Erasure encode → plaintext shards
  2. Generate random CEK
  3. Encrypt each shard with CEK
  4. Distribute encrypted shards (located by consistent hash)
  5. Commitment record = { entity_id, shard_map_root (Merkle root), encoding_params }
     Note: individual shard_ids are in the Merkle tree, NOT listed plainly

LATTICE:
  1. Key = SealedBox(receiver_pubkey, { entity_id, CEK, commitment_ref, policy })
  2. Transmit ~160 bytes to receiver

MATERIALIZE:
  1. Unseal key → entity_id, CEK, commitment_ref
  2. Fetch commitment record → verify signature → get encoding_params, shard_map_root
  3. For index in 0..n-1: compute node = ConsistentHash(entity_id || index)
  4. Fetch encrypted shards from computed nodes (parallel, nearest-first)
  5. Decrypt each shard with CEK
  6. Erasure decode → entity content
  7. Verify H(content || shape || ...) == entity_id
```

**What breaks:**
```
Interceptor captures encrypted key  →  ciphertext, useless       →  ✓ blocked
Attacker knows entity_id            →  can locate nodes, but     →  fetches ciphertext → ✓ blocked (no CEK)
Attacker has commitment log access  →  sees shard_map_root only  →  ✓ blocked (no individual shard_ids)
Compromised node(s)                 →  have ciphertext only      →  ✓ blocked (no CEK)
Attacker has receiver's private key →  unseals key, gets CEK     →  ✗ game over (inherent)
```

| Pros | Cons |
|------|------|
| Lattice key shrinks from ~869B to ~160B | Nodes must support fetch-by-(entity_id, index) not just by shard_id |
| Fixes ALL 3 leakage points | Slightly more complex materialization logic |
| Key approaches theoretical minimum for the information it must carry | Commitment record no longer lists shard_ids (changes log schema) |
| Commitment log reveals less metadata | CEK is still single point — but this is inherent to any symmetric encryption |
| Nodes are pure dumb storage (ciphertext in, ciphertext out) | If CEK is lost/leaked, all shards for that entity are compromised |
| Beautifully clean: key = { who committed, encryption secret, policy } | |
| Fan-out is free: one commit, different CEK per receiver possible | |

**Verdict: The optimal design. Maximum security, minimum key size, clean architecture.**

---

### Option D: Option C + Node Access Tokens (Maximum Security)

**What changes:** Everything from Option C, PLUS: commitment nodes require a signed access
token before serving shards. The sender mints tokens at lattice time.

```
LATTICE KEY:
  SealedBox(receiver_pubkey, {
    entity_id,
    content_encryption_key,
    commitment_ref,
    access_tokens: [             ← NEW
      { node_id, token, expiry }
      ...
    ],
    access_policy
  })
```

Nodes verify the token before serving any shard, even encrypted ones.

**What breaks:**
```
ALL of Option C's protections, PLUS:
Attacker fetches shards anonymously  →  node rejects (no token)  →  ✓ blocked
DDoS on nodes via shard requests     →  unauthenticated rejected →  ✓ mitigated
```

| Pros | Cons |
|------|------|
| Triple defense: encrypted key + encrypted shards + access control | Nodes become stateful (must validate tokens) |
| Even fetching ciphertext requires authorization | Key size grows with number of nodes (~40-60B per token) |
| Rate limiting / abuse prevention at node level | Token revocation is hard (distributed revocation lists) |
| Audit trail of who fetched what | Nodes must have the sender's public key or a token-signing key |
| One-time-use tokens prevent replay | Adds significant infrastructure complexity |
| | Defeats "dumb storage" simplicity of the commitment network |
| | If token-signing key is compromised, all tokens can be forged |

**Verdict: Maximum theoretical security, but the complexity cost is high and the marginal
gain over Option C is small. Encrypted shards already make unauthorized fetches useless.**

---

## Comparative Analysis

```
                    Security Level
                    ▲
                    │
              D ●   │  ← Maximum security, high complexity
                    │
           C ●      │  ← Optimal tradeoff ★ RECOMMENDED
                    │
        B ●         │  ← Good security, suboptimal key size
                    │
     A ●            │  ← Inadequate (fixes 1 of 3 leaks)
                    │
  current ●         │  ← Broken (all 3 leaks open)
                    │
                    └─────────────────────────────► Implementation Complexity
```

| Dimension | Current | A | B | C ★ | D |
|-----------|---------|---|---|------|---|
| Key size | ~869B | ~869B encrypted | ~900B encrypted | **~160B encrypted** | ~300-500B encrypted |
| Passive interception | ✗ Broken | ✓ Fixed | ✓ Fixed | ✓ Fixed | ✓ Fixed |
| Public log + fetch | ✗ Broken | ✗ Broken | ✓ Fixed | ✓ Fixed | ✓ Fixed |
| Compromised nodes | ✗ Broken | ✗ Broken | ✓ Fixed | ✓ Fixed | ✓ Fixed |
| Anonymous shard fetch | Allowed | Allowed | Allowed (ciphertext) | Allowed (ciphertext) | ✓ Blocked |
| Node complexity | Dumb storage | Dumb storage | Dumb storage | Dumb storage | Stateful |
| Code changes | — | Small | Medium | Medium | Large |

---

## Recommendation

**Option C: Encrypted Shards + Derivable Metadata**

Reasons:
1. Closes all three leakage points identified in the attack chain
2. Shrinks the lattice key from ~869 bytes to ~160 bytes (closer to the "O(1) key" claim)
3. Nodes remain dumb ciphertext storage — no access control infrastructure needed
4. The marginal security gain of Option D (blocking anonymous ciphertext fetches) doesn't
   justify the complexity, because ciphertext without the CEK is computationally useless
5. The design is *elegant*: the key carries exactly 3 secrets (entity_id, CEK, commitment_ref)
   and nothing else

The one inherent limit across ALL options: if the receiver's private key is compromised, the
attacker can unseal the lattice key and obtain the CEK. This is fundamental — it's the
equivalent of saying "if someone steals your house key, they can enter your house." No
protocol can fix this without moving to multi-party computation or threshold decryption,
which is a different design entirely.
