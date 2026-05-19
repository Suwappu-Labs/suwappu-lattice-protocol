"""GSX Pre-Blockchain Trust Packaging Layer — Full Demo"""

import time

from src.ltp import *
from src.ltp.anchor import VALID_TRANSITIONS, AnchorSubmission, EntityState, validate_transition
from src.ltp.domain import (
    _ALL_TAGS,
    DOMAIN_COMMIT_RECORD,
    DOMAIN_STH_SIGN,
    domain_hash,
    domain_hash_bytes,
    signer_fingerprint,
)
from src.ltp.encoding import CanonicalEncoder
from src.ltp.envelope import SignedEnvelope
from src.ltp.evidence import EvidenceBundle
from src.ltp.governance import ApprovalRule, SignerEntry, SignerPolicy
from src.ltp.hybrid import AlgorithmId, AlgorithmRegistry, composite_signing_message
from src.ltp.merkle_log.portable_proof import TreeType
from src.ltp.receipt import ApprovalReceipt, ReceiptType
from src.ltp.sequencing import SequenceTracker
from src.ltp.verify import verify_envelope, verify_merkle_proof, verify_receipt, verify_sth

reset_poc_state()

print("=" * 74)
print("  GSX PRE-BLOCKCHAIN TRUST PACKAGING LAYER — FULL DEMO")
print("=" * 74)

# ── Canonical Encoding ───────────────────────────────────────────────────
print("\n▸ Canonical Object Encoding")
enc = (
    CanonicalEncoder(b"GSX-LTP:demo:v1\x00")
    .string("hello")
    .uint64(42)
    .float64(3.14159)
    .length_prefixed_bytes(b"\xde\xad\xbe\xef")
    .sorted_map({"z": "26", "a": "1", "m": "13"})
    .finalize()
)
print(f"  Encoded blob: {len(enc)} bytes")
print(f"  Tag prefix:   GSX-LTP:demo:v1\\x00")
print(f"  Hex preview:  {enc[:32].hex()}...")

# ── Domain Separation ────────────────────────────────────────────────────
print("\n▸ Domain Separation Registry")
print(f"  Registered tags: {len(_ALL_TAGS)}")
for name, tag in list(_ALL_TAGS.items())[:5]:
    print(f"    {name}: {tag}")
print(f"    ... and {len(_ALL_TAGS) - 5} more")

h1 = domain_hash_bytes(DOMAIN_COMMIT_RECORD, b"test-data")
h2 = domain_hash_bytes(DOMAIN_STH_SIGN, b"test-data")
print(f"  Domain isolation check:")
print(f"    COMMIT_RECORD hash: {h1.hex()[:32]}...")
print(f"    STH_SIGN hash:      {h2.hex()[:32]}...")
print(f"    Isolated: {h1 != h2}")

# ── Setup ─────────────────────────────────────────────────────────────────
print("\n▸ Setup: KeyPairs + Network")
alice = KeyPair.generate("alice")
bob = KeyPair.generate("bob")
print(f"  Alice VK fingerprint: {signer_fingerprint(alice.vk).hex()[:32]}...")
print(f"  Bob   VK fingerprint: {signer_fingerprint(bob.vk).hex()[:32]}...")

net = CommitmentNetwork()
for i in range(3):
    net.add_node(f"node-{i}", "us-east-1")
proto = LTPProtocol(net)
print(f"  Network nodes: {len(net.nodes)}")

# ── Commit ────────────────────────────────────────────────────────────────
print("\n▸ COMMIT Phase")
entity = Entity(content=b"GSX trust packaging demo payload", shape="text/plain")
eid, record, cek = proto.commit(entity, alice)
print(f"  Entity ID:      {eid[:48]}...")
print(f"  Sender:         {record.sender_id}")
print(f"  Content hash:   {record.content_hash[:48]}...")
print(f"  Shard map root: {record.shard_map_root[:48]}...")
print(f"  Timestamp:      {record.timestamp}")

# ── Canonical Encoding Integration ────────────────────────────────────────
print("\n▸ Canonical Encoding on Real Objects")
cb = record.canonical_bytes()
crb = record.canonical_record_bytes()
sth = net.log.latest_sth
sth_cb = sth.canonical_bytes()
print(f"  CommitmentRecord.canonical_bytes():        {len(cb)} bytes")
print(f"  CommitmentRecord.canonical_record_bytes(): {len(crb)} bytes")
print(f"  SignedTreeHead.canonical_bytes():           {len(sth_cb)} bytes")
print(f"  Legacy signable_payload() still works:     {len(record.signable_payload())} bytes")
print(f"  Legacy != canonical (different domains):   {record.signable_payload() != cb}")

# ── Signed Envelope ──────────────────────────────────────────────────────
print("\n▸ Signed Message Envelope")
envelope = record.to_envelope(alice.vk, alice.sk, "alice")
print(f"  Version:      {envelope.version}")
print(f"  Payload type: {envelope.payload_type}")
print(f"  Signer ID:    {envelope.signer_id}")
print(f"  Signer KID:   {envelope.signer_kid.hex()[:32]}...")
print(f"  Timestamp:    {envelope.timestamp:.3f}")
print(f"  Signature:    {len(envelope.signature)} bytes")
print(f"  Verify:       {envelope.verify()}")
print(f"  Fingerprint:  {envelope.fingerprint()[:48]}...")

# create_at for deterministic testing
env_det = SignedEnvelope.create_at(
    domain=DOMAIN_COMMIT_RECORD,
    signer_vk=alice.vk,
    signer_sk=alice.sk,
    signer_id="alice",
    payload_type="test",
    payload=b"deterministic",
    timestamp=1700000000.0,
)
print(f"  create_at(ts=1700000000.0): ts={env_det.timestamp}")

# peek_payload
pt, p = SignedEnvelope.peek_payload(envelope)
print(f"  peek_payload: type={pt}, payload={len(p)} bytes (unauthenticated)")

# extract_signer_kid
kid = SignedEnvelope.extract_signer_kid(envelope)
print(f"  extract_signer_kid: {kid.hex()[:32]}...")

# max_drift
stale_env = SignedEnvelope.create_at(
    domain=DOMAIN_COMMIT_RECORD,
    signer_vk=alice.vk,
    signer_sk=alice.sk,
    signer_id="alice",
    payload_type="test",
    payload=b"old",
    timestamp=time.time() - 120,
)
print(f"  Stale envelope (120s old):")
print(f"    verify():              {stale_env.verify()}")
print(f"    verify(max_drift=60):  {stale_env.verify(max_drift=60)}")

# STH envelope
sth_env = SignedTreeHead.sign_envelope(
    sequence=sth.sequence,
    tree_size=sth.tree_size,
    root_hash=sth.root_hash,
    operator_vk=alice.vk,
    operator_sk=alice.sk,
)
print(f"  STH envelope verify: {sth_env.verify()}")

# ── Approval Receipts ────────────────────────────────────────────────────
print("\n▸ Approval Receipts")
receipt = ApprovalReceipt.for_commit(
    entity_id=eid,
    record=record,
    sth=sth,
    signer_kp=alice,
    signer_role="operator",
    sequence=0,
    target_chain_id="base-testnet",
)
print(f"  Receipt type:    {receipt.receipt_type.value}")
print(f"  Receipt ID:      {receipt.receipt_id[:48]}...")
print(f"  Entity:          {receipt.entity_id[:32]}...")
print(f"  Signer role:     {receipt.signer_role}")
print(f"  Sequence:        {receipt.sequence}")
print(f"  Chain:           {receipt.target_chain_id}")
print(f"  Valid until:     {receipt.valid_until:.0f}")
print(f"  Epoch:           {receipt.epoch}")
print(f"  Signature:       {len(receipt.signature)} bytes")
print(f"  Verify(alice):   {receipt.verify(alice.vk)}")
print(f"  Verify(bob):     {receipt.verify(bob.vk)}")
print(f"  Anchor digest:   {receipt.anchor_digest().hex()[:48]}...")
print(f"  Digest length:   {len(receipt.anchor_digest())} bytes")

# Materialize receipt
mat_receipt = ApprovalReceipt.for_materialize(
    entity_id=eid,
    record=record,
    sth=sth,
    signer_kp=alice,
    signer_role="operator",
    sequence=1,
    target_chain_id="base-testnet",
)
print(
    f"  Materialize receipt: type={mat_receipt.receipt_type.value}, verify={mat_receipt.verify(alice.vk)}"
)

# ── Sequence Tracker ─────────────────────────────────────────────────────
print("\n▸ Sequence Tracker")
tracker = SequenceTracker(chain_id="base-testnet")
print(f"  Chain: {tracker.chain_id}")
print(f"  Alice next seq: {tracker.next_sequence(alice.vk)}")

ok, reason = tracker.validate_and_advance(alice.vk, 0, "base-testnet", receipt.valid_until)
print(f"  Seq 0: ok={ok} reason='{reason}'")

ok, reason = tracker.validate_and_advance(alice.vk, 0, "base-testnet", receipt.valid_until)
print(f"  Seq 0 replay: ok={ok} reason='{reason}'")

ok, reason = tracker.validate_and_advance(alice.vk, 1, "base-testnet", receipt.valid_until)
print(f"  Seq 1: ok={ok} reason='{reason}'")

ok, reason = tracker.validate_and_advance(alice.vk, 2, "wrong-chain", receipt.valid_until)
print(f"  Wrong chain: ok={ok} reason='{reason}'")

ok, reason = tracker.validate_and_advance(alice.vk, 2, "base-testnet", time.time() - 1)
print(f"  Expired: ok={ok} reason='{reason}'")

print(f"  Alice current: {tracker.current_sequence(alice.vk)}")
print(f"  Alice next:    {tracker.next_sequence(alice.vk)}")
print(f"  Bob next:      {tracker.next_sequence(bob.vk)}")

# Batch
results = tracker.validate_batch(
    [
        (bob.vk, 0, "base-testnet", time.time() + 3600),
        (bob.vk, 1, "base-testnet", time.time() + 3600),
        (bob.vk, 1, "base-testnet", time.time() + 3600),  # replay
    ]
)
print(f"  Batch [bob seq 0,1,1]: {[(ok, r[:20] if r else '') for ok, r in results]}")

# ── Portable Merkle Proofs ───────────────────────────────────────────────
print("\n▸ Portable Merkle Proofs")
proof = net.log.get_portable_proof(eid)
print(f"  Tree type:   {proof.tree_type.value}")
print(f"  Leaf index:  {proof.leaf_index}")
print(f"  Tree size:   {proof.tree_size}")
print(f"  Leaf hash:   {proof.leaf_hash.hex()[:32]}...")
print(f"  Root hash:   {proof.root_hash.hex()[:32]}...")
print(f"  Path length: {len(proof.path)}")
print(f"  Verify:      {proof.verify()}")
compact = proof.to_compact_bytes()
print(f"  Compact:     {len(compact)} bytes")
canonical = proof.canonical_bytes()
print(f"  Canonical:   {len(canonical)} bytes")

# ── Signer Governance ────────────────────────────────────────────────────
print("\n▸ Signer Governance")
policy = SignerPolicy(
    policy_id="",
    policy_version=1,
    signers=[
        SignerEntry(
            signer_id="alice",
            vk=alice.vk,
            roles={"operator", "admin"},
            valid_from=0,
            valid_until=1000,
        ),
        SignerEntry(signer_id="bob", vk=bob.vk, roles={"auditor"}, valid_from=0, valid_until=1000),
    ],
    approval_rules=[
        ApprovalRule(action_type="COMMIT", required_roles={"operator"}, min_signers=1),
        ApprovalRule(action_type="MATERIALIZE", required_roles={"operator"}, min_signers=1),
        ApprovalRule(action_type="SHARD_AUDIT_PASS", required_roles={"auditor"}, min_signers=1),
    ],
)
policy.sign_policy(alice.sk)
print(f"  Policy ID:      {policy.policy_id[:48]}...")
print(f"  Policy version: {policy.policy_version}")
print(f"  Signers:        {len(policy.signers)}")
print(f"  Rules:          {len(policy.approval_rules)}")
print(f"  Policy hash:    {policy.policy_hash()[:48]}...")
print(f"  Verify(alice):  {policy.verify_policy(alice.vk)}")
print(f"  Alice authorized COMMIT@epoch=0:   {policy.is_signer_authorized(alice.vk, 'COMMIT', 0)}")
print(f"  Bob authorized COMMIT@epoch=0:     {policy.is_signer_authorized(bob.vk, 'COMMIT', 0)}")
print(
    f"  Bob authorized SHARD_AUDIT@epoch=0:{policy.is_signer_authorized(bob.vk, 'SHARD_AUDIT_PASS', 0)}"
)
print(
    f"  Alice authorized COMMIT@epoch=2000:{policy.is_signer_authorized(alice.vk, 'COMMIT', 2000)}"
)

# ── Verification SDK ─────────────────────────────────────────────────────
print("\n▸ Verification SDK (Pure Functions)")
env_result = verify_envelope(envelope)
print(
    f"  verify_envelope:     valid={env_result.valid} reason='{env_result.reason}' artifact='{env_result.artifact}'"
)

receipt_result = verify_receipt(receipt)
print(f"  verify_receipt:      valid={receipt_result.valid} reason='{receipt_result.reason}'")

proof_result = verify_merkle_proof(proof)
print(f"  verify_merkle_proof: valid={proof_result.valid} reason='{proof_result.reason}'")

sth_result = verify_sth(sth)
print(f"  verify_sth:          valid={sth_result.valid} reason='{sth_result.reason}'")

# ── Anchor State Machine ─────────────────────────────────────────────────
print("\n▸ Anchor State Machine")
print(f"  States: {[s.name for s in EntityState]}")
print(f"  Valid transitions: {len(VALID_TRANSITIONS)}")
for current, target in sorted(VALID_TRANSITIONS, key=lambda x: (x[0].value, x[1].value)):
    print(f"    {current.name} → {target.name}")

ok, reason = validate_transition(EntityState.UNKNOWN, EntityState.COMMITTED)
print(f"  UNKNOWN → COMMITTED: ok={ok}")
ok, reason = validate_transition(EntityState.COMMITTED, EntityState.UNKNOWN)
print(f"  COMMITTED → UNKNOWN: ok={ok} reason='{reason}'")

# AnchorSubmission
from src.ltp.primitives import canonical_hash_bytes

sub = AnchorSubmission.from_receipt(
    receipt=receipt,
    policy_hash_bytes=canonical_hash_bytes(policy.policy_hash().encode()),
    target_chain_id_int=84532,  # Base Sepolia
)
calldata = sub.to_calldata()
print(f"  AnchorSubmission calldata: {len(calldata)} bytes")
print(f"    anchor_digest:   {sub.anchor_digest.hex()[:32]}...")
print(f"    merkle_root:     {sub.merkle_root.hex()[:32]}...")
print(f"    signer_vk_hash:  {sub.signer_vk_hash.hex()[:32]}...")
print(f"    sequence:        {sub.sequence}")
print(f"    target_chain_id: {sub.target_chain_id}")
print(f"    receipt_type:    {sub.receipt_type}")

# ── Hybrid Crypto ────────────────────────────────────────────────────────
print("\n▸ Hybrid Crypto (ML-DSA-65 + Ed25519-SHA512)")
registry = AlgorithmRegistry()
print(f"  Supported: {[a.value for a in registry.supported_algorithms()]}")

msg = b"hybrid signing demo"
sig_pure = registry.sign(AlgorithmId.MLDSA65, alice.sk, msg, DOMAIN_COMMIT_RECORD)
print(f"  Pure ML-DSA-65 sig:  {len(sig_pure)} bytes")
print(
    f"  Verify pure:         {registry.verify(AlgorithmId.MLDSA65, alice.vk, msg, DOMAIN_COMMIT_RECORD, sig_pure)}"
)

sig_comp = registry.sign(AlgorithmId.MLDSA65_ED25519_SHA512, alice.sk, msg, DOMAIN_COMMIT_RECORD)
print(f"  Composite xDSA sig:  {len(sig_comp)} bytes (3309 ML-DSA + 64 Ed25519)")
print(
    f"  Verify composite:    {registry.verify(AlgorithmId.MLDSA65_ED25519_SHA512, alice.vk, msg, DOMAIN_COMMIT_RECORD, sig_comp)}"
)

m_prime = composite_signing_message(msg)
print(f"  Composite M' length: {len(m_prime)} bytes")

# ── Evidence Bundle ──────────────────────────────────────────────────────
print("\n▸ Evidence Bundle")
bundle = EvidenceBundle.create(
    entity_id=eid,
    receipts=[receipt.canonical_bytes_unsigned()],
    merkle_proofs=[proof.canonical_bytes()],
    sth_snapshots=[sth.canonical_bytes()],
    policy_hash=policy.policy_hash(),
    metadata={"action": "COMMIT", "chain": "base-testnet"},
)
print(f"  Bundle ID:      {bundle.bundle_id[:48]}...")
print(f"  Entity:         {bundle.entity_id[:32]}...")
print(f"  Receipts:       {len(bundle.receipts)}")
print(f"  Merkle proofs:  {len(bundle.merkle_proofs)}")
print(f"  STH snapshots:  {len(bundle.sth_snapshots)}")
print(f"  Policy hash:    {bundle.policy_hash[:48]}...")
print(f"  Canonical size: {len(bundle.canonical_bytes())} bytes")

# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 74)
print("  SUMMARY")
print("=" * 74)
print(f"  Sections demonstrated:     6 (encoding, domain, envelope, receipt, tier2, hybrid)")
print(f"  Domain tags registered:    {len(_ALL_TAGS)}")
print(f"  Envelope verified:         {envelope.verify()}")
print(f"  Receipt verified:          {receipt.verify(alice.vk)}")
print(f"  Anchor digest (32B):       {receipt.anchor_digest().hex()[:48]}...")
print(f"  Merkle proof verified:     {proof.verify()}")
print(f"  Policy signed & verified:  {policy.verify_policy(alice.vk)}")
print(
    f"  Hybrid crypto operational: {registry.verify(AlgorithmId.MLDSA65_ED25519_SHA512, alice.vk, msg, DOMAIN_COMMIT_RECORD, sig_comp)}"
)
print(f"  Evidence bundle size:      {len(bundle.canonical_bytes())} bytes")
print(f"  ABI calldata size:         {len(calldata)} bytes")
print(
    f"  Sequence tracker state:    alice@seq={tracker.current_sequence(alice.vk)}, bob@seq={tracker.current_sequence(bob.vk)}"
)
print("=" * 74)
print("  GSX Pre-Blockchain Trust Packaging Layer operational.")
print("  All trust artifacts ready for on-chain anchoring.")
print("=" * 74)
