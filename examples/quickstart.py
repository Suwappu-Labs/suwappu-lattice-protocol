"""
ETP Quickstart — Your first transfer in 10 lines.

Usage:
    PYTHONPATH=. python examples/quickstart.py
"""

from src.ltp import CommitmentNetwork, Entity, KeyPair, LTPProtocol, reset_poc_state

reset_poc_state()
alice, bob = KeyPair.generate("alice"), KeyPair.generate("bob")
net = CommitmentNetwork()
[net.add_node(f"n{i}", "us") for i in range(3)]
proto = LTPProtocol(net)

eid, rec, cek = proto.commit(Entity(b"Hello ETP!", "text/plain"), alice)
sealed = proto.lattice(eid, rec, cek, bob)
print(proto.materialize(sealed, bob))  # b'Hello ETP!'
