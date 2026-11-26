"""Canonical hashing, field commitments and Merkle inclusion/absence proofs.

The same Merkle root is produced from *manifest* (leaf key + digest) alone, so a
reader who never receives some leaves can still recompute the externally
verifiable root.  Event leaves commit to every input field individually, which
lets a redacted reader verify the leaf digest without seeing secret values.
"""

import hashlib

from .db import canonical


def digest(value):
    """Domain-free digest of a canonically encoded JSON value."""
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def leaf_hash(value):
    return hashlib.sha256(b"LEAF|" + canonical(value).encode("utf-8")).hexdigest()


def pair_hash(left, right):
    if left > right:
        left, right = right, left
    return hashlib.sha256(b"NODE|" + left.encode("ascii") + b"|" + right.encode("ascii")).hexdigest()


EMPTY_ROOT = hashlib.sha256(b"EMPTY_TREE").hexdigest()


def _levels(entries):
    """entries: sorted list of (key, leaf_digest). Returns per-level node list."""
    level = [leaf_hash({"key": key, "digest": h}) for key, h in entries]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(pair_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd node promoted unchanged
        levels.append(nxt)
        level = nxt
    return levels


def root_for(entries):
    """Root digest for key-sorted (key, digest) entries."""
    entries = sorted(entries, key=lambda item: item[0])
    if not entries:
        return EMPTY_ROOT
    return _levels(entries)[-1][0]


class Tree:
    """In-memory Merkle tree over key-sorted leaves with inclusion/absence proofs."""

    def __init__(self, entries):
        self.entries = sorted(entries, key=lambda item: item[0])
        self.keys = [key for key, _ in self.entries]
        self.levels = _levels(self.entries)
        self.root = self.levels[-1][0] if self.entries else EMPTY_ROOT

    def inclusion(self, key):
        index = self.keys.index(key)
        steps = []
        pos = index
        for level in self.levels[:-1]:
            if pos % 2 == 0:
                if pos + 1 < len(level):
                    steps.append({"side": "right", "hash": level[pos + 1]})
                # odd trailing node is promoted without consuming a step
            else:
                steps.append({"side": "left", "hash": level[pos - 1]})
            pos //= 2
        return {"key": key, "index": index, "size": len(self.entries), "steps": steps}

    def absence(self, key):
        """Boundary proof: insertion position plus neighbour inclusion proofs."""
        lo, hi = 0, len(self.keys)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.keys[mid] < key:
                lo = mid + 1
            else:
                hi = mid
        proof = {"key": key, "insert_at": lo, "size": len(self.keys), "neighbors": []}
        if lo > 0:
            proof["neighbors"].append({"position": "before", **self.inclusion(self.keys[lo - 1])})
        if lo < len(self.keys):
            proof["neighbors"].append({"position": "after", **self.inclusion(self.keys[lo])})
        return proof


def verify_inclusion(root, key, leaf_digest, proof):
    if proof.get("key") != key or proof["index"] >= proof["size"]:
        return False
    current = leaf_hash({"key": key, "digest": leaf_digest})
    pos = proof["index"]
    size = proof["size"]
    steps = list(proof["steps"])
    while size > 1:
        if pos % 2 == 0 and pos + 1 >= size:
            pass  # odd trailing node promoted unchanged
        else:
            if not steps:
                return False
            step = steps.pop(0)
            if step["side"] == "right":
                if pos % 2 or pos + 1 >= size:
                    return False
                current = pair_hash(current, step["hash"])
            else:
                if pos % 2 == 0:
                    return False
                current = pair_hash(step["hash"], current)
        pos //= 2
        size = (size + 1) // 2
    return not steps and current == root


def verify_absence(root, key, entries, proof):
    """entries is the verifier's manifest: list of (key, digest)."""
    keys = sorted(k for k, _ in entries)
    if key in keys:
        return False
    if proof.get("key") != key or proof.get("size") != len(keys):
        return False
    at = proof["insert_at"]
    if at != sum(1 for k in keys if k < key):
        return False
    expected = []
    if at > 0:
        expected.append(("before", keys[at - 1]))
    if at < len(keys):
        expected.append(("after", keys[at]))
    seen = [(n["position"], n["key"]) for n in proof["neighbors"]]
    if seen != expected:
        return False
    index = {k: h for k, h in entries}
    for neighbor in proof["neighbors"]:
        if not verify_inclusion(root, neighbor["key"], index[neighbor["key"]], neighbor):
            return False
    return True


# --- field-level commitments for selective disclosure ----------------------

SENSITIVE_MARKERS = ("value", "secret", "token", "password", "credential", "key_material")
REDACTED_PLACEHOLDER = "<redacted>"


def is_sensitive(field):
    name = str(field).lower()
    return name == "value" or any(marker in name for marker in SENSITIVE_MARKERS[1:])


def field_commitment(field, value):
    return {"field": field, "digest": digest({"field": field, "value": value})}


def event_leaf_digest(leaf):
    """Digest for an event leaf, identical for full and redacted forms.

    Sensitive input fields enter the digest only through fixed placeholder
    commitments, and the decision result through a stable result-commitment
    slot. Hiding secret values therefore cannot change the leaf digest or the
    Merkle root. Privileged plaintext is vouched for by the separate
    ``secret_value_commitments`` and full result hash, which redacted readers
    simply omit.
    """
    payload = leaf["input"]
    fields = []
    for field in sorted(payload):
        if is_sensitive(field):
            fields.append({"field": field, "redacted": True})
        else:
            fields.append(field_commitment(field, payload[field]))
    full_result_hash = leaf.get("_result_hash", digest(leaf["result"]))
    commitment = {"fields": fields}
    return digest({
        "kind": "event",
        "event_id": leaf["event_id"],
        "request_id": leaf["request_id"],
        "kind_name": leaf["kind"],
        "subject": leaf["subject"],
        "at": leaf["at"],
        "received_at": leaf["received_at"],
        "input_commitment": commitment,
        "result_commitment": {"digest": digest({"result": full_result_hash})},
    })


def with_secret_commitments(leaf):
    """Attach value digests and the full result hash before the leaf is sealed."""
    if leaf.get("kind") != "event" or leaf.get("secret_value_commitments"):
        return leaf
    leaf["secret_value_commitments"] = [
        field_commitment(field, value) for field, value in sorted(leaf["input"].items())
        if is_sensitive(field)]
    leaf["_result_hash"] = digest(leaf["result"])
    return leaf


def generic_leaf_digest(leaf):
    return digest(leaf)
