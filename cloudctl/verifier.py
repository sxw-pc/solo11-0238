"""Local independent verifier for compliance certificates.

This module never opens the platform database. An external auditor supplies a
certificate bundle plus the issuer key they hold out of band and can check:

1. the signature over the canonical bundle;
2. the seal root recomputed from the manifest alone;
3. every disclosed leaf's digest against its manifest entry and Merkle proof
   (full leaves and redacted leaves use the same nested field commitment);
4. absence proofs and the truth of every stated proposition;
5. appendix anchors binding late evidence back to the immutable seal root,
   supplement and revocation credentials.
"""

from . import merkle


class VerificationError(ValueError):
    pass


def _check(condition, message, failures):
    if not condition:
        failures.append(message)
    return condition


def _no_secret_survives(leaf):
    """Every sensitive key in input/result must carry only the placeholder."""
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if merkle.is_sensitive(key) and item != merkle.REDACTED_PLACEHOLDER:
                    return False
                if not walk(item):
                    return False
        elif isinstance(value, list):
            return all(walk(item) for item in value)
        return True
    return walk(leaf.get("input", {})) and walk(leaf.get("result", {}))


def verify_bundle(bundle, issuer_secret_hex):
    """Return a structured report; raises VerificationError only on malformed input."""
    failures, checks = [], 0
    if not isinstance(bundle, dict):
        raise VerificationError("bundle must be an object")
    signature = bundle.get("signature", {})
    message = {key: value for key, value in bundle.items() if key != "signature"}
    checks += 1
    _check(merkle is not None, "merkle module missing", failures)
    from .compliance_seal import verify_signature
    checks += 1
    _check(verify_signature(issuer_secret_hex, message, signature),
           "issuer signature does not verify", failures)

    manifest = bundle.get("seal_manifest", [])
    entries = [(item["key"], item["digest"]) for item in manifest]
    checks += 1
    root = merkle.root_for(entries)
    _check(root == bundle.get("seal_root"),
           f"seal root mismatch: manifest gives {root}", failures)
    tree = merkle.Tree(entries)
    index = dict(entries)

    # Every disclosed leaf must match its manifest digest and inclusion proof.
    for key, leaf in bundle.get("leaves", {}).items():
        checks += 1
        digest = merkle.event_leaf_digest(leaf) if leaf.get("kind") == "event" \
            else merkle.generic_leaf_digest(leaf)
        if not _check(digest == index.get(key), f"leaf digest mismatch: {key}", failures):
            continue
        proof = next((p for p in bundle.get("inclusion_proofs", []) if p["key"] == key), None)
        checks += 1
        _check(proof is not None and merkle.verify_inclusion(root, key, digest, proof),
               f"inclusion proof invalid: {key}", failures)
        if leaf.get("kind") == "event":
            if leaf.get("redacted"):
                # A status-only reader must receive no plaintext or value hash.
                _check(not leaf.get("secret_value_commitments"),
                       f"redacted leaf leaked value commitments: {key}", failures)
                _check(_no_secret_survives(leaf),
                       f"redacted leaf still contains a sensitive field: {key}", failures)
            else:
                # A privileged reader can check each secret against its commitment.
                for commitment in leaf.get("secret_value_commitments", []):
                    field = commitment["field"]
                    expected = merkle.field_commitment(field, leaf["input"].get(field))
                    _check(expected == commitment,
                           f"full leaf value commitment mismatch: {key}.{field}", failures)
                _check(merkle.digest(leaf["result"]) == leaf.get("_result_hash"),
                       f"full leaf result hash mismatch: {key}", failures)

    # Every redaction marker must correspond to a disclosed redacted leaf.
    if bundle.get("redactions"):
        for key in bundle["redactions"]:
            leaf = bundle.get("leaves", {}).get(key)
            _check(leaf is not None and leaf.get("redacted") is True,
                   f"redaction marker without redacted leaf: {key}", failures)
        _check(any(bundle["leaves"][k].get("redacted") for k in bundle["redactions"]),
               "redaction set contains no actually redacted leaf", failures)

    # Absence proofs: e.g. no convergence confirmation existed at seal time.
    manifest_pairs = [(item["key"], item["digest"]) for item in manifest]
    for proof in bundle.get("absence_proofs", []):
        checks += 1
        _check(merkle.verify_absence(root, proof["key"], manifest_pairs, proof),
               f"absence proof invalid: {proof.get('key')}", failures)

    # Propositions must be grounded in disclosed/committed leaves and absence.
    for prop in bundle.get("propositions", []):
        checks += 1
        _check(_verify_proposition(prop, bundle, tree, index),
               f"proposition not provable from bundle: {prop.get('statement')}", failures)

    # Appendix volumes: anchor back to the original, immutable seal root.
    for att in bundle.get("attachments", []):
        checks += 1
        att_entries = [(item["key"], item["digest"]) for item in att["manifest"]]
        _check(merkle.root_for(att_entries) == att["root"],
               f"attachment root mismatch: {att['attachment_id']}", failures)
        anchor = att["leaves"].get(att["anchor_key"])
        checks += 1
        _check(anchor is not None and anchor.get("seal_root") == bundle["seal_root"],
               f"attachment anchor not bound to seal root: {att['attachment_id']}", failures)
        for key, leaf in att["leaves"].items():
            digest = merkle.event_leaf_digest(leaf) if leaf.get("kind") == "event" \
                else merkle.generic_leaf_digest(leaf)
            checks += 1
            _check(digest == dict(att_entries).get(key),
                   f"attachment leaf digest mismatch: {key}", failures)

    return {"valid": not failures, "checks": checks, "failures": failures,
            "seal_id": bundle.get("seal_id"), "audience": bundle.get("audience"),
            "role": bundle.get("role"), "root": root,
            "propositions": [p["statement"] for p in bundle.get("propositions", [])],
            "attachments": len(bundle.get("attachments", []))}


def _verify_proposition(prop, bundle, tree, index):
    statement = prop.get("statement")
    leaves = bundle.get("leaves", {})
    if statement == "policy_published":
        leaf = leaves.get(prop["leaf_key"])
        return leaf is not None and leaf["kind_name"] == "policy.publish" \
            and leaf["result"].get("status") == "active"
    if statement == "receipt_applied_only":
        leaf = leaves.get(prop["leaf_key"])
        if leaf is None or leaf["kind_name"] != "drift.receipt" \
                or leaf["result"].get("status") != "applied":
            return False
        # No independently-confirmed assertion for this action exists in the
        # sealed manifest (absence proof is also supplied in the bundle).
        action = prop["action_id"]
        return not any(key.startswith(f"assert:confirm:{action}:") for key in tree.keys)
    if statement == "independently_confirmed":
        leaf = leaves.get(prop["leaf_key"])
        return leaf is not None and leaf["kind_name"] == "drift.confirm" \
            and leaf["result"].get("status") in ("confirmed", "converged")
    return False


def verify_credential(credential, issuer_secret_hex):
    from .compliance_seal import verify_signature
    signature = credential.get("signature", {})
    message = {key: value for key, value in credential.items() if key != "signature"}
    return verify_signature(issuer_secret_hex, message, signature)
