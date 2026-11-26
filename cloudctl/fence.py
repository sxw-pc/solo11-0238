"""Write fencing: skew-aware leases, fence receipts and gateway block proofs.

The control court writing a new lease row is *not* isolation.  Before a new
leader opens writes the court must hold at least one of:

1. a verified fence receipt from the old writer for the new fence epoch
   (the old writer durably promises to reject stale-epoch writes), or
2. signed block proofs from every independent gateway that owns a client
   entry path to the old writer.

The helpers here are deliberately executable: gateway proofs are checked with
HMAC secrets and the simulated gateways in :mod:`cloudctl.cluster` enforce the
same rules the proofs attest to.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .wal_chain import canonical


# ---------------------------------------------------------------------------
# Skew aware lease admission
# ---------------------------------------------------------------------------

def local_time(real_time: int, *, lag: int = 0, drift_offset: int = 0) -> int:
    """What the node's own clock reads at ``real_time``.

    ``lag`` models a slow clock: local time is ``real - lag``.  The drill's
    node A has lag 4: its lease ends at local 30 but it can still consider the
    lease valid at real time 34.
    """
    return real_time - lag + drift_offset


def lease_admits(*, real_time: int, lag: int = 0,
                 lease_until_local: Optional[int],
                 lease_term: Optional[int],
                 write_term: int,
                 highest_fence_epoch: int = 0) -> Tuple[bool, str]:
    """Would a node still accept an old-lease write at ``real_time``?

    Fence epochs are the election terms.  Once the node has durably accepted a
    fence for epoch E, every write carrying a term/epoch below E is rejected
    regardless of its local clock.
    """
    if write_term < highest_fence_epoch:
        return False, "fenced_stale_epoch"
    if lease_term is None or lease_until_local is None:
        return False, "no_local_lease"
    if write_term != lease_term:
        return False, "term_not_lease_holder"
    shown = local_time(real_time, lag=lag)
    if shown <= lease_until_local:
        return True, f"lease_valid_local_{shown}_until_{lease_until_local}"
    return False, f"lease_expired_local_{shown}_until_{lease_until_local}"


# ---------------------------------------------------------------------------
# Signed fence receipts
# ---------------------------------------------------------------------------

def fence_request(*, target: str, epoch: int, nonce: str, at: int,
                  requester: str = "court") -> Dict[str, object]:
    return {"kind": "fence_request", "target": target, "epoch": epoch,
            "nonce": nonce, "at": at, "requester": requester}


def _hmac(secret: str, payload: Mapping[str, object]) -> str:
    return hmac.new(("fence-v1:" + secret).encode("utf-8"),
                    canonical(payload).encode("utf-8"),
                    "sha256").hexdigest()


def fence_receipt(*, node: str, secret: str, epoch: int, nonce: str,
                  boot: int, at: int,
                  prior_lease_term: Optional[int] = None) -> Dict[str, object]:
    body = {"kind": "fence_receipt", "node": node, "epoch": epoch,
            "nonce": nonce, "boot": boot, "at": at,
            "prior_lease_term": prior_lease_term}
    body["sig"] = _hmac(secret, {k: v for k, v in body.items() if k != "sig"})
    return body


def verify_fence_receipt(receipt: Mapping[str, object],
                         node_secret: str) -> bool:
    if receipt.get("kind") != "fence_receipt" or "sig" not in receipt:
        return False
    supplied = str(receipt["sig"])
    expected = _hmac(node_secret,
                     {k: v for k, v in receipt.items() if k != "sig"})
    return hmac.compare_digest(supplied, expected)


def lease_closed_receipt(*, node: str, secret: str, term: int, boot: int,
                         at: int) -> Dict[str, object]:
    """B promises its old term-N write lease is durably closed."""
    body = {"kind": "lease_closed", "node": node, "term": term,
            "boot": boot, "at": at}
    body["sig"] = _hmac(secret, {k: v for k, v in body.items() if k != "sig"})
    return body


def verify_lease_closed(receipt: Mapping[str, object], node_secret: str) -> bool:
    if receipt.get("kind") != "lease_closed" or "sig" not in receipt:
        return False
    supplied = str(receipt["sig"])
    expected = _hmac(node_secret,
                     {k: v for k, v in receipt.items() if k != "sig"})
    return hmac.compare_digest(supplied, expected)


# ---------------------------------------------------------------------------
# Independent gateway block / closed proofs
# ---------------------------------------------------------------------------

def block_proof(*, gateway: str, gateway_secret: str, path_id: str,
                target: str, rule_version: int, at: int,
                state: str = "blocked",
                scope: str = "client-writes") -> Dict[str, object]:
    body = {"kind": "gateway_block_proof", "gateway": gateway,
            "path_id": path_id, "target": target,
            "rule_version": rule_version, "at": at,
            "state": state, "scope": scope}
    body["sig"] = _hmac(gateway_secret,
                        {k: v for k, v in body.items() if k != "sig"})
    return body


def verify_block_proof(proof: Mapping[str, object],
                       gateway_secret: str) -> bool:
    if proof.get("kind") != "gateway_block_proof" or "sig" not in proof:
        return False
    supplied = str(proof["sig"])
    expected = _hmac(gateway_secret,
                     {k: v for k, v in proof.items() if k != "sig"})
    return hmac.compare_digest(supplied, expected)


@dataclass
class FenceCoverage:
    satisfied: bool
    mode: Optional[str] = None          # receipt | gateways | None
    missing_paths: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    evidence_keys: List[str] = field(default_factory=list)

    def reason(self) -> str:
        if self.satisfied:
            return f"fence_satisfied:{self.mode}"
        if self.missing_paths:
            return "missing_gateway_proof:" + ",".join(self.missing_paths)
        return "fence_unsatisfied:" + ",".join(self.problems)


def evaluate_fence(*, old_node: str, epoch: int,
                   required_paths: Sequence[str],
                   node_secrets: Mapping[str, str],
                   gateway_secrets: Mapping[str, str],
                   fence_receipts: Sequence[Mapping[str, object]] = (),
                   gateway_proofs: Sequence[Mapping[str, object]] = (),
                   require_lease_closed: Optional[int] = None,
                   lease_closed_receipts: Sequence[Mapping[str, object]] = (),
                   receipt_can_satisfy: bool = True,
                   ) -> FenceCoverage:
    """Decide whether the old writer is safely contained.

    Receipt path (unless ``receipt_can_satisfy=False``): one valid fence
    receipt for ``old_node`` + ``epoch``.

    Gateway path: one valid, current block proof for every path id in
    ``required_paths`` whose attested target is ``old_node``.  Proofs must be
    signed by the owning independent gateway; a court written row cannot pass.

    ``require_lease_closed`` additionally demands a signed lease-close receipt
    for that old term (plan A asks for B's old lease *and* gateway closure).
    When that stronger closure is requested the receipt-only shortcut is not
    accepted; exhaustive gateway coverage is evaluated as well.
    """
    problems: List[str] = []
    keys: List[str] = []

    # Option 1: old writer fence receipt.
    if receipt_can_satisfy and require_lease_closed is None:
        for receipt in fence_receipts:
            if receipt.get("node") != old_node or receipt.get("epoch") != epoch:
                continue
            secret = node_secrets.get(old_node, "")
            if verify_fence_receipt(receipt, secret):
                keys.append(f"fence-receipt:{old_node}:{epoch}:{receipt.get('nonce')}")
                return FenceCoverage(True, "receipt", evidence_keys=keys)
            problems.append("invalid_fence_receipt_signature")

    # Option 2: exhaustive independent gateway coverage.
    proofs_by_path: Dict[str, Mapping[str, object]] = {}
    for proof in gateway_proofs:
        path_id = str(proof.get("path_id"))
        gw = str(proof.get("gateway"))
        secret = gateway_secrets.get(gw, "")
        if not verify_block_proof(proof, secret):
            problems.append(f"bad_gateway_signature:{gw}")
            continue
        if proof.get("target") != old_node:
            continue
        if proof.get("state") not in ("blocked", "closed"):
            problems.append(f"proof_not_closed:{path_id}:{proof.get('state')}")
            continue
        # Latest rule version wins; callers pass the current expected set.
        prior = proofs_by_path.get(path_id)
        if prior is None or proof["rule_version"] > prior["rule_version"]:
            proofs_by_path[path_id] = proof

    missing = [p for p in required_paths if p not in proofs_by_path]
    if not missing and required_paths:
        keys = [f"gateway-proof:{p}:v{proofs_by_path[p]['rule_version']}"
                for p in required_paths]
        if require_lease_closed is not None:
            close_ok = any(
                r.get("node") == old_node
                and r.get("term") == require_lease_closed
                and verify_lease_closed(r, node_secrets.get(old_node, ""))
                for r in lease_closed_receipts
            )
            if not close_ok:
                return FenceCoverage(False, "gateways",
                                     missing_paths=[],
                                     problems=["missing_lease_closed_receipt"])
            keys.append(f"lease-closed:{old_node}:{require_lease_closed}")
        return FenceCoverage(True, "gateways", evidence_keys=keys)

    if not required_paths:
        problems.append("no_client_paths_registered")
    return FenceCoverage(False, None, missing_paths=missing, problems=problems)
