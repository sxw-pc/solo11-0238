"""Hash chained, physically attributed and countersigned WAL pages.

The legacy :mod:`cloudctl.wal_capture` rows only carry ``node/term/index/
digest/ack``.  A digest at the same index from a higher term can therefore be
mistaken for a valid replacement of a client acknowledged entry.  The pages
in this module retain, on every record:

``node``        physical node that wrote the item,
``boot``        monotonic boot generation of that physical node,
``prev_digest`` content digest of the preceding item in the chain,
``signer``      identity that signed the page (the origin writer),
``sig``         HMAC over every field above.

Replicated/imported copies keep the original ``node``/``signer``/``term`` so a
repaired prefix can always be traced back to the physical writer that the
client receipt was bound to.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence


GENESIS_DIGEST = "0" * 64

# Fields covered by the signature.  ``sig`` itself is obviously excluded.
RECORD_FIELDS = (
    "node", "boot", "term", "index", "digest", "prev_digest",
    "signer", "ack", "request_id",
)
REQUIRED_PAGE_FIELDS = ("node", "boot", "term", "index", "digest",
                        "prev_digest", "signer", "sig")


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def content_digest(payload: object) -> str:
    """Real SHA-256 content digest used when a caller does not pin a label."""
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def record_hash(record: Mapping[str, object]) -> str:
    """Hash of the whole signed record (used as chain head evidence)."""
    material = canonical({k: record.get(k) for k in RECORD_FIELDS})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _key(secret: str) -> bytes:
    return ("cloudctl-wal-v1:" + secret).encode("utf-8")


def signature_for(record: Mapping[str, object], secret: str) -> str:
    material = canonical({k: record.get(k) for k in RECORD_FIELDS})
    return hmac.new(_key(secret), material.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def sign_record(fields: Mapping[str, object], secret: str) -> Dict[str, object]:
    record = {k: fields.get(k) for k in RECORD_FIELDS}
    record["sig"] = signature_for(record, secret)
    return record


def verify_signature(record: Mapping[str, object], secret: str) -> bool:
    supplied = record.get("sig")
    if not isinstance(supplied, str):
        return False
    expected = signature_for(record, secret)
    return hmac.compare_digest(supplied, expected)


def validate_page(record: Mapping[str, object]) -> List[str]:
    """Structural validation; returns a list of problems (empty == valid)."""
    problems: List[str] = []
    if not isinstance(record, Mapping):
        return ["page_not_object"]
    for name in REQUIRED_PAGE_FIELDS:
        if name not in record:
            problems.append(f"missing_{name}")
    if problems:
        return problems
    if not isinstance(record["node"], str) or not record["node"]:
        problems.append("bad_node")
    if type(record["boot"]) is not int or record["boot"] < 1:
        problems.append("bad_boot_generation")
    if type(record["term"]) is not int or record["term"] < 0:
        problems.append("bad_term")
    if type(record["index"]) is not int or record["index"] < 1:
        problems.append("bad_index")
    if not isinstance(record["digest"], str) or not record["digest"]:
        problems.append("bad_digest")
    if not isinstance(record["prev_digest"], str) or not record["prev_digest"]:
        problems.append("bad_prev_digest")
    if not isinstance(record["signer"], str) or not record["signer"]:
        problems.append("bad_signer")
    if type(record["ack"]) is not bool:
        problems.append("bad_ack_marker")
    if record.get("request_id") is not None and not isinstance(record["request_id"], str):
        problems.append("bad_request_id")
    return problems


@dataclass
class ChainVerification:
    ok: bool
    errors: List[str] = field(default_factory=list)
    verified_indexes: List[int] = field(default_factory=list)

    def raise_if_broken(self) -> None:
        if not self.ok:
            raise InvalidChain(";".join(self.errors))


class InvalidChain(ValueError):
    pass


class LogConflict(ValueError):
    """Same log position carries two different content digests."""

    def __init__(self, index: int, digests: Sequence[str], *, detail: str = ""):
        self.index = index
        self.digests = tuple(digests)
        super().__init__(
            f"log_conflict@{index}: {sorted(set(digests))} {detail}".strip()
        )


def verify_chain(records: Sequence[Mapping[str, object]],
                 secrets: Optional[Mapping[str, str]] = None,
                 *, check_signatures: bool = True) -> ChainVerification:
    """Verify contiguity, prev-digest links and HMAC signatures.

    ``secrets`` maps signer identity to HMAC secret.  When omitted a signer is
    accepted structurally (used for offline pages whose key registry lives in
    the court); production callers always pass the registry.
    """
    errors: List[str] = []
    verified: List[int] = []
    ordered = sorted(records, key=lambda r: r["index"])
    expected_index = 1
    expected_prev = GENESIS_DIGEST
    for pos, rec in enumerate(ordered):
        structural = validate_page(rec)
        if structural:
            errors.extend(f"index?{pos}:{problem}" for problem in structural)
            continue
        idx = rec["index"]
        if pos == 0:
            # A witness may retain an anchored partial page (e.g. only item 11
            # carrying the item-10 digest).  Only a chain starting at 1 is
            # required to anchor at the genesis digest.
            if idx == 1 and rec["prev_digest"] != GENESIS_DIGEST:
                errors.append("bad_genesis_prev@1")
        else:
            if idx != expected_index:
                errors.append(f"non_contiguous expected_{expected_index}_got_{idx}")
                # Resynchronise expectations to the actual record.
                expected_index = idx
            if rec["prev_digest"] != expected_prev:
                errors.append(
                    f"broken_prev_link@{idx}: expected {expected_prev[:12]} "
                    f"got {str(rec['prev_digest'])[:12]}"
                )
        if check_signatures:
            signer = rec["signer"]
            secret = None if secrets is None else secrets.get(signer)
            if secret is None:
                errors.append(f"unknown_signer@{idx}:{signer}")
            elif not verify_signature(rec, secret):
                errors.append(f"bad_signature@{idx}:{signer}")
        verified.append(idx)
        expected_prev = rec["digest"]
        expected_index = idx + 1
    return ChainVerification(not errors, errors, verified)


class WalLog:
    """In-memory contiguous WAL for one physical holder."""

    def __init__(self, holder: str, secret: Optional[str] = None, *,
                 origin_secret: Optional[Mapping[str, str]] = None):
        self.holder = holder
        self.secret = secret or f"secret-{holder}"
        self.secrets = dict(origin_secret or {})
        self.secrets.setdefault(holder, self.secret)
        self._records: List[Dict[str, object]] = []

    # ----- construction --------------------------------------------------
    def append(self, *, term: int, digest: Optional[str] = None,
               payload: Optional[object] = None, ack: bool = False,
               request_id: Optional[str] = None, boot: int = 1,
               at_index: Optional[int] = None) -> Dict[str, object]:
        if self._records:
            next_index = int(self._records[-1]["index"]) + 1
            prev_digest = self._records[-1]["digest"]
        else:
            next_index = 1
            prev_digest = GENESIS_DIGEST
        idx = at_index if at_index is not None else next_index
        if idx != next_index:
            raise InvalidChain(f"append out of order: {idx} after {next_index - 1}")
        if digest is None:
            digest = content_digest(payload if payload is not None else
                                    {"request_id": request_id, "index": idx})
        fields = {
            "node": self.holder, "boot": boot, "term": term, "index": idx,
            "digest": digest, "prev_digest": prev_digest,
            "signer": self.holder, "ack": ack, "request_id": request_id,
        }
        rec = sign_record(fields, self.secret)
        self._records.append(rec)
        return rec

    def adopt(self, record: Mapping[str, object], *,
              verify: bool = True) -> Dict[str, object]:
        """Replicate/custody an existing signed record without re-signing."""
        rec = dict(record)
        if verify:
            problems = validate_page(rec)
            if problems:
                raise InvalidChain(",".join(problems))
            secret = self.secrets.get(rec["signer"])
            if secret is None or not verify_signature(rec, secret):
                raise InvalidChain(f"unverified_signer:{rec.get('signer')}")
            if self._records:
                expected_index = int(self._records[-1]["index"]) + 1
                expected_prev = self._records[-1]["digest"]
                if rec["index"] != expected_index:
                    raise InvalidChain(
                        f"adopt expected index {expected_index}, got {rec['index']}")
                if rec["prev_digest"] != expected_prev:
                    raise InvalidChain(f"adopt broken prev link at {rec['index']}")
            # Empty holder: accept a valid signed anchored page (e.g. W only
            # retains item 11 plus the previous-item digest).
        self._records.append(rec)
        return rec

    # ----- reading -------------------------------------------------------
    @property
    def records(self) -> List[Dict[str, object]]:
        return list(self._records)

    @property
    def last_index(self) -> int:
        return self._records[-1]["index"] if self._records else 0

    @property
    def head_digest(self) -> Optional[str]:
        return self._records[-1]["digest"] if self._records else None

    def get(self, index: int) -> Optional[Dict[str, object]]:
        for rec in self._records:
            if rec["index"] == index:
                return rec
        return None

    def digest_at(self, index: int) -> Optional[str]:
        rec = self.get(index)
        return None if rec is None else rec["digest"]

    def tail_after(self, index: int) -> List[Dict[str, object]]:
        return [dict(r) for r in self._records if r["index"] > index]

    def truncate_after(self, index: int) -> List[Dict[str, object]]:
        """Detach a divergent tail; returns the removed raw records."""
        removed = self.tail_after(index)
        self._records = [r for r in self._records if r["index"] <= index]
        return removed

    def verify(self) -> ChainVerification:
        return verify_chain(self._records, self.secrets)

    def raw_json(self) -> str:
        return canonical(self._records)

    @classmethod
    def from_records(cls, holder: str,
                     records: Iterable[Mapping[str, object]],
                     secrets: Mapping[str, str]) -> "WalLog":
        log = cls(holder, secrets.get(holder, f"secret-{holder}"),
                  origin_secret=secrets)
        log._records = [dict(r) for r in sorted(records, key=lambda r: r["index"])]
        return log


def first_conflict(log_a: Sequence[Mapping[str, object]],
                   log_b: Sequence[Mapping[str, object]]) -> Optional[int]:
    """First index present in both logs with different digests."""
    da = {r["index"]: r["digest"] for r in log_a}
    db = {r["index"]: r["digest"] for r in log_b}
    for idx in sorted(set(da) & set(db)):
        if da[idx] != db[idx]:
            return idx
    return None


def conflicts_between(logs: Mapping[str, Sequence[Mapping[str, object]]]
                      ) -> List[Dict[str, object]]:
    by_index: Dict[int, Dict[str, str]] = {}
    for node, records in logs.items():
        for rec in records:
            by_index.setdefault(rec["index"], {})[str(rec["digest"])] = node
    out: List[Dict[str, object]] = []
    for idx in sorted(by_index):
        digest_to_nodes = by_index[idx]
        if len(digest_to_nodes) > 1:
            out.append({"index": idx, "digests": sorted(digest_to_nodes),
                        "writers": digest_to_nodes})
    return out


@dataclass
class PrefixBasis:
    """Machine checkable committed-prefix conclusion.

    ``authoritative_index`` is the highest index that is backed by client
    success receipts and an independently verifiable chain.  Divergent
    unacknowledged records past the common prefix are quarantined as conflict
    originals rather than overwritten.
    """

    authoritative_index: int
    authoritative_digest: str
    common_index: int
    records: List[Dict[str, object]]
    conflicts: List[Dict[str, object]] = field(default_factory=list)
    quarantined: List[Dict[str, object]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    def as_bundle(self) -> Dict[str, object]:
        return {
            "authoritative_index": self.authoritative_index,
            "authoritative_digest": self.authoritative_digest,
            "common_index": self.common_index,
            "conflicts": self.conflicts,
            "quarantined_digests": [q.get("digest") for q in self.quarantined],
            "sources": self.sources,
            "record_count": len(self.records),
        }


def build_prefix_basis(*, target: WalLog,
                       authoritative_source: WalLog,
                       ack_receipts: Mapping[str, Mapping[str, object]],
                       ) -> PrefixBasis:
    """Decide the prefix a new leader is allowed to open with.

    ``ack_receipts`` maps client request id -> durable success receipt.  Every
    receipted ``(index, digest)`` must be present in the authoritative source
    chain.  The target may only keep records that match digest-for-digest; a
    divergent tail is returned for quarantine.  Term never participates in
    overwriting a digest conflict.

    The authoritative source may be an anchored partial witness page (W keeps
    x11 and its ``prev_digest``); its first record must connect to the
    matching digest on the target.
    """
    source_verification = authoritative_source.verify()
    if not source_verification.ok:
        raise InvalidChain("authoritative source invalid: "
                           + ";".join(source_verification.errors))
    target_verification = target.verify()
    if not target_verification.ok:
        raise InvalidChain("target log invalid: "
                           + ";".join(target_verification.errors))

    # 1. Every client ACK receipt must resolve into the source chain.
    required: Dict[int, str] = {}
    for req_id, receipt in ack_receipts.items():
        idx = int(receipt["index"])
        digest = str(receipt["digest"])
        src_rec = authoritative_source.get(idx)
        if src_rec is None:
            raise MissingAuthoritativeEntry(
                f"receipt {req_id} requires missing index {idx}")
        if src_rec["digest"] != digest:
            raise LogConflict(idx, [digest, str(src_rec["digest"])],
                              detail=f"receipt {req_id} vs witness chain")
        required[idx] = digest

    acked_index = max(required, default=0)
    if acked_index == 0:
        raise MissingAuthoritativeEntry("no client acknowledged transaction")

    head_rec = authoritative_source.get(acked_index)
    if head_rec is None:  # defensive, covered above
        raise MissingAuthoritativeEntry(f"missing acked index {acked_index}")

    source_up_to_ack = [r for r in authoritative_source.records
                        if int(r["index"]) <= acked_index]
    if not source_up_to_ack:
        raise MissingAuthoritativeEntry("witness has no records up to acked prefix")

    # 2. Anchor the (possibly partial) source chain onto the target prefix.
    first = source_up_to_ack[0]
    first_index = int(first["index"])
    if first_index == 1:
        if first["prev_digest"] != GENESIS_DIGEST:
            raise InvalidChain("source first page has bad genesis anchor")
        common_index = 0
    else:
        anchor_index = first_index - 1
        anchor_rec = target.get(anchor_index)
        if anchor_rec is None:
            raise MissingAuthoritativeEntry(
                f"target lacks anchor index {anchor_index} needed by witness")
        if anchor_rec["digest"] != first["prev_digest"]:
            raise InvalidChain(
                f"witness page {first_index} prev_digest does not connect to "
                f"target index {anchor_index}")
        common_index = anchor_index

    # 3. Walk source records; matching target records extend common prefix,
    #    the first digest mismatch/missing position is the fork.
    repair_records: List[Dict[str, object]] = []
    conflicts: List[Dict[str, object]] = []
    for rec in source_up_to_ack:
        idx = int(rec["index"])
        t_rec = target.get(idx)
        if not repair_records and t_rec is not None \
                and t_rec["digest"] == rec["digest"]:
            common_index = idx
            continue
        if t_rec is not None and t_rec["digest"] != rec["digest"]:
            conflicts.append({
                "index": idx,
                "target_digest": t_rec["digest"],
                "authoritative_digest": rec["digest"],
                "target_term": t_rec.get("term"),
                "target_ack_marker": bool(t_rec.get("ack")),
                "higher_term_cannot_overwrite":
                    int(t_rec.get("term", 0)) > int(rec.get("term", 0)),
            })
        repair_records.append(dict(rec))

    # Validate repair linkage against the target head that will remain.
    cursor_prev = (target.get(common_index)["digest"]
                   if common_index and target.get(common_index)
                   else GENESIS_DIGEST)
    for rec in repair_records:
        if rec["prev_digest"] != cursor_prev:
            raise InvalidChain(
                f"repair record {rec['index']} does not link after common prefix")
        cursor_prev = rec["digest"]

    # 4. Detached target tail is quarantined, but never a record whose digest
    #    is itself covered by a client success receipt.
    quarantined: List[Dict[str, object]] = []
    for rec in target.tail_after(common_index):
        idx = int(rec["index"])
        if idx in required and required[idx] == rec["digest"]:
            raise InvalidChain(
                f"refusing to quarantine client-acknowledged record at {idx}")
        quarantined.append(dict(rec))

    return PrefixBasis(
        authoritative_index=acked_index,
        authoritative_digest=str(head_rec["digest"]),
        common_index=common_index,
        records=repair_records,
        conflicts=conflicts,
        quarantined=quarantined,
        sources=[authoritative_source.holder],
    )


class MissingAuthoritativeEntry(ValueError):
    pass


def apply_prefix_repair(target: WalLog, basis: PrefixBasis) -> List[Dict[str, object]]:
    """Detach the divergent tail and adopt authoritative records.

    The detached records are returned to the caller so they can be preserved
    as conflict originals (they are never deleted silently).
    """
    removed = target.truncate_after(basis.common_index)
    for rec in basis.records:
        target.adopt(rec)
    return removed
