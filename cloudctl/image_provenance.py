"""Ingest the verifiable supply-chain graph behind offline image builds.

A build packet binds one top-level image digest to its source commit, build
environment, product layers, signing key generation and scanner data.  Layer
evidence maps every layer hash to the upstream layer it physically came from
and to the origin that vouches for that upstream.  Same tag, different content
and shared tainted base layers are therefore visible as graph facts instead of
being hidden inside a "last attestation wins" rule.

All writes are natural-key idempotent so replaying the durable event log after
a restart neither duplicates rows nor changes any decision.
"""

from .db import DecisionError, decision, row, rows


REQUIRED_BUILD_FIELDS = ("build", "image", "tag", "digest", "source_commit",
                         "environment_digest", "layers", "signing_key", "key_generation",
                         "builder", "at")


def _key_exists(connection, table, key_fields, values):
    where = " AND ".join(f"{field}=?" for field in key_fields)
    return row(connection, f"SELECT * FROM {table} WHERE {where}", values)


def record_build(connection, payload):
    missing = [name for name in REQUIRED_BUILD_FIELDS if name not in payload]
    if missing:
        raise DecisionError("missing fields: " + ", ".join(missing))
    build, image, tag = str(payload["build"]), str(payload["image"]), str(payload["tag"])
    digest = str(payload["digest"])
    layers = payload["layers"]
    if (not isinstance(layers, list) or not layers
            or any(not isinstance(item, str) or not item for item in layers)):
        raise DecisionError("layers must be a non-empty list of layer digests")
    if len(set(layers)) != len(layers):
        raise DecisionError("duplicate layer in build manifest")
    key = _key_exists(connection, "image_builds", ("build",), (build,))
    if key:
        immutable = ("image", "tag", "digest", "source_commit", "environment_digest",
                     "signing_key", "key_generation", "builder", "parent_build")
        changed = [name for name in immutable
                   if str(key[name] if key[name] is not None else "") != str(payload.get(name, ""))]
        if changed:
            raise DecisionError("build packet conflicts with an already captured build: "
                                + ", ".join(changed))
        stored = rows(connection, "SELECT layer FROM image_build_layers WHERE build=? ORDER BY position",
                      (build,))
        if [item["layer"] for item in stored] != layers:
            raise DecisionError("build packet conflicts on layer manifest")
        return decision("replayed", "same build packet already captured", build=build, digest=digest)
    parent_build = payload.get("parent_build")
    if parent_build is not None and not _key_exists(connection, "image_builds", ("build",),
                                                    (str(parent_build),)):
        raise DecisionError("parent build is not captured yet")
    packet = str(payload.get("packet", f"build-packet:{build}"))
    packet_digest = str(payload.get("packet_digest", packet))
    connection.execute(
        "INSERT INTO image_builds(build,image,tag,digest,source_commit,environment_digest,"
        "signing_key,key_generation,builder,captured_at,parent_build,packet,packet_digest) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (build, image, tag, digest, str(payload["source_commit"]),
         str(payload["environment_digest"]), str(payload["signing_key"]),
         int(payload["key_generation"]), str(payload["builder"]), int(payload["at"]),
         str(parent_build) if parent_build is not None else None, packet, packet_digest),
    )
    for position, layer in enumerate(layers):
        existing = _key_exists(connection, "image_layers", ("digest",), (layer,))
        if not existing:
            # Position zero is the base image; later manifest entries are product layers.
            kind = "base" if position == 0 else str(payload.get("layer_kinds", {}).get(layer, "product"))
            connection.execute("INSERT INTO image_layers(digest,kind) VALUES(?,?)", (layer, kind))
        elif position == 0 and existing["kind"] == "product":
            connection.execute("UPDATE image_layers SET kind='base' WHERE digest=?", (layer,))
        connection.execute("INSERT INTO image_build_layers(build,layer,position) VALUES(?,?,?)",
                           (build, layer, position))
    return decision("captured", "build bound to source, environment, layers and signing key generation",
                    build=build, image=image, tag=tag, digest=digest, layers=layers,
                    parent_build=str(parent_build) if parent_build is not None else None)


def register_origin(connection, payload):
    origin_id, description = str(payload["origin_id"]), str(payload["description"])
    trusted = bool(payload["trusted"])
    existing = _key_exists(connection, "image_origins", ("origin_id",), (origin_id,))
    if existing:
        if bool(existing["trusted"]) != trusted or existing["description"] != description:
            raise DecisionError("origin record is immutable and conflicts with the new statement")
        return decision("replayed", "origin already registered", origin_id=origin_id, trusted=trusted)
    connection.execute("INSERT INTO image_origins(origin_id,description,trusted) VALUES(?,?,?)",
                       (origin_id, description, int(trusted)))
    return decision("registered", "upstream origin trust position recorded",
                    origin_id=origin_id, trusted=trusted)


def add_layer_evidence(connection, payload):
    for name in ("evidence_id", "layer_digest", "source_layer", "origin_id", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    evidence_id = str(payload["evidence_id"])
    existing = _key_exists(connection, "image_layer_evidence", ("evidence_id",), (evidence_id,))
    if existing:
        same = all(existing[name] == str(payload[name])
                   for name in ("layer_digest", "source_layer", "origin_id"))
        if not same:
            raise DecisionError("evidence id reused with a different layer-origin statement")
        return decision("replayed", "layer evidence already captured", evidence_id=evidence_id)
    origin_id = str(payload["origin_id"])
    if not _key_exists(connection, "image_origins", ("origin_id",), (origin_id,)):
        raise DecisionError("unknown origin; register its trust position first")
    layer_digest, source_layer = str(payload["layer_digest"]), str(payload["source_layer"])
    target = _key_exists(connection, "image_layers", ("digest",), (layer_digest,))
    if not target:
        connection.execute("INSERT INTO image_layers(digest,kind) VALUES(?,?)",
                           (layer_digest, "base"))
    elif target["kind"] == "product":
        # A layer backed by upstream evidence is a base layer, not a pure product layer.
        connection.execute("UPDATE image_layers SET kind='base' WHERE digest=?", (layer_digest,))
    if not _key_exists(connection, "image_layers", ("digest",), (source_layer,)):
        connection.execute("INSERT INTO image_layers(digest,kind) VALUES(?,?)",
                           (source_layer, "upstream"))
    connection.execute(
        "INSERT INTO image_layer_evidence(layer_digest,source_layer,origin_id,evidence_id,recorded_at) "
        "VALUES(?,?,?,?,?)",
        (layer_digest, source_layer, origin_id, evidence_id, int(payload["at"])),
    )
    return decision("captured", "layer-to-upstream provenance edge recorded",
                    evidence_id=evidence_id, layer_digest=layer_digest,
                    source_layer=source_layer, origin_id=origin_id)


def retract_layer_evidence(connection, payload):
    for name in ("evidence_id", "at", "reason"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    evidence_id, at = str(payload["evidence_id"]), int(payload["at"])
    existing = _key_exists(connection, "image_layer_evidence", ("evidence_id",), (evidence_id,))
    if not existing:
        raise DecisionError("unknown evidence id")
    if existing["retracted_at"] is not None:
        if existing["retracted_at"] != at:
            raise DecisionError("evidence retraction time is immutable")
        return decision("replayed", "evidence already retracted", evidence_id=evidence_id)
    connection.execute("UPDATE image_layer_evidence SET retracted_at=? WHERE evidence_id=?",
                       (at, evidence_id))
    return decision("retracted", "provenance edge withdrawn; old permit decisions remain on the books",
                    evidence_id=evidence_id, layer_digest=existing["layer_digest"], at=at)


def register_key(connection, payload):
    key_id, generation = str(payload["key_id"]), int(payload["generation"])
    existing = _key_exists(connection, "image_signing_keys", ("key_id", "generation"),
                           (key_id, generation))
    if existing:
        return decision("replayed", "signing key generation already registered",
                        key_id=key_id, generation=generation,
                        revoked=existing["revoked_at"] is not None)
    connection.execute("INSERT INTO image_signing_keys(key_id,generation,revoked_at) VALUES(?,?,NULL)",
                       (key_id, generation))
    return decision("registered", "signing key generation recorded",
                    key_id=key_id, generation=generation, revoked=False)


def revoke_key(connection, payload):
    key_id, generation = str(payload["key_id"]), int(payload["generation"])
    existing = _key_exists(connection, "image_signing_keys", ("key_id", "generation"),
                           (key_id, generation))
    if not existing:
        raise DecisionError("unknown signing key generation")
    revoked_at = int(payload["at"])
    if existing["revoked_at"] is not None:
        if existing["revoked_at"] != revoked_at:
            raise DecisionError("revocation time is immutable")
        return decision("replayed", "key generation already revoked",
                        key_id=key_id, generation=generation, revoked_at=revoked_at)
    connection.execute(
        "UPDATE image_signing_keys SET revoked_at=?,revoke_reason=? WHERE key_id=? AND generation=?",
        (revoked_at, str(payload.get("reason", "")), key_id, generation),
    )
    return decision("revoked", "signing key generation revoked; historic permits stay on the books",
                    key_id=key_id, generation=generation, revoked_at=revoked_at)


def add_scanner_rule(connection, payload):
    for name in ("rule_id", "scanner_version", "layer_kind", "min_level", "effective_at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    rule_id = str(payload["rule_id"])
    existing = _key_exists(connection, "image_scanner_rules", ("rule_id",), (rule_id,))
    fields = ("scanner_version", "layer_kind", "min_level", "effective_at")
    values = (str(payload["scanner_version"]), str(payload["layer_kind"]),
              str(payload["min_level"]), int(payload["effective_at"]))
    if existing:
        if tuple(existing[name] for name in fields) != values:
            raise DecisionError("scanner rule is immutable")
        return decision("replayed", "scanner rule already recorded", rule_id=rule_id)
    connection.execute(
        "INSERT INTO image_scanner_rules(rule_id,scanner_version,layer_kind,min_level,effective_at) "
        "VALUES(?,?,?,?,?)",
        (rule_id, *values),
    )
    return decision("recorded", "scanner vulnerability rule recorded and time-bounded",
                    rule_id=rule_id, scanner_version=values[0], effective_at=values[3])


def record_scan(connection, payload):
    for name in ("build", "scanner_version", "full_layer", "target_digest", "scanned_at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    build = str(payload["build"])
    build_row = _key_exists(connection, "image_builds", ("build",), (build,))
    if not build_row:
        raise DecisionError("scan references an unknown build")
    full_layer = bool(payload["full_layer"])
    if str(payload["target_digest"]) != build_row["digest"]:
        raise DecisionError("scan does not cover the final digest that will run")
    scanner_version = str(payload["scanner_version"])
    existing = row(
        connection,
        "SELECT * FROM image_scans WHERE build=? AND scanner_version=? AND full_layer=?",
        (build, scanner_version, int(full_layer)),
    )
    if existing:
        if (existing["target_digest"] != str(payload["target_digest"])
                or existing["scanned_at"] != int(payload["scanned_at"])):
            raise DecisionError("scan record is immutable")
        return decision("replayed", "scan already recorded", build=build,
                        scanner_version=scanner_version, full_layer=full_layer)
    connection.execute(
        "INSERT INTO image_scans(build,scanner_version,full_layer,target_digest,scanned_at) "
        "VALUES(?,?,?,?,?)",
        (build, scanner_version, int(full_layer), str(payload["target_digest"]),
         int(payload["scanned_at"])),
    )
    return decision("recorded", "scanner coverage for the final digest recorded",
                    build=build, scanner_version=scanner_version, full_layer=full_layer)


def record_layer_finding(connection, payload):
    for name in ("layer_digest", "vuln_level", "at"):
        if name not in payload:
            raise DecisionError(f"missing field: {name}")
    layer_digest, vuln_level = str(payload["layer_digest"]), str(payload["vuln_level"])
    if vuln_level not in ("none", "low", "medium", "high", "critical"):
        raise DecisionError("unknown vulnerability level")
    existing = _key_exists(connection, "image_layers", ("digest",), (layer_digest,))
    if not existing:
        connection.execute("INSERT INTO image_layers(digest,kind,vuln_level) VALUES(?,?,?)",
                           (layer_digest, "base", vuln_level))
        return decision("recorded", "vulnerability finding recorded for new layer",
                        layer_digest=layer_digest, vuln_level=vuln_level)
    if existing["vuln_level"] != vuln_level:
        raise DecisionError("vulnerability finding is immutable; issue a new rule or order instead")
    return decision("replayed", "same vulnerability finding already recorded",
                    layer_digest=layer_digest, vuln_level=vuln_level)


HANDLERS = {
    "build": record_build,
    "origin": register_origin,
    "layer_evidence": add_layer_evidence,
    "retract_evidence": retract_layer_evidence,
    "layer_finding": record_layer_finding,
    "key": register_key,
    "revoke_key": revoke_key,
    "scanner_rule": add_scanner_rule,
    "scan": record_scan,
}
