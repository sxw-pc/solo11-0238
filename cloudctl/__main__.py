"""Command line entry for the three independent control-plane subsystems."""

import argparse
import json
import sys
from pathlib import Path

from .audit import report, verify_sealed_evidence
from .db import DecisionError, connect, initialize
from .executor import execute
from . import compliance_seal, verifier


def parse():
    parser = argparse.ArgumentParser(prog="python -m cloudctl")
    parser.add_argument("subsystem", choices=("init", "policy", "agent", "drift", "demo", "report",
                                              "seal", "verify"))
    parser.add_argument("operation", nargs="?")
    parser.add_argument("--db", default="state.sqlite")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--input", help="JSON object for one operation")
    parser.add_argument("--request-id")
    parser.add_argument("--bundle", type=Path, help="certificate/credential bundle for verify")
    parser.add_argument("--key", help="issuer key hex for verify")
    return parser.parse_args()


def load_input(arguments):
    if arguments.fixture and arguments.input:
        raise DecisionError("choose --fixture or --input")
    if arguments.fixture:
        return json.loads(arguments.fixture.read_text(encoding="utf-8"))
    if arguments.input:
        return json.loads(arguments.input)
    raise DecisionError("one operation needs --fixture or --input")


def run_scenario(connection, scenario):
    result = []
    for index, step in enumerate(scenario["steps"]):
        subsystem = step["subsystem"]
        operation = step["operation"]
        request_id = step.get("request_id", f"fixture:{index}:{subsystem}.{operation}")
        result.append({"step": index + 1, "request_id": request_id,
                       "result": execute(connection, subsystem, operation, step["payload"], request_id)})
    return {"scenario": scenario.get("name", "unnamed"), "steps": result, "audit": report(connection)}


def run_seal(connection, arguments):
    operation = arguments.operation
    if operation == "audit":
        return verify_sealed_evidence(connection)
    if arguments.input:
        payload = json.loads(arguments.input)
    elif arguments.fixture:
        payload = json.loads(arguments.fixture.read_text(encoding="utf-8"))
    else:
        raise DecisionError("this seal operation needs --input or --fixture")
    if operation == "window":
        return compliance_seal.seal_window(
            connection, payload["service"], payload["start"], payload["end"], payload["at"])
    if operation == "attach":
        return compliance_seal.attach_late(connection, payload["seal_id"], payload["at"])
    if operation == "certify":
        result = compliance_seal.issue_certificate(
            connection, payload["seal_id"], payload["audience"], payload["role"])
        result["audience_key"] = compliance_seal.export_key(
            connection, f"audience:{payload['audience']}")
        return result
    if operation == "supplement":
        return compliance_seal.supplement(
            connection, payload["seal_id"], payload["audience"], payload["role"],
            payload["attachment_ids"], payload["at"])
    if operation == "revoke":
        return compliance_seal.revoke_witness(
            connection, payload["key_id"], payload["at"], payload.get("reason", ""))
    if operation == "archive":
        return compliance_seal.archive_leaves(connection, payload["seal_id"])
    if operation == "key":
        return compliance_seal.export_key(connection, payload["key_id"])
    raise DecisionError(f"unknown seal operation: {operation}")


def run_verify(arguments):
    if not arguments.bundle or not arguments.key:
        raise DecisionError("verify needs --bundle and --key")
    bundle = json.loads(arguments.bundle.read_text(encoding="utf-8"))
    schema = bundle.get("schema", "")
    if schema == "cloudctl-compliance-cert/1":
        return verifier.verify_bundle(bundle, arguments.key)
    if schema in ("cloudctl-compliance-supplement/1", "cloudctl-compliance-revocation/1"):
        return {"valid": verifier.verify_credential(bundle, arguments.key), "schema": schema}
    raise DecisionError(f"unknown bundle schema: {schema}")


def main():
    arguments = parse()
    connection = connect(arguments.db)
    initialize(connection)
    try:
        if arguments.subsystem == "init":
            output = {"status": "initialized", "db": str(arguments.db)}
        elif arguments.subsystem == "report":
            output = report(connection)
        elif arguments.subsystem == "seal":
            output = run_seal(connection, arguments)
        elif arguments.subsystem == "verify":
            output = run_verify(arguments)
        elif arguments.subsystem == "demo":
            source = arguments.fixture or Path(__file__).resolve().parent.parent / "fixtures" / "demo.json"
            output = run_scenario(connection, json.loads(source.read_text(encoding="utf-8")))
        else:
            if not arguments.operation:
                raise DecisionError("subsystem operation is required")
            payload = load_input(arguments)
            if "steps" in payload:
                output = run_scenario(connection, payload)
            else:
                request_id = arguments.request_id or payload.get("request_id")
                if not request_id:
                    raise DecisionError("request_id is required for one operation")
                output = execute(connection, arguments.subsystem, arguments.operation, payload, str(request_id))
        print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
        return 2 if output.get("status") in ("rejected", "blocked", "paused") else 0
    except (DecisionError, ValueError, KeyError, OSError) as error:
        print(json.dumps({"status": "invalid", "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
