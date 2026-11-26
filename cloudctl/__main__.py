"""Command line entry for the three independent control-plane subsystems."""

import argparse
import json
import sys
from pathlib import Path

from .audit import report
from .db import DecisionError, connect, initialize
from .executor import execute


def parse():
    parser = argparse.ArgumentParser(prog="python -m cloudctl")
    parser.add_argument("subsystem", choices=("init", "policy", "agent", "drift", "demo", "report",
                                              "hierarchy", "cluster", "config", "reconcile"))
    parser.add_argument("operation", nargs="?")
    parser.add_argument("--db", default="state.sqlite")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--input", help="JSON object for one operation")
    parser.add_argument("--request-id")
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


def main():
    arguments = parse()
    connection = connect(arguments.db)
    initialize(connection)
    try:
        if arguments.subsystem == "init":
            output = {"status": "initialized", "db": str(arguments.db)}
        elif arguments.subsystem == "report":
            output = report(connection)
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
