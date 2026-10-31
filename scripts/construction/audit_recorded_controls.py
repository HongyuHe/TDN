"""Check retained control outcomes against their recorded command results."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def outcome(command):
    output = command.get("stdout", "")
    error = command.get("stderr", "")
    code = command["returncode"]
    if type(code) is not int:
        raise ValueError("Recorded exit status must be an integer")
    try:
        result = json.loads(output)
    except (ValueError, TypeError):
        result = None
    if isinstance(result, dict) and code == 0:
        if result.get("outcome") == "delivered" and "200 OK" in result.get("response", ""):
            return "delivered"
        if result.get("outcome") == "rejected" and "CERTIFICATE_REQUIRED" in result.get("error", ""):
            return "rejected"
    #* A size error is more specific than an unanswered ping.
    if code != 0 and "message too long" in error.lower():
        return "size-rejected"
    received = re.search(r"\b(\d+) packets transmitted, (\d+) (?:packets )?received", output)
    if received:
        sent, replies = map(int, received.groups())
        if sent > 0 and replies > 0 and code == 0:
            return "delivered"
        if sent > 0 and replies == 0 and code != 0:
            return "no_reply"
    return "unrecognized"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("Preserve previous audits; choose a new output path")
    rows = []
    for bundle in args.bundle:
        evidence_path = bundle / "evidence.json"
        commands_path = bundle / "commands.json"
        evidence = json.loads(evidence_path.read_text())
        commands = json.loads(commands_path.read_text())
        indexed = {command["id"]: command for command in commands}
        if len(indexed) != len(commands):
            raise ValueError("Duplicate command identity in " + str(bundle))
        if "error" not in evidence or evidence["error"] is not None:
            raise ValueError("Collection reports an error in " + str(bundle))
        for probe in evidence["probes"]:
            command = indexed[probe["observation_id"]]
            parsed = outcome(command)
            rows.append({"bundle": str(bundle), "probe": probe["id"],
                         "command": probe["observation_id"],
                         "expected": probe["expected_result"],
                         "recorded": probe["observed_result"], "parsed": parsed,
                         "matches": parsed == probe["expected_result"] == probe["observed_result"],
                         "evidence_sha256": digest(evidence_path),
                         "commands_sha256": digest(commands_path)})
    result = {"at": datetime.now(timezone.utc).isoformat(),
              "auditor_sha256": digest(Path(__file__)), "controls": len(rows),
              "failures": sum(not row["matches"] for row in rows), "rows": rows,
              "scope": "Finite retained ping/TLS outcomes and command bindings; no claim about all executions or the cause of a negative result."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("controls", "failures")}))
    raise SystemExit(1 if result["failures"] else 0)


if __name__ == "__main__":
    main()
