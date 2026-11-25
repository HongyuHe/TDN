"""Name each interface where Lean rejected a step of a permitted Red delivery."""

from ast import literal_eval
import argparse
import json
from pathlib import Path


def decode(trial):
    directory = trial / "delivery-check"
    records = trial / "tdn-full/forwarding/evidence.json"
    if not records.is_file() or not (directory / "lean.jsonl").is_file():
        return None
    observations = json.loads(records.read_text())
    names = {number: name for name, number in observations["portIds"].items()}
    logged = []
    for line in (directory / "lean.jsonl").read_text().splitlines():
        if not line.startswith("{"):
            continue
        message = json.loads(line)
        if message["severity"] == "information" and message["data"].startswith("[("):
            logged.append(literal_eval(message["data"]))
    if len(logged) != 1:
        return None
    rows = []
    for source, destination, failures in logged[0]:
        steps = [
            {
                "step_index": index,
                "iface": names[iface],
                "action": action.rsplit(".", 1)[-1],
            }
            for index, iface, action in failures
        ]
        rows.append(
            {
                "source": names[source],
                "destination": names[destination],
                "failed_steps": steps,
            }
        )
    return {
        "delivery_pairs": len(rows),
        "pairs_with_a_failed_step": sum(bool(r["failed_steps"]) for r in rows),
        "pairs": rows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trial", type=Path)
    args = parser.parse_args()
    result = decode(args.trial)
    if result is None:
        raise SystemExit("A complete Lean path diagnostic is unavailable")
    (args.trial / "path-diagnostics.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    print(
        result["pairs_with_a_failed_step"],
        "of",
        result["delivery_pairs"],
        "paths have a failed step",
    )
