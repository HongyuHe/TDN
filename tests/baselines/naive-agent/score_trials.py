"""Aggregate adjudicated fault instances and the actual times measured by each method."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import statistics

from observe_controls import HERE, NETWORKS
from blind_audit import MODELS, PROMPT
from audit_observations import summarize as observed_responses
from path_diagnostics import decode as delivery_diagnostics


METHODS = ("astra", "sol", "tdn")
CREDITED = ("hit", "assigned_credit")
HEADER_RECHECK = Path("reruns/ipv4-protocol-import")
CHECK_DIRECTORIES = {
    "modes": "lean", "attachments": "attachment-check", "topology": "tdn-full/topology",
    "forwarding": "tdn-full/forwarding", "headers": "tdn-full/headers", "firewall": "tdn-full/firewall",
    "delivery": "delivery-check", "gray connectivity": "gray-paths",
}
KNOWN_TYPES = {
    "gray-firewall-detached": {
        "title": "A Gray Firewall loses every Gray path from an Inner gateway",
        "clause_ids": ["RG-013.04"],
    },
    "firewall-local-empty-udp": {
        "title": "The Outer Firewall admits local UDP outside the approved Black control policy",
        "clause_ids": ["RG-035.04"],
    },
    "inner-empty-ipv4-header": {
        "title": "The Inner gateway accepts an unlisted IPv4 protocol on its Red interface",
        "clause_ids": ["RG-038.03"],
    },
    "inner-peer-loopback": {
        "title": "The configured cross-site Inner tunnel points to the gateway itself",
        "clause_ids": ["RG-007.02"],
    },
    "inner-mode": {
        "title": "Wrong ESP mode on an Inner gateway",
        "clause_ids": ["RG-029.01"],
    },
    "outer-mode": {
        "title": "Wrong ESP mode on an Outer gateway",
        "clause_ids": ["RG-030.01"],
    },
    "delivery-outage": {
        "title": "Black transit drops intended cross-site deliveries",
        "clause_ids": ["RG-008.04"],
    },
    "outer-eligible-deny": {
        "title": "An Outer gateway drops an eligible Inner exchange",
        "clause_ids": ["RG-039.07"],
    },
    "gray-eligible-deny": {
        "title": "A Gray Firewall drops traffic it must allow",
        "clause_ids": ["RG-040.07"],
        "assigned_credit_networks": ["net-02"],
    },
    "firewall-inside-disconnected": {
        "title": "An Outer loses its firewall’s inside connection",
        "clause_ids": ["RG-034.02"],
    },
    "firewall-outside-disconnected": {
        "title": "An Outer Firewall loses its outside connection to Black",
        "clause_ids": ["RG-034.02"],
    },
}


def read(path):
    return json.loads(path.read_text())


def type_verdict(results):
    if "inapplicable" in results:
        return "inapplicable"
    if any(v in ("miss", "timeout") for v in results):
        return "miss"
    if len(results) == len(NETWORKS) and all(v in CREDITED for v in results):
        return "hit"
    if "pending" not in results and "unevaluable" in results:
        return "unevaluable"
    return "pending"


def records(root):
    results = []
    protocol = read(root / "protocol.json")
    delivery_protocol = (
        read(root / "delivery-protocol.json")
        if (root / "delivery-protocol.json").is_file()
        else None
    )
    gray_file = root / "gray-connectivity-protocol.json"
    gray_protocol = read(gray_file) if gray_file.is_file() else None
    recheck_dir = root / HEADER_RECHECK
    recheck = read(recheck_dir / "record.json") if (recheck_dir / "record.json").is_file() else None
    for p in sorted((root / "trials").glob("*/*/adjudication.json")):
        d = read(p)
        folder = p.parent
        family = folder.parent.name
        n = folder.name
        if (
            family not in KNOWN_TYPES
            or n not in NETWORKS
            or d["type"] != family
            or d["network"] != n
        ):
            raise ValueError("Unknown or misplaced trial " + str(p))
        if not (folder / "restoration.json").is_file() or not any(
            json.loads(l)["event"] == "restoration_verified"
            for l in (folder / "events.jsonl").read_text().splitlines()
        ):
            raise ValueError("No verified restoration: " + str(p))
        snap = root / "raw" / "trials" / family / n
        proof_folder = folder
        if family == "inner-empty-ipv4-header" and recheck is not None:
            proof_folder = recheck_dir / "trials" / n
            decision = recheck["networks"][n]
            header = proof_folder / CHECK_DIRECTORIES["headers"] / "result.json"
            d["methods"]["tdn"] = {"verdict": decision["verdict"], "reason": decision["reason"],
                                   "source": os.path.relpath(header, folder)}
            d["tdn_recheck"] = str(HEADER_RECHECK / "record.json")
        for method in METHODS:
            item = d["methods"][method]
            if item["verdict"] not in ("hit", "miss", "unevaluable", "timeout"):
                raise ValueError("Unknown verdict")
            if not (folder / item["source"]).is_file() or not item["reason"]:
                raise ValueError("Missing verdict evidence")
            if method != "tdn":
                log = read(folder / method / "execution.json")
                if (
                    log["prompt"] != PROMPT
                    or log["model"] != MODELS[method]
                    or log["reasoning"] != "high"
                ):
                    raise ValueError(
                        "Detector protocol differs from the designated experiment"
                    )
                if (
                    log["document_sha256"]
                    != protocol["working_tree_files_sha256"][
                        "data/extraction/source/CSfC_documentation_v1.3.0.pdf"
                    ]
                ):
                    raise ValueError("Unexpected document supplied to the Detector")
                expected_run = (
                    "timeout" if item["verdict"] == "timeout" else "completed"
                )
                if (
                    log["status"] != expected_run
                    or log["unexpected_tools"]
                    or log["reader_calls"] == 0
                ):
                    if item["verdict"] != "unevaluable":
                        raise ValueError("Invalid Detector run scored as detection")
                item["seconds"] = log["duration_seconds"]
                change = read(folder / "change.json")
                item["observations"] = observed_responses(
                    folder / method, d["target"], change.get("inserted_rule")
                )
                if (
                    not item["observations"]["visible_success_rows_by_network"]
                    and item["verdict"] != "unevaluable"
                ):
                    raise ValueError(
                        "No successful device observation reached the Detector"
                    )
            else:
                candidates = {
                    name: proof_folder / subdir / "result.json" for name, subdir in CHECK_DIRECTORIES.items()
                    if (name != "delivery" or delivery_protocol) and (name != "gray connectivity" or gray_protocol)
                }
                measured = {k: read(v) for k, v in candidates.items() if v.is_file()}
                if proof_folder != folder:
                    if measured.keys() != candidates.keys():
                        raise ValueError(f"Incomplete protocol-import rerun on {n}")
                    if item["verdict"] == "hit" and not any(
                        line.startswith("lemma protocol_rules_checked ")
                        for line in measured["headers"]["failed_obligations"]
                    ):
                        raise ValueError(f"No Lean rejection of the protocol rule on {n}")
                item["proof_results"] = {
                    name: proof["status"] for name, proof in measured.items()
                }
                for name, proof in measured.items():
                    if name == "gray connectivity":
                        expected = gray_protocol["clean_proofs"][n]
                    elif name == "delivery":
                        expected = delivery_protocol["clean_proofs"][n]
                    else:
                        expected = protocol["clean_proofs"][n][name]
                    if proof["source_sha256"] != expected["source_sha256"]:
                        raise ValueError(
                            "Different proof programs in trial and its clean control: "
                            + str(candidates[name])
                        )
                    if proof_folder != folder:
                        control = read(recheck_dir / "controls" / n / CHECK_DIRECTORIES[name] / "result.json")
                        if control["status"] != "pass" or any(
                            control[key] != expected[key] for key in ("evidence_sha256", "source_sha256")
                        ):
                            raise ValueError(f"The clean {name} rerun differs from the registered input on {n}")
                if item["verdict"] == "hit" and not any(
                    v["status"] == "rejected" for v in measured.values()
                ):
                    raise ValueError("No failed Lean obligation to support detection")
                intervals_ns = {
                    k: v["typecheck_ns"]
                    for k, v in measured.items()
                    if v["status"] in ("rejected", "pass")
                    and v["typecheck_ns"] is not None
                }
                item["proof_seconds"] = {k: ns / 1e9 for k, ns in intervals_ns.items()}
                total_seconds = sum(intervals_ns.values()) / 1e9
                item["seconds"] = total_seconds if len(intervals_ns) == len(candidates) else None
                original = {
                    "modes",
                    "attachments",
                    "topology",
                    "forwarding",
                    "headers",
                    "firewall",
                }
                for field, suite in (
                    ("six_check_seconds", original),
                    ("seven_check_seconds", original | {"delivery"}),
                ):
                    item[field] = (
                        sum(intervals_ns[k] for k in suite) / 1e9 if suite <= intervals_ns.keys() else None
                    )
                item["partial_seconds"] = total_seconds
                if item["verdict"] == "miss" and (
                    len(intervals_ns) != len(candidates)
                    or any(x["status"] != "pass" for x in measured.values())
                ):
                    raise ValueError(
                        "Incomplete or failed verification cannot establish a miss"
                    )
        d["capture"] = (
            read(snap / "capture.json") if (snap / "capture.json").is_file() else None
        )
        d["delivery_paths"] = delivery_diagnostics(proof_folder)
        d["record"] = str(p.relative_to(root))
        results.append(d)
    return results


def summarize(root):
    rows = records(root)
    types = {}
    scope = read(HERE / "clause_scope.json")
    for key, definition in KNOWN_TYPES.items():

        def cell(m, n):
            measured = next(
                (
                    v["methods"][m]["verdict"]
                    for v in rows
                    if v["network"] == n and v["type"] == key
                ),
                None,
            )
            inactive = all(
                scope[c]["scope"][n] == "inapplicable" for c in definition["clause_ids"]
            )
            if inactive and measured:
                raise ValueError("A trial was scored outside its stated scope")
            if inactive:
                if n in definition.get("assigned_credit_networks", ()):
                    return "assigned_credit"
                return "inapplicable"
            return measured or "pending"

        cells = {m: {n: cell(m, n) for n in NETWORKS} for m in METHODS}
        types[key] = {
            **definition,
            "cells": cells,
            "verdicts": {m: type_verdict(list(v.values())) for m, v in cells.items()},
        }
    stats = {}
    for m in METHODS:
        times = [
            r["methods"][m]["seconds"]
            for r in rows
            if r["methods"][m]["seconds"] is not None
            and r["methods"][m]["verdict"] in ("hit", "miss")
        ]
        stats[m] = {
            "trials": dict(Counter(r["methods"][m]["verdict"] for r in rows)),
            "network_cases": dict(Counter(
                cell for group in types.values() for cell in group["cells"][m].values()
            )),
            "types": dict(Counter(v["verdicts"][m] for v in types.values())),
            "times_count": len(times),
            "median_seconds": statistics.median(times) if times else None,
            "min_seconds": min(times, default=None),
            "max_seconds": max(times, default=None),
        }
    return {
        "run": root.name,
        "networks": list(NETWORKS),
        "methods": list(METHODS),
        "rows": rows,
        "types": types,
        "stats": stats,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    result = summarize(args.run)
    (args.run / "score.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    )
    print(len(result["rows"]), "adjudicated trials", result["stats"])
