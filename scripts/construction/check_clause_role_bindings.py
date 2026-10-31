"""Check selected Lean indices and peers against complete raw-bound native inventories."""
import hashlib
import json
import os
from pathlib import Path
from analyze_topology import validated_graph
from import_ike_contexts import parse
from validate_evidence import require

RUN = Path(os.environ.get("TDN_OUTPUT_DIR", "data/construction/2026-10-24T014455Z"))


def check():
    report_path = RUN / "shared-execution-nft-import.json"
    report = json.loads(report_path.read_text())
    graph = validated_graph(Path(report["snapshot"]))
    context = parse(report["snapshot"])
    ids = report["device_ids"]
    gf = sorted(ids[d["id"]] for d in graph["devices"] if d["role"] == "gray-firewall")
    require(gf == [2, 3], "Complete Gray Firewall index binding changed")
    outer = [d["id"] for d in graph["devices"] if d["role"] == "outer"]
    records = context["endpoints"]
    peers = sorted((ids[r["device"]], r["remote_address"]) for r in records if r["device"] in outer)
    require(peers == [(22, 2886997249), (23, 2886994689)], "Outer peer/index binding changed")
    require(len(peers) == len(outer) == 2, "Incomplete Outer scope")
    return {"gray_firewall_indices": gf, "outer_peers": peers,
            "source_report": str(report_path), "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "graph_validation": graph["validation"], "ike_context_validation": context["source_manifest_sha256"],
            "scope": "Role indices and actual reciprocal Outer peer addresses for FreshOuterPeerOutput and FreshGrayAddressClauses. Complete hook semantics and raw filter correspondence remain in the execution import."}


if __name__ == "__main__":
    result = check()
    (RUN / "fresh-clause-role-bindings.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"gray_firewalls": result["gray_firewall_indices"], "outer_peers": result["outer_peers"]}))
