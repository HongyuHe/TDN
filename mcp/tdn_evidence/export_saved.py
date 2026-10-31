"""Project validated snapshot inventories into the existing Lean evidence type."""
import hashlib
import json
from .saved import validated_snapshot
from .service import encode


def export_saved(directory, destination):
    manifest, snapshot, _ = validated_snapshot(directory)
    status = {"observed": "observed", "configured": "configured", "unavailable": "unavailable", "failed": "failed", "not_applicable": "notApplicable"}
    devices = [{"id": d["id"], "role": d["role"], "site": d.get("site"), "securityLevel": d.get("security_level_id"),
                "status": status[d["status"]], "observationIds": d["observation_ids"]} for d in snapshot["devices"]]
    tunnels = [{"id": t["id"], "device": t["device_id"], "peer": t["peer_device_id"], "layer": t["layer"],
                "mechanism": t["mechanism"], "mode": t.get("mode") or "", "status": status[t["status"]], "observationIds": t["observation_ids"]} for t in snapshot["tunnels"]]
    probes = [{"id": p["id"], "source": p["source_device"], "destination": p["destination"],
               "purpose": p["purpose"], "observedResult": p["observed_result"], "status": status[p["status"]], "observationIds": p["observation_ids"]} for p in snapshot["probes"]]
    result = {"id": snapshot["snapshot_id"], "manifestSha256": hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest(),
              "snapshotSha256": hashlib.sha256((directory / "snapshot.json").read_bytes()).hexdigest(),
              "devices": devices, "tunnels": tunnels, "probes": probes}
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw = encode({"snapshot": result})
    if destination.exists() and destination.read_bytes() != raw:
        raise ValueError("Existing saved export differs")
    destination.write_bytes(raw)
    return {"path": str(destination), "sha256": hashlib.sha256(raw).hexdigest(), "type": "TDN.Evidence.Snapshot", "key": "snapshot"}


def export_projection(directory, destination, view):
    from .projections import packet_filters, PROJECTIONS
    from .parsers.topology import validated_graph
    from .parsers.correspondence import check_filter_correspondence
    manifest, snapshot, _ = validated_snapshot(directory)
    if view == "packet_filters":
        check_filter_correspondence(directory, snapshot)
        values, coverage = packet_filters(snapshot)
        unsupported = [c for c in coverage if c["status"] != "parsed"]
        if unsupported:
            raise ValueError("Unsupported filter chains: " + json.dumps(unsupported))
        values["coverage"] = coverage
    elif view == "topology":
        graph = validated_graph(directory)
        values = {"nodes": [d["id"] for d in graph["devices"]],
                  "edges": [list(pair) for pair in sorted(graph["edges"])],
                  "grayEdges": [list(pair) for pair in sorted(graph["gray_edges"])],
                  "firewalls": graph["firewall"], "grayFirewalls": graph["gray_fw"],
                  "outerRegions": graph["outer_sides"], "grayRegions": graph["gray_sides"]}
    elif view in PROJECTIONS:
        version, project = PROJECTIONS[view]
        values = project(directory, snapshot)
        values["projectionVersion"] = version
    else:
        raise ValueError("Supported saved views: inventory, packet_filters, topology")
    values["provenance"] = {"manifestSha256": hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest(),
                            "snapshotId": manifest["snapshot_id"], "view": view}
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw = encode(values)
    if destination.exists() and destination.read_bytes() != raw:
        raise ValueError("Existing projection differs")
    destination.write_bytes(raw)
    return {"path": str(destination), "sha256": hashlib.sha256(raw).hexdigest(), "view": view, "keys": list(values)}
