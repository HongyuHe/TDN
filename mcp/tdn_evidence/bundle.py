"""Construct vendor-independent JSON values consumed by TDN.Import.Network."""
import ipaddress
import json
from .contracts import installed_route_observations
from .service import digest, encode


def prepare_bundle(directory, manifest):
    observations = manifest["observations"]
    families = installed_route_observations(manifest)
    routes = []
    coverage = []
    for observation in observations:
        coverage.append({"id": observation["id"], "device": observation["device"], "worker": observation["worker"],
                         "status": observation["status"], "sha256": observation["sha256"],
                         "started": observation["started"], "finished": observation["finished"],
                         "adapter": observation["adapter"], "capability": observation["capability"],
                         "parserVersion": observation["parser_version"]})
        if observation["id"] not in families:
            continue
        family = families[observation["id"]]
        for record in observation["records"]:
            prefix = record["destination"]
            if prefix == "default":
                prefix = "0.0.0.0/0" if family == 4 else "::/0"
            network = ipaddress.ip_network(prefix, strict=False)
            if network.version != family:
                raise ValueError("Forwarding address-family mismatch")
            gateway = record["gateway"]
            if gateway is not None and ipaddress.ip_address(gateway).version != family:
                raise ValueError("Next-hop address-family mismatch")
            routes.append({"device": observation["device"], "family": family,
                           "destinationLow": int(network.network_address), "destinationHigh": int(network.broadcast_address),
                           "prefixLength": network.prefixlen, "gateway": None if gateway is None else int(ipaddress.ip_address(gateway)),
                           "output": record["output"], "table": record["table"], "kind": record["kind"],
                           "protocol": record["protocol"], "metric": record["metric"], "scope": record["scope"],
                           "observationId": observation["id"]})
    bundle = {"schemaVersion": 1, "id": manifest["id"], "network": manifest["network"],
              "manifestSha256": digest((directory / "manifest.json").read_bytes()), "consistency": manifest["consistency"],
              "devices": [{"id": d["id"], "worker": d["worker"], "container": d["container"],
                           "adapters": d["adapters"], "declaredRole": d["declared_role"]} for d in manifest["devices"]],
              "observations": coverage, "routes": routes}
    output = directory / "lean.json"
    raw = encode({"snapshot": bundle})
    if output.exists() and output.read_bytes() != raw:
        raise ValueError("Existing immutable Lean bundle differs")
    output.write_bytes(raw)
    (directory / "lean.sha256").write_text(digest(raw) + "\n")
    return {"collection": manifest["id"], "path": str(output), "sha256": digest(raw),
            "schema_version": 1, "routes": len(routes), "scope": "Observed routes and evidence coverage; forwarding execution requires additional local conditions"}
