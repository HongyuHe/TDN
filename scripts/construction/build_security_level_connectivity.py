"""Build Lean inputs for the two November 4 RG-008 experiments."""
import argparse
import hashlib
import json
from pathlib import Path

from build_outer_tunnel_no_bypass import ROOT, build_delivery, digest, read


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")


def build_profile(profile, policy, labels_export, destination):
    name = profile["id"]
    title = name.title()
    cohort_path = f"data/evidence/continuation/MtuSizing_{title}.json"
    certificate_path = f"data/evidence/nestedProtection/{title}IPsec.json"
    cohort = read(cohort_path)
    certificate = read(certificate_path)
    snapshot_path = policy.parent / f"{name}-snapshot.json"
    spec_path = policy.parent / f"{name}-spec.json"
    if hashlib.sha256(snapshot_path.read_bytes()).hexdigest() != profile["snapshotSha256"]:
        raise ValueError(f"Snapshot hash mismatch in {name}")
    if hashlib.sha256(spec_path.read_bytes()).hexdigest() != profile["specSha256"]:
        raise ValueError(f"Specification hash mismatch in {name}")
    assignments = [row for row in labels_export["assignments"] if row["profile"] == name]
    labels = [dict(network=row["network"], innerDevice=row["innerDevice"], level=row["assignedLevel"])
              for row in assignments]
    if labels != [dict(network=row["network"], innerDevice=row["innerDevice"], level=row["assignedLevel"])
                  for row in profile["assignments"]]:
        raise ValueError(f"MCP assignments and policy disagree for {name}")
    endpoints = {entry["sourceHost"]: entry["network"] for entry in cohort["sourceEntries"]}
    snapshot = json.loads(snapshot_path.read_text())
    probes = snapshot["probes"]
    established = []
    for capture in ("rawKeysBefore", "rawKeysAfter"):
        keys = cohort[capture]
        sessions = {(row["device"], row["peerDevice"], row["ike"]["uniqueid"], row["ike"]["child"]["uniqueid"])
                    for row in keys["authentication"]}
        for sa in keys["associations"]:
            key = (sa["device"], sa["peerDevice"], sa["ikeUniqueId"], sa["child"]["uniqueid"])
            if (key not in sessions or sa["child"]["state"] != "INSTALLED"
                    or sa["direction"] not in ("inbound", "outbound") or not sa["publicStateObservation"]):
                raise ValueError(f"Unaccounted installed association in {name} {capture}")
        for record in keys["authentication"]:
            ike = record["ike"]
            child = ike["child"]
            if ike["state"] != "ESTABLISHED" or child["state"] != "INSTALLED":
                raise ValueError(f"Unestablished peer session for {record['device']}")
            for direction in ("inbound", "outbound"):
                matches = [sa for sa in keys["associations"] if sa["device"] == record["device"]
                           and sa["peerDevice"] == record["peerDevice"] and sa["direction"] == direction
                           and sa["ikeUniqueId"] == ike["uniqueid"] and sa["child"]["uniqueid"] == child["uniqueid"]]
                if not matches:
                    raise ValueError(f"No installed {direction} SA for {record['device']}")
            established.append(dict(device=record["device"], peer=record["peerDevice"],
                                    ike=ike["uniqueid"], child=child["uniqueid"],
                                    observation=record["saObservation"], capture=keys["manifestSha256"]))
    plans = []
    for flow in cohort["sourceFlows"]:
        delivery = build_delivery(title, cohort, flow)
        moves = delivery["moves"]
        path = delivery["path"]
        path.update(route=moves[1]["step"]["route"], policy=moves[3]["step"]["policy"],
                    association=moves[3]["step"]["association"], routeOuterPacket=moves[4]["step"]["route"],
                    nextIface=moves[5]["step"]["next"])
        plans.append(dict(path=path, moves=moves, recipient=delivery["destinationEndpoint"]["networkId"]))
    inventory = dict(assignments=labels, established=established, plans=plans,
                     sources={cohort_path:digest(cohort_path), certificate_path:digest(certificate_path),
                              str(policy.relative_to(ROOT)): hashlib.sha256(policy.read_bytes()).hexdigest(),
                              str(snapshot_path.relative_to(ROOT)):profile["snapshotSha256"]})
    architecture = read("data/evidence/RedConnectivity.json")["profiles"][name]
    roster = next(row for row in read("data/evidence/RedSolutionReferences.json")["profiles"]
                  if row["profile"] == name)
    for row in (architecture, roster):
        if row["snapshotSha256"] != profile["snapshotSha256"] or row["profileSha256"] != profile["specSha256"]:
            raise ValueError(f"Architecture or roster identity mismatch in {name}")
    required = [[edge["sourceNetwork"], edge["peerNetwork"]] for edge in architecture["configuredPeers"]]
    expected = [(endpoints[probe["source_device"]], endpoints[probe["destination_device"]])
                for probe in probes if probe["expected_result"] == "delivered"]
    if len(required) != len(plans) or set(map(tuple, required)) != set(expected):
        raise ValueError(f"Configured peer pairs and probe policy disagree in {name}")
    inventory["requiredPairs"] = required
    inventory["capture"] = dict(placements=architecture["placements"], roster=roster,
                                endpoints=architecture["endpoints"], peers=architecture["configuredPeers"],
                                probes=architecture["probes"], epoch=certificate["authenticationBindings"][0]["epoch"])
    for path in ("data/evidence/RedConnectivity.json", "data/evidence/RedSolutionReferences.json"):
        inventory["sources"][path] = digest(path)
    write_json(destination / f"{title}.json", inventory)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", type=Path, required=True)
    args = parser.parse_args()
    policy = ROOT / "data/extraction/networks/profiles/security-level-assignments-20261111/policy.json"
    labels = json.loads(args.labels.read_text())
    for profile in json.loads(policy.read_text())["profiles"]:
        build_profile(profile, policy, labels, ROOT / "data/evidence/securityLevelConnectivity")


if __name__ == "__main__":
    main()
