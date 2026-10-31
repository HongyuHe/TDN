"""Check saved configuration facts without constructing standalone Lean proofs.

Results concern the named finite records. Source collection, parser correctness,
inventory completeness, and implementation behavior remain separate assumptions.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def all_records(rows, predicate):
    """Reject empty inventories so absent evidence cannot pass a check."""
    return isinstance(rows, list) and bool(rows) and all(predicate(row) for row in rows)


def cnsa1(suite):
    return suite == {"aesBits": 256, "gcm": True, "signature": "ecdsaP384sha384",
                     "establishment": "ecdhP384", "integrity": "sha384"}


def vpn_mode(policy):
    return (all_records(policy["ikeVersions"], lambda value: value == 2)
            and all_records(policy["ikeModes"], lambda value: value in {"cbc", "gcm"})
            and all_records(policy["espProposals"], lambda proposal:
                            proposal["mode"] == "gcm" or
                            (proposal["mode"] == "cbc" and proposal["hmacIntegrity"] is True)))


def contiguous(batches, total):
    cursor = 0
    if not batches or total <= 0:
        return False
    for batch in batches:
        if (batch["offset"] != cursor or batch["bytes"] <= 0
                or batch["next"] != cursor + batch["bytes"] or not batch["fingerprint"]):
            return False
        cursor = batch["next"]
    return cursor == total


def separated_assignments(assignments):
    return bool(assignments) and all(
        a["workstation"] != b["workstation"] or a["inner"] == b["inner"]
        for a in assignments for b in assignments)


def dns_prefix(device):
    expected = [{"atoms": [{"protocol": {"name": protocol}},
                           {"destinationPorts": {"ports": [53]}}], "verdict": "deny"}
                for protocol in ["tcp", "udp"]]
    return (device["guards"] == expected
            and all({"connectionStates": {"states": ["ESTABLISHED"]}} in rule["atoms"]
                    for rule in device["earlierRules"])
            and (device["family"] != 6 or not device["earlierRules"]))


class Records:
    def __init__(self, root):
        self.root = Path(root)
        manifest = json.loads((self.root / "data/evidence/manifest.json").read_text())
        self.expected = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
        self.inputs = {}
        self.cache = {}

    def read(self, relative, expected=None):
        #* Retained result records may name the original snapshot directory.
        if relative.startswith("artifacts/snapshots/"):
            relative = "data/snapshots/" + relative.removeprefix("artifacts/snapshots/")
        path = (self.root / relative).resolve()
        if not path.is_relative_to(self.root.resolve()):
            raise ValueError("Evidence path leaves the repository: " + relative)
        raw = path.read_bytes()
        digest = sha256(raw).hexdigest()
        if expected is not None and digest != expected:
            raise ValueError("Evidence differs from its retained manifest: " + relative)
        self.inputs[str(path.relative_to(self.root.resolve()))] = digest
        return json.loads(raw)

    def get(self, module, field):
        if module not in self.cache:
            name = module + ".json"
            self.cache[module] = self.read("data/evidence/" + name, self.expected[name])
        matches = [value for name, value in self.cache[module].items() if name.endswith("." + field)]
        if len(matches) != 1:
            raise ValueError(f"Expected one {module}.{field} record")
        return matches[0]


def evaluate(records):
    results = []
    get = records.get

    def check(ids, claim, predicate):
        try:
            passed = predicate()
            if type(passed) is not bool:
                raise ValueError("A record check must return a Boolean")
            result = {"groups": [f"RG-{number:03}" for number in ids],
                      "claim": claim, "passed": passed}
        except (KeyError, ValueError, TypeError, IndexError, OSError) as error:
            result = {"groups": [f"RG-{number:03}" for number in ids],
                      "claim": claim, "passed": False, "error": str(error)}
        results.append(result)

    check([1, 18, 19], "Recorded Inner IKE offers use the selected CNSA1 suite choices.",
          lambda: all_records(get("FreshSharedClassicalIKE", "offered"), cnsa1))

    def distinct_field(module, field, pairs):
        components = get(module, "components")
        return (bool(components) and all(any(c["role"] == role for c in components)
                                       for pair in pairs for role in pair)
                and all(a[field] and b[field] and a[field] != b[field]
                        for a in components for b in components if (a["role"], b["role"]) in pairs))

    check([4], "Recorded Inner and Outer OS families differ.",
          lambda: distinct_field("FreshOSDiversity", "osFamily", {("inner", "outer")}))
    check([5], "Recorded security role pairs occupy distinct hardware identities.",
          lambda: distinct_field("FreshPhysicalPartition", "physicalDevice",
                                 {("inner", "outer"), ("inner", "grayFirewall"),
                                  ("outer", "outerFirewall"), ("inner", "outerFirewall"),
                                  ("grayFirewall", "outer"), ("grayFirewall", "outerFirewall")}))

    def issuers_present():
        rows = get("FreshRecordedOperations", "issuances")
        return len(rows) == 4 and all(rows[peer]["signer"] in row["loadedAuthorities"]
                                     for row, peer in zip(rows, [1, 0, 3, 2]))

    check([10], "Each recorded site/layer has its opposite peer's signing CA loaded.", issuers_present)
    def forwarding_lists():
        from import_enterprise_gray_filters import parse
        relative = "data/snapshots/2026-10-24T014455Z/central-gray-management-v3"
        records.read(relative + "/manifest.json")
        captured = parse(records.root / relative)["records"]
        chains = get("FreshEnterpriseGrayFilters", "forwardChains")
        return (len(captured) == len(chains)
                and all_records(captured, lambda row: row["forward_default"] == "deny")
                and all_records(chains, lambda rules:
                                all_records(rules, lambda r: r["verdict"] == "allow" and bool(r["atoms"]))))

    check([11], "Raw-bound forwarding chains have DROP defaults and explicit allow rules; Filter supplies general first-match reasoning.",
          forwarding_lists)
    check([16], "Enabled MACsec VLAN and XPN options are marked supported.",
          lambda: all_records(get("FreshMACsecOptions", "options"), lambda r:
                              (not r["xpnEnabled"] or r["xpnSupported"] is True)
                              and (not r["clearVlanEnabled"] or r["clearVlanSupported"] is True)))
    check([17], "Every recorded peer policy requires certificate verification.",
          lambda: all_records(get("FreshVPNObservedClauses", "policies"),
                              lambda r: r["requiresPeerCertificate"] is True))

    def unique_certificates():
        rows = get("FreshVPNObservedClauses", "certificates")
        fingerprints = [row["fingerprint"] for row in rows]
        return bool(fingerprints) and all(fingerprints) and len(set(fingerprints)) == len(fingerprints)

    check([20], "Recorded loaded certificate fingerprints are nonempty and unique.", unique_certificates)
    check([22], "Loaded VPN policies select IKEv2 and the supported CBC/GCM alternatives.",
          lambda: all_records(get("FreshSharedVPNModes", "policies"), vpn_mode))
    check([23], "Recorded ESP hard lifetimes are positive and at most 28,800 seconds.",
          lambda: all_records(get("FreshVPNObservedClauses", "espHardSeconds"),
                              lambda seconds: type(seconds) is int and 0 < seconds <= 28800))
    check([25], "Recorded MACsec encryption and key-wrap choices use the selected 256-bit algorithms.",
          lambda: all_records(get("FinalMACsecAlgorithms", "devices"), lambda r:
                              r["keyWrapAlgorithm"] == "AES Key Wrap" and r["keyWrapBits"] == 256
                              and r["protectionAlgorithm"] == "AES GCM" and r["protectionBits"] == 256))
    check([26], "The recorded EAP suite matches the selected CNSA2 settings.",
          lambda: get("FinalMACsecRuntime", "negotiatedSuite") ==
          {"aesBits": 256, "gcm": True, "signature": "mldsa87", "establishment": "mlkem1024", "integrity": "sha384"})

    def routing_processes():
        from import_routing_processes import selected_processes
        report = records.read("data/construction/2026-10-24T014455Z/fresh-routing-processes.json")
        rows = selected_processes(report["source"])
        return bool(rows) and {name for name, _ in rows} == set(get("FreshRoutingProcesses", "outerDevices"))

    check([31], "Saved Outer process inventories contain only the recognized waiting and IKE services.", routing_processes)
    check([36], "Every recorded unused interface is disabled.",
          lambda: all_records(get("FreshUnusedInterfaces", "interfaces"), lambda r: r["enabled"] is False))
    check([41, 42], "The captured time-service bridge equals the selected Red-side bridge.",
          lambda: bool(get("FreshRedTimePlacement", "serviceBridge")) and
          get("FreshRedTimePlacement", "serviceBridge") == get("FreshRedTimePlacement", "insideBridge"))
    check([43], "Captured DNS deny prefixes and preceding ESTABLISHED-only rules have the expected shape.",
          lambda: all_records(get("FreshDNSHardening", "devices"), dns_prefix))
    check([44], "Configured AW assignments do not share workstations between Inner and Outer layers.",
          lambda: separated_assignments(get("FreshRecordedOperations", "assignments")))
    check([45], "Recorded unused AW states are powered off, including the final state.",
          lambda: all_records(get("FreshRecordedOperations", "powerStates"),
                              lambda r: r["inUse"] is True or r["poweredOn"] is False)
          and get("FreshRecordedOperations", "powerStates")[-1] == {"inUse": False, "poweredOn": False})
    check([46], "Observed management TLS versions are 1.2 or 1.3.",
          lambda: all_records(get("FreshRecordedOperations", "tlsVersions"), lambda r: r in {"TLSv1.2", "TLSv1.3"}))
    check([48], "Recorded credential requests precede signing and use, with matching paths and loaded issuers.",
          lambda: all_records(get("FreshRecordedOperations", "issuances"), lambda r:
                              r["requestOutput"] == r["signedRequest"]
                              and r["certificateOutput"] == r["configuredCertificate"]
                              and r["requestOrder"] < r["signingOrder"] < r["useOrder"]
                              and r["signer"] in r["loadedAuthorities"] and r["trustAnchor"] in r["loadedAuthorities"]))

    def branches():
        rows = get("FreshPlacementClauses", "independentBranches")
        inner = get("FreshSharedTopology", "innerNodes")
        outer = get("FreshSharedTopology", "outerNodes")
        edges = get("FreshSharedTopology", "grayEdges")
        return (bool(rows) and bool(inner) and {r[0] for r in rows} == set(inner)
                and all(r[1][0] in outer and bool(r[1][1]) and r[1][1][-1] == r[1][0]
                        and all(n not in inner for n in r[1][1])
                        and all([a, b] in edges for a, b in zip([r[0]] + r[1][1], r[1][1])) for r in rows))

    check([53], "Each selected Inner has a supplied path to an Outer without entering another Inner.", branches)

    def readback():
        from import_recorded_operations import responses
        base = records.root / "data/snapshots/2026-10-24T014455Z"
        for bundle in ["role-admin-deploy-v4", "role-admin-effective-v3", "role-admin-matrix-v3"]:
            records.read(str((base / bundle / "manifest.json").relative_to(records.root)))
        rows = responses(base)
        return all(any(row["role"] == role and row["status"] == 200 and row["settings"] == get("FreshRecordedOperations", field)
                       for row in rows) for role, field in
                   [("Auditor", "auditorConfiguration"), ("SecurityAdministrator", "administratorConfiguration")])

    check([58, 68], "Successful recorded role readbacks match the saved configuration fragments.", readback)
    check([62], "Saved offload journals cover the source bytes contiguously and survive the recorded restart unchanged.",
          lambda: contiguous(get("FreshAuditOffload", "beforeRestart"), get("FreshAuditOffload", "sourceBytes"))
          and get("FreshAuditOffload", "beforeRestart") == get("FreshAuditOffload", "afterRestart"))

    def rotation():
        before = get("FreshAuditorRotation", "observedBefore")
        after = get("FreshAuditorRotation", "capturedAfter")
        entries = [entry for archive in after["archives"] for entry in archive] + after["active"]
        return bool(before) and entries[:len(before)] == before

    check([69], "The recorded post-rotation store retains the observed pre-rotation log prefix.", rotation)

    def retained_tests():
        selected = get("FreshRecordedOperations", "selectedTests")
        saved = get("FreshRecordedOperations", "savedResults")
        if not selected or len({r[0] for r in saved}) != len(saved):
            return False
        indexed = dict(saved)
        for identity in selected:
            path = indexed[identity]
            if not path:
                return False
            records.read(path)
        return True

    check([72], "Every selected test has a unique, readable saved result file.", retained_tests)
    return {"scope": "Finite checks of saved records; partial RG clauses only. No live-network or whole-RG compliance claim.",
            "results": results, "input_sha256": records.inputs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    report = evaluate(Records(args.root))
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if all(result["passed"] for result in report["results"]) else 1)


if __name__ == "__main__":
    main()
