"""Expose declared Red services separately from measured listeners and probe outcomes."""

import hashlib
import json
from pathlib import Path

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "services", "diagnostics", "pairs", "cases", "observations", "coverage"]
LEAN_VIEW = "red_service_policy"
SCOPE = "Declared paired-host HTTP 8080 and ICMP echo workload, installed filtering, listeners and finite probes."
SOURCE_SHA256 = "d91d1dba48863ca2deaa3f8e078ca3787e72d48c30252bc16b8a2ca49aab12cb"


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    require(hashlib.sha256((root / "collector.py").read_bytes()).hexdigest() == SOURCE_SHA256,
            "Unknown Red service collector")
    document = json.loads((root / "observations.json").read_text())
    require(document["schema"] == "tdn-red-service-policy/v1" and document["applied"] is True
            and document["error"] is None, "Incomplete Red service capture")
    pairs = document["pairs"]
    hosts = {row["host"]: row for row in pairs}
    require(bool(pairs) and len(hosts) == len(pairs), "Duplicate or empty Red host inventory")
    records = {row["id"]: row for row in document["records"]}
    require(len(records) == len(document["records"]), "Duplicate Red service observation")
    services = {row["device"]: row for row in document["services"]}
    diagnostics = {row["device"]: row for row in document["diagnostics"]}
    require(len(services) == len(document["services"]) == len(pairs) and set(services) == set(hosts),
            "Incomplete service declaration")
    require(len(diagnostics) == len(document["diagnostics"]) == len(pairs) and set(diagnostics) == set(hosts),
            "Incomplete diagnostic declaration")
    expected_cases = set()
    for name, pair in hosts.items():
        peer = hosts.get(pair["peerHost"])
        require(peer is not None and peer["localAddress"] == pair["peerAddress"]
                and peer["profile"] == pair["profile"] and peer["level"] == pair["level"],
                "Red peer binding mismatch")
        service, diagnostic = services[name], diagnostics[name]
        require(service["inner"] == diagnostic["inner"] == pair["inner"]
                and service["address"] == diagnostic["address"] == pair["localAddress"],
                "Service endpoint binding mismatch")
        require(service["protocol"] == "tcp" and service["port"] == 8080
                and diagnostic["protocol"] == "icmp" and diagnostic["types"] == [0, 8]
                and diagnostic["port"] is None and diagnostic["modelPort"] == 0,
                "Unsupported declared Red service")
        listeners = [record for record in records.values()
                     if record["command"] == ["docker", "exec", name, "ss", "-lntp"]]
        require(bool(listeners) and listeners[-1]["returncode"] == 0
                and pair["localAddress"] + ":8080" in listeners[-1]["stdout"],
                "Missing final Red service listener")
        for device in [name, pair["inner"]]:
            require((root / (device + ".after.rules")).is_file(), "Missing installed filter read-back")
        expected_cases.update(name + "/" + kind for kind in ["paired-ping", "paired-http", "wrong-port"])
        if any(other["profile"] == pair["profile"] and other["level"] != pair["level"] for other in pairs):
            expected_cases.add(name + "/cross-level")
    require(len(document["cases"]) == len(expected_cases)
            and {row["id"] for row in document["cases"]} == expected_cases,
            "Incomplete Red service probe coverage")
    cases = []
    for case in document["cases"]:
        pair = hosts[case["device"]]
        label = case["id"].split("/")[-1]
        require(case["expected"] is (label in {"paired-ping", "paired-http"}),
                "Probe expectation differs from declared policy")
        probe = records[case["observation"]]
        if case["kind"] == "icmp-echo":
            require(probe["command"] == ["docker", "exec", pair["host"], "ping", "-n", "-c", "1", "-W", "2", pair["peerAddress"]]
                    and probe["returncode"] in {0, 1}, "Invalid echo observation")
            observed = probe["returncode"] == 0
        else:
            if label == "cross-level":
                require(case["port"] == 8080 and any(other["profile"] == pair["profile"]
                        and other["level"] != pair["level"] and other["localAddress"] == case["destination"]
                        for other in pairs), "Cross-level probe endpoint mismatch")
            else:
                require(case["destination"] == pair["peerAddress"] and
                        case["port"] == (8081 if label == "wrong-port" else 8080),
                        "Paired probe endpoint mismatch")
            require(case["kind"] == "tcp-http" and probe["command"][:5] ==
                    ["docker", "exec", pair["host"], "python3", "-c"] and probe["returncode"] == 0,
                    "Invalid HTTP observation")
            response = json.loads(probe["stdout"])
            require(isinstance(response["connected"], bool), "Malformed HTTP result")
            require("HTTPConnection(" + repr(case["destination"]) + "," + str(case["port"]) + ",timeout=2)"
                    in probe["command"][5], "Probe command endpoint differs from recorded case")
            if response["connected"]:
                require(response["service_ok"] == (response["status"] == 200
                        and response["body"] == "TDN Red service on TCP 8080\n"),
                        "HTTP result differs from its response body")
            observed = response.get("service_ok", False) if case["expected"] else response["connected"]
            for key in ["beforeCounter", "afterCounter"]:
                record = records[case[key]]
                require(record["returncode"] == 0 and record["command"] ==
                        ["docker", "exec", pair["inner"], "iptables", "-nvx", "-L", "FORWARD"],
                        "Invalid forwarding counter observation")
        require(case["observed"] == observed, "Stored probe result differs from raw observation")
        cases.append(case | {"observed": observed, "matches_expected": observed == case["expected"],
                             "evidenceStatus": "observed"})
    devices = [{"id": name, "role": "red-host"} for name in hosts]
    devices += [{"id": row["inner"], "role": "inner-encryptor"} for row in pairs]
    raw = [{"id": row["id"], "device": row["command"][2] if row["command"][:2] == ["docker", "exec"]
            and row["command"][2] not in {"-i", "-d"} else None, "record": row} for row in records.values()]
    report = {"devices": devices,
              "services": [row | {"evidenceStatus": "declared"} for row in services.values()],
              "diagnostics": [row | {"evidenceStatus": "declared"} for row in diagnostics.values()],
              "pairs": [row | {"device": row["inner"], "evidenceStatus": "declared"} for row in pairs],
              "cases": cases, "observations": raw,
              "coverage": [{"scope": SCOPE, "hosts": len(hosts), "cases": len(cases)}],
              "scope": [SCOPE, document["decision"], document["scope"], document["icmpPortRepresentation"]],
              "manifestSha256": manifest_hash, "projectionVersion": "red-service-policy-v1"}
    return {"runtime_backend": "Twinet-FRR-OVS-IPsec-native-containers",
            "started_at": document["started_at"], "ended_at": document["ended_at"]}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    rows = [row for row in report["observations"] if row["id"] == observation]
    require(len(rows) == 1, "Unknown Red service observation")
    return rows[0]["record"]["stderr" if stderr else "stdout"]


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
