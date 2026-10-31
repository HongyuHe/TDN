"""Generate both useful directions for every mechanism and observed protected VLAN stack."""
import argparse
import json
from pathlib import Path
from generate_mixed_witness import render
from validate_evidence import require


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--bridged-reports", type=Path, required=True)
    parser.add_argument("--traces", type=Path, required=True)
    args = parser.parse_args()
    args.traces.mkdir(parents=True, exist_ok=True)
    modules = []
    cases = [(p, False) for p in sorted(args.reports.glob("*.json"))]
    cases += [(p, True) for p in sorted(args.bridged_reports.glob("*.json"))]
    for path, ethernet in cases:
        report = json.loads(path.read_text())
        for reverse in [False, True]:
            direction = "Reverse" if reverse else "Forward"
            for count in ([0, 1, 2] if ethernet else [0]):
                label = direction + ("VLAN" + str(count) if ethernet else "")
                tags, observation = [], None
                if ethernet:
                    filename = "opaque-" + str(count) + ("-B-A.json" if reverse else "-A-B.json")
                    observation = json.loads((Path(report["bundle"]) / filename).read_text())
                    require(observation["matches"] and all(row["exact_expected_tags"] and
                            row["payload_sha256"] == observation["expected_payload_sha256"]
                            for row in observation["matches"]), "Opaque payload control differs")
                    tags = [protocol * 65536 + tci for protocol, tci in observation["expected_tags"]]
                module = "TDN.Evidence.FreshBridgedMACsecChecks" if ethernet else "TDN.Evidence.FreshPairingStackChecks"
                content, trace = render(report, module, ethernet, tags, reverse, label)
                name = "Fresh" + report["namespace"] + label
                Path("TDN/Evidence/" + name + ".lean").write_text(content)
                trace["observation"] = observation
                (args.traces / (name + ".json")).write_text(json.dumps(trace, indent=2) + "\n")
                modules.append("TDN.Evidence." + name)
                print(name, len(trace["actions"]))
    Path("TDN/Evidence/FreshMixedDeliverySuite.lean").write_text(
        "\n".join("import " + module for module in modules) + "\n")


if __name__ == "__main__":
    main()
