"""Import complete raw-bound loaded VPN mode inventories for the selected cases."""
import argparse
import json
from pathlib import Path

from loaded_policy import loaded_policies
from import_snapshot import lean_list, quoted
from validate_evidence import validate_bundle, require


def parse(bundle):
    bundle = Path(bundle)
    validation = validate_bundle(bundle)
    snapshot = json.loads((bundle / "snapshot.json").read_text())
    policies, bindings = loaded_policies(bundle, snapshot)
    require(policies and bindings, "Empty VPN mode inventory")
    return {"bundle": str(bundle), "validation": validation, "policies": policies, "bindings": bindings,
            "scope": "Complete loaded VPN gateway connection and CHILD proposal inventory at the recorded load/runtime snapshot.",
            "implementation_contract": [
                "The exact-file loader and captured runtime connection inventory correspond to the retained strongSwan configuration.",
                "The explicit proposal token interpretation follows the recorded strongSwan implementation; the RFC 7296 protocol implementation is trusted.",
                "All inventoried Inner and Outer VPN gateways are included. Static manual-SA cases have no IKE configuration claim.",
                "SPI rekeying does not alter this fixed loaded mode-policy claim; arbitrary later reconfiguration is outside the snapshot scope."
            ]}


def generate(data, namespace):
    entries = []
    for row in data["policies"]:
        esp = lean_list(["⟨." + p["mode"] + ", " + str(p["hmac"]).lower() + "⟩" for p in row["esp_proposals"]])
        entries.append("⟨" + quoted(row["device"] + "/" + row["connection"]) + ", " +
                       lean_list([str(v) for v in row["ike_versions"]]) + ", " +
                       lean_list(["." + mode for mode in row["ike_modes"]]) + ", " + esp + "⟩")
    return """import TDN.Targets.Protocol

namespace TDN.Imported.""" + namespace + """

def policies : List Targets.VPNModePolicy := """ + lean_list(entries) + """

lemma nonempty_gateway_inventory : policies ≠ [] := by decide

theorem complete_loaded_mode_configuration :
    Targets.msc_ike_version_and_encryption_modes policies := by
  apply Targets.vpn_mode_policies_from_complete_local_checks
  · decide
  · decide
  · decide

end TDN.Imported.""" + namespace + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.bundle)
    Path(args.output).write_text(generate(data, args.namespace))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"gateways": len(data["bindings"]), "connections": len(data["policies"]),
                      "manifest_sha256": data["validation"]["source_manifest_sha256"]}))


if __name__ == "__main__":
    main()
