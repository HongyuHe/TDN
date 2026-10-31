"""Import nonempty unconfigured, unattached, administratively down interface inventories."""
import argparse
import json
from pathlib import Path

from analyze_topology import validated_graph
from validate_evidence import require


def parse(bundle):
    graph = validated_graph(Path(bundle))
    roles = {d["id"]: d["role"] for d in graph["snapshot"]["devices"]}
    selected = [i for i in graph["inactive_interfaces"]
                if roles[i["interface_id"].split(":")[0]] in
                {"inner", "outer", "gray-firewall", "firewall"}]
    require(selected, "No nonempty unused Solution Component interface scope")
    for row in selected:
        require(row["admin_up"] is False and row["addresses"] == row["routes"] == row["attachments"] == 0 and
                row["configured_local_remote"] is False, "Unused-interface classification is unsupported")
    return {"bundle": str(bundle), "validation": graph["validation"], "interfaces": selected,
            "scope": "PF2 for actual unconfigured GRE-family fallback interfaces on selected Solution Components. Other unused-interface classes and PF1 minimality remain separate.",
            "contract": "Accurate complete raw interface, address, route and attachment observations; Linux administratively-down interface interpretation; fixed captured interval."}


def generate(data):
    rows = ", ".join("⟨"+json.dumps(i["interface_id"])+", false⟩" for i in data["interfaces"])
    return """import TDN.Targets.InterfaceDisablement

namespace TDN.Imported.FreshUnusedInterfaces
open Targets

def interfaces : List UnusedInterfaceState := ["""+rows+"""]

lemma no_active_unused_interface : interfaces.filter (fun interface => interface.enabled) = [] := by decide
lemma actual_unused_inventory_nonempty : interfaces.length = """+str(len(data["interfaces"]))+""" := by decide

theorem captured_unused_interfaces_are_disabled : ∀ interface ∈ interfaces, interface.enabled = false :=
  unused_interfaces_disabled_from_empty_active_subset interfaces no_active_unused_interface

end TDN.Imported.FreshUnusedInterfaces
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.bundle)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2)+"\n")
    print(json.dumps({"selected_unused_interfaces": len(data["interfaces"])}))


if __name__ == "__main__":
    main()
