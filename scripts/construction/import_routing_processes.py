"""Bind retained complete namespace process inventories to the OR8 service model."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "evidence"))
from derive_routing_inventory import derive
from validate_evidence import require


def selected_processes(data):
    rows = []
    for configuration in data["configurations"]:
        devices = configuration["encryption_devices"]
        require(devices and len({d["device_id"] for d in devices}) == len(devices),
                "Empty or duplicate encryption inventory")
        outers = [d for d in devices if d["role"] == "outer"]
        require(outers, "No applicable Outer device")
        for device in outers:
            processes = []
            require(device["recorded_host_processes"], "Empty process inventory")
            for process in device["recorded_host_processes"]:
                pair = (process["name"], process["command"])
                require(pair in {("sleep", "sleep infinity"),
                                 ("charon", "/usr/lib/ipsec/charon")},
                        "Uninterpreted program may supply routing service")
                require(process["recognized_fixed_program"] is True, "Program recognition differs")
                processes.append((process["host_pid"], "waiting" if pair[0] == "sleep" else "ike"))
            rows.append((device["device_id"], processes))
    require(len({name for name, _ in rows}) == len(rows), "Duplicate cross-configuration identity")
    return rows


def generate(rows):
    q = json.dumps
    lines = ["import TDN.Requirements.RoutingProcesses", "",
             "namespace TDN.Deployments.FreshRoutingProcesses", "open Requirements", "",
             "def outerDevices : List String := [" + ", ".join(q(name) for name, _ in rows) + "]",
             "", "def inventory (device : String) : List (ProcessServices.Process ObservedNetworkService) :="]
    for name, processes in rows:
        values = ", ".join("⟨" + str(pid) + ", [." + service + "]⟩" for pid, service in processes)
        lines.append("  if device = " + q(name) + " then [" + values + "] else")
    lines.extend(["  []", "",
                  "lemma complete_outer_count : outerDevices.length = " + str(len(rows)) + " := by decide",
                  "lemma process_capabilities_checked : ∀ device ∈ outerDevices, ∀ process ∈ inventory device,",
                  "    ObservedNetworkService.routingProtocol ∉ process.services := by",
                  "  simp [outerDevices, inventory]", "",
                  "/-- Fixed captured process state under complete enumeration and program correspondence.",
                  "The result does not assert future-launch prevention or binary attestation. -/",
                  "theorem captured_outers_have_no_routing_protocol_service :",
                  "    outer_routing_protocols_disabled outerDevices inventory :=",
                  "  outer_routing_protocols_from_process_inventory outerDevices inventory process_capabilities_checked",
                  "", "end TDN.Deployments.FreshRoutingProcesses", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--bundles", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = derive(args.inventory, args.bundles)
    rows = selected_processes(data)
    Path(args.output).write_text(generate(rows))
    report = {"source": data, "selected_outer_processes": rows,
              "contract": [
                  "All relevant processes in each namespace were observable during the retained host enumeration. No relevant transient or permission-denied process was silently skipped.",
                  "Recorded command/name identities correspond to the ordinary loaded sleep and strongSwan charon programs. Those selected programs provide waiting and IKE/IPsec control, not routing-protocol execution.",
                  "No hidden modified executable, unobserved kernel routing-protocol implementation or future launch is represented by this fixed captured process state.",
                  "Encryption-terminal forwarding remains permitted under original CP page24 and is not equated with a routing protocol."
              ], "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"outer_devices": len(rows), "processes": sum(len(p) for _, p in rows)}))


if __name__ == "__main__":
    main()
