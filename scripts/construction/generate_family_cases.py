"""Generate each family case and its checked delivery trace using shared importers."""
import argparse
import json
from import_snapshot import lean_list, quoted
from pathlib import Path
from network_names import address_family_module, forwarding_lean
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundles", required=True)
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()
    for family in ["444", "446", "464", "466", "644", "646", "664", "666"]:
        report = str(Path(args.run_dir) / ("fresh-family" + family + "-import.json"))
        commands = [
            [sys.executable, "scripts/construction/import_family_execution.py",
             str(Path(args.bundles) / ("families-" + family)),
             "--namespace", address_family_module(family), "--output", "TDN/Deployments/" + address_family_module(family) + ".lean",
             "--report", report],
            [sys.executable, "scripts/construction/generate_execution_witness.py", report,
             "--module", "TDN.Deployments." + address_family_module(family), "--namespace", address_family_module(family),
             "--source-port", "HA:red", "--destination-port", "HB:red",
             "--output", "TDN/Deployments/" + address_family_module(family) + "_SampleTrace.lean",
             "--trace", str(Path(args.run_dir) / ("family" + family + "-positive-trace.json"))]
        ]
        for command in commands:
            print(command, flush=True)
            subprocess.run(command, check=True)

    gates = []
    priorities = []
    for family in ["444", "446", "464", "466", "644", "646", "664", "666"]:
        report = json.loads((Path(args.run_dir) / ("fresh-family" + family + "-import.json")).read_text())
        expected = {d["id"] for d in report["model_snapshot"]["devices"] if d["role"] in {"inner", "outer"}}
        if set(report["early_header_gates"]) != expected:
            raise ValueError("Missing early header gate at an encryption gateway")
        for device, gate in report["early_header_gates"].items():
            for hook, values in gate["hooks"].items():
                identity = quoted(family + "/" + device + "/" + hook)
                gates.append("(" + identity + ", " + lean_list([str(value) for value in values]) + ")")
                priorities.append("(" + identity + ", (" + str(gate["priority"]) + " : Int))")
    source = """import TDN.Models.IpHeaderAclGuards

namespace TDN.Deployments.SnapshotFamilyImmediateHeaders
open PacketPolicy

def gates : List (String × List Nat) := """ + lean_list(gates) + """
def gatePriorities : List (String × Int) := """ + lean_list(priorities) + """

def rules (values : List Nat) : List Rule := [⟨[.ipv6NextHeaders values], .allow⟩]

lemma gate_values_checked : ∀ gate ∈ gates, gate.2 = [6, 17, 50, 58] := by
  unfold gates
  decide

lemma every_gate_precedes_defragmentation : ∀ gate ∈ gatePriorities, gate.2 < (-400 : Int) := by
  unfold gatePriorities
  decide


theorem admitted_header_before_defragmentation_is_permitted (gate : String × List Nat)
    (member : gate ∈ gates) (packet : Packet) (accepted : Accepts (rules gate.2) packet) :
    packet.ipv6NextHeader ∈ [6, 17, 50, 58] := by
  apply accepted_immediate_header (rules gate.2) [6, 17, 50, 58] ?_ packet accepted
  intro rule inRules allow
  have same : rule = ⟨[.ipv6NextHeaders gate.2], .allow⟩ := by simpa [rules] using inRules
  subst rule
  simp [ImmediateHeaderGuard, gate_values_checked gate member]

end TDN.Deployments.SnapshotFamilyImmediateHeaders
"""
    Path("TDN/Deployments/SnapshotFamilyImmediateHeaders.lean").write_text(source)


if __name__ == "__main__":
    main()
