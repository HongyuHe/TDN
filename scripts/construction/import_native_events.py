import argparse
import json
from pathlib import Path
from import_extensions import import_redundancy
from import_snapshot import quoted,lean_list
from source_paths import source_path
from validate_evidence import require


def generate(output,report_path):
    report=import_redundancy("native_redundancy_events")
    manifest=json.loads((source_path("native_redundancy_events")/"manifest.json").read_text())
    snapshot_manifest=json.loads((source_path("native_redundant")/"manifest.json").read_text())
    require(manifest["spec_sha256"]==snapshot_manifest["configuration_hashes"]["spec"] and report["configuration_id"]==snapshot_manifest["configuration_id"],"native event spec does not bind native redundant profile")
    lines=["import TDN.Evidence.SupplementalTypes","namespace TDN.Imported.NativeRedundancy","def probes : List Evidence.MechanismProbe := "+lean_list(["⟨"+", ".join([quoted(p["id"]),quoted(p["expected"]),quoted(p["observed"]),str(p["transmitted"]),str(p["received"])])+"⟩" for p in report["probes"]]),"theorem recorded_probe_outcomes : probes ≠ [] ∧ ∀ p ∈ probes, p.expected = p.observed := by unfold probes; decide",'theorem outage_and_restoration_witnesses : (∃ p ∈ probes, p.observed = "no_reply") ∧ (∃ p ∈ probes, p.id = "standby-restored-1" ∧ 0 < p.received) := by unfold probes; decide',"end TDN.Imported.NativeRedundancy"]
    report["platform_scope"]="Native FRR CLI manual route selection; distinct event interval bound by configuration/spec identity. No automatic or physical failover claim."
    output.write_text("\n\n".join(lines)+"\n");report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"probes":len(report["probes"])}))

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--lean-output",required=True,type=Path);parser.add_argument("--report",required=True,type=Path);args=parser.parse_args();generate(args.lean_output,args.report)
