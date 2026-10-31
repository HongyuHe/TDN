import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import os
from source_paths import source_path

parser=argparse.ArgumentParser()
parser.add_argument("--label",required=True)
parser.add_argument("--input-manifest",default=os.environ.get("TDN_INPUT_MANIFEST","inputs/source_paths.json"))
parser.add_argument("--output-dir",default=os.environ.get("TDN_OUTPUT_DIR","outputs"))
parser.add_argument("--history-dir",default="history")
parser.add_argument("--recorder",default="scripts/construction/record.py")
args=parser.parse_args()
for value in [args.output_dir,args.history_dir,args.recorder]:
    if Path(value).is_absolute() or ".." in Path(value).parts:
        raise ValueError("output/history/recorder paths must be project-relative")
Path(args.output_dir).mkdir(parents=True,exist_ok=True)
os.environ["TDN_OUTPUT_DIR"]=args.output_dir
os.environ["TDN_INPUT_MANIFEST"]=args.input_manifest
commands=[
    ["python3","scripts/construction/import_provenance.py","--report","outputs/provenance-import.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("baseline")),"--lean-output","TDN/Evidence/Baseline.lean","--report","outputs/baseline-import.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("adjacency")),"--lean-output","TDN/Evidence/Adjacency.lean","--report","outputs/adjacency-import.json"],
    ["python3","scripts/construction/analyze_topology.py",str(source_path("adjacency")),"--lean-output","TDN/Evidence/Topology.lean","--report","outputs/topology-analysis.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("loaded")),"--lean-output","TDN/Evidence/LoadedBaseline.lean","--report","outputs/loaded-baseline-import.json"],
    ["python3","scripts/construction/import_mechanisms.py",str(source_path("matrix")),str(source_path("pairings")),"--lean-output","TDN/Evidence/Mechanisms.lean","--report","outputs/mechanism-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("shared_before")),"--lean-output","TDN/Evidence/SharedBefore.lean","--report","outputs/shared_before-gray.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("shared_after")),"--lean-output","TDN/Evidence/SharedAfter.lean","--report","outputs/shared_after-gray.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("redundant_after")),"--lean-output","TDN/Evidence/RedundantAfter.lean","--report","outputs/redundant_after-gray.json"],
    ["python3","scripts/construction/import_events.py","--lean-output","TDN/Evidence/Events.lean","--report","outputs/events-import.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("shared_before")),"--lean-output","TDN/Evidence/SharedBeforePolicies.lean","--report","outputs/shared_before-policies.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("shared_after")),"--lean-output","TDN/Evidence/SharedAfterPolicies.lean","--report","outputs/shared_after-policies.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("redundant_after")),"--lean-output","TDN/Evidence/RedundantAfterPolicies.lean","--report","outputs/redundant_after-policies.json"],
    ["python3","scripts/construction/import_headers.py","--lean-output","TDN/Evidence/Headers.lean","--report","outputs/header-import.json"],
    ["python3","scripts/construction/import_ike_headers.py","--lean-output","TDN/Evidence/IKEHeaders.lean","--report","outputs/ike-header-import.json"],
    ["python3","scripts/construction/import_domains.py","--lean-output","TDN/Evidence/Domains.lean","--report","outputs/domain-import.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("coherent_baseline")),"--lean-output","TDN/Evidence/CoherentBaseline.lean","--report","outputs/coherent_baseline-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("coherent_baseline")),"--lean-output","TDN/Evidence/CoherentBaselineGray.lean","--report","outputs/coherent_baseline-gray.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("coherent_same_level")),"--lean-output","TDN/Evidence/CoherentSameLevel.lean","--report","outputs/coherent_same_level-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("coherent_same_level")),"--lean-output","TDN/Evidence/CoherentSameLevelGray.lean","--report","outputs/coherent_same_level-gray.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("coherent_shared")),"--lean-output","TDN/Evidence/CoherentShared.lean","--report","outputs/coherent_shared-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("coherent_shared")),"--lean-output","TDN/Evidence/CoherentSharedGray.lean","--report","outputs/coherent_shared-gray.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("coherent_redundant")),"--lean-output","TDN/Evidence/CoherentRedundant.lean","--report","outputs/coherent_redundant-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("coherent_redundant")),"--lean-output","TDN/Evidence/CoherentRedundantGray.lean","--report","outputs/coherent_redundant-gray.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("coherent_management")),"--lean-output","TDN/Evidence/CoherentManagement.lean","--report","outputs/coherent_management-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("coherent_management")),"--lean-output","TDN/Evidence/CoherentManagementGray.lean","--report","outputs/coherent_management-gray.json"],
    ["python3","scripts/construction/bind_domains.py","--lean-output","TDN/Evidence/SameLevelBinding.lean","--report","outputs/same-level-binding.json"],
    ["python3","scripts/construction/import_management.py","--lean-output","TDN/Evidence/Management.lean","--report","outputs/management-import.json"],
    ["python3","scripts/construction/import_supplemental.py","--lean-output","TDN/Evidence/Supplemental.lean","--report","outputs/supplemental-import.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("four_shared")),"--lean-output","TDN/Evidence/FourShared.lean","--report","outputs/four_shared-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("four_shared")),"--lean-output","TDN/Evidence/FourSharedGray.lean","--report","outputs/four_shared-gray.json"],
    ["python3","scripts/construction/bind_domains.py","--source-key","four_shared","--namespace","FourSharedBinding","--lean-output","TDN/Evidence/FourSharedBinding.lean","--report","outputs/four_shared-binding.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("four_redundant")),"--lean-output","TDN/Evidence/FourRedundant.lean","--report","outputs/four_redundant-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("four_redundant")),"--lean-output","TDN/Evidence/FourRedundantGray.lean","--report","outputs/four_redundant-gray.json"],
    ["python3","scripts/construction/bind_domains.py","--source-key","four_redundant","--namespace","FourRedundantBinding","--lean-output","TDN/Evidence/FourRedundantBinding.lean","--report","outputs/four_redundant-binding.json"],
    ["python3","scripts/construction/import_authentication.py","--lean-output","TDN/Evidence/Authentication.lean","--report","outputs/authentication-import.json"],
    ["python3","scripts/construction/import_extensions.py","--lean-output","TDN/Evidence/Extensions.lean","--report","outputs/extensions-import.json"],
    ["python3","scripts/construction/import_snapshot.py",str(source_path("native_baseline")),"--lean-output","TDN/Evidence/NativeBaseline.lean","--report","outputs/native_baseline-import.json"],
    ["python3","scripts/construction/audit_gray_paths.py",str(source_path("native_baseline")),"--lean-output","TDN/Evidence/NativeBaselineGray.lean","--report","outputs/native_baseline-gray.json"],
    ["lake","build"],
    ["python3","scripts/construction/update_register.py"],
    ["python3","scripts/construction/check_register_claims.py"],
    ["lake","env","lean","outputs/RegisterClaims.lean"],
    ["lake","env","lean","tests/Semantics.lean"],
    ["lake","env","lean","tests/Axioms.lean"],
    ["lake","env","lean","tests/TopologyInterpretation.lean"],
    ["lake","env","lean","tests/Operations.lean"],
    ["python3","-m","unittest","discover","-s","tests","-p","test_*.py","-v"],
]
native_commands=[]
for key,name in [("native_baseline","NativeBaseline"),("native_same_level","NativeSameLevel"),("native_shared","NativeShared"),("native_redundant","NativeRedundant"),("native_management","NativeManagement")]:
    if key!="native_baseline":
        native_commands.extend([["python3","scripts/construction/import_snapshot.py",str(source_path(key)),"--lean-output","TDN/Evidence/"+name+".lean","--report","outputs/"+key+"-import.json"],["python3","scripts/construction/audit_gray_paths.py",str(source_path(key)),"--lean-output","TDN/Evidence/"+name+"Gray.lean","--report","outputs/"+key+"-gray.json"]])
    native_commands.append(["python3","scripts/construction/import_headers.py","--source-key",key,"--chain-module",name,"--namespace",name+"Headers","--lean-output","TDN/Evidence/"+name+"Headers.lean","--report","outputs/"+key+"-headers.json"])
    native_commands.extend([["python3","scripts/construction/analyze_topology.py",str(source_path(key)),"--scenario-key","native_declaration","--lean-output","TDN/Evidence/"+name+"Topology.lean","--report","outputs/"+key+"-topology.json"],["python3","scripts/construction/bind_domains.py","--source-key",key,"--namespace",name+"Binding","--declaration-key","native_declaration","--lean-output","TDN/Evidence/"+name+"Binding.lean","--report","outputs/"+key+"-binding.json"]])
native_commands.append(["python3","scripts/construction/import_management.py","--source-key","native_management","--namespace","NativeManagementTLS","--lean-output","TDN/Evidence/NativeManagementTLS.lean","--report","outputs/native_management-tls.json"])
native_commands.extend([["python3","scripts/construction/import_inventory.py","--lean-output","TDN/Evidence/NativeInventory.lean","--report","outputs/native_inventory-import.json"],["python3","scripts/construction/import_native_events.py","--lean-output","TDN/Evidence/NativeRedundancy.lean","--report","outputs/native_redundancy-import.json"]])
native_commands.append(["python3","scripts/construction/import_mka_audit.py","--lean-output","TDN/Evidence/MKASource.lean","--report","outputs/mka-source-import.json"])
index=commands.index(["lake","build"])
commands[index:index]=native_commands
commands.append(["python3","scripts/construction/review_coverage.py"])
commands=[[str(Path(args.output_dir)/part.removeprefix("outputs/")) if part.startswith("outputs/") else part for part in command] for command in commands]
results=[]
for index,command in enumerate(commands):
    subprocess.run(["python3",args.recorder,"checkpoint","--history-dir",args.history_dir,"--actor","construction","--label",args.label+"-pre-"+str(index),"--reason","Preserve exact source immediately before validation command","--details",json.dumps({"command":command}),"--paths","TDN","TDN.lean","scripts","tests","lakefile.toml","lake-manifest.json","lean-toolchain",args.output_dir,args.input_manifest],check=True,capture_output=True,text=True)
    started=datetime.now(timezone.utc).isoformat()
    run=subprocess.run(command,text=True,capture_output=True)
    log=Path(args.output_dir)/(args.label+"-"+str(index)+".log")
    log.write_text(run.stdout+run.stderr)
    results.append({"command":command,"started_at":started,"ended_at":datetime.now(timezone.utc).isoformat(),"returncode":run.returncode,"log":str(log)})
    subprocess.run(["python3",args.recorder,"event","--history-dir",args.history_dir,"--actor","construction","--label",args.label+"-result-"+str(index),"--reason","Preserve exact validation command result","--details",json.dumps(results[-1])],check=True,capture_output=True,text=True)
    print(json.dumps(results[-1]),flush=True)
Path(args.output_dir,args.label+"-validation.json").write_text(json.dumps(results,indent=2)+"\n")
if all(r["returncode"]==0 for r in results):
    subprocess.run(["python3","scripts/construction/finalize_validation.py",str(Path(args.output_dir,args.label+"-validation.json"))],check=True)
    subprocess.run(["python3","scripts/construction/write_reports.py"],check=True)
raise SystemExit(0 if all(r["returncode"]==0 for r in results) else 1)
