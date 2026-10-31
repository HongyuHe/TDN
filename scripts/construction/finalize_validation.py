import argparse
import hashlib
import json
from pathlib import Path
import re
from source_paths import output_path

parser=argparse.ArgumentParser();parser.add_argument("validation",type=Path);args=parser.parse_args()
rows=json.loads(args.validation.read_text())
if not rows or any(r["returncode"]!=0 for r in rows):raise ValueError("Cannot finalize an unsuccessful validation")
register_path=output_path("theorem_register.json");register=json.loads(register_path.read_text())
reference={"kind":"completed_validation","path":str(args.validation),"sha256":hashlib.sha256(args.validation.read_bytes()).hexdigest(),"completed_at":max(r["ended_at"] for r in rows),"commands":len(rows)}
for group in register["groups"]:
    for item in group["claim_dependencies"]+group["evidence_dependencies"]+group["established_scopes"]:item["validation"]=reference
    for scope in group["established_scopes"]:scope["validation_reference_kind"]="completed_validation"
for item in register["evidence_catalog"].values():
    if item["kind"]!="historical_finite_experiment":item["validation"]=reference
register["dependency_validation_reference"]=reference
register_path.write_text(json.dumps(register,indent=2)+"\n")
files=[]
for root in [Path("TDN"),Path("scripts"),Path("tests")]:
    for path in sorted(root.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix in {".py",".lean"}:
            files.append({"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
for name in ["TDN.lean","lakefile.toml","lake-manifest.json","lean-toolchain"]:
    path=Path(name);files.append({"path":name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
counts=[]
for row in rows:
    if row["command"][:3]==["python3","-m","unittest"]:
        counts+=re.findall(r"Ran (\d+) tests",Path(row["log"]).read_text())
report={"validation":reference,"python_tests":int(counts[-1]) if counts else None,"files":files}
output_path("validated-source-manifest.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({"finalized":reference,"source_files":len(files),"python_tests":report["python_tests"]}))
