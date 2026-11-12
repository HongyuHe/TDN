"""Verify that a JSON edit invalidates the Lean module that imports it."""
from pathlib import Path
import subprocess,json
root=Path(__file__).resolve().parents[3];source=root/'TDN/Import/DependencyProbe.lean';data=root/'data/evidence/DependencyProbe.json'; results=[]
assert not source.exists() and not data.exists()
source.write_text('import TDN.Import.SnapshotLoader\nnamespace TDN.ImportTests\nload_network_records probe : Nat from "../../data/evidence/DependencyProbe.json" ["value"]\nexample : probe = 1 := by native_decide\nend TDN.ImportTests\n')
try:
 for value,expected in [(1,0),(2,1),(1,0)]:
  data.write_text(json.dumps({'value':value})+'\n')
  r=subprocess.run(['lake','build','TDN.Import.DependencyProbe'],cwd=root,capture_output=True,text=True)
  results.append({'value':value,'exit':r.returncode,'output':r.stdout+r.stderr})
  assert (r.returncode!=0)==(expected!=0),results[-1]
 print('Lake cache invalidation: pass, failed after data mutation, passed after restoration')
finally:
 source.unlink(missing_ok=True);data.unlink(missing_ok=True)
 (root/'mcp/artifacts/build-invalidation.json').write_text(json.dumps(results,indent=2))
