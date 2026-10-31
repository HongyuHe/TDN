import hashlib,json
from pathlib import Path
from datetime import datetime,timezone
out=Path('artifacts/snapshots/2026-10-24T014455Z/public-runtime-supplement-v5');inventory=json.loads((out/'inventory.json').read_text())
for row in inventory['files']:
 p=Path(row['path']);assert p.stat().st_size==row['bytes']and hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256']
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
manifest={'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'source_binding_scope':'This exact helper verifies the final public inventory and writes this manifest. The acquisition URL, fetched archive hash and selected export are separately recorded in public-build metadata. The source-audit reference file is a reference, not the acquisition collector.','files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()and p.name!='manifest.json']}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'validated_public_files':len(inventory['files'])}))
