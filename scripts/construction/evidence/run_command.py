import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
p=argparse.ArgumentParser()
p.add_argument("--output-dir",type=Path,default=Path("outputs/commands"))
p.add_argument("label")
p.add_argument("command",nargs=argparse.REMAINDER)
a=p.parse_args()
start=datetime.now(timezone.utc)
root=a.output_dir
root.mkdir(parents=True,exist_ok=True)
path=root/(start.strftime("%Y%m%dT%H%M%S.%fZ")+"-"+a.label+".json")
r=subprocess.run(a.command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
entry={"started_at":start.isoformat(),"ended_at":datetime.now(timezone.utc).isoformat(),"command":a.command,"returncode":r.returncode,"output":r.stdout}
path.write_text(json.dumps(entry,indent=2)+"\n")
print(r.stdout)
print("Command evidence:",path)
sys.exit(r.returncode)
