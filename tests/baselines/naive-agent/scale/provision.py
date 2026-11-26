"""Start or remove only the benchmark's dedicated, disconnected Twinet replicas."""

import argparse
import json
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scale.profiles import NETWORKS, profile
from supervisor_transport import call


BINARY_SHA = "555098b40130410a5827e2010316a3bc00e77c90eb2cfba1f4a150a32a9ce5dd"
REMOTE = r"""
import hashlib, json, os, socket, subprocess, sys
from pathlib import Path

operation, profile, sha = json.load(sys.stdin)
names = {"Base":"XB", "10xLevels":"XL", "10xDevices":"XD"}
name = profile["network"]
prefix = names[name]
spec = profile["topology"]
root = Path("/var/tmp/tdn-scale-study")
base = root / name
assert operation in ("up", "down") and name in names
assert spec["name"] == "baseline-" + prefix.lower()
assert all(d["id"].startswith(prefix+"_") for d in spec["devices"])
assert Path(profile["deployment_directory"]) == base/"state"
os.umask(0o077)
for folder in (root, base):
    folder.mkdir(exist_ok=True)
    st=folder.lstat()
    assert not folder.is_symlink() and st.st_uid==0 and not (st.st_mode & 0o077)
binary = root/("twinet-"+sha)
if not binary.exists():
    src=Path("/var/tmp/tdn-scale-tools")/binary.name
    if not src.is_file():
        src=Path("/users/hy/tdn-evidence-v2/Twinet/bin/twinet")
    data=src.read_bytes()
    assert hashlib.sha256(data).hexdigest()==sha
    with binary.open("xb") as f: f.write(data)
    binary.chmod(0o700)
assert not binary.is_symlink() and binary.stat().st_uid==0 and hashlib.sha256(binary.read_bytes()).hexdigest()==sha
path=base/"spec.json"
if path.exists():
    assert json.loads(path.read_text())==spec
elif operation=="up":
    with path.open("x") as f: json.dump(spec,f)
else:
    raise ValueError("No registered replica")
if (base/"active.json").exists():
    raise ValueError("A trial still owns the replica")
with (base/(operation+".log")).open("a") as log:
    result=subprocess.run([str(binary),"msc",operation,"--spec",str(path),"--state-dir",str(base/"state")],
                          stdout=log,stderr=subprocess.STDOUT,timeout=5400)
if result.returncode:
    raise RuntimeError((base/(operation+".log")).read_text()[-1600:])
print(json.dumps({"network":name,"operation":operation,"devices":len(spec["devices"]),"links":len(spec["links"]),"binary":sha}))
"""


def provision(name, operation):
    p = profile(name)
    raw = json.dumps([operation, p, BINARY_SHA]).encode()
    result = call(
        p["worker"], ["sudo", "-n", "python3", "-c", REMOTE], data=raw, timeout=5460
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace")[-2000:])
    return json.loads(result.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["up", "down"])
    parser.add_argument("network", choices=NETWORKS)
    args = parser.parse_args()
    print(json.dumps(provision(args.network, args.action)))
