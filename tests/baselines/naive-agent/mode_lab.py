"""Collect effective IPsec modes and temporarily change one benchmark endpoint at a time."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

from cohort import NETWORKS, registered_profile, runtime_profile as profile
from supervisor_transport import call as supervisor_call


WORKER = "hy@clnode176.clemson.cloudlab.us"
REMOTE_PROBE = """
from concurrent.futures import ThreadPoolExecutor
import json,re,subprocess,sys
def probe(node):
    dev,role=node
    p=subprocess.run(["docker","exec",dev,"swanctl","--list-conns","--raw"],capture_output=True,text=True,timeout=15)
    if p.returncode:raise RuntimeError("connection listing failed for "+dev)
    modes=re.findall(r"children\\s*\\{protected\\s*\\{mode=([A-Z_]+)\\b",p.stdout)
    if len(modes)!=1:raise ValueError("unexpected protected CHILD inventory on "+dev)
    return {"device":dev,"role":role,"mode":modes[0],"output":p.stdout}
with ThreadPoolExecutor(max_workers=8) as pool:
    print(json.dumps(list(pool.map(probe,json.load(sys.stdin)))))
"""
REMOTE_EDIT = """
from pathlib import Path
import hashlib,json,os,re,subprocess,sys,tempfile
req=json.load(sys.stdin)
name=req["device"]
if not re.fullmatch(r"(QF|QR|QM|XB|XL|XD)_[IO]_A1",name):raise ValueError("endpoint outside benchmark")
root=Path("/var/tmp/tdn-naive-rg-mode-lease")
config=Path(req["directory"])/"devices"/name/"swanctl/swanctl.conf"
def digest(data):return hashlib.sha256(data).hexdigest()
def install(data):
    with tempfile.NamedTemporaryFile(dir=config.parent,delete=False) as f:
        f.write(data); temp=Path(f.name)
    os.chmod(temp,config.stat().st_mode & 0o777);os.replace(temp,config)
    p=subprocess.run(["docker","exec",name,"swanctl","--load-conns"],capture_output=True,text=True,timeout=20)
    if p.returncode:raise RuntimeError("could not load connection")
def rollback():
    current=config.read_bytes();before=(root/"before").read_bytes();expected=(root/"after.sha256").read_text()
    if current!=before and digest(current)!=expected:raise ValueError("another editor changed the endpoint")
    install(before)
    for f in ("before","after.sha256","device","directory","rollback.py","timer-unit"): (root/f).unlink(missing_ok=True)
    root.rmdir()
if req["action"]=="edit":
    if root.exists():raise ValueError("another benchmark lease is active")
    old=config.read_bytes()
    if b"secrets {" in old:raise ValueError("unexpected secret section")
    new,count=re.subn(rb"(?m)^(\\s*mode\\s*=\\s*)tunnel(\\s*)$",rb"\\g<1>transport\\g<2>",old)
    if count!=1:raise ValueError("expected exactly one configured tunnel mode")
    root.mkdir(mode=0o700)
    (root/"before").write_bytes(old);(root/"after.sha256").write_text(digest(new));(root/"device").write_text(name)
    (root/"directory").write_text(req["directory"])
    unit="tdn-rg-rollback-"+req["nonce"]
    if not re.fullmatch(r"tdn-rg-rollback-[a-f0-9]{12}",unit):raise ValueError("invalid lease id")
    (root/"timer-unit").write_text(unit)
    recovery=root/"rollback.py"
    recovery.write_text(req["recovery"])
    try:
        subprocess.run(["systemd-run","--quiet","--unit",unit,"--on-active=75m","/usr/bin/python3",str(recovery),
                        name,req["directory"],str(root)],check=True)
        install(new)
    except BaseException:
        rollback()
        raise
    print(json.dumps({"device":name,"previous_sha256":digest(old),"loaded_sha256":digest(new),"watchdog":unit}))
elif req["action"]=="restore":
    if (root/"device").read_text()!=name or (root/"directory").read_text()!=req["directory"]:raise ValueError("lease mismatch")
    unit=(root/"timer-unit").read_text();previous=digest((root/"before").read_bytes())
    rollback()
    subprocess.run(["systemctl","stop",unit+".timer"],capture_output=True)
    print(json.dumps({"device":name,"restored_sha256":digest(config.read_bytes()),"expected_sha256":previous}))
else:raise ValueError("unknown operation")
"""
RECOVERY = """
import json,sys
from pathlib import Path
root=Path(sys.argv[3])
if root.exists() and (root/"device").read_text()==sys.argv[1]:
    import io
    sys.stdin=io.StringIO(json.dumps({"action":"restore","device":sys.argv[1],"directory":sys.argv[2]}))
    exec(SOURCE)
"""


def remote(script, request, host=WORKER):
    p=supervisor_call(host,["sudo","-n","python3","-c",script],data=json.dumps(request).encode(),timeout=160)
    if p.returncode:raise RuntimeError(p.stderr[-1500:].decode(errors='replace'))
    return json.loads(p.stdout)


def snapshot(profile):
    nodes=[(d["id"],d["role"]) for d in profile["topology"]["devices"] if d["role"] in ("inner","outer")]
    result=remote(REMOTE_PROBE,nodes,profile["worker"])
    if {r["device"] for r in result}!=set(d for d,_ in nodes):raise ValueError("Incomplete device inventory")
    return result


def evidence(raw):
    return {role:[[r["device"],r["mode"]] for r in raw if r["role"]==role] for role in ("inner","outer")}


def edit(profile,device,action,nonce):
    if not registered_profile(profile):raise ValueError("Network outside protocol")
    return remote(REMOTE_EDIT,{"action":action,"device":device,"directory":profile["deployment_directory"],
                               "nonce":nonce,"recovery":"SOURCE="+repr(REMOTE_EDIT)+"\n"+RECOVERY},profile["worker"])
