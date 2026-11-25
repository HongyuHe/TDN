"""Match both ends of each observed veth before checking public firewall placement."""
import inspect
import json
from pathlib import Path
import sys

from measure import typecheck
from mode_lab import remote
from observe_controls import HERE, collect_network, local_command, read_device


def live(profile):
    text="from concurrent.futures import ThreadPoolExecutor\nimport json, subprocess, sys\n"
    text+="\n".join(inspect.getsource(f) for f in (local_command,read_device,collect_network))
    return remote(text+"\nprint(json.dumps(collect_network(json.load(sys.stdin))))",profile)


def attachments(profile,observed):
    spec={d["id"]:d for d in profile["topology"]["devices"]}
    records={d["device"]:d for d in observed["devices"]}
    if set(records)!=set(spec) or not all(v["interfaces_ok"] for v in records.values()):
        raise ValueError("Missing live device interface inventory")
    if any(records[n]["role"]!=d["role"] for n,d in spec.items()):raise ValueError("Role mismatch")
    zone={(d["id"],i["name"]):i["zone"] for d in spec.values() for i in d["interfaces"]}
    ends=[(n,i) for n,r in records.items() for i in r["interfaces"] if i.get("link_index") is not None]
    peers={}
    for n,i in ends:
        matches=[(other,j["ifname"]) for other,j in ends if other!=n and i["link_index"]==j["ifindex"] and j["link_index"]==i["ifindex"]]
        if len(matches)>1:raise ValueError("Ambiguous interface peer")
        if matches:peers[n,i["ifname"]]=matches[0]
    outer=sorted(n for n,d in spec.items() if d["role"]=="outer")
    firewalls=sorted(n for n,d in spec.items() if d["role"]=="firewall")
    black=sorted(n for n,d in spec.items() if d["role"]=="transport" and any(i["zone"]=="black" for i in d["interfaces"]))
    if not outer or not black or not firewalls:raise ValueError("Incomplete required roles")
    inside=[];outside=[]
    for n in firewalls:
        p=peers.get((n,"inside"))
        if p and p[0] in outer and zone.get(p)=="black":inside.append([p[0],n])
        p=peers.get((n,"outside"))
        if p and p[0] in black and zone.get(p)=="black":outside.append([n,p[0]])
    return {"outer":outer,"firewall":firewalls,"black":black,"inside":inside,"outside":outside}


def check(profile,observed,folder):
    return typecheck(HERE/"AttachmentChecks.lean",folder,attachments(profile,observed),
                     {"example : PublicAttachments outers firewalls black inside outside := by native_decide"})


def from_native(profile,native):
    snapshot=json.loads((native/"snapshot.json").read_text())
    devices=[]
    for dev in profile["topology"]["devices"]:
        observations=[o for o in snapshot["observations"] if o["kind"]=="interfaces" and o["device_id"]==dev["id"]]
        if len(observations)!=1 or observations[0]["returncode"]!=0:
            raise ValueError("Missing or repeated live interface observation on "+dev["id"])
        response=json.loads((native/observations[0]["raw_path"]).read_text())
        devices.append({"device":dev["id"],"role":dev["role"],"interfaces_ok":True,"interfaces":json.loads(response["stdout"])})
    return {"network":profile["network"],"devices":devices}
