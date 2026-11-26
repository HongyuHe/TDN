"""Exercise the registered local-header and Outer forwarding faults on a benchmark replica."""

import ipaddress
import json

from mode_lab import WORKER, remote
from cohort import registered_profile


REMOTE_RULE = """
from pathlib import Path
import hashlib,json,os,re,subprocess,sys
r=json.load(sys.stdin);dev=r['device'];rule=r['rule'];chain=r.get('chain','FORWARD')
if not re.fullmatch(r'(?:QF|QR|QM|XB|XL|XD)_(?:O_A1|OF_A1|I_A1)',dev):
    raise ValueError('Device outside the experiment')
if r['family']=='inner-empty-ipv4-header':
    red_rule=['-i','red','-s','10.1.1.10/32','-d','10.1.1.1/32','-p','253','-m','length','--length','0:20','-j','ACCEPT']
    if not dev.endswith('_I_A1') or chain!='INPUT' or rule!=red_rule:
        raise ValueError('The header-only test is fixed to the local Red interface and excludes payload bytes')
elif dev.endswith('_I_A1'):raise ValueError('Unknown Inner interface test')
elif r['family']=='firewall-local-empty-udp':
    empty_udp=['-i','outside','-s','172.21.11.2/32','-d','172.21.11.1/32','-p','udp','--sport','65431','--dport','65432','-m','length','--length','0:28','-j','ACCEPT']
    if not dev.endswith('_OF_A1') or chain!='INPUT' or rule!=empty_udp:
        raise ValueError('The local UDP test excludes application data and forwarding')
elif r['family']=='outer-eligible-deny' and chain=='FORWARD' and dev.endswith('_O_A1'):
    import ipaddress
    if len(rule)!=8 or rule[0:2]!=['-i',r['iface']] or rule[2]!='-s' or rule[4]!='-d' or rule[-2:]!=['-j','DROP']:
        raise ValueError('Unexpected allowlist test')
    if not (ipaddress.IPv4Address(rule[3]).is_private and ipaddress.IPv4Address(rule[5]).is_private):
        raise ValueError('Only private emulated peers are eligible')
else:raise ValueError('Unknown test family')
root=Path('/var/tmp/tdn-naive-rg-mode-lease')
def cmd(args):return subprocess.check_output(['docker','exec',dev,'iptables','-w','4',*args],text=True,timeout=12)
def rules():return cmd(['-S',chain])
def digest(blob):return hashlib.sha256(blob.encode()).hexdigest()
def restore():
    before=(root/'before').read_text();after=(root/'after').read_text();now=rules()
    if now!=before:
        if now!=after:raise ValueError('Another editor changed the chain')
        cmd(['-D',chain,'1'])
    if rules()!=before:raise ValueError('Failed to restore the original rules')
    for f in root.iterdir():f.unlink()
    root.rmdir()
if r['action']=='edit':
    if not re.fullmatch(r'[a-f0-9]{12}',r['nonce']):raise ValueError('Invalid lease id')
    root.mkdir(mode=0o700)
    unit='tdn-rg-rollback-'+r['nonce'];before=rules()
    (root/'before').write_text(before);(root/'after').write_text(before)
    (root/'device').write_text(dev);(root/'unit').write_text(unit)
    (root/'rollback.py').write_text(r['recovery'])
    try:
        subprocess.run(['systemd-run','--quiet','--unit',unit,'--on-active=75m','/usr/bin/python3',str(root/'rollback.py')],check=True)
        cmd(['-I',chain,'1',*rule]);after=rules();(root/'after').write_text(after)
        original=before.splitlines();changed=after.splitlines()
        if len(changed)!=len(original)+1 or changed[:1]+changed[2:]!=original:
            raise ValueError('Expected exactly one inserted rule')
    except BaseException:
        restore();raise
    print(json.dumps({'device':dev,'before':digest(before),'after':digest(after),'unit':unit,'inserted_rule':changed[1]}))
elif r['action']=='restore':
    if (root/'device').read_text()!=dev or (root/'unit').read_text()!='tdn-rg-rollback-'+r['nonce']:raise ValueError('Lease mismatch')
    unit=(root/'unit').read_text();expected=digest((root/'before').read_text());restore()
    subprocess.run(['systemctl','stop',unit+'.timer'],capture_output=True)
    print(json.dumps({'device':dev,'restored':digest(rules()),'expected':expected}))
else:raise ValueError('Unsupported operation')
"""
REMOTE_PINGS = """
from concurrent.futures import ThreadPoolExecutor
import json,subprocess,sys
def ping(row):
    device,dst,addr=row
    p=subprocess.run(['docker','exec',device,'ping','-n','-c','2','-W','2',addr],capture_output=True,text=True,timeout=9)
    return {'source':device,'destination':dst,'address':addr,'delivered':p.returncode==0,'returncode':p.returncode,'output':p.stdout}
with ThreadPoolExecutor(max_workers=8) as pool:print(json.dumps(list(pool.map(ping,json.load(sys.stdin)))))
"""


def intended_pairs(profile):
    hosts = [d for d in profile["topology"]["devices"] if d["role"] == "host"]
    pairs = []
    for src in hosts:
        identity = src.get("network", src["level"])
        for dst in hosts:
            if src["site"] == dst["site"] or identity != dst.get(
                "network", dst["level"]
            ):
                continue
            address = next(
                i["address"] for i in dst["interfaces"] if i["zone"] == "red"
            )
            pairs.append(
                [src["id"], dst["id"], str(ipaddress.ip_interface(address).ip)]
            )
    if not pairs:
        raise ValueError("No intended cross-site pairs")
    return pairs


def ping(profile):
    return remote(REMOTE_PINGS, intended_pairs(profile), profile["worker"])


def probe(profile, selected):
    if selected["family"] in ("inner-empty-ipv4-header", "firewall-local-empty-udp"):
        from local_packet_probe import probe as local_probe

        return local_probe(selected)
    if selected["family"] == "outer-eligible-deny":
        return ping(profile)
    raise ValueError("Unregistered forwarding case")


def selection(profile, family):
    if not registered_profile(profile):
        raise ValueError("Unknown benchmark network")
    if family in ("inner-empty-ipv4-header", "firewall-local-empty-udp"):
        from local_packet_probe import selection as local_link

        return {**local_link(profile, family), "worker": profile["worker"]}
    devices = profile["topology"]["devices"]
    if family != "outer-eligible-deny":
        raise ValueError("Unregistered forwarding case")
    prefix = devices[0]["id"].split("_")[0]
    inner = next(d for d in devices if d["id"] == prefix + "_I_A1")
    peer = next(d for d in devices if d["id"] == inner["tunnel"]["peer"])
    name, iface = "_O_A1", "gray"
    addr = lambda d: str(
        ipaddress.ip_interface(
            next(i["address"] for i in d["interfaces"] if i["zone"] == "gray")
        ).ip
    )
    return {
        "family": family,
        "worker": profile["worker"],
        "device": prefix + name,
        "iface": iface,
        "rule": ["-i", iface, "-s", addr(inner), "-d", addr(peer), "-j", "DROP"],
    }


def change(selection, action, nonce):
    req = {**selection, "action": action, "nonce": nonce}
    recovered = {**selection, "action": "restore", "nonce": nonce}
    req["recovery"] = (
        "import io,sys\nsys.stdin=io.StringIO("
        + repr(json.dumps(recovered))
        + ")\nexec("
        + repr(REMOTE_RULE)
        + ")\n"
    )
    return remote(REMOTE_RULE, req, selection.get("worker", WORKER))


def counter(selection):
    code = """
import sys,json,subprocess
r=json.load(sys.stdin)
p=subprocess.run(['docker','exec',r['device'],'iptables','-w','4','-nvx','-L',r.get('chain','FORWARD'),'1'],capture_output=True,text=True,check=True)
values=[line.split() for line in p.stdout.splitlines() if line.split() and line.split()[0].isdigit()]
expected='ACCEPT' if r['family'] in ('inner-empty-ipv4-header','firewall-local-empty-udp') else 'DROP'
if len(values)!=1 or values[0][2]!=expected:raise ValueError('The first rule differs from the test rule')
print(json.dumps({'packets':int(values[0][0]),'rule':p.stdout}))
"""
    return remote(code, selection, selection.get("worker", WORKER))
