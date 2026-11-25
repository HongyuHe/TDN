"""Exercise an invalid same-device tunnel endpoint without sending a packet to another peer."""

import ipaddress
import json
import re

from mode_lab import remote


def loaded_peers(rows):
    peers = {}
    for row in rows:
        matches = re.findall(r"\bremote_addrs=\[([^\]]+)\]", row["output"])
        if len(matches) != 1:
            raise ValueError("The endpoint has more than one protected connection")
        peers[row["device"]] = str(ipaddress.IPv4Address(matches[0]))
    return peers


PUBLIC_CONNECTION_LOADER = """from pathlib import Path
import subprocess, sys, tempfile

with tempfile.TemporaryDirectory(prefix="tdn-public-connection-") as directory:
    work = Path(directory)
    for name in ("x509", "x509ca"):
        (work / name).symlink_to(Path("/etc/swanctl") / name, target_is_directory=True)
    config = work / "swanctl.conf"
    config.write_text(sys.stdin.read())
    config.chmod(0o600)
    result = subprocess.run(["swanctl", "--load-conns", "--file", str(config)])
    sys.exit(result.returncode)
"""


CHANGE = """
from pathlib import Path
import hashlib,ipaddress,json,re,subprocess,sys
r=json.load(sys.stdin);dev=r['device'];nonce=r['nonce']
if not re.fullmatch(r'(NT|NF|NR|NM)_I_A1',dev) or not re.fullmatch(r'[a-f0-9]{12}',nonce):
    raise ValueError('Select the designated Inner on an original benchmark network')
expected=str(ipaddress.IPv4Address(r['expected']));original='/etc/swanctl/swanctl.conf'
if expected!='10.200.1.2':raise ValueError('Unexpected original endpoint')
def call(*args,body=None):
    return subprocess.check_output(list(args),input=body,text=True,stderr=subprocess.PIPE,timeout=18)
def conns():return call('docker','exec',dev,'swanctl','--list-conns','--raw')
def content():return call('docker','exec',dev,'cat',original)
def sha(text):return hashlib.sha256(text.encode()).hexdigest()
lease=Path('/var/tmp/tdn-naive-rg-mode-lease');unit='tdn-rg-rollback-'+nonce
def restore():
    meta=json.loads((lease/'peer.json').read_text())
    if meta['device']!=dev or meta['nonce']!=nonce or sha(content())!=meta['saved_file']:
        raise ValueError('Peer lease or original configuration differs')
    observed=conns()
    if sha(observed) not in (meta['original'],meta['expected_runtime'],meta.get('observed_after')):
        raise ValueError('Another change reached the loaded configuration')
    if sha(observed)!=meta['original']:call('docker','exec',dev,'swanctl','--load-conns')
    restored=sha(conns())
    if restored!=meta['original']:raise ValueError('Original running configuration failed to reload')
    subprocess.run(['systemctl','stop',unit+'.timer'],capture_output=True)
    for f in lease.iterdir():f.unlink()
    lease.rmdir()
    return restored
if r['action']=='restore':
    print(json.dumps({'device':dev,'restored':restore()}));sys.exit()
if r['action']!='edit':raise ValueError('Unknown action')
before=conns();conf=content()
if re.search(r'(?im)^\\s*(secrets|include)\\b',conf) or 'PRIVATE KEY' in conf:
    raise ValueError('Expected a public certificate-based connection file')
field='remote_addrs=['+expected+']'
if before.count(field)!=1 or 'mode=TUNNEL' not in before or 'class=public key' not in before:
    raise ValueError('Unexpected active configuration')
candidate,n=re.subn(r'(?m)^(\\s*remote_addrs\\s*=\\s*)'+re.escape(expected)+r'(\\s*)$',r'\\g<1>127.0.0.2\\g<2>',conf)
if n!=1:raise ValueError('Expected exactly one saved remote address')
after=before.replace(field,'remote_addrs=[127.0.0.2]')
lease.mkdir(mode=0o700)
meta={'device':dev,'nonce':nonce,'original':sha(before),'expected_runtime':sha(after),'saved_file':sha(conf)}
(lease/'peer.json').write_text(json.dumps(meta));(lease/'rollback.py').write_text(r['recovery'])
loader=__PUBLIC_CONNECTION_LOADER__
try:
    call('systemd-run','--quiet','--unit',unit,'--on-active=75m','/usr/bin/python3',str(lease/'rollback.py'))
    try:
        result=subprocess.run(['docker','exec','-i',dev,'python3','-c',loader],input=candidate,text=True,capture_output=True,timeout=18)
        if result.returncode:raise ValueError('Loading the public connection failed: '+result.stderr.strip()[-500:])
    finally:
        meta['observed_after']=sha(conns());(lease/'peer.json').write_text(json.dumps(meta))
    if conns()!=after or sha(content())!=meta['saved_file']:
        raise ValueError('The endpoint substitution did not produce the expected running state')
except BaseException:
    restore();raise
print(json.dumps({**meta,'original_address':expected,'running_address':'127.0.0.2','explicit_session_termination':False}))
""".replace("__PUBLIC_CONNECTION_LOADER__", repr(PUBLIC_CONNECTION_LOADER))


def change(profile, action, nonce):
    device = next(
        d
        for d in profile["topology"]["devices"]
        if d["role"] == "inner" and d["id"].endswith("_A1")
    )
    request = {
        "action": action,
        "device": device["id"],
        "expected": device["tunnel"]["remote"],
        "nonce": nonce,
    }
    recovery = {**request, "action": "restore"}
    request["recovery"] = (
        "import io,sys\nsys.stdin=io.StringIO("
        + repr(json.dumps(recovery))
        + ")\nexec("
        + repr(CHANGE)
        + ")\n"
    )
    return remote(CHANGE, request)


RECONNECT = """
import json,re,subprocess,sys,time
req=json.load(sys.stdin);dev=req['device'];address=req['address']
if not re.fullmatch(r'(NT|NF|NR|NM)_I_A1',dev) or address not in ('10.200.1.2','127.0.0.2'):
    raise ValueError('Unknown designated Inner connection')
other=dev.replace('_I_A1','_I_B1')
def swan(name,*args):
    return subprocess.run(['docker','exec',name,'swanctl',*args],text=True,capture_output=True,timeout=14)
def public_state(name):
    result=swan(name,'--list-sas','--raw')
    if result.returncode:raise ValueError('Could not query live associations')
    return [{'id':int(num),'established':'state=ESTABLISHED' in fields,'installed':'state=INSTALLED' in fields,
             'remote_address':re.search(r'\\bremote-host=(\\S+)',fields).group(1)}
            for num,fields in re.findall(r'list-sa event \\{msc \\{uniqueid=(\\d+)([^\\n]+)',result.stdout)]
conf=swan(dev,'--list-conns','--raw')
if conf.returncode or ('remote_addrs=['+address+']') not in conf.stdout:
    raise ValueError('Loaded peer differs from the selected control or fault')
initial=public_state(dev)
old=[sa for sa in initial if sa['installed'] and sa['established'] and sa['remote_address']=='10.200.1.2']
if len(old)!=1:raise ValueError('Exactly one original installed cross-site tunnel is required')
closed=swan(dev,'--terminate','--ike-id',str(old[0]['id']),'--timeout','5')
if closed.returncode:raise ValueError('The original connection did not close cleanly')
opened=swan(dev,'--initiate','--child','protected','--timeout','7')
local=public_state(dev);peer=public_state(other)
def installed(rows,address):return any(sa['installed'] and sa['established'] and sa['remote_address']==address for sa in rows)
connected=installed(local,'10.200.1.2') and installed(peer,'10.100.1.2')
for _ in range(6):
    if connected==(address=='10.200.1.2') and (connected or not installed(local,'10.200.1.2') and not installed(peer,'10.100.1.2')):break
    time.sleep(1);local=public_state(dev);peer=public_state(other)
    connected=installed(local,'10.200.1.2') and installed(peer,'10.100.1.2')
if connected!=(address=='10.200.1.2') or (not connected and (installed(local,'10.200.1.2') or installed(peer,'10.100.1.2'))):
    raise ValueError('The two endpoints do not confirm the expected fresh connection result')
print(json.dumps({'device':dev,'expected_cross_site_peer':other,'loaded_address':address,'prior_local':initial,
    'termination_status':closed.returncode,'initiation_status':opened.returncode,
    'fresh_local':local,'fresh_peer':peer,'cross_site_child_installed':connected}))
"""


def reconnect(profile, faulty=False):
    gateway = next(
        d["id"]
        for d in profile["topology"]["devices"]
        if d["role"] == "inner" and d["id"].endswith("_A1")
    )
    return remote(
        RECONNECT,
        {"device": gateway, "address": "127.0.0.2" if faulty else "10.200.1.2"},
    )
