"""Check the original peer pairs and re-establish any missing installed tunnel."""

from mode_lab import remote
from delivery_lab import ping


HEALTH = """
import json,subprocess,sys,time
from concurrent.futures import ThreadPoolExecutor
request=json.load(sys.stdin)
nodes=request["nodes"]
def status(node):
    p=subprocess.run(['docker','exec',node['id'],'swanctl','--list-sas','--raw'],capture_output=True,text=True,timeout=12)
    return {'device':node['id'],'installed':p.returncode==0 and 'state=INSTALLED' in p.stdout,'established':'state=ESTABLISHED' in p.stdout}
def initiate(node):
    return subprocess.run(['docker','exec',node['id'],'swanctl','--initiate','--child','protected','--timeout','12'],
                          capture_output=True,text=True,timeout=18).returncode
before=[status(n) for n in nodes];missing={r['device'] for r in before if not r['installed']}
attempted=[]
for role in ['outer','inner']:
    fix=[n for n in nodes if request['repair'] and n['site']=='A' and n['role']==role and (n['id'] in missing or n['tunnel']['peer'] in missing)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        attempted.extend(dict(device=n['id'],code=code) for n,code in zip(fix,pool.map(initiate,fix)))
for _ in range(4):
    after=[status(n) for n in nodes]
    if all(r['installed'] and r['established'] for r in after):break
    time.sleep(2)
print(json.dumps({'before':before,'after':after,'attempted':attempted}))
"""


def verify(p, *, repair=True):
    nodes = [d for d in p["topology"]["devices"] if d["role"] in ("inner", "outer")]
    sa = remote(HEALTH, {"nodes":nodes,"repair":repair}, p["worker"])
    probes = ping(p)
    return {
        "tunnels": sa,
        "delivery": probes,
        "ready": all(x["installed"] and x["established"] for x in sa["after"])
        and all(x["delivered"] for x in probes),
    }
