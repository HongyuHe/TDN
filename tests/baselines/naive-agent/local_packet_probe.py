"""Observe a single header-only datagram on one of two original local links."""

from mode_lab import WORKER, remote
from cohort import SCALE_PREFIXES


IP_HEADER = "inner-empty-ipv4-header"
FIREWALL_UDP = "firewall-local-empty-udp"
PREFIX = {"net-03": "QF", "net-04": "QR", "net-05": "QM", **SCALE_PREFIXES}


def selection(profile, family):
    prefix = PREFIX[profile["network"]]
    if family == IP_HEADER:
        host, gateway = prefix + "_R_A1", prefix + "_I_A1"
        source_role, dest_role, zone = "host", "inner", "red"
        source_iface, dest_iface = "red", "red"
        source, dest, width = "10.1.1.10", "10.1.1.1", 24
        protocol = ["-p", "253", "-m", "length", "--length", "0:20"]
    elif family == FIREWALL_UDP:
        host, gateway = prefix + "_BLACK", prefix + "_OF_A1"
        source_role, dest_role, zone = "transport", "firewall", "black"
        source_iface, dest_iface = "p11", "outside"
        if profile["network"] in SCALE_PREFIXES:
            source_iface = "p1_1"
        source, dest, width = "172.21.11.2", "172.21.11.1", 30
        protocol = [
            "-p",
            "udp",
            "--sport",
            "65431",
            "--dport",
            "65432",
            "-m",
            "length",
            "--length",
            "0:28",
        ]
    else:
        raise ValueError("Unknown local diagnostic")
    devices = {d["id"]: d for d in profile["topology"]["devices"]}
    for name, role, iface, address in (
        (host, source_role, source_iface, source),
        (gateway, dest_role, dest_iface, dest),
    ):
        device = devices[name]
        if device["role"] != role or not any(
            i["name"] == iface
            and i["zone"] == zone
            and i.get("address") == f"{address}/{width}"
            for i in device["interfaces"]
        ):
            raise ValueError("The original local test endpoints differ")
    ends = {(host, source_iface), (gateway, dest_iface)}
    if not any(
        {(v["device"], v["interface"]) for v in edge.values()} == ends
        for edge in profile["topology"]["links"]
    ):
        raise ValueError("The endpoints must be directly connected")
    return {
        "family": family,
        "device": gateway,
        "source_device": host,
        "iface": dest_iface,
        "chain": "INPUT",
        "rule": [
            "-i",
            dest_iface,
            "-s",
            source + "/32",
            "-d",
            dest + "/32",
            *protocol,
            "-j",
            "ACCEPT",
        ],
    }


PROBE = """
import json,re,select,subprocess,sys,time
row=json.load(sys.stdin);host=row['source_device'];gateway=row['device'];family=row['family']
prefix=host.split('_')[0]
if prefix not in ('QF','QR','QM','XB','XL','XD'):raise ValueError('Unknown network')
if family=='inner-empty-ipv4-header' and (host,gateway)==(prefix+'_R_A1',prefix+'_I_A1'):
    source,dest,source_iface,dest_iface,number,total='10.1.1.10','10.1.1.1','red','red',253,20
    group,column='Ip:','InUnknownProtos'
    emit='''import socket
with socket.socket(socket.AF_INET,socket.SOCK_RAW,253) as s:
    s.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,1)
    s.bind(("10.1.1.10",0))
    assert s.sendto(b"",("10.1.1.1",0))==0'''
elif family=='firewall-local-empty-udp' and (host,gateway)==(prefix+'_BLACK',prefix+'_OF_A1'):
    source,dest,source_iface,dest_iface,number,total='172.21.11.2','172.21.11.1','p11','outside',17,28
    if prefix in ('XB','XL','XD'):source_iface='p1_1'
    group,column='Udp:','NoPorts'
    emit='''import socket
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,1)
    s.bind(("172.21.11.2",65431))
    assert s.sendto(b"",("172.21.11.1",65432))==0'''
else:raise ValueError('Select one of the designated directly connected endpoints')
def cmd(*args):
    return subprocess.check_output(args,text=True,stderr=subprocess.PIPE,timeout=12)
def run(device,*args):
    return cmd('docker','exec',device,*args)
def stack_counter():
    pairs=[l.split()[1:] for l in run(gateway,'cat','/proc/net/snmp').splitlines() if l.startswith(group)]
    return int(dict(zip(*pairs))[column])
raw_protocols={int(line.split()[1].split(':')[-1],16) for line in run(gateway,'cat','/proc/net/raw').splitlines()[1:]}
if raw_protocols.intersection({number,255}):
    raise ValueError('A raw socket could receive the diagnostic')
if number==17:
    for table in ('udp','udp6'):
        if any(int(l.split()[1].split(':')[-1],16)==65432 for l in run(gateway,'cat','/proc/net/'+table).splitlines()[1:]):
            raise ValueError('An application has opened the destination port')
for device,iface,expected in [(host,source_iface,source),(gateway,dest_iface,dest)]:
    addr=json.loads(run(device,'ip','-4','-j','address','show','dev',iface))
    if [a['local'] for i in addr for a in i['addr_info']]!=[expected]:
        raise ValueError('Unexpected address on the local test segment')
route=json.loads(run(host,'ip','-4','-j','route','get',dest))[0]
if route.get('dev')!=source_iface or route.get('gateway') or route.get('prefsrc')!=source:
    raise ValueError('The diagnostic must stay on its directly connected segment')
pid=cmd('docker','inspect','-f','{{.State.Pid}}',gateway).strip()
selection=f'src host {source} and dst host {dest} and ip proto {number} and ip[2:2] = {total}'
if number==17:selection+=' and udp src port 65431 and udp dst port 65432'
monitor=subprocess.Popen(['nsenter','-t',pid,'-n','tcpdump','--immediate-mode','-l','-n','-v','-Q','in','-i',dest_iface,'-c','1',selection],
    text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    deadline=time.monotonic()+7
    while time.monotonic()<deadline:
        if select.select([monitor.stderr],[],[],.5)[0] and ('listening on '+dest_iface) in monitor.stderr.readline():
            break
    else:raise ValueError('The receive capture did not start')
    before=stack_counter()
    run(host,'python3','-c',emit)
    observed,errors=monitor.communicate(timeout=6)
    after=stack_counter()
    if monitor.returncode or not observed or after-before not in (0,1):raise ValueError('Ambiguous test packet or local counter')
    print(json.dumps([{'source':host,'destination':gateway,'total_ipv4_bytes':total,'payload_bytes':0,
        'ingress':dest_iface,'capture':observed,'protocol':number,'kernel_counter':column,'counter_before':before,'counter_after':after,
        'accepted_by_local_ip':after==before+1}]))
finally:
    if monitor.poll() is None:
        monitor.terminate();monitor.wait(timeout=5)
"""


def probe(selected):
    return remote(PROBE, selected, selected.get("worker", WORKER))
