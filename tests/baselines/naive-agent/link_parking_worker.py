"""Disconnect the selected ports of one benchmark firewall and restore their original identities."""

import json
from pathlib import Path
import re
import subprocess
import sys
import time


req = json.load(sys.stdin)
dev, nonce = req["device"], req["nonce"]
if not re.fullmatch(r"(QF|QR|QM|XB|XL|XD)_OF_A1", dev) or not re.fullmatch(r"[a-f0-9]{12}", nonce):
    raise ValueError("Select a designated firewall on an original benchmark network")
ports = req.get("ports", [req.get("side", "inside")])
if ports not in (["inside"], ["outside"]):
    raise ValueError("Select one inside or outside interface on the Outer Firewall")

lease = Path("/var/tmp/tdn-naive-rg-mode-lease")
park, unit = "tdn-disconnected-" + nonce, "tdn-rg-rollback-" + nonce


def cmd(argv):
    return subprocess.check_output(argv,text=True,stderr=subprocess.PIPE,timeout=20)


pid=cmd(['docker','inspect','-f','{{.State.Pid}}',dev]).strip()
ns = ["nsenter","-t",pid,"-n"]


def ip(*args):
    return cmd([*ns, "ip", *args])


def address(iface):
    return json.loads(ip("-j", "-d", "address", "show", "dev", iface))[0]


def identity(row):
    return {k:row.get(k) for k in ("ifname","ifindex","address","mtu","link_index","altnames","addr_info","flags")}


def routes(iface):
    return json.loads(ip("-4","-j","route","show","table","all","dev",iface))


def ospf_routes(rows):
    fields = ("dst","gateway","dev","metric","table","protocol","prefsrc","type","scope","multipath","nexthops")
    return sorted(json.dumps({k:r[k] for k in fields if k in r},sort_keys=True) for r in rows if r.get("protocol")=="ospf")


def settings(iface):
    read_values = """from pathlib import Path
import json, sys
values = {}
for version in ('ipv4','ipv6'):
    for f in (Path('/proc/sys/net')/version/'conf'/sys.argv[1]).iterdir():
        if f.name in ('stable_secret','mc_forwarding'):continue
        try:value=f.read_text().strip()
        except OSError:continue
        if value.lstrip('-').isdigit():values[f'net.{version}.conf.{sys.argv[1]}.{f.name}']=value
print(json.dumps(values))"""
    return json.loads(cmd([*ns,"python3","-c",read_values,iface]))


def original(iface):
    row = address(iface)
    parameters = settings(iface)
    route_rows = routes(iface)
    kinds = {"kernel","ospf"} if iface == "outside" else {"kernel"}
    if (row.get("linkinfo",{}).get("info_kind") != "veth" or "UP" not in row["flags"] or row.get("master") or
        row.get("qdisc") != "noqueue" or len(row["addr_info"]) != 1 or row["addr_info"][0]["family"] != "inet" or
        row["addr_info"][0].get("valid_life_time") != 4294967295 or row["addr_info"][0].get("preferred_life_time") != 4294967295 or
        parameters.get(f"net.ipv6.conf.{iface}.disable_ipv6") != "1" or any(r.get("protocol") not in kinds for r in route_rows) or
        json.loads(ip("-6","-j","route","show","table","all","dev",iface)) or
        any(json.loads(cmd([*ns,"tc","-j","filter","show","dev",iface,hook])) for hook in ("ingress","egress"))):
        raise ValueError("Additional configuration on the selected interface: "+iface)
    return {"address": row, "settings":parameters, "ospf":ospf_routes(route_rows)}


def park_inventory():
    return json.loads(cmd(["ip","-n",park,"-j","-d","address","show"]))


def recover_port(iface,saved):
    old = saved["address"]
    if any(row["ifname"] == iface for row in park_inventory()):
        if any(row["ifname"] == iface for row in json.loads(ip("-j","link","show"))):
            raise ValueError("The original interface name has been reused")
        cmd(["ip","-n",park,"link","set","dev",iface,"netns",pid])
    current = address(iface)
    if any(current.get(k) != old.get(k) for k in ("address","ifindex","link_index")):
        raise ValueError("Original interface identity has changed")
    params = settings(iface)
    for k,val in saved["settings"].items():
        if params.get(k) != val:
            cmd([*ns,"sysctl","-q","-w",k+"="+val])
    if settings(iface) != saved["settings"]:
        raise ValueError("Interface settings differ after restoration")
    for alias in set(old.get("altnames",[])) - set(current.get("altnames",[])):
        ip("link","property","add","dev",iface,"altname",alias)
    for a in old["addr_info"]:
        if not any(v["local"] == a["local"] and v["prefixlen"] == a["prefixlen"] for v in current["addr_info"]):
            ip("addr","add",a["local"]+"/"+str(a["prefixlen"]),"broadcast",a["broadcast"],"dev",iface)
    ip("link","set","dev",iface,"up")
    if identity(address(iface)) != identity(old):
        raise ValueError("Restored address, link, or carrier differs on "+iface)


def clear_lease():
    for child in lease.iterdir():
        child.unlink()
    lease.rmdir()


def result(saved, restored):
    addresses = {name: identity(address(name) if restored else saved[name]["address"]) for name in ports}
    paths = {name: ospf_routes(routes(name)) if restored else saved[name]["ospf"] for name in ports}
    field = "restored" if restored else "original"
    route_field = "ospf_routes_after" if restored else "ospf_routes_before"
    return {"device":dev, "ports":ports, field:addresses[ports[0]] if len(ports)==1 else addresses,
            route_field:paths[ports[0]] if len(ports)==1 else paths}


def restore():
    meta = json.loads((lease/"ports.json").read_text())
    if (meta["nonce"],meta["device"],meta["ports"]) != (nonce,dev,ports):
        raise ValueError("The live trial lease differs")
    saved = meta["saved"]
    for iface in ports:
        recover_port(iface,saved[iface])
    for _ in range(36):
        if all(ospf_routes(routes(i)) == saved[i]["ospf"] for i in ports):
            break
        time.sleep(2)
    else:
        raise ValueError("The original OSPF destinations, next hops and metrics have not returned")
    record = result(saved, True)
    cmd(["ip","netns","del",park])
    clear_lease()
    subprocess.run(["systemctl","stop",unit+".timer"],capture_output=True)
    return record


def disconnect():
    saved = {iface: original(iface) for iface in ports}
    record = result(saved, False)
    lease.mkdir(mode=0o700)
    (lease/"ports.json").write_text(json.dumps({"nonce":nonce,"device":dev,"ports":ports,"saved":saved}))
    (lease/"rollback.py").write_text(req["recovery"])
    try:
        cmd(["ip","netns","add",park])
    except BaseException:
        clear_lease()
        raise
    try:
        opened = park_inventory()
        defaults = {row["ifname"] for row in opened}
        if "lo" not in defaults or any("UP" in v["flags"] or v.get("addr_info") or
            (v["ifname"] != "lo" and v.get("linkinfo",{}).get("info_kind") not in ("gre","gretap","erspan")) for v in opened):
            raise ValueError("Unexpected interfaces in the empty namespace")
        cmd(["systemd-run","--quiet","--unit",unit,"--on-active=75m","/usr/bin/python3",str(lease/"rollback.py")])
        for iface in ports:
            ip("link","set","dev",iface,"netns",park)
            cmd(["ip","-n",park,"link","set","dev",iface,"down"])
        actual = park_inventory()
        if {row["ifname"] for row in actual} != defaults | set(ports) or any("UP" in row["flags"] for row in actual):
            raise ValueError("The selected ports are not fully disconnected")
        if set(ports) & {row["ifname"] for row in json.loads(ip("-j","link","show"))}:
            raise ValueError("A selected interface remains on the firewall")
    except BaseException:
        restore()
        raise
    return {**record,"isolated":True,"unit":unit}


if req["action"] == "edit":
    print(json.dumps(disconnect()))
elif req["action"] == "restore":
    print(json.dumps(restore()))
else:
    raise ValueError("Unknown operation")
