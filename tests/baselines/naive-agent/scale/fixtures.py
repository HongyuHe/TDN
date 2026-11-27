"""Nine fixed configuration changes in the three dedicated Twinet replicas."""

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

from architecture_worker import Replica
from level_policy import bindings, designate, inventory

PREFIX = {"Base": "XB", "10xLevels": "XL", "10xDevices": "XD"}
LINK = "outer-firewall-alternate-path"
MULTICAST = "outer-black-multicast"
APPLICATION = "inner-gray-application"
WEB = "gray-ordinary-http"
INGRESS = "outer-gray-wrong-ingress"
PEER = "outer-unintended-peer"
AUTH = "inner-cross-level-auth"
INBOUND = "inner-gray-plaintext-delivery"
IKE = "gray-authorized-ike-deny"
CASES = {LINK, MULTICAST, APPLICATION, WEB, INGRESS, PEER, AUTH, INBOUND, IKE}
ROOT = Path("/var/tmp/tdn-scale-study")


def command(argv, *, data=None, required=True, timeout=30):
    p = subprocess.run(
        [str(i) for i in argv],
        input=data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if required and p.returncode:
        raise RuntimeError(f"{argv[0]} exited {p.returncode}: " + p.stderr[-360:])
    return p


def container(node, *args, **opts):
    return command(["docker", "exec", "-i", node, *args], **opts)


def rules(key, pre):
    if key == IKE:
        return [
            (
                pre + "_GF_A",
                "FORWARD",
                [
                    "-i",
                    "s1",
                    "-o",
                    "g1",
                    "-s",
                    "10.100.1.2",
                    "-d",
                    "10.200.1.2",
                    "-p",
                    "udp",
                    "--dport",
                    "500",
                ],
            )
        ]
    if key == MULTICAST:
        return [
            (
                pre + "_O_A1",
                "INPUT",
                [
                    "-i",
                    "black",
                    "-s",
                    "10.200.254.240",
                    "-d",
                    "239.192.0.77",
                    "-p",
                    "udp",
                    "--dport",
                    "39101",
                ],
            )
        ]
    if key == APPLICATION:
        return [
            (
                pre + "_I_A1",
                "INPUT",
                [
                    "-i",
                    "gray",
                    "-s",
                    "10.100.1.240",
                    "-d",
                    "10.100.1.2",
                    "-p",
                    "udp",
                    "--dport",
                    "39102",
                ],
            )
        ]
    if key == INGRESS:
        return [
            (
                pre + "_O_A1",
                "INPUT",
                [
                    "-i",
                    "gray",
                    "-s",
                    "10.110.2.254",
                    "-d",
                    "10.110.1.1",
                    "-p",
                    "udp",
                    "--dport",
                    "39104",
                ],
            )
        ]
    if key == PEER:
        return [
            (
                pre + "_O_A1",
                "OUTPUT",
                [
                    "-o",
                    "black",
                    "-s",
                    "172.20.11.1",
                    "-d",
                    "192.0.2.245",
                    "-p",
                    "tcp",
                    "--dport",
                    "39106",
                ],
            ),
            (
                pre + "_O_A1",
                "INPUT",
                [
                    "-i",
                    "black",
                    "-s",
                    "192.0.2.245",
                    "-d",
                    "172.20.11.1",
                    "-p",
                    "tcp",
                    "--sport",
                    "39106",
                ],
            ),
        ]
    if key == INBOUND:
        return [
            (
                pre + "_I_A1",
                "FORWARD",
                [
                    "-i",
                    "gray",
                    "-o",
                    "red",
                    "-s",
                    "10.100.1.240",
                    "-d",
                    "10.1.1.10",
                    "-p",
                    "udp",
                    "--dport",
                    "39108",
                ],
            )
        ]
    if key == WEB:
        return [
            (
                pre + "_GF_A",
                "FORWARD",
                [
                    "-i",
                    "s1",
                    "-o",
                    "g1",
                    "-s",
                    "10.100.1.240",
                    "-d",
                    "10.120.1.240",
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                ],
            ),
            (
                pre + "_GF_A",
                "FORWARD",
                [
                    "-i",
                    "g1",
                    "-o",
                    "s1",
                    "-s",
                    "10.120.1.240",
                    "-d",
                    "10.100.1.240",
                    "-p",
                    "tcp",
                    "--sport",
                    "80",
                ],
            ),
        ]
    return []


def acl(spec, option, verdict):
    if option not in {"-C", "-D"}:
        raise ValueError("Historical firewall fixtures support inspection and rollback only")
    node, chain, matches = spec
    return container(
        node,
        "iptables",
        "-w",
        "5",
        option,
        chain,
        *matches,
        "-j",
        verdict,
        required=option != "-C",
    )


def interface(rep, node):
    p = rep.net(node, "ip", "-j", "-d", "link", "show", "dev", "lan2", check=False)
    return json.loads(p.stdout)[0] if not p.returncode else None


def restore_placement(rep, pre):
    first, second = pre + "_O_A1", pre + "_BLACK"
    a, b = interface(rep, first), interface(rep, second)
    if a and b and a["link_index"] == b["ifindex"] and b["link_index"] == a["ifindex"]:
        rep.net(first, "ip", "link", "del", "lan2")
    elif a or b:
        raise ValueError("Link ownership changed")


def alter(rep, key, pre, edit):
    if edit and key != AUTH:
        raise ValueError("This fixed-location fixture is available for archived replay only")
    if key == LINK:
        return restore_placement(rep, pre)
    if key == AUTH:
        row = next(r for r in bindings(rep.spec) if r[0] == pre + "_R_B1")
        designate(row, "S2" if edit else row[3])
        node = pre + "_I_A1"
        closed = container(
            node,
            "swanctl",
            "--terminate",
            "--ike",
            "msc",
            "--timeout",
            "5",
            required=False,
        )
        fresh = container(
            node,
            "swanctl",
            "--initiate",
            "--child",
            "protected",
            "--timeout",
            "12",
            required=False,
        )
        if fresh.returncode:
            raise ValueError("Fresh authentication did not complete")
        return {
            "red": row[0],
            "admin": row[2],
            "assigned_level": "S2" if edit else row[3],
            "terminated": closed.returncode,
            "negotiation": fresh.stdout[-900:],
        }
    verdict = "DROP" if key == IKE else "ACCEPT"
    for rule in rules(key, pre):
        present = acl(rule, "-C", verdict).returncode == 0
        if present:
            acl(rule, "-D", verdict)


@contextmanager
def probe_iface(rep, node, parent, addr, routes):
    name = "tdn-m-" + secrets.token_hex(5)
    local = "tdm" + secrets.token_hex(4)
    command(["ip", "netns", "add", name])
    try:
        rep.net(
            node,
            "ip",
            "link",
            "add",
            "link",
            parent,
            "name",
            local,
            "netns",
            name,
            "type",
            "macvlan",
            "mode",
            "bridge",
        )
        base = ["ip", "-n", name]
        command([*base, "link", "set", local, "name", "eth0"])
        command([*base, "address", "add", addr, "dev", "eth0"])
        command([*base, "link", "set", "eth0", "up"])
        for dst, via in routes:
            command(
                [
                    *base,
                    "route",
                    "add",
                    dst,
                    *(["via", via] if via else []),
                    "dev",
                    "eth0",
                ]
            )
        yield ["ip", "netns", "exec", name]
    finally:
        command(["ip", "netns", "del", name], required=False)


RECEIVE = """
import json,socket,struct,sys
addr,port,iface,marker,proto=sys.argv[1:]
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='http' else socket.SOCK_DGRAM)
s.settimeout(4)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
if addr.startswith('239.'):
    s.bind(('',int(port)));s.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(addr)+socket.inet_aton('172.20.11.1'))
else:
    s.bind((addr,int(port)))
if proto=='http':s.listen(1)
else:s.setsockopt(socket.IPPROTO_IP,8,1)
print('ready',flush=True)
try:
    if proto=='http':
        c,peer=s.accept();c.settimeout(2);data=c.recv(1024);c.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n');iface='eth0'
    else:
        data,ctrl,_,peer=s.recvmsg(1024,128)
        iface=next(socket.if_indextoname(struct.unpack('I4s4s',v[:12])[0]) for lvl,typ,v in ctrl if lvl==0 and typ==8)
    print(json.dumps({'received':marker.encode() in data,'source':peer[0],'interface':iface,'length':len(data)}))
except socket.timeout:print(json.dumps({'received':False}))
"""
SEND = """
import json,socket,sys
src,dst,port,marker,kind=sys.argv[1:]
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if kind=='http' else socket.SOCK_DGRAM);s.settimeout(2);s.bind((src,0))
try:
    if dst.startswith('239.'):s.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_IF,socket.inet_aton(src))
    if kind=='http':
        s.connect((dst,int(port)));s.sendall(('GET /'+marker+' HTTP/1.0\\r\\nHost: lab.invalid\\r\\n\\r\\n').encode());received=s.recv(128).decode()
    else:s.sendto(marker.encode(),(dst,int(port)));received=''
    print(json.dumps({'sent':True,'response':received}))
except OSError as e:print(json.dumps({'sent':False,'error':str(e)}))
"""


def transfer(client, server, src, dst, port, iface, kind="udp"):
    marker = secrets.token_hex(12)
    p = subprocess.Popen(
        [*server, "python3", "-u", "-c", RECEIVE, dst, str(port), iface, marker, kind],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        import select

        if (
            not select.select([p.stdout], [], [], 10)[0]
            or p.stdout.readline().strip() != "ready"
        ):
            raise RuntimeError("Test receiver failed to bind its registered address")
        sent = json.loads(
            command(
                [*client, "python3", "-c", SEND, src, dst, str(port), marker, kind]
            ).stdout
        )
        out, err = p.communicate(timeout=10)
        if p.returncode:
            raise RuntimeError("Test receiver failed: " + err[-180:])
        received = json.loads(out)
        observed = (
            received["received"]
            and received["source"] == src
            and received["interface"] == iface
        )
        return {
            "source": src,
            "destination": dst,
            "port": port,
            "emitter": sent,
            "endpoint": received,
            "observed": observed,
        }
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()


def plaintext_probe(rep, pre, client):
    source, destination = "10.100.1.240", "10.1.1.10"
    marker = secrets.token_hex(12)

    def watch(node, iface):
        return subprocess.Popen(
            [
                "nsenter",
                "-t",
                str(rep.pids[node]),
                "-n",
                "timeout",
                "3",
                "tcpdump",
                "-nU",
                "-s",
                "256",
                "-i",
                iface,
                "-c",
                "1",
                "-w",
                "-",
                "udp and src 10.100.1.240 and dst 10.1.1.10 and dst port 39108",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    sensors = [watch(pre + "_I_A1", "gray"), watch(pre + "_R_A1", "red")]
    try:
        time.sleep(0.45)
        sent = json.loads(
            command(
                [
                    *client,
                    "python3",
                    "-c",
                    SEND,
                    source,
                    destination,
                    "39108",
                    marker,
                    "udp",
                ]
            ).stdout
        )
        seen = []
        for proc in sensors:
            data, err = proc.communicate(timeout=6)
            if proc.returncode not in (0, 124) or len(data) < 24:
                raise ValueError("Incomplete interface capture: " + err.decode()[-140:])
            seen.append(marker.encode() in data)
        return {
            "emitter": sent,
            "source": source,
            "destination": destination,
            "payload_sha256": sha256(marker.encode()).hexdigest(),
            "gray_arrival": seen[0],
            "red_egress": seen[1],
            "observed": all(seen),
        }
    finally:
        for proc in sensors:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


def check(rep, key, pre):
    def docker(suffix):
        return ["docker", "exec", pre + "_" + suffix]

    if key == LINK:
        a, b = interface(rep, pre + "_O_A1"), interface(rep, pre + "_BLACK")
        return {
            "endpoints": [a, b],
            "observed": bool(
                a
                and b
                and a["link_index"] == b["ifindex"]
                and b["link_index"] == a["ifindex"]
            ),
        }
    if key == MULTICAST:
        with probe_iface(
            rep,
            pre + "_OF_A1",
            "inside",
            "10.200.254.240/32",
            [("239.192.0.77/32", None)],
        ) as client:
            return transfer(
                client, docker("O_A1"), "10.200.254.240", "239.192.0.77", 39101, "black"
            )
    if key in {APPLICATION, INBOUND}:
        with probe_iface(
            rep,
            pre + "_GF_A",
            "s1",
            "10.100.1.240/24",
            [("10.1.1.10/32", "10.100.1.2")],
        ) as client:
            if key == APPLICATION:
                return transfer(
                    client, docker("I_A1"), "10.100.1.240", "10.100.1.2", 39102, "gray"
                )
            return plaintext_probe(rep, pre, client)
    if key == WEB:
        with probe_iface(
            rep,
            pre + "_I_A1",
            "gray",
            "10.100.1.240/24",
            [("10.120.1.240/32", "10.100.1.254")],
        ) as client:
            with probe_iface(
                rep,
                pre + "_GR_A",
                "g1",
                "10.120.1.240/24",
                [("10.100.1.240/32", "10.120.1.254")],
            ) as server:
                return transfer(
                    client, server, "10.100.1.240", "10.120.1.240", 80, "eth0", "http"
                )
    if key == INGRESS:
        a = container(pre + "_O_A1", "ip", "-j", "route", "get", "10.110.2.254")
        rec = transfer(
            docker("GR_A"), docker("O_A1"), "10.110.2.254", "10.110.1.1", 39104, "gray"
        )
        return {
            **rec,
            "reverse_route": json.loads(a.stdout),
            "observed": rec["observed"] and json.loads(a.stdout)[0]["dev"] == "gray2",
        }
    if key == PEER:
        with probe_iface(
            rep, pre + "_OF_A1", "inside", "192.0.2.245/32", [("172.20.11.1/32", None)]
        ) as server:
            result = transfer(
                docker("O_A1"),
                server,
                "172.20.11.1",
                "192.0.2.245",
                39106,
                "eth0",
                "http",
            )
            result["registered_outer_peer"] = rep.devices[pre + "_O_A1"]["tunnel"][
                "remote"
            ]
            return result
    node = pre + "_I_A1"
    other = pre + "_I_B1"
    count = None
    if key == IKE:
        rule = rules(IKE, pre)[0]

        def packets():
            if acl(rule, "-C", "DROP").returncode:
                return None
            text = container(
                pre + "_GF_A", "iptables", "-w", "-nvxL", "FORWARD", "--line-numbers"
            ).stdout
            rows = [
                row.split()
                for row in text.splitlines()
                if "DROP" in row
                and "s1" in row.split()
                and "g1" in row.split()
                and "10.100.1.2" in row.split()
                and "10.200.1.2" in row.split()
                and "dpt:500" in row
            ]
            if len(rows) != 1:
                raise ValueError("Ambiguous IKE deny counter")
            return int(rows[0][1])

        before = packets()
        closed = container(
            node,
            "swanctl",
            "--terminate",
            "--ike",
            "msc",
            "--timeout",
            "5",
            required=False,
        )
        fresh = container(
            node,
            "swanctl",
            "--initiate",
            "--child",
            "protected",
            "--timeout",
            "8",
            required=False,
        )
        after = packets()
        count = {
            "before": before,
            "after": after,
            "closed": closed.returncode,
            "initiated": fresh.returncode,
            "output": fresh.stdout[-600:],
            "same_level": rep.devices[node]["level"] == rep.devices[other]["level"],
        }

    def sas(n):
        return container(n, "swanctl", "--list-sas").stdout

    def bound(rows, address):
        blocks = re.split(r"(?m)^(?=\S)", rows)
        return any(
            "ESTABLISHED, IKEv2" in row
            and re.search(r"(?m)^  remote\s+.*@\s*" + re.escape(address) + r"\[", row)
            and ", INSTALLED, TUNNEL" in row
            for row in blocks
        )

    a, b = sas(node), sas(other)
    src = rep.devices[node]["tunnel"]["local"]
    dst = rep.devices[other]["tunnel"]["local"]
    record = {
        "initiator": node,
        "other": other,
        "initiator_sas": a,
        "other_sas": b,
        "observed": bound(a, dst) and bound(b, src),
    }
    if key == IKE:
        pair = record["observed"]
        record["installed_at_both_ends"] = pair
        record["negotiation"] = count
        if count["before"] is None and not pair:
            raise RuntimeError("Clean designated peers failed to authenticate")
        record["observed"] = (
            not pair
            and count["before"] is not None
            and count["after"] > count["before"]
            and count["same_level"]
        )
    if key == AUTH:
        data = [r for r in inventory(rep.spec) if r["attached_inner"] in (node, other)]
        record["enclaves"] = data
        record["observed"] = (
            record["observed"]
            and len(data) == 2
            and len({r["record"]["security_level"] for r in data}) == 2
        )
    return record


def handle(req):
    name, key, action, nonce = [req[k] for k in ("network", "case", "action", "nonce")]
    if (
        name not in PREFIX
        or key not in CASES
        or action not in {"observe", "edit", "restore", "inventory-init"}
        or not re.fullmatch("[a-f0-9]{16}", nonce)
    ):
        raise ValueError("Unknown benchmark operation")
    if action == "edit" and key != AUTH:
        raise ValueError("This historical fixture is replay-only")
    rep = Replica(name)
    pre = PREFIX[name]
    if action == "inventory-init":
        if key != AUTH:
            raise ValueError("Unexpected enrollment")
        return inventory(rep.spec, install=True)
    root = ROOT / name
    lease = root / "active.json"
    if action == "observe":
        return check(rep, key, pre)
    unit = "tdn-scale-restore-" + nonce
    if action == "edit":
        with lease.open("x") as f:
            json.dump({"key": key, "nonce": nonce}, f)
        try:
            command(
                [
                    "systemd-run",
                    "--quiet",
                    "--on-active=24min",
                    "--unit=" + unit,
                    sys.executable,
                    str(Path(__file__).resolve()),
                    name,
                    key,
                    nonce,
                ]
            )
            return {"changed": alter(rep, key, pre, True), "lease": nonce}
        except Exception:
            handle({**req, "action": "restore"})
            raise
    if not lease.exists():
        return {"already_restored": True}
    if json.loads(lease.read_text()) != {"key": key, "nonce": nonce}:
        raise ValueError("Lease belongs to another trial")
    detail = alter(rep, key, pre, False)
    lease.unlink()
    command(["systemctl", "stop", unit + ".timer"], required=False)
    return {"restored": True, "detail": detail}


if __name__ == "__main__":
    os.umask(0o077)
    if len(sys.argv) == 4:
        name, key, nonce = sys.argv[1:]
        request = {"network": name, "case": key, "nonce": nonce, "action": "restore"}
    else:
        request = json.load(sys.stdin)
    print(json.dumps(handle(request)))
