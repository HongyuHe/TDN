"""Operate three fixed conformance cases on private Twinet replicas. Run as the benchmark worker."""

from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

LEASE = Path("/var/tmp/tdn-naive-rg-mode-lease")
ROOT = Path("/var/tmp/tdn-multilevel-replicas")
PREFIX = {"net-03": "QF", "net-04": "QR", "net-05": "QM", "Base": "XB", "10xLevels": "XL", "10xDevices": "XD"}
FAMILIES = {"shared-inner-gateway", "gray-cross-level-path", "gray-cross-level-forward"}
SPI = 0x54444E31
LEFT, RIGHT = "10.100.1.2", "10.100.2.2"
TEST_SRC, TEST_DST = "192.0.2.247", "198.51.100.247"
TEST_PORT = "lan2"
RED_SINK = "10.2.1.248"
TEMP_CONFIG = "/run/tdn-extra-child.conf"


def run(argv, *, data=None, check=True, timeout=25):
    p = subprocess.run(
        [str(v) for v in argv],
        input=data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and p.returncode:
        raise RuntimeError(
            f"{argv[0]} failed ({p.returncode}): " + (p.stderr or p.stdout)[-400:]
        )
    return p


def in_device(device, *command, **kwargs):
    return run(["docker", "exec", "-i", device, *command], **kwargs)


class Replica:
    def __init__(self, network):
        prefix = PREFIX[network]
        directory = (Path("/var/tmp/tdn-scale-study") if prefix.startswith("X") else ROOT) / network
        self.network = network
        self.spec = json.loads((directory / "spec.json").read_text())
        self.devices = {d["id"]: d for d in self.spec["devices"]}
        self.a, self.b, self.peer, self.host, self.fw = [
            prefix + "_" + suffix for suffix in ("I_A1", "I_A2", "I_B1", "R_A2", "GF_A")
        ]
        if self.spec["name"] != "baseline-" + prefix.lower() or any(
            not n.startswith(prefix + "_") for n in self.devices
        ):
            raise ValueError("Unexpected replica identity")
        inspected = json.loads(run(["docker", "inspect", *self.devices]).stdout)
        self.pids = {}
        for container in inspected:
            labels = container["Config"]["Labels"]
            name = container["Name"].removeprefix("/")
            if (
                labels.get("twinet.msc.device") != name
                or labels.get("twinet.msc.lab") != self.spec["name"]
                or labels.get("twinet.msc.state") != str(directory / "state")
                or container["HostConfig"]["NetworkMode"] != "none"
                or not container["State"]["Running"]
            ):
                raise ValueError(f"{name} is not an isolated running Twinet replica")
            self.pids[name] = container["State"]["Pid"]
        if set(self.pids) != set(self.devices) or len(set(self.pids.values())) != len(
            self.devices
        ):
            raise ValueError("Incomplete replica inventory")
        if self.devices[self.a]["level"] == self.devices[self.b]["level"] or [
            self.devices[n]["tunnel"]["local"] for n in (self.a, self.b)
        ] != [LEFT, RIGHT]:
            raise ValueError("Wrong Inner endpoint or security level")

    def net(self, dev, *cmd, **kwargs):
        return run(["nsenter", "-t", self.pids[dev], "-n", *cmd], **kwargs)


def rule():
    return [
        "-i",
        "s1",
        "-o",
        "s2",
        "-s",
        LEFT + "/32",
        "-d",
        RIGHT + "/32",
        "-p",
        "esp",
        "-j",
        "ACCEPT",
    ]


def add_link(rep, family):
    gray = family == "gray-cross-level-path"
    other = rep.b if gray else rep.host
    for name in (rep.a, other):
        if (
            rep.net(
                name, "ip", "link", "show", "dev", TEST_PORT, check=False
            ).returncode
            == 0
        ):
            raise ValueError(f"{name}/{TEST_PORT} already exists")
    rep.net(
        rep.a,
        "ip",
        "link",
        "add",
        TEST_PORT,
        "type",
        "veth",
        "peer",
        "name",
        "tdnpeer",
        "netns",
        str(rep.pids[other]),
    )
    rep.net(other, "ip", "link", "set", "tdnpeer", "name", TEST_PORT)
    for name, address in ((rep.a, "10.1.2.253"), (other, "10.1.2.252")):
        rep.net(name, "sysctl", "-qw", "net.ipv6.conf." + TEST_PORT + ".disable_ipv6=1")
        if gray:
            rep.net(name, "tc", "qdisc", "add", "dev", TEST_PORT, "clsact")
            rep.net(
                name,
                "tc",
                "filter",
                "add",
                "dev",
                TEST_PORT,
                "ingress",
                "matchall",
                "action",
                "drop",
            )
        else:
            rep.net(name, "ip", "address", "add", address + "/32", "dev", TEST_PORT)
        rep.net(name, "ip", "link", "set", "dev", TEST_PORT, "up")


def child_config(original, local):
    if re.search(r"^\s*secrets\s*\{", original, re.M) or "red2 {" in original:
        raise ValueError("Expected the public single-CHILD configuration")
    blocks = list(re.finditer(r"(?m)^( *)protected \{\n[^{}]*?^\1\}", original))
    if len(blocks) != 1:
        raise ValueError("Expected one protected CHILD")
    block = blocks[0]
    new = block[0].replace("protected {", "red2 {")
    field = "local_ts" if local else "remote_ts"
    new, changed = re.subn(
        r"(?m)^(\s*" + field + r"\s*=\s*)10\.1\.1\.0/24\s*$", r"\g<1>10.1.2.0/24", new
    )
    new, reqids = re.subn(r"(?m)^(\s*reqid\s*=\s*)101$", r"\g<1>31001", new)
    if changed != 1 or reqids != 1:
        raise ValueError("Unexpected selectors or request ID")
    new = re.sub(
        r"(?m)^(\s*(?:start_action|close_action)\s*=\s*)trap$", r"\g<1>none", new
    )
    public = original[: block.end()] + "\n" + new + original[block.end() :]
    return public.replace(
        "certs = cert.pem", "certs = /etc/swanctl/x509/cert.pem"
    ).replace("cacerts = ca.pem", "cacerts = /etc/swanctl/x509ca/ca.pem")


def red_routes(rep):
    return [
        (rep.a, ["10.1.2.252/32", "dev", TEST_PORT]),
        (
            rep.host,
            [
                RED_SINK + "/32",
                "via",
                "10.1.2.253",
                "dev",
                TEST_PORT,
                "onlink",
                "src",
                "10.1.2.252",
            ],
        ),
    ]


def red_policy():
    return [
        "-i",
        TEST_PORT,
        "-o",
        "gray",
        "-s",
        "10.1.2.252/32",
        "-d",
        RED_SINK + "/32",
        "-p",
        "icmp",
        "-m",
        "policy",
        "--dir",
        "out",
        "--pol",
        "ipsec",
        "--reqid",
        "31001",
        "--mode",
        "tunnel",
        "-j",
        "ACCEPT",
    ]


def child_traffic(rep):
    def counters():
        answer = {}
        children = re.split(
            r"(?m)^  (\S+): #\d+, reqid (\d+), INSTALLED, TUNNEL, ESP:",
            in_device(rep.a, "swanctl", "--list-sas").stdout,
        )
        for name, reqid, rest in zip(children[1::3], children[2::3], children[3::3]):
            out = re.search(
                r"(?m)^    out\s+([a-fA-F0-9]+),\s*\d+ bytes,\s*(\d+) packets", rest
            )
            if out and name in ("protected", "red2"):
                if name in answer:
                    raise ValueError("Ambiguous installed CHILD during the test")
                answer[name] = {
                    "reqid": int(reqid),
                    "spi": out[1],
                    "packets": int(out[2]),
                }
        if {k: v["reqid"] for k, v in answer.items()} != {
            "protected": 101,
            "red2": 31001,
        }:
            raise ValueError(
                "Expected both installed CHILDs on the same running gateway"
            )
        return answer

    samples = []
    for host, source, child in (
        (rep.a.replace("_I_A1", "_R_A1"), "10.1.1.10", "protected"),
        (rep.host, "10.1.2.252", "red2"),
    ):
        before = counters()
        result = rep.net(
            host,
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            source,
            RED_SINK,
            check=False,
        )
        if result.returncode != 1:
            raise ValueError(
                "The documentation test needs an unused destination on the remote Red subnet"
            )
        after = counters()
        samples.append(
            {
                "host": host,
                "source": source,
                "destination": RED_SINK,
                "gateway": rep.a,
                "child": child,
                "before": before,
                "after": after,
            }
        )
    return samples


def enter(rep, family):
    if family in ("gray-cross-level-path", "shared-inner-gateway"):
        add_link(rep, family)
    if family == "shared-inner-gateway":
        for name in (rep.peer, rep.a):
            original = in_device(name, "cat", "/etc/swanctl/swanctl.conf").stdout
            added = child_config(original, name == rep.a)
            in_device(name, "tee", TEMP_CONFIG, data=added)
            in_device(name, "swanctl", "--load-conns", "--file", TEMP_CONFIG)
        in_device(
            rep.a,
            "swanctl",
            "--initiate",
            "--child",
            "red2",
            "--timeout",
            "15",
            timeout=22,
        )
        for node, route in red_routes(rep):
            rep.net(node, "ip", "route", "add", *route)
        in_device(rep.a, "iptables", "-w", "-I", "FORWARD", "1", *red_policy())
    elif family == "gray-cross-level-forward":
        in_device(rep.fw, "iptables", "-w", "-I", "FORWARD", "1", *rule())


def leave(rep, family):
    if family == "gray-cross-level-forward":
        if (
            in_device(
                rep.fw, "iptables", "-w", "-C", "FORWARD", *rule(), check=False
            ).returncode
            == 0
        ):
            in_device(rep.fw, "iptables", "-w", "-D", "FORWARD", *rule())
        return
    if family == "shared-inner-gateway":
        if (
            in_device(
                rep.a, "iptables", "-w", "-C", "FORWARD", *red_policy(), check=False
            ).returncode
            == 0
        ):
            in_device(rep.a, "iptables", "-w", "-D", "FORWARD", *red_policy())
        for node, route in red_routes(rep):
            if json.loads(
                rep.net(node, "ip", "-j", "route", "show", "exact", route[0]).stdout
            ):
                rep.net(node, "ip", "route", "del", *route)
        for name in (rep.a, rep.peer):
            in_device(
                name, "swanctl", "--load-conns", "--file", "/etc/swanctl/swanctl.conf"
            )
        for name in (rep.a, rep.peer):
            sas = in_device(name, "swanctl", "--list-sas", "--child", "red2").stdout
            if "INSTALLED" in sas:
                in_device(
                    name, "swanctl", "--terminate", "--child", "red2", "--timeout", "10"
                )
            in_device(name, "rm", "-f", TEMP_CONFIG)
    if (
        rep.net(rep.a, "ip", "link", "show", "dev", TEST_PORT, check=False).returncode
        == 0
    ):
        rep.net(rep.a, "ip", "link", "del", "dev", TEST_PORT)


def precheck(rep, family):
    if family == "gray-cross-level-forward":
        if (
            in_device(
                rep.fw, "iptables", "-w", "-C", "FORWARD", *rule(), check=False
            ).returncode
            == 0
        ):
            raise ValueError("The test permit already exists")
    else:
        other = rep.b if family == "gray-cross-level-path" else rep.host
        for dev in (rep.a, other):
            if (
                rep.net(
                    dev, "ip", "link", "show", "dev", TEST_PORT, check=False
                ).returncode
                == 0
            ):
                raise ValueError("The extra interface already exists")
        if family == "shared-inner-gateway":
            for node, route in red_routes(rep):
                if json.loads(
                    rep.net(node, "ip", "-j", "route", "show", "exact", route[0]).stdout
                ):
                    raise ValueError("The assigned diagnostic route already exists")
            if (
                in_device(
                    rep.a, "iptables", "-w", "-C", "FORWARD", *red_policy(), check=False
                ).returncode
                == 0
            ):
                raise ValueError("The extra Red interface policy already exists")
            for name in (rep.a, rep.peer):
                if (
                    in_device(name, "test", "-e", TEMP_CONFIG, check=False).returncode
                    == 0
                ):
                    raise ValueError("The temporary connection file already exists")
                if "red2" in in_device(name, "swanctl", "--list-conns").stdout:
                    raise ValueError("The extra CHILD already exists")
                child_config(
                    in_device(name, "cat", "/etc/swanctl/swanctl.conf").stdout,
                    name == rep.a,
                )


def collect(rep):
    from concurrent.futures import ThreadPoolExecutor

    def collect_one(item):
        n, d = item
        result = {"interfaces": rep.net(n, "ip", "-j", "-d", "addr", "show").stdout}
        if d["role"] == "inner":
            result["sas"] = in_device(n, "swanctl", "--list-sas").stdout
        if d["role"] == "gray-firewall":
            result["filters4"] = in_device(n, "iptables-save", "-t", "filter").stdout
        return n, result

    with ThreadPoolExecutor(max_workers=12) as pool:
        return dict(pool.map(collect_one, rep.devices.items()))


def receive_records():
    import select
    import socket
    import struct

    stop = time.monotonic() + 4
    seen = {"ingress": [], "egress": []}
    with ExitStack() as cleanup:
        sockets = {}
        for iface, side in (("s1", "ingress"), ("s2", "egress")):
            sock = cleanup.enter_context(
                socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            )
            sock.bind((iface, 0))
            sockets[sock] = side
        print("ready", flush=True)
        while time.monotonic() < stop:
            readable, _, _ = select.select(
                list(sockets), [], [], max(0, stop - time.monotonic())
            )
            for sock in readable:
                frame, addr = sock.recvfrom(65535)
                side = sockets[sock]
                if (addr[2] == socket.PACKET_OUTGOING) != (side == "egress") or frame[
                    12:14
                ] != b"\x08\x00":
                    continue
                ip = frame[14:]
                if (
                    len(ip) < 28
                    or ip[0] >> 4 != 4
                    or ip[9] != 50
                    or ip[12:20] != socket.inet_aton(LEFT) + socket.inet_aton(RIGHT)
                ):
                    continue
                length = int.from_bytes(ip[2:4], "big")
                esp = ip[(ip[0] & 15) * 4 : length]
                if (
                    len(esp) < 24
                    or length > len(ip)
                    or struct.unpack("!I", esp[:4])[0] != SPI
                ):
                    continue
                seen[side].append(
                    {
                        "iface": addr[0],
                        "source": LEFT,
                        "destination": RIGHT,
                        "protocol": 50,
                        "spi": SPI,
                        "seq": int.from_bytes(esp[4:8], "big"),
                        "esp_sha256": sha256(esp).hexdigest(),
                    }
                )
    print(json.dumps(seen))


def trial_packet(rep):
    with ExitStack() as changes:

        def installed(add, remove, *, iptables=False):
            command = (
                (lambda *argv, **kw: in_device(rep.a, *argv, **kw))
                if iptables
                else (lambda *argv, **kw: rep.net(rep.a, *argv, **kw))
            )
            command(*add)
            changes.callback(command, *remove)

        def ip(object_, args):
            installed(["ip", *object_, "add", *args], ["ip", *object_, "del", *args])

        def output(args):
            installed(
                ["iptables", "-w", "-I", "OUTPUT", "1", *args],
                ["iptables", "-w", "-D", "OUTPUT", *args],
                iptables=True,
            )

        ip(["addr"], [TEST_SRC + "/32", "dev", "lo"])
        for dest in (RIGHT, TEST_DST):
            current = rep.net(
                rep.a, "ip", "-j", "route", "show", "exact", dest + "/32"
            ).stdout
            if not json.loads(current):
                ip(["route"], [dest + "/32", "via", "10.100.1.254", "dev", "gray"])
            elif not all(
                r.get("gateway") == "10.100.1.254" and r.get("dev") == "gray"
                for r in json.loads(current)
            ):
                raise ValueError("The packet fixture would replace an existing route")
        state = ["src", LEFT, "dst", RIGHT, "proto", "esp", "spi", hex(SPI)]
        #* The receiving gateway has no matching test key. Only the firewall transit is measured.
        key = "0x" + secrets.token_hex(20)
        installed(
            [
                "ip",
                "xfrm",
                "state",
                "add",
                *state,
                "reqid",
                "31999",
                "mode",
                "tunnel",
                "aead",
                "rfc4106(gcm(aes))",
                key,
                "128",
            ],
            ["ip", "xfrm", "state", "delete", *state],
        )
        selector = ["dir", "out", "src", TEST_SRC + "/32", "dst", TEST_DST + "/32"]
        installed(
            [
                "ip",
                "xfrm",
                "policy",
                "add",
                *selector,
                "tmpl",
                "src",
                LEFT,
                "dst",
                RIGHT,
                "proto",
                "esp",
                "reqid",
                "31999",
                "mode",
                "tunnel",
            ],
            ["ip", "xfrm", "policy", "delete", *selector],
        )
        output(["-s", TEST_SRC, "-d", TEST_DST, "-p", "icmp", "-j", "ACCEPT"])
        output(
            [
                "-s",
                LEFT,
                "-d",
                RIGHT,
                "-p",
                "esp",
                "-m",
                "esp",
                "--espspi",
                str(SPI),
                "-j",
                "ACCEPT",
            ]
        )
        with subprocess.Popen(
            [
                "nsenter",
                "-t",
                str(rep.pids[rep.fw]),
                "-n",
                "python3",
                __file__,
                "receive",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as observer:
            if observer.stdout.readline().strip() != "ready":
                raise RuntimeError(
                    "Firewall observation sockets did not start: "
                    + observer.stderr.read()[-300:]
                )
            ping = rep.net(
                rep.a,
                "ping",
                "-n",
                "-c",
                "1",
                "-W",
                "1",
                "-I",
                TEST_SRC,
                TEST_DST,
                check=False,
            )
            if ping.returncode not in (0, 1):
                raise RuntimeError("The test packet could not be originated")
            out, err = observer.communicate(timeout=8)
            if observer.returncode:
                raise RuntimeError(err[-400:])
        packets = json.loads(out)
        if len(packets["ingress"]) != 1:
            raise ValueError(
                "One kernel-generated ESP packet must arrive at the Gray Firewall"
            )
        return packets


def handle(request):
    network, family, op, nonce = (
        request[k] for k in ("network", "family", "action", "nonce")
    )
    if family not in FAMILIES or not re.fullmatch(r"[a-f0-9]{16}", nonce):
        raise ValueError("Unregistered benchmark case")
    rep = Replica(network)
    if op == "read":
        return collect(rep)
    if op == "usage" and family == "shared-inner-gateway":
        if json.loads((LEASE / "architecture.json").read_text()) != [
            network,
            family,
            nonce,
        ]:
            raise ValueError("The shared assignment must be active")
        return child_traffic(rep)
    if op == "packet" and family == "gray-cross-level-forward":
        return trial_packet(rep)
    marker = LEASE / "architecture.json"
    identity = [network, family, nonce]
    if op == "edit":
        if (
            family == "gray-cross-level-forward"
            and request.get("permit") != "peer-addresses"
        ):
            raise ValueError(
                "The controller must request the registered address-pair ESP permit"
            )
        precheck(rep, family)
        LEASE.mkdir(mode=0o700)
        marker.write_text(json.dumps(identity))
        unit = "tdn-architecture-" + nonce
        try:
            local = LEASE / "worker.py"
            local.write_bytes(Path(__file__).read_bytes())
            run(
                [
                    "systemd-run",
                    "--quiet",
                    "--unit",
                    unit,
                    "--on-active=85m",
                    "/usr/bin/python3",
                    local,
                    "recover",
                    network,
                    family,
                    nonce,
                ]
            )
            enter(rep, family)
        except BaseException:
            handle({**request, "action": "restore"})
            raise
        return {
            "network": network,
            "family": family,
            "device": rep.fw if family.endswith("forward") else rep.a,
        }
    if op != "restore" or json.loads(marker.read_text()) != identity:
        raise ValueError("Active trial identity differs")
    leave(rep, family)
    run(["systemctl", "stop", "tdn-architecture-" + nonce + ".timer"], check=False)
    (LEASE / "worker.py").unlink(missing_ok=True)
    marker.unlink()
    LEASE.rmdir()
    return {"network": network, "restored": True}


if __name__ == "__main__":
    if sys.argv[1:] == ["receive"]:
        receive_records()
    elif len(sys.argv) == 5 and sys.argv[1] == "recover":
        print(
            json.dumps(
                handle(
                    dict(
                        zip(("network", "family", "nonce"), sys.argv[2:]),
                        action="restore",
                    )
                )
            )
        )
    else:
        print(json.dumps(handle(json.load(sys.stdin))))
