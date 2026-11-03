"""Observe negotiated MACsec and explicit Ethernet admission in isolated namespaces."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time


def utc():
    return datetime.now(timezone.utc).isoformat()


def capture():
    receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    receiver.setsockopt(263, 8, 1)
    receiver.settimeout(0.2)
    running = True

    def stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    while running:
        try:
            captured, ancillary, flags, metadata = receiver.recvmsg(65535, socket.CMSG_SPACE(20))
        except socket.timeout:
            continue
        if metadata[0] == "lo" or len(captured) < 14:
            continue
        auxiliary = None
        raw = captured
        for level, kind, value in ancillary:
            if level == 263 and kind == 8:
                status, length, snap_length, mac, network, tci, tpid = struct.unpack("=IIIHHHH", value[:20])
                auxiliary = {"status": status, "length": length, "snapLength": snap_length,
                             "macOffset": mac, "networkOffset": network, "vlanTCI": tci, "vlanTPID": tpid}
                if status & 16:
                    if not status & 64:
                        raise RuntimeError("VLAN metadata omits its TPID")
                    raw = captured[:12] + tpid.to_bytes(2, "big") + tci.to_bytes(2, "big") + captured[12:]
        print(json.dumps({"at": utc(), "monotonicNs": time.monotonic_ns(),
                          "interface": metadata[0], "packetType": metadata[2],
                          "capturedBytes": captured.hex(), "packetAuxiliary": auxiliary,
                          "receiveFlags": flags,
                          "source": raw[6:12].hex(), "destination": raw[:6].hex(),
                          "etherType": int.from_bytes(raw[12:14], "big"),
                          "bytes": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()}), flush=True)
    packets, drops = struct.unpack("II", receiver.getsockopt(263, 6, 8))
    print(json.dumps({"recordType": "captureStatistics", "packets": packets, "drops": drops,
                      "at": utc(), "monotonicNs": time.monotonic_ns()}), flush=True)


def inject(interface, frame):
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sender.bind((interface, 0))
    raw = bytes.fromhex(frame)
    for _ in range(3):
        sender.send(raw)
        time.sleep(0.05)
    print(json.dumps({"sent": 3, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}))


class Experiment:
    def __init__(self, root, label, filters_first=False):
        if not re.fullmatch(r"[a-z0-9]{1,6}", label):
            raise ValueError("Label must contain one through six lowercase letters or digits")
        self.root = Path(root) / label
        self.root.mkdir(parents=True, exist_ok=False)
        self.public = self.root / "public"
        self.private = self.root / "private"
        self.public.mkdir()
        self.private.mkdir(mode=0o700)
        self.label = label
        self.filters_first = filters_first
        self.prefix = "l231-" + label + "-"
        self.namespaces = []
        self.commands = []
        self.probes = []
        self.processes = []
        self.streams = []
        self.keys = []
        self.macsec = {}
        self.supplicant = shutil.which("wpa_supplicant")
        self.nft = shutil.which("nft")
        if self.supplicant is None or self.nft is None:
            raise RuntimeError("The experiment requires wpa_supplicant and nft")
        self.macs = {"A": "02:00:00:31:00:01", "B": "02:00:00:31:00:02",
                     "X": "02:00:00:31:00:03"}
        self.started = utc()

    def safe(self, value):
        text = str(value)
        for key in self.keys:
            text = text.replace(key, "[REDACTED_TEST_KEY]")
        return re.sub(r"(?m)^([^\n]*hexdump[^\n]*:)[^\n]*$",
                      r"\1 [REDACTED_HEXDUMP]", text)

    def run(self, command, node=None, check=True, input_text=None):
        command = list(map(str, command))
        actual = (["ip", "netns", "exec", self.prefix + node] if node else []) + command
        started = utc()
        started_monotonic = time.monotonic_ns()
        result = subprocess.run(actual, input=input_text, text=True, capture_output=True, timeout=20)
        row = {"id": "cmd-%04d" % len(self.commands), "device": node,
               "command": [self.safe(word) for word in actual], "startedAt": started, "endedAt": utc(),
               "startedMonotonicNs": started_monotonic, "endedMonotonicNs": time.monotonic_ns(),
               "returncode": result.returncode, "stdout": self.safe(result.stdout),
               "stderr": self.safe(result.stderr)}
        if input_text is not None:
            row["stdinSha256"] = hashlib.sha256(input_text.encode()).hexdigest()
        self.commands.append(row)
        if check and result.returncode:
            raise RuntimeError(json.dumps(row))
        return result.stdout

    def namespace(self, node):
        self.run(["ip", "netns", "add", self.prefix + node])
        self.namespaces.append(node)
        self.run(["ip", "link", "set", "dev", "lo", "up"], node)
        self.run(["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1",
                  "net.ipv6.conf.default.disable_ipv6=1"], node)

    def connect(self, node):
        first = "l2" + self.label + node.lower()
        second = first + "t"
        self.run(["ip", "link", "add", first, "type", "veth", "peer", "name", second])
        for interface, owner, final in [(first, node, "wire"), (second, "T", node.lower())]:
            self.run(["ip", "link", "set", "dev", interface, "netns", self.prefix + owner])
            self.run(["ip", "link", "set", "dev", interface, "name", final], owner)
            self.run(["ip", "link", "set", "dev", final, "up"], owner)
        self.run(["ip", "link", "set", "dev", "wire", "address", self.macs[node],
                  "allmulticast", "on", "promisc", "on"], node)
        self.run(["ip", "link", "set", "dev", node.lower(), "master", "br0"], "T")

    def start(self, command, node, filename):
        stream = (self.private / filename).open("w")
        self.streams.append(stream)
        actual = ["ip", "netns", "exec", self.prefix + node, *map(str, command)]
        process = subprocess.Popen(actual, stdout=stream, stderr=stream)
        self.processes.append(process)
        self.commands.append({"id": "cmd-%04d" % len(self.commands), "device": node,
                              "command": actual, "startedAt": utc(), "processPid": process.pid,
                              "kind": "process-start", "returncode": None,
                              "stdout": "", "stderr": ""})
        return process

    def state(self, phase):
        output = {}
        for node in self.namespaces:
            output[node] = {}
            commands = {"interfaces": ["ip", "-j", "-d", "address"],
                        "links": ["ip", "-j", "-s", "-d", "link"],
                        "routes": ["ip", "-j", "route", "show", "table", "all"],
                        "neighbors": ["ip", "-j", "neigh"],
                        "namespace": ["readlink", "/proc/self/ns/net"],
                        "filters": ["nft", "-j", "-a", "list", "ruleset"]}
            if node in ["A", "B"]:
                commands["macsec"] = ["ip", "-s", "macsec", "show"]
            for category, command in commands.items():
                self.run(command, node)
                output[node][category] = self.commands[-1]["id"]
        (self.public / (phase + ".json")).write_text(json.dumps(output, indent=2) + "\n")
        return output

    def frames(self, node):
        path = self.private / (node + "-frames.jsonl")
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]

    def rules(self, node):
        peer = "B" if node == "A" else "A"
        chains = []
        for direction, sender, receiver in [("ingress", peer, node), ("egress", node, peer)]:
            sci = self.macs[sender].replace(":", "") + "0001"
            overhead = 4 if direction == "ingress" else 18
            lengths = ", ".join(str(size) + " . " + str(size + overhead)
                                for size in range(32, 1497))
            chains.append("\n".join([
                " chain " + direction + " {",
                '  type filter hook ' + direction + ' device "wire" priority -500; policy drop;',
                "  ether saddr " + self.macs[sender] +
                " ether daddr 01:80:c2:00:00:03 ether type 0x888e" +
                " @ll,112,8 3 @ll,120,8 5 @ll,128,16 . meta length { " + lengths + " }" +
                " @ll,176,64 0x" + sci +
                ' counter accept comment "bound-mka"',
                "  ether saddr " + self.macs[sender] + " ether daddr " + self.macs[receiver] +
                ' ether type 0x88e5 counter accept comment "protected-unicast"',
                '  counter drop comment "default-deny"',
                " }"]))
        return "table netdev tdn_l2 {\n" + "\n".join(chains) + "\n}\n"

    def probe(self, label, command, node):
        before = self.state(label + "-before")
        started = utc()
        output = self.run(command, node, check=False)
        action = self.commands[-1]["id"]
        code = self.commands[-1]["returncode"]
        time.sleep(0.5)
        after = self.state(label + "-after")
        self.probes.append({"id": label, "device": node, "startedAt": started, "endedAt": utc(),
                            "commandObservation": action, "returncode": code,
                            "before": before, "after": after})
        return output

    def install_filters(self):
        for node in ["A", "B"]:
            rules = self.rules(node)
            (self.public / (node + ".nft")).write_text(rules)
            self.run(["nft", "-f", "-"], node, input_text=rules)

    def execute(self):
        script = Path(__file__).resolve()
        for command in [["uname", "-a"], [self.nft, "--version"], [self.supplicant, "-v"],
                        ["sha256sum", self.supplicant, self.nft]]:
            self.run(command)
        for node in ["T", "A", "B", "X"]:
            self.namespace(node)
        self.run(["ip", "link", "add", "br0", "type", "bridge", "mcast_snooping", "0",
                  "group_fwd_mask", "8"], "T")
        self.run(["ip", "link", "set", "dev", "br0", "up"], "T")
        for node in ["A", "B", "X"]:
            self.connect(node)
        for node in ["A", "B"]:
            self.start([sys.executable, "-u", script, "capture"], node, node + "-frames.jsonl")
        if self.filters_first:
            self.install_filters()
            self.state("pre-authentication-filters")
        cak = secrets.token_hex(32)
        self.keys.append(cak)
        ckn = secrets.token_hex(16)
        for node, priority in [("A", 0), ("B", 1)]:
            config = ('ap_scan=0\neapol_version=3\nnetwork={\n key_mgmt=NONE\n eapol_flags=0\n'
                      ' macsec_policy=1\n macsec_integ_only=0\n macsec_csindex=1\n'
                      ' macsec_replay_protect=1\n macsec_replay_window=0\n macsec_port=1\n'
                      ' mka_priority=' + str(priority) + '\n mka_cak=' + cak + '\n mka_ckn=' + ckn + '\n}\n')
            private = self.private / (node + ".conf")
            private.write_text(config)
            private.chmod(0o600)
            (self.public / (node + ".conf.public")).write_text(self.safe(config))
            self.start([self.supplicant, "-d", "-t", "-Dmacsec_linux", "-iwire", "-c", private],
                       node, node + "-wpa.log")
        for attempt in range(60):
            for node in ["A", "B"]:
                links = json.loads(self.run(["ip", "-j", "-d", "link"], node))
                match = [row["ifname"] for row in links if row.get("linkinfo", {}).get("info_kind") == "macsec"]
                if match:
                    self.macsec[node] = match[0]
            if len(self.macsec) == 2 and all("RXSC:" in self.run(["ip", "macsec", "show"], node)
                                             for node in ["A", "B"]):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Negotiated MACsec associations did not appear")
        for node, address, peer, peer_address in [("A", "10.231.0.1/30", "B", "10.231.0.2"),
                                                 ("B", "10.231.0.2/30", "A", "10.231.0.1")]:
            interface = self.macsec[node]
            self.run(["ip", "address", "add", address, "dev", interface], node)
            self.run(["ip", "link", "set", "dev", interface, "up", "allmulticast", "on", "promisc", "on"], node)
            self.run(["ip", "neigh", "replace", peer_address, "lladdr", self.macs[peer],
                      "nud", "permanent", "dev", interface], node)
            self.run(["ip", "route", "add", "224.0.0.0/4", "dev", interface], node)
        self.state("negotiated-filtered" if self.filters_first else "negotiated-unfiltered")
        group_sender = [sys.executable, "-c", "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                        "s.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_IF,socket.inet_aton('10.231.0.1'));"
                        "s.sendto(b'TDN-L2-GROUP-PROBE',('239.1.1.1',42310))"]
        if not self.filters_first:
            self.probe("unfiltered-group", group_sender, "A")
            self.install_filters()
        self.state("filters-installed")
        for node, destination in [("A", "10.231.0.2"), ("B", "10.231.0.1")]:
            self.probe("unicast-" + node, ["ping", "-n", "-c", "3", "-W", "1", destination], node)
        self.probe("egress-group-denied", group_sender, "A")
        if self.filters_first:
            self.run(["nft", "insert", "rule", "netdev", "tdn_l2", "egress",
                      "ether", "saddr", self.macs["A"], "ether", "type", "0x88e5",
                      "counter", "accept", "comment", "ingress-test-source-bypass"], "A")
            self.probe("ingress-fresh-group-denied", group_sender, "A")
            rules = json.loads(self.run(["nft", "-j", "-a", "list", "ruleset"], "A"))
            handle = next(entry["rule"]["handle"] for entry in rules["nftables"]
                          if entry.get("rule", {}).get("comment") == "ingress-test-source-bypass")
            self.run(["nft", "delete", "rule", "netdev", "tdn_l2", "egress", "handle", handle], "A")
            self.state("source-egress-restored")
        time.sleep(3)
        frames = self.frames("A")
        mka = next(bytes.fromhex(row["bytes"]) for row in frames
                   if row["interface"] == "wire" and row["source"] == self.macs["A"].replace(":", "")
                   and row["etherType"] == 0x888e and len(bytes.fromhex(row["bytes"])) > 54
                   and bytes.fromhex(row["bytes"])[15] == 5)
        group = next(bytes.fromhex(row["bytes"]) for row in frames
                     if row["interface"] == "wire" and row["etherType"] == 0x88e5
                     and bytes.fromhex(row["bytes"])[0] & 1)
        unicast = next(bytes.fromhex(row["bytes"]) for row in frames
                       if row["interface"] == "wire" and row["etherType"] == 0x88e5
                       and row["source"] == self.macs["A"].replace(":", "")
                       and not bytes.fromhex(row["bytes"])[0] & 1)
        wrong_actor = bytearray(mka)
        wrong_actor[22] ^= 2
        wrong_source = bytearray(mka)
        wrong_source[6] ^= 2
        malformed = mka[:20]
        wrong_length = bytearray(mka)
        wrong_length[17] ^= 1
        tagged_mka = mka[:12] + bytes.fromhex("81000007") + mka[12:]
        tagged_unicast = unicast[:12] + bytes.fromhex("81000007") + unicast[12:]
        for label, raw in [("ingress-group-denied", group), ("mka-wrong-actor", bytes(wrong_actor)),
                           ("mka-wrong-source", bytes(wrong_source)), ("mka-truncated", malformed),
                           ("mka-wrong-length", bytes(wrong_length)),
                           ("tagged-mka", tagged_mka), ("tagged-unicast", tagged_unicast)]:
            self.probe(label, [sys.executable, script, "inject", "--interface", "wire", "--frame", raw.hex()], "X")
        self.state("final")

    def finish(self, error):
        for process in reversed(self.processes):
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in self.streams:
            stream.close()
        for node in ["A", "B"]:
            for suffix in ["frames.jsonl", "wpa.log"]:
                source = self.private / (node + "-" + suffix)
                if source.exists():
                    (self.public / source.name).write_text(self.safe(source.read_text()))
        (self.public / "collector.source.py").write_bytes(Path(__file__).read_bytes())
        result = {"schema": "tdn-l2-admission/v1", "startedAt": self.started, "endedAt": utc(),
                  "label": self.label, "namespaces": {node: self.prefix + node for node in self.namespaces},
                  "filtersBeforeAuthentication": self.filters_first,
                  "roles": {"A": "outer", "B": "outer", "T": "transport", "X": "test-injector"},
                  "declaredLinkAddresses": self.macs, "macsecInterfaces": self.macsec,
                  "probes": self.probes, "error": self.safe(error) if error else None,
                  "scope": ["Isolated MACsec/MKA and L2-filter experiment, not a full two-layer deployment",
                            "Test PSK and software devices do not establish external approval",
                            "Raw frames, ordered nft rules and counter observations are retained separately",
                            "Filter admission and protocol validation are separate operations",
                            "Only namespaces created by this run are removed after collection"]}
        (self.public / "observations.json").write_text(json.dumps(result, indent=2) + "\n")
        (self.public / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        files = [{"path": str(path.relative_to(self.public)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "bytes": path.stat().st_size} for path in sorted(self.public.rglob("*")) if path.is_file()]
        (self.public / "manifest.json").write_text(json.dumps({"schema": "tdn-l2-admission/v1", "files": files}, indent=2) + "\n")
        for node in reversed(self.namespaces):
            subprocess.run(["ip", "netns", "delete", self.prefix + node], capture_output=True)
        print(json.dumps({"label": self.label, "public": str(self.public), "error": result["error"],
                          "commands": len(self.commands), "probes": len(self.probes)}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["collect", "capture", "inject"])
    parser.add_argument("--root")
    parser.add_argument("--label")
    parser.add_argument("--interface")
    parser.add_argument("--frame")
    parser.add_argument("--filters-first", action="store_true")
    args = parser.parse_args()
    if args.operation == "capture":
        capture()
    elif args.operation == "inject":
        inject(args.interface, args.frame)
    else:
        experiment = Experiment(args.root, args.label, args.filters_first)
        error = None
        try:
            experiment.execute()
        except Exception as exc:
            error = str(exc)
        finally:
            experiment.finish(error)
        if error:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
