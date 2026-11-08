"""Capture routed MACsec traffic before and after disabling link protection."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time

from l2_admission_lab import capture


PAYLOAD = "TDN-MACSEC-PHYSICAL-BOUNDARY"
ADDRESSES = {"R": "10.242.0.2", "Ared": "10.242.0.1",
             "A": "10.243.0.1", "B": "10.243.0.2"}
MACS = {"R": "02:00:00:42:00:02", "Ared": "02:00:00:42:00:01",
        "A": "02:00:00:43:00:01", "B": "02:00:00:43:00:02"}


def utc():
    return datetime.now(timezone.utc).isoformat()


def sink():
    import socket
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind((ADDRESSES["B"], 44731))
    receiver.settimeout(0.2)
    running = True

    def stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    while running:
        try:
            payload, peer = receiver.recvfrom(65535)
        except socket.timeout:
            continue
        print(json.dumps({"at": utc(), "monotonicNs": time.monotonic_ns(),
                          "payload": payload.hex(), "peer": list(peer)}), flush=True)


class Experiment:
    def __init__(self, output, label, integrity_only=False):
        if not re.fullmatch(r"[a-z0-9]{1,6}", label):
            raise ValueError("Use one through six lowercase letters or digits")
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=False)
        self.prefix = "mb31-" + label + "-"
        self.created = []
        self.processes = []
        self.commands = []
        self.cases = []
        self.keys = [secrets.token_hex(32), secrets.token_hex(32)]
        self.started = utc()
        self.integrity_only = integrity_only

    def public(self, value):
        text = str(value)
        for key in self.keys:
            text = text.replace(key, "[REDACTED_TEST_KEY]")
        return text

    def run(self, command, node=None, stdin=None, check=True):
        argv = (["ip", "netns", "exec", self.prefix + node] if node else []) + list(map(str, command))
        started = utc()
        result = subprocess.run(argv, input=stdin, text=True, capture_output=True, timeout=30)
        row = {"id": "cmd-%04d" % len(self.commands), "node": node,
               "command": [self.public(arg) for arg in argv], "startedAt": started,
               "endedAt": utc(), "returncode": result.returncode,
               "stdout": self.public(result.stdout), "stderr": self.public(result.stderr)}
        if stdin is not None:
            row["stdin"] = self.public(stdin)
        self.commands.append(row)
        if check and result.returncode:
            raise RuntimeError(json.dumps(row))
        return result.stdout, row["id"]

    def start(self, operation, node, filename):
        stream = (self.output / filename).open("w")
        argv = ["ip", "netns", "exec", self.prefix + node, sys.executable,
                "-u", str(Path(__file__).resolve()), operation]
        process = subprocess.Popen(argv, stdout=stream, stderr=stream)
        self.processes.append((process, stream))
        self.commands.append({"id": "cmd-%04d" % len(self.commands), "node": node,
                              "command": argv, "startedAt": utc(), "pid": process.pid,
                              "kind": "process-start", "outputFile": filename})
        return process, stream

    def stop(self, item):
        process, stream = item
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        stream.close()
        self.processes.remove(item)

    def link(self, first, second, first_name, second_name):
        left = "m" + secrets.token_hex(4)
        right = "m" + secrets.token_hex(4)
        self.run(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
        for temporary, node, name in [(left, first, first_name), (right, second, second_name)]:
            self.run(["ip", "link", "set", temporary, "netns", self.prefix + node])
            self.run(["ip", "link", "set", temporary, "name", name], node)
            key = "Ared" if node == "A" and name == "red" else node
            self.run(["ip", "link", "set", name, "address", MACS[key], "up"], node)

    def rules(self, drop_plaintext):
        verdict = "drop" if drop_plaintext else "accept"
        return "\n".join([
            "table netdev tdn_boundary {",
            ' chain ingress { type filter hook ingress device "wire" priority -500; policy accept;',
            '  counter accept comment "incoming"',
            " }",
            ' chain egress { type filter hook egress device "wire" priority -500; policy drop;',
            '  ether type 0x88e5 counter accept comment "protected"',
            '  ether type 0x0800 counter ' + verdict + ' comment "plaintext"',
            '  counter drop comment "other"',
            " }",
            "}", ""])

    def install_filter(self, node, drop_plaintext, replace=False):
        text = ("delete table netdev tdn_boundary\n" if replace else "") + self.rules(drop_plaintext)
        self.run(["nft", "-f", "-"], node, stdin=text)

    def state(self, name):
        state = {}
        for node in self.created:
            state[node] = {}
            commands = {"interfaces": ["ip", "-j", "-d", "address"],
                        "links": ["ip", "-j", "-s", "-d", "link"],
                        "routes": ["ip", "-j", "route", "show", "table", "all"],
                        "neighbors": ["ip", "-j", "neigh"],
                        "filters": ["nft", "-j", "-a", "list", "ruleset"],
                        "filtersText": ["nft", "-a", "list", "ruleset"],
                        "forwarding": ["sysctl", "-n", "net.ipv4.ip_forward"],
                        "namespace": ["readlink", "/proc/self/ns/net"]}
            if node in ["A", "B"]:
                commands["macsec"] = ["ip", "-s", "macsec", "show"]
            for kind, command in commands.items():
                _, reference = self.run(command, node)
                state[node][kind] = reference
        (self.output / (name + ".json")).write_text(json.dumps(state, indent=2) + "\n")
        return state

    def prepare(self):
        self.run(["uname", "-a"])
        self.run(["ip", "-Version"])
        self.run(["nft", "--version"])
        for node in ["R", "A", "B"]:
            self.run(["ip", "netns", "add", self.prefix + node])
            self.created.append(node)
            self.run(["ip", "link", "set", "lo", "up"], node)
            self.run(["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1",
                      "net.ipv6.conf.default.disable_ipv6=1"], node)
        self.link("R", "A", "red", "red")
        self.link("A", "B", "wire", "wire")
        self.run(["ip", "address", "add", ADDRESSES["R"] + "/30", "dev", "red"], "R")
        self.run(["ip", "address", "add", ADDRESSES["Ared"] + "/30", "dev", "red"], "A")
        self.run(["sysctl", "-qw", "net.ipv4.ip_forward=1"], "A")
        for node, peer, key_index, receive_index in [("A", "B", 0, 1), ("B", "A", 1, 0)]:
            self.run(["ip", "link", "add", "link", "wire", "name", "mac0", "type", "macsec",
                      "port", "1", "cipher", "gcm-aes-256", "encrypt", "on", "protect", "on",
                      "validate", "strict", "send_sci", "on", "replay", "on", "window", "0"], node)
            self.run(["ip", "macsec", "add", "mac0", "tx", "sa", "0", "pn", "1", "on",
                      "key", "01" if node == "A" else "02", self.keys[key_index]], node)
            self.run(["ip", "macsec", "add", "mac0", "rx", "port", "1", "address", MACS[peer]], node)
            self.run(["ip", "macsec", "add", "mac0", "rx", "port", "1", "address", MACS[peer],
                      "sa", "0", "pn", "1", "on", "key", "01" if peer == "A" else "02",
                      self.keys[receive_index]], node)
            self.run(["ip", "link", "set", "mac0", "up"], node)
            self.run(["ip", "address", "add", ADDRESSES[node] + "/30", "dev", "mac0"], node)
            self.run(["ip", "neigh", "replace", ADDRESSES[peer], "lladdr", MACS[peer],
                      "nud", "permanent", "dev", "mac0"], node)
            self.install_filter(node, False)
        self.run(["ip", "neigh", "replace", ADDRESSES["Ared"], "lladdr", MACS["Ared"],
                  "nud", "permanent", "dev", "red"], "R")
        self.run(["ip", "neigh", "replace", ADDRESSES["R"], "lladdr", MACS["R"],
                  "nud", "permanent", "dev", "red"], "A")
        self.run(["ip", "route", "add", "10.243.0.0/30", "via", ADDRESSES["Ared"]], "R")
        self.run(["ip", "route", "add", "10.242.0.0/30", "via", ADDRESSES["A"]], "B")

    def probe(self, name):
        processes = []
        for node in self.created:
            processes.append(self.start("capture", node, name + "-" + node + "-frames.jsonl"))
        processes.append(self.start("sink", "B", name + "-deliveries.jsonl"))
        time.sleep(0.5)
        before = self.state(name + "-before")
        started = utc()
        program = ("import socket,time,json; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                   "s.bind(('" + ADDRESSES["R"] + "',44730));"
                   "results=[s.sendto(" + repr(PAYLOAD.encode()) + ",('" + ADDRESSES["B"] + "',44731)) for _ in range(3)];"
                   "print(json.dumps({'sent':len(results),'payloadBytes':results}))")
        _, action = self.run([sys.executable, "-c", program], "R")
        time.sleep(0.7)
        after = self.state(name + "-after")
        for item in reversed(processes):
            self.stop(item)
        self.cases.append({"id": name, "startedAt": started, "endedAt": utc(),
                           "sendObservation": action, "before": before, "after": after,
                           "captures": {node: name + "-" + node + "-frames.jsonl" for node in self.created},
                           "deliveries": name + "-deliveries.jsonl"})

    def execute(self):
        self.prepare()
        self.probe("protected")
        if self.integrity_only:
            self.run(["ip", "link", "set", "mac0", "type", "macsec", "encrypt", "off"], "A")
            self.probe("integrity-only")
            self.run(["ip", "link", "set", "mac0", "type", "macsec", "encrypt", "on"], "A")
        self.run(["ip", "link", "set", "mac0", "type", "macsec", "protect", "off"], "A")
        self.probe("unprotected-allowed")
        self.install_filter("A", True, replace=True)
        self.probe("unprotected-denied")

    def finish(self, error):
        for item in list(reversed(self.processes)):
            self.stop(item)
        for node in reversed(self.created):
            self.run(["ip", "netns", "delete", self.prefix + node], check=False)
        cleanup = {node: not Path("/var/run/netns", self.prefix + node).exists() for node in self.created}
        document = {"schema": "tdn-macsec-boundary/v1", "startedAt": self.started, "endedAt": utc(),
                    "namespaces": {node: self.prefix + node for node in self.created},
                    "roles": {"R": "source-host", "A": "encryption-component", "B": "peer-encryption-component"},
                    "addresses": ADDRESSES, "linkAddresses": MACS, "payloadHex": PAYLOAD.encode().hex(),
                    "physicalLinks": [["R:red", "A:red"], ["A:wire", "B:wire"]],
                    "macsecParents": {"A:mac0": "A:wire", "B:mac0": "B:wire"},
                    "cases": self.cases, "cleanup": cleanup, "error": self.public(error) if error else None,
                    "scope": ["Isolated Linux namespaces and manually provisioned test SAs",
                              "No MKA or certificate authentication claim",
                              "The source emits a routed UDP application payload through A",
                              "Physical reception is distinct from successful MACsec validation and application delivery",
                              "Linux administrative link state and installed active SAs are recorded; no MKA controlled-port variable is observed"]}
        (self.output / "observations.json").write_text(json.dumps(document, indent=2) + "\n")
        (self.output / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        (self.output / "collector.source.py").write_bytes(Path(__file__).read_bytes())
        (self.output / "capture.source.py").write_bytes(Path(__file__).with_name("l2_admission_lab.py").read_bytes())
        files = [{"path": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size}
                 for p in sorted(self.output.iterdir()) if p.is_file()]
        (self.output / "manifest.json").write_text(json.dumps({"schema": document["schema"], "files": files}, indent=2) + "\n")
        print(json.dumps({"output": str(self.output), "cases": len(self.cases), "error": document["error"],
                          "cleanup": cleanup}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["collect", "capture", "sink"])
    parser.add_argument("--output")
    parser.add_argument("--label")
    parser.add_argument("--integrity-only", action="store_true")
    args = parser.parse_args()
    if args.operation == "capture":
        capture()
    elif args.operation == "sink":
        sink()
    else:
        experiment = Experiment(args.output, args.label, args.integrity_only)
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
