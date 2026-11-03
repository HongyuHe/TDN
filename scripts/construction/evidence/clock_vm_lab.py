"""Collect guest clock discipline and strongSwan clock-use evidence in isolated VMs."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


IMAGE_URL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
IMAGE_SHA256 = "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94"
GUESTS = [
    {"id": "TC_I_A", "zone": "red", "layer": "inner", "index": 0, "side": "a"},
    {"id": "TC_I_B", "zone": "red", "layer": "inner", "index": 1, "side": "b"},
    {"id": "TC_O_A", "zone": "gray", "layer": "outer", "index": 2, "side": "a"},
    {"id": "TC_O_B", "zone": "gray", "layer": "outer", "index": 3, "side": "b"},
]


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            result.update(chunk)
    return result.hexdigest()


class Lab:
    def __init__(self, root, phase):
        self.root = Path(root).resolve()
        self.private = self.root / "private"
        self.images = self.root / "images"
        self.output = self.root / "captures" / phase
        self.output.mkdir(parents=True, exist_ok=False)
        self.private.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.images.mkdir(parents=True, exist_ok=True)
        self.records = []
        self.phase = phase

    def run(self, command, required=True, timeout=60):
        started = utc()
        try:
            result = subprocess.run(list(map(str, command)), capture_output=True,
                                    text=True, timeout=timeout)
            row = {"command": list(map(str, command)), "startedAt": started,
                   "endedAt": utc(), "returncode": result.returncode,
                   "stdout": result.stdout, "stderr": result.stderr}
        except subprocess.TimeoutExpired as error:
            row = {"command": list(map(str, command)), "startedAt": started,
                   "endedAt": utc(), "returncode": 124,
                   "stdout": (error.stdout or b"").decode() if isinstance(error.stdout, bytes)
                   else error.stdout or "", "stderr": "Command timed out"}
        row["id"] = f"{self.phase}:{len(self.records):04d}"
        self.records.append(row)
        with (self.output / "observations.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        if required and row["returncode"]:
            raise RuntimeError(f"{row['id']}: command failed: {row['stderr'][-1500:]}")
        return row

    def ssh_command(self, guest, command):
        return ["ssh", "-i", self.private / "access", "-p", 22610 + guest["index"],
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o",
                "StrictHostKeyChecking=accept-new", "-o",
                f"UserKnownHostsFile={self.private / 'known-hosts'}", "lab@127.0.0.1", command]

    def guest(self, guest, command, required=True, timeout=60):
        return self.run(self.ssh_command(guest, command), required, timeout)

    def guest_exec(self, guest, arguments, required=True, timeout=60):
        return self.guest(guest, shlex.join(list(map(str, arguments))), required, timeout)

    def copy_to_guest(self, guest, source, destination):
        return self.run(["scp", "-q", "-i", self.private / "access", "-P", 22610 + guest["index"],
                         "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o",
                         f"UserKnownHostsFile={self.private / 'known-hosts'}", source,
                         "lab@127.0.0.1:" + destination])

    def finish(self, error):
        document = {"phase": self.phase, "finishedAt": utc(), "error": error,
                    "guests": GUESTS, "records": self.records,
                    "scope": "Separate clock-use experiment; not a full MSC deployment or a repair of other profiles."}
        (self.output / "observations.json").write_text(json.dumps(document, indent=2) + "\n")
        files = [{"path": path.name, "sha256": digest(path)}
                 for path in sorted(self.output.iterdir()) if path.is_file()]
        (self.output / "manifest.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
        print(json.dumps({"phase": self.phase, "error": error, "observations": len(self.records)}), flush=True)

    def bootstrap(self):
        image = self.images / "noble-server-cloudimg-amd64.img"
        if not image.exists():
            self.run(["curl", "--fail", "--location", "--silent", "--show-error",
                      "--max-time", "600", "--output", image, IMAGE_URL], timeout=610)
        if digest(image) != IMAGE_SHA256:
            raise RuntimeError("The image differs from the recorded official SHA256SUMS entry")
        self.run(["qemu-img", "info", "--output=json", image])
        if not (self.private / "access").exists():
            self.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.private / "access"])
        public_key = (self.private / "access.pub").read_text().strip()
        self.run(["date", "-u", "+%s.%N"])
        self.run(["timedatectl", "show"], required=False)
        for bridge in ["tc31red", "tc31gray", "tc31idata", "tc31odata"]:
            self.run(["ip", "link", "add", bridge, "type", "bridge"])
            self.run(["ip", "link", "set", bridge, "up"])
        for guest in GUESTS:
            index = guest["index"]
            folder = self.private / guest["id"]
            folder.mkdir(mode=0o700)
            zone_octet = 203 if guest["zone"] == "red" else 204
            data_octet = 205 if guest["layer"] == "inner" else 206
            last = 11 + index % 2
            mac_clock = f"52:54:31:00:{index:02x}:01"
            mac_data = f"52:54:31:00:{index:02x}:02"
            user_data = {
                "hostname": guest["id"].lower().replace("_", "-"),
                "users": [{"name": "lab", "sudo": "ALL=(ALL) NOPASSWD:ALL",
                           "shell": "/bin/bash", "ssh_authorized_keys": [public_key]}],
                "ssh_pwauth": False, "disable_root": True,
                "package_update": True,
                "packages": ["chrony", "strongswan-swanctl", "charon-systemd",
                             "libstrongswan-extra-plugins", "tcpdump", "python3"],
                "runcmd": [["systemctl", "stop", "chrony"],
                           ["systemctl", "stop", "strongswan"],
                           ["touch", "/var/lib/tdn-clock-bootstrap-ready"]],
            }
            (folder / "user-data").write_text("#cloud-config\n" + json.dumps(user_data) + "\n")
            (folder / "meta-data").write_text(json.dumps({"instance-id": guest["id"],
                                                         "local-hostname": guest["id"].lower()}))
            network = {"version": 2, "ethernets": {
                "management": {"match": {"macaddress": f"52:54:31:00:{index:02x}:00"},
                               "set-name": "mgmt0", "dhcp4": True, "dhcp6": False},
                "clock": {"match": {"macaddress": mac_clock}, "set-name": "clock0",
                          "addresses": [f"10.{zone_octet}.0.{last}/24"]},
                "data": {"match": {"macaddress": mac_data}, "set-name": "data0",
                         "addresses": [f"10.{data_octet}.0.{last}/24"]}}}
            (folder / "network-config").write_text(json.dumps(network))
            self.run(["genisoimage", "-output", folder / "seed.iso", "-volid", "cidata",
                      "-joliet", "-rock", folder / "user-data", folder / "meta-data", folder / "network-config"])
            self.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image,
                      folder / "disk.qcow2", "8G"])
            for tap, bridge in [(f"tc31c{index}", "tc31red" if guest["zone"] == "red" else "tc31gray"),
                                (f"tc31d{index}", "tc31idata" if guest["layer"] == "inner" else "tc31odata")]:
                self.run(["ip", "tuntap", "add", "dev", tap, "mode", "tap"])
                self.run(["ip", "link", "set", tap, "master", bridge])
                self.run(["ip", "link", "set", tap, "up"])
            self.run(["qemu-system-x86_64", "-name", guest["id"], "-enable-kvm", "-cpu", "host",
                      "-m", "1536", "-smp", "2", "-drive", f"file={folder / 'disk.qcow2'},if=virtio",
                      "-drive", f"file={folder / 'seed.iso'},media=cdrom,readonly=on",
                      "-netdev", f"user,id=management,hostfwd=tcp:127.0.0.1:{22610 + index}-:22",
                      "-device", f"virtio-net-pci,netdev=management,mac=52:54:31:00:{index:02x}:00",
                      "-netdev", f"tap,id=clock,ifname=tc31c{index},script=no,downscript=no",
                      "-device", f"virtio-net-pci,netdev=clock,mac={mac_clock}",
                      "-netdev", f"tap,id=data,ifname=tc31d{index},script=no,downscript=no",
                      "-device", f"virtio-net-pci,netdev=data,mac={mac_data}", "-display", "none",
                      "-serial", f"file:{folder / 'serial.log'}", "-daemonize", "-pidfile", folder / "qemu.pid"])
        for guest in GUESTS:
            for attempt in range(90):
                ready = self.guest(guest, "test -f /var/lib/tdn-clock-bootstrap-ready", required=False, timeout=10)
                if ready["returncode"] == 0:
                    break
                time.sleep(3)
            if ready["returncode"]:
                raise RuntimeError(f"Guest bootstrap did not finish: {guest['id']}")
            self.guest(guest, "hostname; uname -r; ip -j address; dpkg-query -W chrony strongswan-swanctl charon-systemd; systemctl is-active chrony", required=False)
        self.run(["ip", "-j", "-d", "link", "show"])
        self.run(["date", "-u", "+%s.%N"])


    def configure(self):
        sources = []
        for zone, octet in [("red", 203), ("gray", 204)]:
            namespace = f"tc31ntp-{zone}"
            address = f"10.{octet}.0.1"
            host_link = f"tc31n{zone[0]}h"
            peer_link = f"tc31n{zone[0]}p"
            self.run(["ip", "netns", "add", namespace])
            self.run(["ip", "link", "add", host_link, "type", "veth", "peer", "name", peer_link])
            self.run(["ip", "link", "set", host_link, "master", f"tc31{zone}"])
            self.run(["ip", "link", "set", host_link, "up"])
            self.run(["ip", "link", "set", peer_link, "netns", namespace])
            self.run(["ip", "netns", "exec", namespace, "ip", "address", "add", address + "/24", "dev", peer_link])
            self.run(["ip", "netns", "exec", namespace, "ip", "link", "set", peer_link, "up"])
            self.run(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"])
            source_id = "TC_TIME_" + zone.upper()
            packet_log = self.private / f"{source_id}-exchanges.jsonl"
            source_command = ["ip", "netns", "exec", namespace, "python3",
                              str(self.root / "clock_ntp_source.py"), "--address", address,
                              "--source", source_id, "--output", str(packet_log)]
            error_stream = (self.private / f"{source_id}-stderr.log").open("w")
            process = subprocess.Popen(source_command, stdout=subprocess.DEVNULL,
                                       stderr=error_stream, start_new_session=True)
            error_stream.close()
            (self.private / f"{source_id}.pid").write_text(str(process.pid))
            sources.append({"id": source_id, "zone": zone, "managementNetwork": zone == "gray",
                            "namespace": namespace, "interface": peer_link, "address": address,
                            "bridge": f"tc31{zone}", "pid": process.pid, "command": source_command,
                            "trustBasis": "Laboratory operator-selected local time service; no external certification claim"})
            self.run(["ip", "netns", "exec", namespace, "ip", "-j", "address"])
        (self.private / "time-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
        (self.output / "time-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
        for layer in ["inner", "outer"]:
            authority = self.private / f"ca-{layer}"
            authority.mkdir(mode=0o700)
            self.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384",
                      "-out", authority / "key.pem"])
            self.run(["openssl", "req", "-new", "-x509", "-sha384", "-days", "10", "-key", authority / "key.pem",
                      "-subj", f"/CN=TDN clock {layer} laboratory CA", "-out", authority / "cert.pem",
                      "-addext", "basicConstraints=critical,CA:TRUE",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        for guest in GUESTS:
            index = guest["index"]
            folder = self.private / guest["id"]
            authority = self.private / f"ca-{guest['layer']}"
            identity = guest["id"].lower().replace("_", "-")
            peer = GUESTS[index ^ 1]
            peer_identity = peer["id"].lower().replace("_", "-")
            octet = 205 if guest["layer"] == "inner" else 206
            source_octet = 203 if guest["zone"] == "red" else 204
            local = 11 + index % 2
            remote = 11 + peer["index"] % 2
            self.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384",
                      "-out", folder / "key.pem"])
            self.run(["openssl", "req", "-new", "-key", folder / "key.pem", "-subj",
                      f"/CN={identity}", "-out", folder / "request.pem"])
            (folder / "extensions.txt").write_text("basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\nextendedKeyUsage=1.3.6.1.5.5.7.3.17\n"
                f"subjectAltName=DNS:{identity}\n")
            self.run(["openssl", "x509", "-req", "-sha384", "-days", "2", "-in", folder / "request.pem",
                      "-CA", authority / "cert.pem", "-CAkey", authority / "key.pem", "-CAcreateserial",
                      "-extfile", folder / "extensions.txt", "-out", folder / "cert.pem"])
            self.run(["openssl", "x509", "-in", folder / "cert.pem", "-noout", "-dates", "-subject", "-fingerprint", "-sha256"])
            configuration = f"""connections {{
  clock {{
    version = 2
    local_addrs = 10.{octet}.0.{local}
    remote_addrs = 10.{octet}.0.{remote}
    proposals = aes256gcm16-prfsha384-ecp384
    local {{
      auth = pubkey
      certs = clock.pem
      id = {identity}
    }}
    remote {{
      auth = pubkey
      id = {peer_identity}
    }}
    children {{
      protected {{
        local_ts = 10.{octet + 2}.0.{local}/32
        remote_ts = 10.{octet + 2}.0.{remote}/32
        esp_proposals = aes256gcm16-ecp384
        mode = tunnel
      }}
    }}
  }}
}}
"""
            (folder / "swanctl.conf").write_text(configuration)
            chrony = (f"server 10.{source_octet}.0.1 iburst minpoll 0 maxpoll 1\n"
                      "makestep 0.1 -1\nrtcsync\nlog tracking measurements statistics\n"
                      "logdir /var/log/chrony\ndriftfile /var/lib/chrony/chrony.drift\n")
            (folder / "chrony.conf").write_text(chrony)
            self.copy_to_guest(guest, folder / "key.pem", "/home/lab/clock-key.pem")
            self.copy_to_guest(guest, folder / "cert.pem", "/home/lab/clock-cert.pem")
            self.copy_to_guest(guest, authority / "cert.pem", "/home/lab/clock-ca.pem")
            self.copy_to_guest(guest, folder / "swanctl.conf", "/home/lab/clock-swanctl.conf")
            self.copy_to_guest(guest, folder / "chrony.conf", "/home/lab/clock-chrony.conf")
            for incoming, destination, mode in [
                ("clock-key.pem", "/etc/swanctl/private/clock.pem", "600"),
                ("clock-cert.pem", "/etc/swanctl/x509/clock.pem", "644"),
                ("clock-ca.pem", "/etc/swanctl/x509ca/clock.pem", "644"),
                ("clock-swanctl.conf", "/etc/swanctl/swanctl.conf", "644"),
                ("clock-chrony.conf", "/etc/chrony/chrony.conf", "644"),
            ]:
                self.guest_exec(guest, ["sudo", "install", "-m", mode, "/home/lab/" + incoming, destination])
            self.guest_exec(guest, ["rm", "/home/lab/clock-key.pem"])
            self.guest_exec(guest, ["sudo", "systemctl", "start", "chrony"])
            self.guest_exec(guest, ["sudo", "chronyc", "waitsync", "30", "0.05", "1000", "1"], timeout=40)
            self.guest_exec(guest, ["chronyc", "-n", "tracking"])
            self.guest_exec(guest, ["chronyc", "-n", "sources", "-v"])
            self.guest_exec(guest, ["sudo", "systemctl", "start", "strongswan"])
            self.guest_exec(guest, ["sudo", "swanctl", "--load-all"])
        for guest in [GUESTS[0], GUESTS[2]]:
            self.guest_exec(guest, ["sudo", "swanctl", "--initiate", "--child", "protected", "--timeout", "20"], timeout=30)
        self.run(["ip", "-j", "-d", "link", "show"])

    def collect_guest_clock(self, guest, stage):
        observer = r'''import hashlib,json,os,pathlib,subprocess,time
def call(args):
    result=subprocess.run(args,capture_output=True,text=True)
    return {"command":args,"returncode":result.returncode,"stdout":result.stdout,"stderr":result.stderr}
rows=[call(args) for args in [
 ["systemctl","show","strongswan","-p","MainPID","-p","ExecStart","-p","ActiveState"],
 ["systemctl","show","chrony","-p","MainPID","-p","ExecStart","-p","ActiveState"],
 ["chronyc","-c","tracking"],["chronyc","-c","sources"],["chronyc","-c","sourcestats"],
 ["ip","-j","address"],["ip","-j","route","show","table","all"],
 ["ps","-eo","pid,comm,args"],["ss","-lntup"],
 ["systemctl","list-unit-files","--state=enabled","--no-pager"],
 ["dpkg-query","-W","chrony","strongswan-swanctl","charon-systemd","libstrongswan","libc6"]]]
pid=int(subprocess.check_output(["systemctl","show","strongswan","-p","MainPID","--value"],text=True).strip())
exe=pathlib.Path(f"/proc/{pid}/exe").resolve()
maps=pathlib.Path(f"/proc/{pid}/maps").read_text()
paths={line.split()[-1] for line in maps.splitlines() if "/" in line}
files=[]
for name in sorted(paths | {str(exe)}):
    p=pathlib.Path(name)
    if p.is_file(): files.append({"path":name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()})
print(json.dumps({"clockRealtimeNs":time.clock_gettime_ns(time.CLOCK_REALTIME),
 "clockMonotonicNs":time.clock_gettime_ns(time.CLOCK_MONOTONIC),
 "kernelBootId":pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
 "observerTimeNamespace":os.readlink("/proc/self/ns/time"),"charonPid":pid,
 "charonTimeNamespace":os.readlink(f"/proc/{pid}/ns/time"),"charonExecutable":str(exe),
 "charonExecutableAndLibraries":files,
 "chronyConfig":pathlib.Path("/etc/chrony/chrony.conf").read_text(),
 "swanctlConfig":pathlib.Path("/etc/swanctl/swanctl.conf").read_text(),"records":rows}))
'''
        result = self.guest_exec(guest, ["sudo", "python3", "-c", observer])
        result["stage"] = stage
        value = json.loads(result["stdout"])
        if value["charonPid"] <= 0:
            raise RuntimeError("No active charon process in clock observation")
        return value

    def observe(self):
        self.run(["date", "-u", "+%s.%N"])
        cases = []
        for guest in GUESTS:
            peer = GUESTS[guest["index"] ^ 1]
            before = self.collect_guest_clock(guest, "before-negative-clock")
            for endpoint in [guest, peer]:
                self.guest_exec(endpoint, ["sudo", "swanctl", "--terminate", "--ike", "clock"], required=False)
            self.guest_exec(guest, ["sudo", "systemctl", "stop", "chrony"])
            self.guest_exec(guest, ["sudo", "date", "-u", "-s", "2020-01-01 00:00:00"])
            wrong = self.collect_guest_clock(guest, "incorrect-clock")
            negative = self.guest_exec(guest, ["sudo", "swanctl", "--initiate", "--child", "protected",
                                               "--timeout", "20"], required=False, timeout=30)
            self.guest_exec(guest, ["sudo", "journalctl", "-u", "strongswan", "-b", "-n", "120",
                                   "-o", "json", "--no-pager"])
            if negative["returncode"] == 0:
                raise RuntimeError("Authentication unexpectedly passed with an out-of-validity clock")
            self.guest_exec(guest, ["sudo", "systemctl", "start", "chrony"])
            correction = self.guest_exec(guest, ["sudo", "chronyc", "waitsync", "30", "0.05", "1000", "1"], timeout=40)
            synchronized = self.collect_guest_clock(guest, "corrected-clock")
            for endpoint in [guest, peer]:
                self.guest_exec(endpoint, ["sudo", "swanctl", "--terminate", "--ike", "clock"], required=False)
            positive = self.guest_exec(guest, ["sudo", "swanctl", "--initiate", "--child", "protected",
                                               "--timeout", "20"], timeout=30)
            self.guest_exec(guest, ["sudo", "swanctl", "--list-sas", "--raw"])
            self.guest_exec(guest, ["sudo", "journalctl", "-u", "strongswan", "-b", "-n", "180",
                                   "-o", "json", "--no-pager"])
            after = self.collect_guest_clock(guest, "after-certificate-authentication")
            if len({value["charonPid"] for value in [before, wrong, synchronized, after]}) != 1:
                raise RuntimeError("Charon process changed during the clock experiment")
            if len({value["kernelBootId"] for value in [before, wrong, synchronized, after]}) != 1:
                raise RuntimeError("Guest kernel changed during the clock experiment")
            cases.append({"guest": guest, "before": before, "wrongClock": wrong,
                          "synchronized": synchronized, "after": after,
                          "negativeAuthentication": negative["id"], "clockCorrection": correction["id"],
                          "positiveAuthentication": positive["id"],
                          "selectedCriterion": {"maximumRemainingCorrectionSeconds": 0.05,
                                                "maximumSkewPpm": 1000,
                                                "source": "actual chronyc waitsync command; not a CP numerical requirement"}})
            (self.output / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
        for source in json.loads((self.private / "time-sources.json").read_text()):
            self.run(["ip", "netns", "exec", source["namespace"], "ip", "-j", "address"])
            self.run(["ip", "netns", "exec", source["namespace"], "ss", "-lunp"])
            self.run(["readlink", f"/proc/{source['pid']}/exe"])
            source_log = self.private / f"{source['id']}-exchanges.jsonl"
            (self.output / source_log.name).write_bytes(source_log.read_bytes())
        (self.output / "time-sources.json").write_bytes((self.private / "time-sources.json").read_bytes())
        self.run(["ip", "-j", "-d", "link", "show"])
        self.run(["date", "-u", "+%s.%N"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--phase", choices=["bootstrap", "configure", "observe"], required=True)
    parser.add_argument("--label")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run on the dedicated experiment worker with sudo")
    lab = Lab(args.root, args.label or args.phase)
    error = None
    try:
        getattr(lab, args.phase)()
    except Exception as exception:
        error = str(exception)
    finally:
        lab.finish(error)
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
