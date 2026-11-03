#!/usr/bin/env python3
"""Build an isolated software-token and VPN experiment with public observations."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import time


IMAGE = "tdn-key-token:v31-002"
NETWORK = "tdn-v31-token-001"
BACKEND_MODULE = "/usr/lib/softhsm/libsofthsm2.so"
CLIENT_MODULE = "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"
ENDPOINTS = [("A", "172.29.214.11", "192.0.2.11"), ("B", "172.29.214.12", "192.0.2.12")]


class Lab:
    def __init__(self, root, phase, label):
        self.root = root.resolve()
        self.private = self.root / "private"
        self.output = self.root / "public" / (phase + "-" + label)
        self.output.mkdir(parents=True, exist_ok=False)
        self.records = []
        self.phase = phase

    def run(self, command, *, allow_failure=False, timeout=90):
        command = [str(value) for value in command]
        started = datetime.now(timezone.utc).isoformat()
        try:
            value = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            code, stdout, stderr = value.returncode, value.stdout, value.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = 124, "", "timeout"
        record = {"id": self.phase + "-%04d" % len(self.records), "command": command,
                  "startedAt": started, "endedAt": datetime.now(timezone.utc).isoformat(),
                  "returncode": code, "stdout": stdout, "stderr": stderr}
        if "PRIVATE KEY-----" in stdout + stderr:
            raise RuntimeError("Private output refused")
        self.records.append(record)
        if code and not allow_failure:
            raise RuntimeError("Command failed: " + record["id"] + ": " + stderr[-800:])
        return record

    def device(self, name, arguments, **kwargs):
        return self.run(["docker", "exec", name] + list(arguments), **kwargs)

    def finish(self, error=None):
        document = {"phase": self.phase, "records": self.records, "error": error,
                    "scope": ["Separate two-peer VPN key experiment, not a complete MSC topology.",
                              "Gateway filesystems contain public certificates, user PIN and RPC client only; token storage belongs to separate backend containers.",
                              "Backend software, host/hypervisor and collector correctness remain explicit trust assumptions.",
                              "Finite export attempts supplement a source-based API enforcement argument; no hardware certification is claimed."]}
        (self.output / "observations.json").write_text(json.dumps(document, indent=2) + "\n")
        for name in ["key_token_lab.py", "token_operations.py"]:
            shutil.copy2(self.root / name, self.output / name)
        (self.output / "manifest.json").write_text(json.dumps({"files": [
            {"path": str(path.relative_to(self.output)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(self.output.rglob("*")) if path.is_file()]}, indent=2) + "\n")
        print(json.dumps({"output": str(self.output), "records": len(self.records), "error": error}))

    def bootstrap(self):
        self.private.mkdir(mode=0o700, exist_ok=False)
        self.run(["docker", "network", "create", "--subnet", "172.29.214.0/24", NETWORK])
        self.run(["docker", "image", "inspect", IMAGE])
        self.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384",
                  "-out", self.private / "ca.key"])
        self.run(["openssl", "req", "-new", "-x509", "-sha384", "-days", "3", "-key", self.private / "ca.key",
                  "-subj", "/CN=TDN token laboratory CA", "-out", self.private / "ca.pem"])
        for suffix, address, protected in ENDPOINTS:
            backend, gateway = "KT31_T_" + suffix, "KT31_G_" + suffix
            home = self.private / suffix
            token, socket, credentials = home / "token", home / "socket", home / "credentials"
            for folder in [token, socket, credentials]:
                folder.mkdir(parents=True, mode=0o700)
            (token / "objects").mkdir(mode=0o700)
            pin, so_pin, label = secrets.token_hex(16), secrets.token_hex(16), "KT31_" + suffix
            (token / "pin.json").write_text(json.dumps({"pin": pin, "soPin": so_pin, "label": label}))
            (credentials / "pin.json").write_text(json.dumps({"pin": pin, "label": label}))
            for pin_file in [token / "pin.json", credentials / "pin.json"]:
                pin_file.chmod(0o600)
            (token / "softhsm.conf").write_text("directories.tokendir = /token/objects\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n")
            self.run(["docker", "run", "-d", "--name", backend, "--network", "none", "--cap-drop", "ALL",
                      "--security-opt", "no-new-privileges", "-e", "SOFTHSM2_CONF=/token/softhsm.conf",
                      "-e", "XDG_RUNTIME_DIR=/run/p11", "-v", str(token) + ":/token",
                      "-v", str(socket) + ":/run/p11", "-v", str(self.root / "token_operations.py") + ":/lab/token_operations.py:ro", IMAGE])
            self.device(backend, ["python3", "/lab/token_operations.py", "initialize", "--module", BACKEND_MODULE,
                                  "--credentials", "/token/pin.json"])
            self.run(["docker", "exec", "-d", backend, "sh", "-c",
                      "p11-kit server --foreground --name /run/p11/token.sock --provider " + BACKEND_MODULE
                      + " pkcs11:token=" + label + " > /token/server.log 2>&1"])
            for _ in range(50):
                if (socket / "token.sock").exists():
                    break
                time.sleep(0.1)
            if not (socket / "token.sock").exists():
                self.device(backend, ["cat", "/token/server.log"], allow_failure=True)
                raise RuntimeError("Token RPC socket did not appear")
            self.run(["docker", "run", "-d", "--name", gateway, "--network", NETWORK, "--ip", address,
                      "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                      "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "NET_BIND_SERVICE",
                      "--security-opt", "no-new-privileges", "-e", "P11_KIT_SERVER_ADDRESS=unix:path=/run/p11/token.sock",
                      "-v", str(socket) + ":/run/p11:ro", "-v", str(credentials) + ":/credentials",
                      "-v", str(self.root / "token_operations.py") + ":/lab/token_operations.py:ro", IMAGE])
            self.device(gateway, ["python3", "/lab/token_operations.py", "generate", "--module", CLIENT_MODULE,
                                  "--credentials", "/credentials/pin.json", "--public-output", "/credentials/public.pem"])
            extension = home / "certificate.ext"
            extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:" + gateway + ".lab\n")
            self.run(["openssl", "x509", "-new", "-force_pubkey", credentials / "public.pem", "-subj", "/CN=" + gateway + ".lab",
                      "-CA", self.private / "ca.pem", "-CAkey", self.private / "ca.key", "-CAcreateserial", "-days", "2",
                      "-sha384", "-extfile", extension, "-out", credentials / "cert.pem"])
            shutil.copy2(self.private / "ca.pem", credentials / "ca.pem")
            for name in ["public.pem", "cert.pem", "ca.pem"]:
                shutil.copy2(credentials / name, self.output / (gateway + "-" + name))

    def configure(self):
        for index, (suffix, address, protected) in enumerate(ENDPOINTS):
            peer_suffix, peer_address, peer_protected = ENDPOINTS[1 - index]
            gateway, peer = "KT31_G_" + suffix, "KT31_G_" + peer_suffix
            credentials = self.private / suffix / "credentials"
            pin = json.loads((credentials / "pin.json").read_text())["pin"]
            plugin = "pkcs11 {\n load = yes\n modules { remote { path = " + CLIENT_MODULE + "\n load_certs = no\n } }\n}\n"
            configuration = """connections {
 protected {
  version = 2
  local_addrs = ADDRESS
  remote_addrs = PEERADDRESS
  proposals = aes256gcm16-prfsha384-ecp384
  local { auth = pubkey
   id = LOCAL.lab
   certs = cert.pem
  }
  remote { auth = pubkey
   id = PEER.lab
  }
  children { protected {
   local_ts = PROTECTED/32
   remote_ts = PEERPROTECTED/32
   esp_proposals = aes256gcm16-ecp384
   mode = tunnel
   reqid = 301
  } }
 }
}
secrets { token-local {
 handle = 01
 module = remote
 pin = PIN
} }
"""
            for old, value in [("PEERPROTECTED", peer_protected), ("PEERADDRESS", peer_address),
                               ("PROTECTED", protected), ("ADDRESS", address), ("LOCAL", gateway), ("PEER", peer)]:
                configuration = configuration.replace(old, value)
            (credentials / "swanctl.conf").write_text(configuration.replace("PIN", pin))
            (credentials / "swanctl.conf").chmod(0o600)
            (credentials / "pkcs11.conf").write_text(plugin)
            (self.output / (gateway + "-swanctl.public.conf")).write_text(configuration.replace("PIN", "[REDACTED_PIN]"))
            (self.output / (gateway + "-pkcs11.conf")).write_text(plugin)
            self.device(gateway, ["sh", "-c", "mkdir -p /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private; cp /credentials/cert.pem /etc/swanctl/x509/cert.pem; cp /credentials/ca.pem /etc/swanctl/x509ca/ca.pem; cp /credentials/swanctl.conf /etc/swanctl/swanctl.conf; cp /credentials/pkcs11.conf /etc/strongswan.d/charon/pkcs11.conf"])
            self.device(gateway, ["ip", "address", "add", protected + "/32", "dev", "lo"])
            self.device(gateway, ["ip", "route", "add", peer_protected + "/32", "via", peer_address])
            self.run(["docker", "exec", "-d", gateway, "sh", "-c", "/usr/lib/ipsec/charon > /credentials/charon.log 2>&1"])
            time.sleep(0.5)
            self.device(gateway, ["swanctl", "--load-all"])
        self.device("KT31_G_A", ["swanctl", "--initiate", "--child", "protected", "--timeout", "30"], timeout=40)

    def observe(self):
        for suffix, address, protected in ENDPOINTS:
            gateway, backend = "KT31_G_" + suffix, "KT31_T_" + suffix
            self.device(gateway, ["python3", "/lab/token_operations.py", "exercise", "--module", CLIENT_MODULE,
                                  "--credentials", "/credentials/pin.json"])
            for command in [["swanctl", "--stats"], ["swanctl", "--list-sas"], ["swanctl", "--list-algs"],
                            ["swanctl", "--list-certs"], ["ip", "-s", "xfrm", "state", "list", "nokeys"],
                            ["find", "/etc/swanctl/private", "-type", "f"], ["cat", "/proc/self/mountinfo"],
                            ["ps", "-eo", "pid,uid,gid,comm"], ["ss", "-H", "-l", "-n", "-p", "-A", "all"],
                            ["sha256sum", CLIENT_MODULE, "/usr/lib/ipsec/plugins/libstrongswan-pkcs11.so"],
                            ["dpkg-query", "-W"], ["cat", "/credentials/charon.log"]]:
                self.device(gateway, command)
            self.device(gateway, ["ls", "/token/objects"], allow_failure=True)
            self.device(backend, ["sha256sum", BACKEND_MODULE])
            self.device(backend, ["find", "/token", "-type", "f", "-printf", "%m %u %g %s %p\n"])
            self.run(["docker", "inspect", gateway, backend])
        self.device("KT31_G_A", ["ping", "-n", "-I", "192.0.2.11", "-c", "3", "-W", "1", "192.0.2.12"])
        self.device("KT31_G_B", ["ping", "-n", "-I", "192.0.2.12", "-c", "3", "-W", "1", "192.0.2.11"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["bootstrap", "configure", "observe"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--label", default="001")
    args = parser.parse_args()
    lab = Lab(args.root, args.phase, args.label)
    error = None
    try:
        getattr(lab, args.phase)()
    except Exception as failure:
        error = str(failure)
    finally:
        lab.finish(error)
    if error:
        raise SystemExit(1)
