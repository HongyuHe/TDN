#!/usr/bin/env python3
"""Capture public key-access boundaries without exporting private key material."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


PROCESS_OBSERVER = r'''
import hashlib,json,pathlib,subprocess
def read_command(command):
    result=subprocess.run(command,capture_output=True,text=True)
    return {"command":command,"returncode":result.returncode,"stdout":result.stdout,"stderr":result.stderr}
lookup=read_command(["pgrep","-x","charon"])
processes=[]
for raw_pid in lookup["stdout"].split():
    pid=int(raw_pid)
    base=pathlib.Path("/proc")/str(pid)
    executable=str((base/"exe").resolve())
    maps=(base/"maps").read_text()
    paths={executable}
    for line in maps.splitlines():
        parts=line.split(maxsplit=5)
        if len(parts)==6 and parts[5].startswith("/"):
            paths.add(parts[5].removesuffix(" (deleted)"))
    modules=[]
    for name in sorted(paths):
        path=pathlib.Path(name)
        try:
            modules.append({"path":name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"bytes":path.stat().st_size})
        except OSError as error:
            modules.append({"path":name,"error":str(error)})
    profile=read_command(["cat",str(base/"attr/current")])
    processes.append({"pid":pid,"executable":executable,"status":(base/"status").read_text(),
        "maps":maps,"modules":modules,"securityProfile":profile})
print(json.dumps({"lookup":lookup,"processes":processes},sort_keys=True))
'''

PUBLIC_KEY_OBSERVER = r'''
import hashlib,json,pathlib,subprocess
records=[]
for directory in ["/etc/swanctl/private","/etc/swanctl/x509"]:
    base=pathlib.Path(directory)
    if not base.exists():
        records.append({"directory":directory,"missing":True})
        continue
    for path in sorted(base.iterdir()):
        if not path.is_file():continue
        metadata=path.stat()
        if directory.endswith("private"):
            command=["openssl","pkey","-in",str(path),"-pubout","-outform","DER"]
            result=subprocess.run(command,capture_output=True)
            public_der=result.stdout
        else:
            command=["openssl","x509","-in",str(path),"-pubkey","-noout"]
            result=subprocess.run(command,capture_output=True)
            if result.returncode==0:
                result=subprocess.run(["openssl","pkey","-pubin","-outform","DER"],input=result.stdout,capture_output=True)
            public_der=result.stdout
        records.append({"path":str(path),"mode":oct(metadata.st_mode & 0o7777),"uid":metadata.st_uid,
            "gid":metadata.st_gid,"bytes":metadata.st_size,"command":command,"returncode":result.returncode,
            "publicSPKISha256":hashlib.sha256(public_der).hexdigest() if result.returncode==0 else None,
            "publicDERBytes":len(public_der) if result.returncode==0 else None,
            "stderr":result.stderr.decode(errors="replace")})
print(json.dumps(records,sort_keys=True))
'''


def collect(devices, output):
    output.mkdir(parents=True, exist_ok=False)
    records = []

    def run(device, kind, arguments):
        command = (["docker", "exec", device] if device else []) + arguments
        started = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=35)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = 124, "", "timeout"
        except OSError as error:
            code, stdout, stderr = 127, "", str(error)
        if "PRIVATE KEY-----" in stdout + stderr:
            raise ValueError("Private key output refused")
        records.append({"id": "key-audit-%04d" % len(records), "device": device, "kind": kind,
                        "command": command, "startedAt": started,
                        "endedAt": datetime.now(timezone.utc).isoformat(),
                        "returncode": code, "stdout": stdout, "stderr": stderr})

    for device in devices:
        expression = '{"Name":{{json .Name}},"Id":{{json .Id}},"Image":{{json .Image}},"Pid":{{json .State.Pid}},"Running":{{json .State.Running}},"StartedAt":{{json .State.StartedAt}},"User":{{json .Config.User}},"Privileged":{{json .HostConfig.Privileged}},"CapAdd":{{json .HostConfig.CapAdd}},"CapDrop":{{json .HostConfig.CapDrop}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},"AppArmorProfile":{{json .AppArmorProfile}},"Mounts":{{json .Mounts}},"Ports":{{json .NetworkSettings.Ports}}}'
        run(None, "container-boundary:" + device, ["docker", "inspect", "--format", expression, device])
        commands = {
            "daemon-process": ["python3", "-c", PROCESS_OBSERVER],
            "public-key-bindings": ["python3", "-c", PUBLIC_KEY_OBSERVER],
            "daemon-stats": ["swanctl", "--stats"],
            "daemon-algorithms": ["swanctl", "--list-algs"],
            "daemon-certificates": ["swanctl", "--list-certs", "--type", "x509"],
            "listeners": ["ss", "-H", "-l", "-n", "-p", "-A", "all"],
            "accounts": ["getent", "passwd"],
            "groups": ["getent", "group"],
            "process-identities": ["ps", "-eo", "pid,ppid,uid,gid,comm"],
            "mounts": ["cat", "/proc/self/mountinfo"],
            "ssh-effective-configuration": ["sshd", "-T"],
            "credential-path-access": ["find", "/etc/swanctl", "-maxdepth", "3", "-printf", "%y %m %U %G %p\n"],
            "vici-socket-access": ["stat", "-Lc", "%a %u %g %F %n", "/var/run/charon.vici"],
            "packages": ["dpkg-query", "-W"],
            "kernel": ["uname", "-a"],
            "proc-security": ["cat", "/proc/self/attr/current"],
        }
        for kind, command in commands.items():
            run(device, kind, command)
    for kind, command in {
        "host-docker-socket": ["stat", "-Lc", "%a %u %g %F %n", "/var/run/docker.sock"],
        "host-docker-group": ["getent", "group", "docker"],
        "host-listeners": ["ss", "-H", "-l", "-n", "-p", "-A", "all"],
        "host-apparmor-profiles": ["cat", "/sys/kernel/security/apparmor/profiles"],
        "host-ssh-effective": ["sshd", "-T"],
    }.items():
        run(None, kind, command)
    document = {"devices": devices, "records": records,
                "scope": ["Public runtime and administration-interface audit, not a universal no-export proof.",
                          "Private files are read only by OpenSSL to derive public SPKI hashes; no private key bytes or password hashes are exported.",
                          "Host Docker/SSH controls are recorded separately from device services.",
                          "Collector-issued reads do not establish the absence of all other interfaces or future accesses."]}
    (output / "observations.json").write_text(json.dumps(document, indent=2) + "\n")
    shutil.copy2(__file__, output / "collector.py")
    manifest = {"files": [{"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                           for path in sorted(output.iterdir()) if path.is_file()]}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"records": len(records), "failed": [row["id"] for row in records if row["returncode"]]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    collect(arguments.device, arguments.output)
