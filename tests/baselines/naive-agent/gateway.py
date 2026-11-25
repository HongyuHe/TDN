"""Expose only public, allowlisted observations of the five experimental networks."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
from threading import Lock
import urllib.parse

from common import BASE, now, run_remote, sha256, write_json
from worker import PUBLIC_COMMANDS, TUNNEL_COMMANDS


HTTP_OBSERVATIONS = r'''
import json
from pathlib import Path
import urllib.request
rows = []
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        args = path.read_bytes().decode().split('\0')
        if 'http.server' not in args:
            continue
        host = args[args.index('--bind') + 1] if '--bind' in args else '127.0.0.1'
        port = args[args.index('http.server') + 1]
        url = 'http://' + host + ':' + port + '/'
        body = urllib.request.urlopen(url, timeout=2).read(4096).decode(errors='replace')
        rows.append({'url': url, 'body': body})
    except Exception:
        pass
print(json.dumps(rows))
'''


class Gateway:
    def __init__(self, run, token):
        self.run = run
        self.token = token
        self.lock = Lock()
        self.sequence = 0
        self.pool = ThreadPoolExecutor(max_workers=8)
        rows = json.loads((run / "deployments.json").read_text())
        self.networks = {}
        for row in rows:
            spec = row["spec"]
            self.networks[row["id"]] = {
                "id": row["id"], "description": row["profile"],
                "black_transport": "Public Internet represented by an isolated emulated underlay",
                "devices": [{"id": d["id"], "role": d["role"], "site": d.get("site"),
                             "security_level": d.get("level"), "interfaces": d["interfaces"]}
                            for d in spec["devices"]],
                "links": spec["links"],
                "inventory_source": "Deployment inventory; current addresses and interface state are available through queries",
            }

    def kinds(self, device):
        kinds = dict(PUBLIC_COMMANDS)
        kinds["firewall4"] = ["iptables-save"]
        kinds["firewall6"] = ["ip6tables-save"]
        kinds["ipv4_interface_settings"] = ["python3", "-c", "import json;from pathlib import Path;p=Path('/proc/sys/net/ipv4/conf');print(json.dumps({d.name:{k:(d/k).read_text().strip() for k in ['rp_filter','forwarding','accept_source_route','accept_redirects']} for d in p.iterdir() if d.is_dir()}))"]
        kinds["http_services"] = ["python3", "-c", HTTP_OBSERVATIONS]
        if device["role"] in {"inner", "outer"}:
            kinds.update(TUNNEL_COMMANDS)
            kinds["public_ca"] = ["openssl", "x509", "-in", "/etc/swanctl/x509ca/ca.pem", "-noout", "-text", "-fingerprint", "-sha256"]
        if device["role"] == "switch":
            kinds.update({"ovs_bridge": ["ovs-vsctl", "show"],
                          "ovs_flows": ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "br0"]})
        if device["role"] in {"inner", "outer", "transport", "firewall", "gray-firewall", "gray-router"}:
            kinds["routing_config"] = ["vtysh", "-c", "show running-config"]
            kinds["routing_neighbors"] = ["vtysh", "-c", "show ip ospf neighbor json"]
        return kinds

    def query(self, network, name, kind):
        if network not in self.networks:
            raise ValueError("Unknown network")
        devices = {d["id"]: d for d in self.networks[network]["devices"]}
        if name not in devices:
            raise ValueError("Device is not part of the selected network")
        commands = self.kinds(devices[name])
        if kind not in commands:
            raise ValueError("Unknown or inapplicable observation kind")
        container = name
        if kind.startswith("routing_") and devices[name]["role"] == "outer":
            container += "-routing"
        response = run_remote(["sudo", "-n", "docker", "exec", container, *commands[kind]], timeout=40)
        if "PRIVATE KEY-----" in response["stdout"] or "PRIVATE KEY-----" in response["stderr"]:
            raise ValueError("Private material is outside the observation interface")
        if kind == "ipsec_config" and "secrets {" in response["stdout"]:
            raise ValueError("A combined public/private configuration cannot be exported")
        with self.lock:
            self.sequence += 1
            ident = f"observation-{self.sequence:06}"
        result = {"id": ident, "network": network, "device": name, "kind": kind,
                  "command": commands[kind], "returncode": response["returncode"],
                  "stdout": response["stdout"], "stderr": response["stderr"],
                  "collected_at": response["ended_at"], "elapsed_seconds": response["elapsed_seconds"]}
        result["stdout_sha256"] = sha256(result["stdout"].encode())
        write_json(self.run / "detector-session/observations" / (ident + ".json"), result)
        return result

    def log(self, method, path, status):
        with self.lock:
            with (self.run / "detector-session/requests.jsonl").open("a") as stream:
                stream.write(json.dumps({"at": now(), "method": method, "path": path, "status": status}) + "\n")


def handler(gateway):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def send(self, status, value):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            gateway.log(self.command, self.path, status)

        def do_GET(self):
            if self.headers.get("Authorization") != "Bearer " + gateway.token:
                self.send(401, {"error": "Authentication required"})
                return
            try:
                route = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(route.query)
                if route.path == "/api":
                    self.send(200, {
                        "networks": [{"id": n["id"], "description": n["description"], "devices": len(n["devices"])} for n in gateway.networks.values()],
                        "endpoints": {
                            "/api/networks": "Full network inventory, interface roles and declared links",
                            "/api/query?network=net-01&device=DEVICE&kind=KIND": "A fresh public device observation",
                            "/api/batch?network=net-01&kind=KIND&role=ROLE": "A fresh observation from every applicable device, optionally restricted by role",
                            "/api/capabilities?network=net-01&device=DEVICE": "The exact allowed observation commands for a device",
                        },
                        "access": "Read-only device observations. No host shell, arbitrary file reads, or other deployments are exposed.",
                    })
                elif route.path == "/api/networks":
                    self.send(200, {"networks": list(gateway.networks.values())})
                elif route.path in {"/api/query", "/api/batch", "/api/capabilities"}:
                    network = query["network"][0]
                    devices = gateway.networks[network]["devices"]
                    if route.path == "/api/capabilities":
                        device = next(d for d in devices if d["id"] == query["device"][0])
                        self.send(200, {"commands": gateway.kinds(device)})
                    elif route.path == "/api/query":
                        self.send(200, gateway.query(network, query["device"][0], query["kind"][0]))
                    else:
                        kind = query["kind"][0]
                        role = query.get("role", [None])[0]
                        selected = [d for d in devices if (role is None or d["role"] == role) and kind in gateway.kinds(d)]
                        rows = list(gateway.pool.map(lambda d: gateway.query(network, d["id"], kind), selected))
                        self.send(200, {"network": network, "kind": kind, "observations": rows})
                else:
                    self.send(404, {"error": "Unknown endpoint"})
            except (ValueError, KeyError, StopIteration) as error:
                self.send(400, {"error": str(error)})
            except Exception as error:
                self.send(502, {"error": type(error).__name__ + ": " + str(error)})

        def do_POST(self):
            self.send(405, {"error": "The observation gateway is read-only"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--access-file", type=Path, default=BASE / ".runtime/gateway.json")
    args = parser.parse_args()
    run = BASE / "runs" / args.run_id
    (run / "detector-session").mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    gateway = Gateway(run, token)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler(gateway))
    configuration = {"url": f"http://127.0.0.1:{server.server_port}", "token": token, "started_at": now()}
    output = args.access_file
    write_json(output, configuration)
    output.chmod(0o600)
    print(json.dumps({"url": configuration["url"], "configuration": str(output)}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
