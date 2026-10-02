#!/usr/bin/env python3
"""Translate a verified Twinet export into data declarations, never proof axioms.

Only the current IPv4 profile and its ACCEPT-only FORWARD rule syntax are
supported. Required translation projects out optional management before semantic
validation. Retained evidence remains strict. Full historical diagnostics use
the explicit include_management mode and cannot gate required regeneration.
"""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex

ROOT = Path(__file__).resolve().parents[1]
CURRENT_EVIDENCE = ROOT / "artifacts/msc-2026-10-01T193731Z"
HISTORICAL_EVIDENCE = ROOT / "artifacts/msc-2026-09-27T215205Z"


def quoted(value):
    return json.dumps(value, ensure_ascii=False)


def sequence(values):
    return "[" + ", ".join(values) + "]"


def optional(value, render=quoted):
    return "none" if value is None else "some (" + render(value) + ")"


def record(**fields):
    return "{ " + ", ".join(k + " := " + v for k, v in fields.items()) + " }"


def prefix(value):
    net = ipaddress.IPv4Network(value, strict=False)
    return record(address=str(int(net.network_address)), length=str(net.prefixlen))


def parse_forward_data(text, device):
    """Parse the supported FORWARD subset without approximating unknown rules."""
    rules = []
    default = None
    for line in text.splitlines():
        if line.startswith(":FORWARD "):
            if default is not None:
                raise ValueError(f"{device}: repeated FORWARD policy")
            policy = line.split()[1]
            if policy not in {"DROP", "ACCEPT"}:
                raise ValueError(f"{device}: unsupported default policy")
            default = policy == "ACCEPT"
        if not line.startswith("-A FORWARD "):
            continue
        tokens = shlex.split(line)[2:]
        fields = {}
        direction = reqid = None
        modules = set()
        seen = set()
        while tokens:
            key = tokens.pop(0)
            if not tokens:
                raise ValueError(f"{device}: missing argument for {key}")
            value = tokens.pop(0)
            if key != "-m":
                if key in seen:
                    raise ValueError(f"{device}: unsupported repeated forwarding field {key}")
                seen.add(key)
            if key in {"-i", "-o"}:
                if not value or "+" in value:
                    raise ValueError(f"{device}: unsupported interface wildcard")
                fields[{"-i": "input", "-o": "output"}[key]] = value
            elif key in {"-s", "-d"}:
                fields[{"-s": "source", "-d": "destination"}[key]] = str(ipaddress.IPv4Network(value, strict=False))
            elif key == "-p" and value in {"esp", "udp", "tcp", "icmp"}:
                fields["protocol"] = {"esp": 50, "udp": 17, "tcp": 6, "icmp": 1}[value]
            elif key in {"--dports", "--dport"}:
                if "destinationPorts" in fields:
                    raise ValueError(f"{device}: unsupported repeated port match")
                fields["destinationPorts"] = [int(p) for p in value.split(",")]
                if any(p < 0 or p > 65535 for p in fields["destinationPorts"]):
                    raise ValueError(f"{device}: invalid destination port")
            elif key == "-m" and value in {"policy", "multiport", "udp", "tcp", "u32"}:
                if value in modules:
                    raise ValueError(f"{device}: unsupported repeated match module {value}")
                modules.add(value)
            elif key == "--u32":
                number = r"(0x[0-9a-fA-F]+|[0-9]+)"
                guard = re.fullmatch(number + ">>" + number + "&" + number + "=" + number, value)
                if guard is None or [int(v, 16 if v.startswith("0x") else 10)
                                     for v in guard.groups()] != [0, 24, 15, 5]:
                    raise ValueError(f"{device}: unsupported u32 expression")
                fields["noOptions"] = True
            elif key == "--dir" and value in {"in", "out"}:
                direction = value
            elif key == "--reqid":
                reqid = int(value)
                if not 0 <= reqid < 2 ** 32:
                    raise ValueError(f"{device}: invalid policy request ID")
            elif key == "--pol" and value == "ipsec":
                fields["_ipsec"] = True
            elif key == "--mode" and value == "tunnel":
                fields["_tunnel"] = True
            elif key == "-j" and value == "ACCEPT":
                fields["_accept"] = True
            else:
                raise ValueError(f"{device}: unsupported forwarding token {key} {value}")
        if not fields.pop("_accept", False):
            raise ValueError(f"{device}: expected an ACCEPT target")
        if ("u32" in modules) != ("noOptions" in fields):
            raise ValueError(f"{device}: incomplete u32 match")
        if "destinationPorts" in fields and fields.get("protocol") not in {6, 17}:
            raise ValueError(f"{device}: port match without TCP/UDP protocol")
        if any(module in modules and fields.get("protocol") != protocol
               for module, protocol in [("tcp", 6), ("udp", 17)]):
            raise ValueError(f"{device}: conflicting protocol module")
        if "policy" in modules:
            if direction is None or reqid is None or not fields.pop("_ipsec", False) or not fields.pop("_tunnel", False):
                raise ValueError(f"{device}: incomplete tunnel policy match")
            fields[direction + "Policy"] = reqid
        elif direction is not None or reqid is not None or "_ipsec" in fields or "_tunnel" in fields:
            raise ValueError(f"{device}: policy fields without policy module")
        rules.append(dict(sorted(fields.items())))
    if default is None:
        raise ValueError(f"{device}: missing FORWARD policy")
    return {"device": device, "defaultAccept": default, "rules": rules}


def render_forward(table):
    """Keep Lean rendering separate from the shared, language-neutral facts."""
    rules = []
    for rule in table["rules"]:
        fields = {}
        for key, value in rule.items():
            if key == "noOptions":
                fields[key] = str(value).lower()
            elif key in {"input", "output"}:
                fields[key] = "some " + quoted(value)
            elif key in {"source", "destination"}:
                fields[key] = "some " + prefix(value)
            elif key == "destinationPorts":
                fields[key] = sequence(map(str, value))
            else:
                fields[key] = "some " + str(value)
        rules.append(record(**fields))
    return record(device=quoted(table["device"]), defaultAccept=str(table["defaultAccept"]).lower(), rules=sequence(rules))


def parse_forward(text, device):
    return render_forward(parse_forward_data(text, device))


def sampled_tunnel_established(text, name, tunnel):
    """Match one IKE session and one of its CHILD SAs, never global tokens.

    The supported swanctl text format uses unindented IKE headers, two-space
    CHILD headers, and four-space traffic selectors. A missing/malformed field
    cannot provide a positive observation. Rekey overlap may contain several
    sessions/children; one complete matching installed child is sufficient.
    """
    sessions = re.split(r"(?m)(?=^\S)", text)
    for session in sessions:
        lines = session.splitlines()
        if not lines or not re.fullmatch(r"\S+: #\d+, ESTABLISHED, IKEv2, .+", lines[0]):
            continue
        parent = session.split("\n  protected:", 1)[0]
        identities_match = all(
            re.search(rf"(?m)^  {side}\s+'{re.escape(identity)}' @ {re.escape(address)}\[\d+\]\s*$", parent)
            for side, identity, address in [
                ("local", f"{name}.msc.test", tunnel["local"]),
                ("remote", f"{tunnel['peer']}.msc.test", tunnel["remote"]),
            ]
        )
        if not identities_match:
            continue
        children = re.split(r"(?m)(?=^  \S+: #\d+, reqid )", session)[1:]
        for child in children:
            header = child.splitlines()[0]
            expected = rf"  protected: #\d+, reqid {tunnel['reqid']}, INSTALLED, TUNNEL, ESP:AES_GCM_16-256(?:/\S+)?"
            if not re.fullmatch(expected, header):
                continue
            selectors_match = all(
                re.search(rf"(?m)^    {side}\s+{re.escape(selector)}\s*$", child)
                for side, selector in [("local", tunnel["local_ts"]), ("remote", tunnel["remote_ts"])]
            )
            if selectors_match:
                return True
    return False


def parse_crypto_config(text, name):
    """Read the explicit single-connection MSC configuration, with no defaults.

    Includes, inheritance, duplicate sections/keys, and unknown settings are
    rejected. The result describes the hashed intended file, not loaded daemon
    configuration. No certificates or private keys are read.
    """
    allowed = {
        (): {"connections"},
        ("connections",): {"msc"},
        ("connections", "msc"): {"local", "remote", "children"},
        ("connections", "msc", "children"): {"protected"},
    }
    keys = {
        ("connections", "msc"): {"version", "local_addrs", "remote_addrs", "proposals", "reauth_time", "rekey_time", "over_time", "dpd_delay", "keyingtries", "mobike"},
        ("connections", "msc", "local"): {"auth", "certs", "id"},
        ("connections", "msc", "remote"): {"auth", "id", "cacerts", "revocation"},
        ("connections", "msc", "children", "protected"): {"local_ts", "remote_ts", "mode", "reqid", "esp_proposals", "rekey_time", "life_time", "start_action", "dpd_action", "close_action"},
    }
    stack, sections, values = [], set(), {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "}":
            if not stack:
                raise ValueError(f"{name}: unbalanced swanctl section")
            stack.pop()
        elif line.endswith("{"):
            section = line[:-1].strip()
            path = tuple(stack)
            if section not in allowed.get(path, set()) or path + (section,) in sections:
                raise ValueError(f"{name}: unsupported/repeated swanctl section")
            stack.append(section)
            sections.add(tuple(stack))
        elif "=" in line:
            key, value = (item.strip() for item in line.split("=", 1))
            path = tuple(stack)
            full = path + (key,)
            if key not in keys.get(path, set()) or full in values or not value or any(c in value for c in '{}#"'):
                raise ValueError(f"{name}: unsupported/repeated swanctl setting")
            values[full] = value
        else:
            raise ValueError(f"{name}: unsupported swanctl syntax")
    if stack:
        raise ValueError(f"{name}: unclosed swanctl section")
    if set(values) != {path + (key,) for path, names in keys.items() for key in names}:
        raise ValueError(f"{name}: incomplete swanctl configuration")
    base = ("connections", "msc")
    child = base + ("children", "protected")

    def duration(path, key):
        value = values[path + (key,)]
        match = re.fullmatch(r"(\d+)(s|m|h|d)", value)
        if match is None:
            raise ValueError(f"{name}: unsupported swanctl duration")
        return int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]

    def natural(path, key):
        value = values[path + (key,)]
        if not value.isascii() or not value.isdecimal():
            raise ValueError(f"{name}: invalid swanctl natural number")
        return int(value)

    return dict(device=name, version=natural(base, "version"),
                localAddress=values[base + ("local_addrs",)], remoteAddress=values[base + ("remote_addrs",)],
                localSelector=values[child + ("local_ts",)], remoteSelector=values[child + ("remote_ts",)],
                reqid=natural(child, "reqid"), mode=values[child + ("mode",)],
                ikeProposal=values[base + ("proposals",)], espProposal=values[child + ("esp_proposals",)],
                reauthSeconds=duration(base, "reauth_time"), ikeRekeySeconds=duration(base, "rekey_time"),
                overSeconds=duration(base, "over_time"), childLifeSeconds=duration(child, "life_time"),
                localAuth=values[base + ("local", "auth")], remoteAuth=values[base + ("remote", "auth")],
                localIdentity=values[base + ("local", "id")], remoteIdentity=values[base + ("remote", "id")],
                localCertificate=values[base + ("local", "certs")], remoteCA=values[base + ("remote", "cacerts")],
                revocation=values[base + ("remote", "revocation")])


def parse_public_certificates(text, name):
    """Retain public identity metadata from every sampled EE and CA record.

    Validity strings and CRL bodies are not interpreted by this bounded parser.
    Missing observations are handled separately, never converted to empty success.
    """
    headers = list(re.finditer(r"(?m)^List of X\.509 (.+)\s*$", text))
    expected = ["End Entity Certificates", "CA Certificates", "CRLs"]
    if [m[1] for m in headers] != expected or text[:headers[0].start()].strip():
        raise ValueError(f"{name}: unsupported certificate inventory sections")
    result = []
    for index in [0, 1]:
        body = text[headers[index].end():headers[index + 1].start()]
        blocks = list(re.finditer(r'(?m)^  subject:\s+"([^"\n]+)"\s*$', body))
        preamble = body[:blocks[0].start()] if blocks else body
        if preamble.strip():
            raise ValueError(f"{name}: unsupported certificate record")
        for position, block in enumerate(blocks):
            end = blocks[position + 1].start() if position + 1 < len(blocks) else len(body)
            fields = {}
            for line in body[block.start():end].splitlines():
                if not line.strip() or re.fullmatch(r"\s+not after\s+.+", line):
                    continue
                match = re.fullmatch(r"  (\w+):\s*(.*?)\s*", line)
                if not match or match[1] in fields:
                    raise ValueError(f"{name}: unsupported or repeated certificate field")
                fields[match[1]] = match[2]
            required = {"subject", "issuer", "validity", "serial", "flags", "subjkeyId", "pubkey", "keyid", "subjkey"}
            if index == 0:
                required |= {"altNames", "authkeyId"}
            if not required <= fields.keys() or fields.keys() - required - {"altNames", "authkeyId"}:
                raise ValueError(f"{name}: missing or unsupported certificate fields")
            for field in ["subject", "issuer"]:
                if not re.fullmatch(r'"[^"\n]+"', fields[field]):
                    raise ValueError(f"{name}: malformed certificate name")
            for field in ["serial", "subjkeyId", "keyid", "subjkey", "authkeyId"]:
                if field in fields and not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})*", fields[field]):
                    raise ValueError(f"{name}: malformed certificate identifier")
            key = re.fullmatch(r"[A-Za-z0-9_-]+ \d+ bits(, has private key)?", fields["pubkey"])
            if not key:
                raise ValueError(f"{name}: unsupported public-key description")
            result.append({"subject": fields["subject"][1:-1], "issuer": fields["issuer"][1:-1],
                           "serial": fields["serial"].lower(), "subjectKeyId": fields["subjkeyId"].lower(),
                           "authorityKeyId": fields.get("authkeyId", "").lower(), "keyId": fields["keyid"].lower(),
                           "altNames": fields.get("altNames", "").split(), "isCA": index == 1,
                           "hasPrivateKey": key[1] is not None})
    return result


def render_public_certificate(certificate):
    return record(**{key: str(value).lower() if isinstance(value, bool) else
                     sequence(quoted(v) for v in value) if isinstance(value, list) else quoted(value)
                     for key, value in certificate.items()})


def retained_projection(spec, status):
    """Remove optional devices, ports, and cables before interpreting evidence.

    The original specification hash still identifies the complete source export.
    The projection assumes the optional administration plane is absent, as the
    experiment scope requires. Retained device observations and credentials are
    never weakened or repaired by this operation.
    """
    spec = json.loads(json.dumps(spec))
    excluded = {d["id"] for d in spec["devices"] if d["role"] == "admin" or
                all(i["zone"] == "management" for i in d["interfaces"])}
    management_ports = {(d["id"], i["name"]) for d in spec["devices"]
                        for i in d["interfaces"] if i["zone"] == "management"}
    spec["links"] = [link for link in spec["links"] if all(
        end["device"] not in excluded and (end["device"], end["interface"]) not in management_ports
        for end in [link["a"], link["b"]])]
    spec["devices"] = [d for d in spec["devices"] if d["id"] not in excluded]
    for device in spec["devices"]:
        device["interfaces"] = [i for i in device["interfaces"] if i["zone"] != "management"]
        device.pop("admin", None)
    status = {**status, "devices": [d for d in status["devices"] if d["device"] not in excluded]}
    return spec, status


def translate(snapshot, checks_path, *, as_data=False, include_management=False):
    manifest = json.loads((snapshot / "manifest.json").read_text())
    if manifest["schema_version"] != 1 or manifest["kind"] != "twinet-msc-observation":
        raise ValueError("unsupported observation schema")
    def verify(name):
        if name not in manifest["sha256"]:
            raise ValueError(f"unhashed evidence file: {name}")
        path = snapshot / name
        path.resolve().relative_to(snapshot.resolve())
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != manifest["sha256"][name]:
            raise ValueError(f"invalid evidence checksum: {name}")

    def read(name):
        verify(name)
        return (snapshot / name).read_text()

    #* Optional files cannot make required regeneration fail. Every consumed
    #* file is verified before use; full diagnostics additionally verify all files.
    if include_management:
        for name in manifest["sha256"]:
            verify(name)
    spec = json.loads(read("spec.json"))
    status = json.loads(read("status.json"))
    checks = json.loads(checks_path.read_text()) if include_management else None
    #* JSON strings and numbers must never acquire Boolean meaning by truthiness.
    #* A valid false outcome is retained; malformed or missing outcomes are errors.
    if include_management and (not isinstance(checks, dict) or type(checks.get("passed")) is not bool):
        raise ValueError("probe report passed must be a Boolean")
    if include_management and not isinstance(checks.get("checks"), list):
        raise ValueError("probe report checks must be a list")
    for index, check in enumerate(checks["checks"] if include_management else []):
        if not isinstance(check, dict) or type(check.get("passed")) is not bool:
            raise ValueError(f"probe {index} passed must be a Boolean")
    #* Twinet hashes compact JSON in its exported struct-field order.
    digest = hashlib.sha256(json.dumps(spec, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    identities = [manifest, status] + ([checks] if include_management else [])
    if any(item["spec_sha256"] != digest for item in identities):
        raise ValueError("specification, snapshot, and probe identities differ")
    if spec["version"] != 2:
        raise ValueError("the Lean model covers native MSC version 2 only")
    if not include_management:
        spec, status = retained_projection(spec, status)
    devices = {d["id"]: d for d in spec["devices"]}
    if len(devices) != len(spec["devices"]):
        raise ValueError("duplicate device ID")
    observed = {d["device"]: d for d in status["devices"]}
    if set(observed) != set(devices) or len(observed) != len(status["devices"]):
        raise ValueError("observation device inventory mismatch")
    if any(o.get("deployed_spec_sha256") != digest for o in observed.values()):
        raise ValueError("a running device belongs to a different specification")
    interfaces = {(d["id"], p["name"]): p for d in devices.values() for p in d["interfaces"]}
    if len(interfaces) != sum(len(d["interfaces"]) for d in devices.values()):
        raise ValueError("duplicate device interface")
    for name, device in devices.items():
        if observed[name]["role"] != device["role"]:
            raise ValueError("observed device role differs from its declaration")
        if device["role"] in {"host", "inner", "outer"} and device.get("level") not in {"S1", "S2"}:
            raise ValueError("extend the Lean security-level type before importing another level")
    zones = {"red", "gray", "black", "management"}
    links, management = [], {}
    for link in spec["links"]:
        a, b = link["a"], link["b"]
        az = interfaces[a["device"], a["interface"]]["zone"]
        bz = interfaces[b["device"], b["interface"]]["zone"]
        if az != bz or az not in zones:
            raise ValueError("cable endpoints disagree on zone")
        links.append(record(a=quoted(a["device"]), aPort=quoted(a["interface"]), b=quoted(b["device"]), bPort=quoted(b["interface"]), zone="." + az))
        if az == "management":
            management.setdefault(a["device"], set()).add(b["device"])
            management.setdefault(b["device"], set()).add(a["device"])
    domains = {}
    for start in management:
        if start in domains:
            continue
        component, todo = set(), [start]
        while todo:
            node = todo.pop()
            if node not in component:
                component.add(node)
                todo.extend(management[node] - component)
        subnets = {str(ipaddress.IPv4Interface(p["address"]).network)
                   for node in component for p in devices[node]["interfaces"]
                   if p["zone"] == "management" and p.get("address")}
        if len(subnets) != 1:
            raise ValueError("management component lacks one unambiguous subnet")
        domains.update({node: next(iter(subnets)) for node in component})

    device_rows, tunnel_rows, tables, observations = [], [], [], []
    table_data, tunnel_observations, crypto_configs, certificate_inventories = [], {}, [], []
    roles = {r: r for r in ["transport", "firewall", "host", "inner", "outer", "switch", "admin"]}
    roles["gray-firewall"] = "grayFirewall"
    for d in devices.values():
        name = d["id"]
        device_rows.append(record(
            id=quoted(name), role="." + roles[d["role"]],
            site=optional(d.get("site"), lambda v: {"A": ".a", "B": ".b"}[v]),
            level=optional(d.get("level") if d.get("level") in {"S1", "S2"} else None, lambda v: "." + v.lower()),
            interfaces=sequence(record(name=quoted(p["name"]), zone="." + p["zone"], address=quoted(p.get("address", ""))) for p in d["interfaces"]),
            routes=sequence(record(network=quoted(r["prefix"]), via=quoted(r["via"])) for r in d.get("routes", [])),
            managementDomain=optional(domains.get(name)), admin=optional(d.get("admin"))))
        intended = parse_forward_data(read(f"devices/{name}/intended.iptables"), name)
        actual = parse_forward_data(read(f"devices/{name}/observed.iptables"), name)
        if intended != actual:
            raise ValueError(f"{name}: observed FORWARD rules differ from intended rules")
        table_data.append(actual)
        tables.append(render_forward(actual))
        tunnel = d.get("tunnel")
        if tunnel:
            tunnel_rows.append(record(owner=quoted(name), peer=quoted(tunnel["peer"]), localAddress=quoted(tunnel["local"]), remoteAddress=quoted(tunnel["remote"]), localSelector=quoted(tunnel["local_ts"]), remoteSelector=quoted(tunnel["remote_ts"]), trust=quoted(tunnel["trust"]), reqid=str(tunnel["reqid"])))
            config = parse_crypto_config(read(f"devices/{name}/intended.swanctl.conf"), name)
            crypto_configs.append(config)
        o = observed[name]
        if tunnel:
            certificate_text = o["facts"].get("certificates")
            certificates = None
            if certificate_text is not None and "certificates" not in o.get("errors", {}):
                certificates = parse_public_certificates(certificate_text, name)
            certificate_inventories.append({"device": name, "observedAt": o["observed_at"],
                                           "certificates": certificates})
        #* A positive SA observation summarizes the command text, not a PKI proof.
        #* Missing output or an observation error remains unknown.
        sas = o["facts"].get("sas")
        up = None
        if tunnel and sas is not None and "sas" not in o.get("errors", {}):
            up = sampled_tunnel_established(sas, name, tunnel)
        tunnel_observations[name] = up
        observations.append(record(device=quoted(name), observedAt=quoted(o["observed_at"]), running=str(o["state"] == "running").lower(), deployedSpecHash=quoted(o["deployed_spec_sha256"]), errors=sequence(quoted(k + ": " + v) for k, v in sorted(o.get("errors", {}).items())), tunnelEstablished=optional(up, lambda v: str(v).lower())))

    #* The current profile represents each Red network by one host and one inner.
    #* Build both sides as sets so cable order cannot select or discard an owner.
    hosts = {name for name, d in devices.items() if d["role"] == "host"}
    inners = {name for name, d in devices.items() if d["role"] == "inner"}
    inner_for_host = {name: set() for name in hosts}
    host_for_inner = {name: set() for name in inners}
    for link in spec["links"]:
        a, b = link["a"]["device"], link["b"]["device"]
        if a not in hosts and b not in hosts:
            continue
        if a in hosts and b in inners:
            host, inner = a, b
        elif b in hosts and a in inners:
            host, inner = b, a
        else:
            raise ValueError("Red host attachment must connect to an inner encryptor")
        if any(interfaces[end["device"], end["interface"]]["zone"] != "red"
               for end in [link["a"], link["b"]]):
            raise ValueError("Red host attachment must use Red interfaces")
        inner_for_host[host].add(inner)
        host_for_inner[inner].add(host)
    if not hosts or not inners or any(len(neighbors) != 1 for neighbors in inner_for_host.values()):
        raise ValueError("each Red host requires exactly one attached inner encryptor")
    if any(len(neighbors) != 1 for neighbors in host_for_inner.values()):
        raise ValueError("each inner encryptor requires exactly one attached Red host")
    owners = {inner: next(iter(attached)) for inner, attached in host_for_inner.items()}
    for inner, host in owners.items():
        if any(devices[host].get(field) is None or
               devices[host][field] != devices[inner].get(field) for field in ["site", "level"]):
            raise ValueError("Red host and its inner encryptor must share site and security level")
        if devices[inner].get("tunnel", {}).get("peer") not in owners:
            raise ValueError("inner tunnel peer lacks a dedicated Red host")
    pairs = sorted((host, owners[devices[inner]["tunnel"]["peer"]]) for inner, host in owners.items())
    passed = include_management and checks["passed"] is True and bool(checks["checks"]) and all(c["passed"] is True for c in checks["checks"])
    if as_data:
        return {"spec": spec, "status": status, "checks": checks,
                "manifest": manifest, "spec_hash": digest, "domains": domains,
                "tables": table_data, "tunnel_observations": tunnel_observations,
                "crypto_configs": crypto_configs,
                "certificate_inventories": certificate_inventories,
                "authorized_pairs": pairs, "checks_passed": passed}
    header = '''import TDN.MSC.Types

/-!
# Imported node-1 deployment data

Generated by `scripts/import_msc_snapshot.py`; edit the source snapshot or the
translator, then regenerate. Do not manually adjust these facts to make a proof
pass. The importer verifies every consumed file's SHA-256 and rejects unsupported
or drifting retained FORWARD rules. Lean checks the downstream proofs, not the
importer. Required data exclude optional management before semantic validation;
the separately generated HistoricalDeployment retains full-export diagnostics.

Topology and tunnel records describe intent. Forward tables match the sampled
observed configuration. Observations and probe results retain their own times.
Neither the file hashes nor the successful probes establish ongoing correctness.
-/
'''
    namespace = "HistoricalDeployment" if include_management else "Deployment"
    header += f"namespace TDN.MSC.{namespace}\n"
    defs = [
        ("specHash", "String", quoted(digest)),
        ("manifestSHA256", "String", quoted(hashlib.sha256((snapshot / "manifest.json").read_bytes()).hexdigest())),
        ("runtimeRevision", "String", quoted(manifest["build"]["vcs.revision"])),
        ("observationStarted", "String", quoted(manifest["started"])),
        ("observationFinished", "String", quoted(manifest["finished"])),
        ("devices", "List Device", "[\n  " + ",\n  ".join(device_rows) + "\n]"),
        ("links", "List Link", "[\n  " + ",\n  ".join(links) + "\n]"),
        ("tunnels", "List Tunnel", "[\n  " + ",\n  ".join(tunnel_rows) + "\n]"),
        ("cryptoConfigs", "List CryptoConfig", sequence(record(**{k: quoted(v) if isinstance(v, str) else str(v) for k, v in c.items()}) for c in crypto_configs)),
        ("certificateInventories", "List CertificateInventory", sequence(record(
            device=quoted(c["device"]), observedAt=quoted(c["observedAt"]),
            certificates=optional(c["certificates"], lambda values: sequence(render_public_certificate(v) for v in values)))
            for c in certificate_inventories)),
        ("forwardTables", "List ForwardTable", "[\n  " + ",\n  ".join(tables) + "\n]"),
        ("observations", "List DeviceObservation", "[\n  " + ",\n  ".join(observations) + "\n]"),
        ("authorizedHostPairs", "List (String × String)", sequence("(" + quoted(a) + ", " + quoted(b) + ")" for a, b in pairs)),
    ]
    if include_management:
        defs += [("probeSHA256", "String", quoted(hashlib.sha256(checks_path.read_bytes()).hexdigest())),
                 ("probeAt", "String", quoted(checks["at"])),
                 ("probeCount", "Nat", str(len(checks["checks"]))),
                 ("sampledChecksPassed", "Bool", str(passed).lower())]
    return header + "\n\n".join(f"def {name} : {typ} :=\n{value}" for name, typ, value in defs) + f"\n\nend TDN.MSC.{namespace}\n"


def load_snapshot(snapshot, checks_path):
    """Validate the same evidence and expose normalized inputs to other backends.

    This shared boundary intentionally makes importer bugs common-mode. Neither
    Lean nor Souffle proves that the Python normalization matches Linux.
    """
    #* The original Datalog/ASP comparison explicitly retains historical scope.
    return translate(snapshot, checks_path, as_data=True, include_management=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--checks", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--include-management", action="store_true", help="generate optional HistoricalDeployment with full-export diagnostics")
    parser.add_argument("--check", action="store_true", help="reject stale generated data without writing")
    args = parser.parse_args()
    evidence = HISTORICAL_EVIDENCE if args.include_management else CURRENT_EVIDENCE
    args.snapshot = args.snapshot or evidence / "snapshot"
    args.checks = args.checks or evidence / "check.json"
    if args.output is None:
        module = "HistoricalDeployment" if args.include_management else "Deployment"
        args.output = ROOT / f"TDN/MSC/{module}.lean"
    body = translate(args.snapshot, args.checks, include_management=args.include_management)
    if args.check:
        if args.output.read_text() != body:
            raise SystemExit("Generated Lean data are stale; rerun the importer.")
        print("Snapshot hashes, identities, forwarding rules, and generated Lean data verified.")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body)
        print(args.output)


if __name__ == "__main__":
    main()
