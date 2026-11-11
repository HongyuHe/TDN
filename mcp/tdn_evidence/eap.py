"""Bind public EAP-TLS, key-derivation, MKA and wire observations from one exchange."""
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import ssl

from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "interfaces", "authentication", "events", "wire_frames", "probes"]
LEAN_VIEW = "authentication_correlation"
SCOPE = "One instrumented EAP-TLS exchange and subsequent negotiated MACsec traffic per capture"
REF = re.compile(r"^(\d+\.\d+): TDN_REF title=(.*?) size=(\d+) digest=([0-9a-f]{64})$")
CERT = re.compile(r"^(\d+\.\d+): TDN_PEER_CERT ssl=\S+ sha256=([0-9a-f]{64}) subject=(.*?) verified=1$")
INSTALL = re.compile(r"^(\d+\.\d+): TDN_INSTALL direction=(receive|transmit) interface=(\S+) sci=([0-9a-f:]+) an=(\d+) result=0$")
AUTH = re.compile(r"^(\d+\.\d+): TDN_MKA_AUTH interface=(\S+) peer=([0-9a-f:]+) result=0$")
PUBLIC = re.compile(r"^(\d+\.\d+): TDN_PUBLIC type=(\w+) size=(\d+) hex=([0-9a-f]+)$")
TLS_MESSAGE = re.compile(r"^(\d+\.\d+): TDN_TLS_MESSAGE ssl=(\S+) direction=(read|write) type=(\d+)$")
RADIUS_ACCEPT = re.compile(r"^(\d+\.\d+): TDN_RADIUS_ACCEPT interface=(\S+) peer=([0-9a-f:]+) identifier=(\d+) verified=1$")
MKA_SEND = re.compile(r"^(\d+\.\d+): TDN_MKA_SEND interface=(\S+) result=(-?\d+)$")
COMPLETION_SEND = re.compile(r"^(\d+\.\d+): TDN_(RADIUS_RESPONSE|EAP_SUCCESS)_SEND result=(-?\d+) size=(\d+)$")


def micros(value):
    return int(Decimal(str(value)) * 1000000)


def parsed_events(text, device, observation):
    events = []
    for index, line in enumerate(text.splitlines(), 1):
        record = None
        if match := REF.fullmatch(line):
            at, title, size, digest = match.groups()
            record = {"kind": "reference", "title": title, "bytes": int(size), "sha256": digest}
        elif match := CERT.fullmatch(line):
            at, digest, subject = match.groups()
            record = {"kind": "verified_certificate", "sha256": digest, "subject": subject}
        elif match := INSTALL.fullmatch(line):
            at, direction, interface, sci, number = match.groups()
            address, port = sci.split("::")
            require(0 <= int(number) <= 3, "Invalid MACsec association number")
            record = {"kind": "installed_association", "direction": direction, "interface": interface,
                      "sci": address.replace(":", "") + format(int(port), "04x"), "associationNumber": int(number)}
        elif match := AUTH.fullmatch(line):
            at, interface, peer = match.groups()
            record = {"kind": "authenticated_mka_peer", "interface": interface, "peerAddress": peer.replace(":", "")}
        elif match := PUBLIC.fullmatch(line):
            at, kind, size, encoded = match.groups()
            require(kind in {"EAP_SESSION", "TLS_HANDSHAKE", "RADIUS_REQUEST", "RADIUS_RESPONSE",
                             "MKA_SEND", "MKA_RECEIVE", "MKA_AUTHENTICATED",
                             "RADIUS_RESPONSE_SEND", "EAP_SUCCESS_SEND", "EAP_SUCCESS_RECEIVE"},
                    "Unexpected public record type")
            require(len(encoded) == 2 * int(size), "Public record length mismatch")
            record = {"kind": "public_record", "recordType": kind, "bytes": int(size), "hex": encoded}
        elif match := TLS_MESSAGE.fullmatch(line):
            at, connection, direction, kind = match.groups()
            record = {"kind": "tls_message", "connection": connection, "direction": direction, "messageType": int(kind)}
        elif match := RADIUS_ACCEPT.fullmatch(line):
            at, interface, peer, identifier = match.groups()
            record = {"kind": "verified_radius_accept", "interface": interface,
                      "peerAddress": peer.replace(":", ""), "identifier": int(identifier)}
        elif match := MKA_SEND.fullmatch(line):
            at, interface, result = match.groups()
            record = {"kind": "mka_send_result", "interface": interface, "result": int(result)}
        elif match := COMPLETION_SEND.fullmatch(line):
            at, message, result, size = match.groups()
            record = {"kind": "completion_send_result", "messageType": message,
                      "result": int(result), "bytes": int(size)}
        elif "TDN_" in line and "hexdump" not in line:
            raise ValueError("Unknown or malformed instrumented event")
        if record is not None:
            events.append(record | {"atMicroseconds": micros(at), "device": device,
                                    "observation": observation, "line": index})
    require(all(a["atMicroseconds"] <= b["atMicroseconds"] for a, b in zip(events, events[1:])),
            "Instrumented events are not ordered")
    return events


def unique_reference(events, title, size=None):
    selected = [e for e in events if e["kind"] == "reference" and e["title"] == title]
    require(bool(selected), "Missing public reference: " + title)
    require(len({e["sha256"] for e in selected}) == 1, "Multiple key/session generations require a richer parser")
    if size is not None:
        require(all(e["bytes"] == size for e in selected), "Unexpected reference length: " + title)
    return selected[0]


def parse(directory):
    directory = Path(directory)
    manifest_hash = validate_files(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    evidence = json.loads((directory / "evidence.json").read_text())
    case = json.loads((directory / "case.json").read_text())
    require(manifest["error"] is None and evidence["error"] is None, "Authentication capture failed")
    require(manifest["configuration_id"] == evidence["configuration_id"], "Capture identity mismatch")
    require({d["id"] for d in evidence["devices"]} == {"P0", "P1", "AS"} and len(evidence["devices"]) == 3,
            "Unexpected EAP device inventory")
    authenticator, supplicant = case["authenticator"], case["supplicant"]
    require({authenticator, supplicant} == {"P0", "P1"}, "Invalid EAP roles")
    commands = json.loads((directory / "commands.json").read_text())
    by_id = {row["id"]: row for row in commands}
    require(len(by_id) == len(commands), "Duplicate command identifier")
    namespaces = {device["id"]: device["namespace"] for device in evidence["devices"]}
    logs, wire, raw_ids = {}, [], set()
    for command in commands:
        argv = command["command"]
        if len(argv) != 2 or argv[0] != "cat":
            continue
        filename = Path(argv[1]).name
        require(command["returncode"] == 0, "Log collection failed")
        if filename in {"P0.log", "P1.log", "AS.log"}:
            device = filename[:-4]
            require(device not in logs, "Duplicate daemon log")
            logs[device] = parsed_events(command["stdout"], device, command["id"])
            raw_ids.add(command["id"])
        elif filename in {"P0-headers.log", "P1-headers.log"}:
            device = filename.split("-")[0]
            for line in command["stdout"].splitlines():
                row = json.loads(line)
                if row["ethertype"] == "88e5":
                    require(row["macsec_sci"] is not None and row["macsec_pn"] > 0,
                            "Unsupported MACsec frame header")
                    wire.append(row | {"device": device, "observation": command["id"],
                                       "atMicroseconds": micros(row["at"])})
            raw_ids.add(command["id"])
    require(set(logs) == {"P0", "P1", "AS"}, "Incomplete daemon logs")
    phase = json.loads((directory / "stable-after.json").read_text())
    require(set(phase) == set(namespaces), "Incomplete final interface inventory")
    interfaces = []
    for device, observations in phase.items():
        observation = observations["interfaces"]
        command = by_id[observation["observation_id"]]
        require(command["command"] == ["ip", "netns", "exec", namespaces[device], "ip", "-j", "-d", "address"] and
                command["returncode"] == observation["returncode"] == 0 and command["stdout"] == observation["value"],
                "Interface inventory differs from its raw observation")
        interfaces.extend({"device": device, "observation": command["id"], "interface": row}
                          for row in json.loads(observation["value"]))
        raw_ids.add(command["id"])
    sessions = {device: unique_reference(events, "TDN_EAP_SESSION", 65) for device, events in logs.items()}
    require(len({record["sha256"] for record in sessions.values()}) == 1, "EAP session identifiers disagree")
    peers = {}
    for device in [authenticator, supplicant]:
        events = logs[device]
        msk = unique_reference(events, "TDN_MSK_KDF_INPUT", 32)
        cak = unique_reference(events, "Derived CAK", 32)
        ckn = unique_reference(events, "Derived CKN", 16)
        require(sessions[device]["atMicroseconds"] <= msk["atMicroseconds"], "KDF input precedes its session binding")
        require(msk["atMicroseconds"] < cak["atMicroseconds"] <= ckn["atMicroseconds"], "KDF order mismatch")
        auth = [event for event in events if event["kind"] == "authenticated_mka_peer"]
        require(bool(auth) and cak["atMicroseconds"] < auth[0]["atMicroseconds"], "MKA precedes CAK derivation")
        require(unique_reference(events, "TDN_MKA_AUTH_CAK", 32)["sha256"] == cak["sha256"] and
                unique_reference(events, "TDN_MKA_AUTH_CKN", 16)["sha256"] == ckn["sha256"], "MKA uses a different CAK or CKN")
        installed = []
        for direction in ["receive", "transmit"]:
            matches = [event for event in events if event["kind"] == "installed_association" and event["direction"] == direction]
            require(len(matches) == 1, "Expected one installed association per direction")
            key = unique_reference(events, "TDN_SAK_INSTALLED_" + direction, 32)
            key_id = unique_reference(events, "TDN_INSTALLED_KEY_ID_" + direction, 16)
            require(auth[0]["atMicroseconds"] < matches[0]["atMicroseconds"] < key["atMicroseconds"],
                    "Installation does not follow peer authentication")
            installed.append(matches[0] | {"sakSha256": key["sha256"], "keyIdSha256": key_id["sha256"]})
        peers[device] = {"device": device, "role": "authenticator" if device == authenticator else "supplicant",
            "session": sessions[device]["sha256"], "mskInputSha256": msk["sha256"], "cakSha256": cak["sha256"],
            "cknSha256": ckn["sha256"], "installed": installed}
    for key in ["mskInputSha256", "cakSha256", "cknSha256"]:
        require(peers[authenticator][key] == peers[supplicant][key], "Peer derivation references disagree: " + key)
    issued = unique_reference(logs[authenticator], "KaY: generated new SAK", 32)
    require(all(any(event["kind"] == "authenticated_mka_peer" and
                    event["atMicroseconds"] < issued["atMicroseconds"] for event in logs[device])
                for device in peers), "SAK issuance precedes peer authentication")
    associations = [entry for peer in peers.values() for entry in peer["installed"]]
    require(all(entry["sakSha256"] == issued["sha256"] and issued["atMicroseconds"] < entry["atMicroseconds"]
                for entry in associations), "Installed SAK differs from issued SAK or installation precedes issuance")
    require(len({entry["keyIdSha256"] for entry in associations}) == 1, "Installed SAK identifiers disagree")
    for peer in peers.values():
        tx = next(entry for entry in peer["installed"] if entry["direction"] == "transmit")
        other = peers[supplicant if peer["device"] == authenticator else authenticator]
        rx = next(entry for entry in other["installed"] if entry["direction"] == "receive")
        require((tx["sci"], tx["associationNumber"]) == (rx["sci"], rx["associationNumber"]),
                "Transmit association has no matching peer receive association")
        require(any(row["device"] == peer["device"] and row["pkttype"] == 4 and
                    row["macsec_sci"] == tx["sci"] and row["macsec_an"] == tx["associationNumber"] and
                    tx["atMicroseconds"] < row["atMicroseconds"] for row in wire), "No bound encrypted transmission")
    certs = {name: hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory / (name + ".pem.public")).read_text())).hexdigest()
             for name in ["ca", "as", "peer"]}
    for device, certificate in [(supplicant, "as"), ("AS", "peer")]:
        verified = [e for e in logs[device] if e["kind"] == "verified_certificate"]
        require(len(verified) == 1 and verified[0]["sha256"] == certs[certificate], "Verified certificate differs from public certificate")
        require(verified[0]["atMicroseconds"] < sessions[device]["atMicroseconds"], "Session precedes peer certificate verification")
    probes = evidence["probes"]
    require({p["source_device"] for p in probes} == {"P0", "P1"}, "Both traffic directions are required")
    for probe in probes:
        command = by_id[probe["observation_id"]]
        require(probe["observed_result"] == probe["expected_result"] == "delivered" and command["returncode"] == 0,
                "Useful traffic probe failed")
        require(command["command"] == ["ip", "netns", "exec", namespaces[probe["source_device"]],
                "ping", "-n", "-c", "3", "-W", "1", "-s", "64", probe["destination"]],
                "Probe outcome is not bound to its source and destination")
        raw_ids.add(command["id"])
    scope = [
        "A successful TLS exchange between the supplicant and AS; authenticator receives the MSK through RADIUS.",
        "The authenticator has no separate client TLS handshake or client certificate in this exchange.",
        "Equal SHA-256 references bind observations under the collector and collision-resistance assumptions; secret values are not exported.",
        "The public session identifier binds the exchange. Full handshake transcript and random nonces are unavailable in this capture.",
        "MACsec headers bind SCI and association number after installation. Payload probes cover selected packets, not every possible execution.",
        "Instrumentation and Linux/OpenSSL behavior remain implementation assumptions; no product certification or universal protocol-conformance claim."
    ]
    report = {"devices": evidence["devices"], "interfaces": interfaces,
        "declaredLinks": evidence["links"], "authentication": [{"sessionSha256": sessions["AS"]["sha256"],
        "supplicant": supplicant, "authenticator": authenticator, "server": "AS", "certificates": certs,
        "peers": list(peers.values()), "issuedSakSha256": issued["sha256"], "issuedAtMicroseconds": issued["atMicroseconds"]}],
        "events": sorted([event for events in logs.values() for event in events], key=lambda e: e["atMicroseconds"]),
        "wire_frames": wire, "probes": probes, "scope": scope, "rawObservationIds": sorted(raw_ids),
        "manifestSha256": manifest_hash, "projectionVersion": "eap-correlation-v1"}
    return manifest | {"runtime_backend": "instrumented-hostap-linux-netns"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def query_report(manifest, report, capabilities, collection, category, device, offset, limit):
    require(category is None or category in capabilities, "Unknown experiment capability")
    require(device is None or device in {row["id"] for row in report["devices"]}, "Unknown experiment device")
    rows = []
    for name in capabilities if category is None else [category]:
        for record in report[name]:
            owner = record.get("device", record.get("id") if name == "devices" else record.get("source_device"))
            if device is not None and owner is not None and owner != device:
                continue
            rows.append({"category": name, "device": owner, "record": record,
                         "source_uri": f"evidence://{collection}/manifest"})
    end = min(offset + limit, len(rows))
    return {"collection": collection, "source_kind": "saved_experiment", "records": rows[offset:end],
        "total": len(rows), "next_offset": end if end < len(rows) else None,
        "manifest_sha256": report["manifestSha256"], "runtime_backend": manifest["runtime_backend"], "scope": report["scope"]}


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    require(observation in report["rawObservationIds"], "Observation is not in the validated authentication capture")
    records = json.loads((Path(directory) / "commands.json").read_text())
    record = next(row for row in records if row["id"] == observation)
    return record.get("stderr" if stderr else "stdout", "")


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)


def export_report(report, destination, view):
    raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.exists() or destination.read_bytes() == raw, "Existing authentication export differs")
    destination.write_bytes(raw)
    return {"path": str(destination), "sha256": hashlib.sha256(raw).hexdigest(), "view": view, "keys": list(report)}
