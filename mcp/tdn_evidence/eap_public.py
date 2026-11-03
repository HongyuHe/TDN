"""Validate public TLS and RADIUS bytes against a captured EAP/MKA exchange."""
import hashlib
import ipaddress
import json
from pathlib import Path
import zlib

from . import eap
from .parsers.snapshot import require


CAPABILITIES = eap.CAPABILITIES + ["exchanges"]
LEAN_VIEW = "authentication_exchange"
SCOPE = "Complete initial TLS 1.3 mutual-certificate exchange and verified RADIUS key delivery"


def one(items, message):
    require(len(items) == 1, message)
    return items[0]


def vector(data, offset, width):
    require(offset + width <= len(data), "Truncated length field")
    size = int.from_bytes(data[offset:offset + width], "big")
    end = offset + width + size
    require(end <= len(data), "Truncated vector")
    return data[offset + width:end], end


def extensions(data):
    result, offset = {}, 0
    while offset < len(data):
        require(offset + 4 <= len(data), "Truncated TLS extension")
        kind = int.from_bytes(data[offset:offset + 2], "big")
        value, offset = vector(data, offset + 2, 2)
        require(kind not in result, "Duplicate TLS extension")
        result[kind] = value
    return result


def hello(data, server):
    require(data[:2] == b"\x03\x03" and len(data) >= 35, "Unsupported TLS hello")
    random = data[2:34]
    require(random.hex() != "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
            "HelloRetryRequest needs separate transcript handling")
    _, offset = vector(data, 34, 1)
    if server:
        require(offset + 3 <= len(data) and data[offset + 2] == 0, "Invalid ServerHello fields")
        cipher = int.from_bytes(data[offset:offset + 2], "big")
        offset += 3
    else:
        _, offset = vector(data, offset, 2)
        _, offset = vector(data, offset, 1)
        cipher = None
    raw, end = vector(data, offset, 2)
    require(end == len(data), "Trailing hello bytes")
    ext = extensions(raw)
    if server:
        require(ext.get(43) == b"\x03\x04", "Only TLS 1.3 is supported")
    return random, cipher, ext


def certificate_chain(message):
    data = message[4:]
    if message[0] == 25:
        require(len(data) >= 8 and int.from_bytes(data[:2], "big") == 1,
                "Unsupported certificate compression algorithm")
        expected = int.from_bytes(data[2:5], "big")
        require(0 < expected <= 65535, "Certificate expansion exceeds capture limit")
        compressed, end = vector(data, 5, 3)
        require(end == len(data), "Trailing compressed certificate bytes")
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(compressed, expected + 1)
        require(len(decoded) == expected and decoder.eof and not decoder.unused_data and
                not decoder.unconsumed_tail, "Invalid compressed certificate length or stream")
        data = decoded
    else:
        require(message[0] == 11, "Expected certificate handshake message")
    context, offset = vector(data, 0, 1)
    require(not context, "Post-handshake client authentication is outside this parser")
    chain, end = vector(data, offset, 3)
    require(end == len(data), "Trailing certificate message bytes")
    fingerprints, offset = [], 0
    while offset < len(chain):
        cert, offset = vector(chain, offset, 3)
        require(bool(cert), "Empty certificate")
        _, offset = vector(chain, offset, 2)
        fingerprints.append(hashlib.sha256(cert).hexdigest())
    require(bool(fingerprints), "Missing certificate chain")
    return fingerprints


def tls_messages(events):
    messages, pending, connections = [], None, set()
    for event in events:
        if event["kind"] == "tls_message":
            require(pending is None, "TLS message has no public bytes")
            pending = event
            connections.add(event["connection"])
        elif event["kind"] == "public_record" and event["recordType"] == "TLS_HANDSHAKE":
            require(pending is not None, "TLS public bytes have no message metadata")
            raw = bytes.fromhex(event["hex"])
            require(len(raw) >= 4 and raw[0] == pending["messageType"] and
                    int.from_bytes(raw[1:4], "big") == len(raw) - 4, "Invalid TLS handshake header")
            messages.append({"type": raw[0], "direction": pending["direction"], "hex": event["hex"],
                "atMicroseconds": event["atMicroseconds"], "observation": event["observation"],
                "line": event["line"]})
            pending = None
    require(pending is None and len(connections) == 1, "Missing TLS bytes or multiple TLS connections")
    kinds = [m["type"] for m in messages]
    require(len(kinds) == 10 and kinds[:4] == [1, 2, 8, 13] and kinds[4] in [11, 25] and
            kinds[5:7] == [15, 20] and kinds[7] in [11, 25] and kinds[8:] == [15, 20],
            "Incomplete or unsupported initial mutual TLS transcript")
    return messages


def radius(raw, expected_code):
    require(len(raw) >= 20 and raw[0] == expected_code and
            int.from_bytes(raw[2:4], "big") == len(raw), "Invalid RADIUS header")
    attrs, offset = [], 20
    while offset < len(raw):
        require(offset + 2 <= len(raw), "Truncated RADIUS attribute")
        kind, length = raw[offset:offset + 2]
        require(length >= 2 and offset + length <= len(raw), "Invalid RADIUS attribute length")
        attrs.append({"type": kind, "hex": raw[offset + 2:offset + length].hex()})
        offset += length
    return {"code": raw[0], "identifier": raw[1], "authenticatorHex": raw[4:20].hex(),
            "attributes": attrs, "hex": raw.hex()}


def attribute(record, kind):
    return bytes.fromhex(one([a for a in record["attributes"] if a["type"] == kind],
                            "Expected one RADIUS attribute " + str(kind))["hex"])


def detailed_exchange(report):
    auth = report["authentication"][0]
    supplicant, authenticator = auth["supplicant"], auth["authenticator"]
    logs = {device: [e for e in report["events"] if e["device"] == device]
            for device in [supplicant, authenticator, "AS"]}
    client, server = tls_messages(logs[supplicant]), tls_messages(logs["AS"])
    require([m["hex"] for m in client] == [m["hex"] for m in server], "TLS peer transcripts differ")
    require([m["direction"] for m in client] == ["write"] + ["read"] * 6 + ["write"] * 3 and
            all(a["direction"] != b["direction"] for a, b in zip(client, server)),
            "TLS handshake directions differ")
    encoded = [bytes.fromhex(m["hex"]) for m in client]
    client_random, _, _ = hello(encoded[0][4:], False)
    server_random, cipher, server_extensions = hello(encoded[1][4:], True)
    require(certificate_chain(encoded[4])[0] == auth["certificates"]["as"] and
            certificate_chain(encoded[7])[0] == auth["certificates"]["peer"],
            "Transcript certificates differ from verified public certificates")
    session_records = {device: one([e for e in logs[device] if e["kind"] == "public_record" and
        e["recordType"] == "EAP_SESSION"], "Expected one public EAP session per participant") for device in logs}
    session = bytes.fromhex(session_records["AS"]["hex"])
    require(len(session) == 65 and session[0] == 13 and
            all(bytes.fromhex(e["hex"]) == session for e in session_records.values()) and
            hashlib.sha256(session).hexdigest() == auth["sessionSha256"], "Public EAP session mismatch")
    require(server[-1]["atMicroseconds"] < session_records["AS"]["atMicroseconds"],
            "AS session export precedes the complete client handshake")
    master = eap.unique_reference(logs[supplicant], "EAP-TLS: Derived key", 64)
    delivered = eap.unique_reference(logs[authenticator], "MSK: ", 64)
    require(master["sha256"] == delivered["sha256"], "Derived and delivered full MSKs differ")
    for device, full in [(supplicant, master), (authenticator, delivered)]:
        index = logs[device].index(full)
        prefix = logs[device][index + 1]
        peer = next(p for p in auth["peers"] if p["device"] == device)
        require(prefix["kind"] == "reference" and prefix["title"] == "TDN_MSK_PREFIX32" and
                prefix["bytes"] == 32 and prefix["sha256"] == peer["mskInputSha256"],
                "Full MSK is not bound to its CAK derivation input")
    accepted = one([e for e in logs[authenticator] if e["kind"] == "verified_radius_accept"],
                   "Expected one verified backend delivery")
    def public(kind):
        return one([e for e in logs[authenticator] if e["kind"] == "public_record" and
                    e["recordType"] == kind], "Expected one " + kind)
    request_event, response_event = public("RADIUS_REQUEST"), public("RADIUS_RESPONSE")
    request = radius(bytes.fromhex(request_event["hex"]), 1)
    response = radius(bytes.fromhex(response_event["hex"]), 2)
    require(request["identifier"] == response["identifier"] == accepted["identifier"],
            "RADIUS request/response identifiers differ")
    require(session_records["AS"]["atMicroseconds"] < accepted["atMicroseconds"] <=
            request_event["atMicroseconds"] <= response_event["atMicroseconds"] < delivered["atMicroseconds"],
            "Backend delivery order mismatch")
    require(attribute(response, 102) == session, "RADIUS EAP-Key-Name differs from TLS session")
    require(len(attribute(request, 80)) == len(attribute(response, 80)) == 16,
            "Missing RADIUS Message-Authenticator")
    require(attribute(request, 32).decode("ascii") == authenticator,
            "Backend NAS identity differs from the authenticator")
    peer_mac = attribute(request, 31).decode("ascii").replace("-", "").lower()
    require(peer_mac == accepted["peerAddress"], "Backend peer identity differs")
    require(any(i["device"] == supplicant and i["interface"].get("ifname") == "eth0" and
                i["interface"].get("address", "").replace(":", "") == peer_mac for i in report["interfaces"]),
            "Backend peer MAC differs from observed supplicant interface")
    vendor_types = []
    for entry in response["attributes"]:
        if entry["type"] != 26:
            continue
        value = bytes.fromhex(entry["hex"])
        require(len(value) >= 8 and value[:4] == (311).to_bytes(4, "big") and
                value[5] == len(value) - 4 and value[6] & 128,
                "Unsupported protected RADIUS key attribute")
        vendor_types.append(value[4])
    require(sorted(vendor_types) == [16, 17], "Missing protected MPPE key pair")
    request_bytes = bytes.fromhex(request["hex"])
    channel = len(request_bytes).to_bytes(4, "big") + request_bytes + len(session).to_bytes(4, "big") + session
    transcript = b"".join(encoded)
    return {"sessionHex": session.hex(), "supplicant": supplicant, "authenticator": authenticator,
        "server": "AS", "deviceCertificateSha256": auth["certificates"]["peer"],
        "serverCertificateSha256": auth["certificates"]["as"], "trustAnchorSha256": auth["certificates"]["ca"],
        "transcriptHex": transcript.hex(), "transcriptSha256": hashlib.sha256(transcript).hexdigest(),
        "transcriptEncoding": "Concatenated TLS 1.3 Handshake structures, including their one-byte type and three-byte length, through client Finished. CompressedCertificate bytes are retained as sent.",
        "deviceNonceHex": client_random.hex(), "serverNonceHex": server_random.hex(),
        "tlsVersion": "1.3", "cipherSuite": cipher,
        "serverKeyShareGroup": int.from_bytes(server_extensions.get(51, b"")[:2], "big"),
        "masterSessionKeyReference": "sha256:" + master["sha256"],
        "masterSessionKeyBytes": 64, "cakInputBytes": 32,
        "cakInputReference": "sha256:" + auth["peers"][0]["mskInputSha256"],
        "channelBindingHex": channel.hex(),
        "channelBindingEncoding": "Four-byte big-endian length plus exact verified Access-Request; four-byte big-endian length plus EAP session ID from the verified Access-Accept. This is an evidence encoding of the authenticated backend exchange, not a TLS exporter or a claim of RFC 6677 channel binding.",
        "protectedRecordHex": response["hex"], "backendNonceHex": request["authenticatorHex"],
        "backendRequest": request, "backendResponse": response,
        "backendPeerAddress": peer_mac, "backendIdentityHex": attribute(request, 1).hex(),
        "clientMessages": client, "serverMessages": server,
        "tlsCompletedAtMicroseconds": session_records["AS"]["atMicroseconds"],
        "backendVerifiedAtMicroseconds": accepted["atMicroseconds"],
        "implementationBoundary": "OpenSSL verifies handshake signatures and Finished; hostap verifies RADIUS integrity and decrypts protected key attributes. Public records and opaque key hashes bind those observed operations. The parser does not independently verify secret-dependent cryptography."}


def configured_endpoints(directory, report, exchange):
    def settings(device):
        values = {}
        for line in (Path(directory) / (device + ".conf.public")).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line in {"network={", "}"}:
                continue
            require("=" in line, "Malformed public authentication configuration")
            key, value = line.split("=", 1)
            require(key not in values, "Multiple authentication profiles need a richer parser")
            values[key] = value.strip('"')
        return values
    authenticator = settings(exchange["authenticator"])
    server = settings("AS")
    supplicant = settings(exchange["supplicant"])
    def owns(device, address):
        return any(row["device"] == device and any(a.get("local") == address
            for a in row["interface"].get("addr_info", [])) for row in report["interfaces"])
    require(authenticator.get("eap_server") == "0" and server.get("eap_server") == "1" and
            authenticator.get("auth_server_port") == server.get("radius_server_auth_port") == "1812",
            "Configured EAP backend differs from captured RADIUS roles")
    require(owns("AS", authenticator.get("auth_server_addr")) and
            owns(exchange["authenticator"], authenticator.get("own_ip_addr")),
            "Configured backend address has no observed endpoint")
    require(attribute(exchange["backendRequest"], 4) ==
            ipaddress.IPv4Address(authenticator["own_ip_addr"]).packed and
            authenticator.get("nas_identifier") == exchange["authenticator"],
            "Configured backend identity differs from authenticated request")
    require(supplicant.get("eap") == "TLS" and
            supplicant.get("identity", "").encode().hex() == exchange["backendIdentityHex"],
            "Configured EAP identity differs from authenticated request")
    for config, key, expected in [(server, "ca_cert", "ca.pem"),
            (supplicant, "ca_cert", "ca.pem"), (server, "server_cert", "as.pem"),
            (supplicant, "client_cert", "peer.pem")]:
        require(Path(config.get(key, "")).name == expected,
                "Configured certificate path differs from collected public certificate")
    return {"serverAddress": authenticator["auth_server_addr"],
        "authenticatorAddress": authenticator["own_ip_addr"], "serverPort": 1812,
        "supplicantIdentity": supplicant["identity"], "serverNameConstraint": supplicant.get("domain_match"),
        "trustAnchorFile": "ca.pem.public", "deviceCertificateFile": "peer.pem.public",
        "serverCertificateFile": "as.pem.public",
        "sourceFiles": [exchange["authenticator"] + ".conf.public",
                        exchange["supplicant"] + ".conf.public", "AS.conf.public"]}


def parse(directory):
    manifest, report = eap.parse(directory)
    exchange = detailed_exchange(report)
    exchange["configuredEndpoints"] = configured_endpoints(directory, report, exchange)
    report["exchanges"] = [exchange]
    report["projectionVersion"] = "eap-public-v1"
    report["scope"] = [s for s in report["scope"] if "Full handshake transcript" not in s]
    report["scope"].append("Exact public initial TLS transcript, hello randoms, EAP session, verified backend records and full-MSK hashes are bound to the captured exchange.")
    return manifest, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return eap.query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    parse(directory)
    return eap.read_experiment_raw(directory, observation, stderr)


def export_experiment(directory, destination):
    _, report = parse(directory)
    return eap.export_report(report, destination, LEAN_VIEW)
