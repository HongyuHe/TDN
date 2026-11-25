"""Test one actual Linux input or forwarding path using a tagged laboratory packet."""

import ipaddress
import json
import socket
import struct
import subprocess
import uuid

from worker import docker, now


RECEIVE = r'''
import json, socket, sys, time
p = json.loads(sys.argv[1])
if p['forwarded']:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((p['interface'], 0))
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, p['protocol'])
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, p['interface'].encode() + b'\0')
    if p['multicast']:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     socket.inet_aton(p['destination']) + socket.inet_aton(p['local_address']))
s.settimeout(0.2)
marker = bytes.fromhex(p['marker'])
print('READY', flush=True)
end = time.monotonic() + 3
observed = None
while time.monotonic() < end:
    try:
        data, source = s.recvfrom(65535)
        if marker in data and (not p['forwarded'] or source[2] == socket.PACKET_OUTGOING):
            address = [value.hex() if isinstance(value, bytes) else value for value in source] if isinstance(source, tuple) else str(source)
            observed = {'bytes_hex': data.hex(), 'socket_address': address}
            break
    except socket.timeout:
        pass
print(json.dumps({'observed': observed is not None, 'packet': observed}), flush=True)
'''

SEND = r'''
import json, socket, sys
p = json.loads(sys.argv[1])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((p['interface'], 0))
sent = s.send(bytes.fromhex(p['frame']))
print(json.dumps({'bytes_sent': sent}))
'''


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def mac(device, iface):
    result = docker(device, ["cat", f"/sys/class/net/{iface}/address"])
    if result["returncode"]:
        raise RuntimeError(result)
    return bytes.fromhex(result["stdout"].strip().replace(":", ""))


def peer_for(spec, device, iface):
    for link in spec["links"]:
        for side, opposite in [("a", "b"), ("b", "a")]:
            if link[side] == {"device": device, "interface": iface}:
                return link[opposite]["device"], link[opposite]["interface"]
    raise ValueError(f"No direct peer for {device}:{iface}")


def make_frame(source, destination, protocol, source_port, destination_port, marker, source_mac, destination_mac):
    source_bytes, destination_bytes = socket.inet_aton(source), socket.inet_aton(destination)
    if protocol == 17:
        payload = struct.pack("!HHHH", source_port, destination_port, 8 + len(marker), 0) + marker
    elif protocol == 6:
        tcp = struct.pack("!HHIIBBHHH", source_port, destination_port, 12345678, 0, 5 << 4, 2, 4096, 0, 0) + marker
        pseudo = source_bytes + destination_bytes + struct.pack("!BBH", 0, 6, len(tcp))
        value = checksum(pseudo + tcp)
        payload = tcp[:16] + struct.pack("!H", value) + tcp[18:]
    elif protocol == 47:
        payload = b"\0\0\x08\0" + marker
    else:
        raise ValueError("Probe protocol is not allowlisted")
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                         int.from_bytes(marker[:2], "big"), 0, 8, protocol, 0, source_bytes, destination_bytes)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return destination_mac + source_mac + b"\x08\0" + header + payload


def probe(profile, case):
    p = case["parameters"]
    target = case["device"]
    spec = profile["topology"]
    devices = {d["id"]: d for d in spec["devices"]}
    sender, sender_iface = peer_for(spec, target, p["ingress"])
    sender_record = next(i for i in devices[sender]["interfaces"] if i["name"] == sender_iface)
    target_record = next(i for i in devices[target]["interfaces"] if i["name"] == p["ingress"])
    target_address = ipaddress.ip_interface(target_record["address"])
    fallback = str(list(target_address.network.hosts())[-1])
    source = p.get("source") or sender_record.get("address", fallback).split("/")[0]
    destination = p["destination"]
    if not ipaddress.ip_address(source).is_private:
        raise ValueError("The probe source must stay inside the laboratory address space")
    if not (ipaddress.ip_address(destination).is_private or ipaddress.ip_address(destination).is_multicast):
        raise ValueError("The probe destination must stay inside the laboratory address space")
    protocol = {"udp": 17, "tcp": 6, "gre": 47}[p["protocol"]]
    marker = uuid.uuid4().bytes
    forwarded = p["chain"] == "FORWARD"
    receiver = {"forwarded": forwarded, "interface": p["egress"] if forwarded else p["ingress"],
                "protocol": protocol, "marker": marker.hex(), "destination": destination,
                "multicast": ipaddress.ip_address(destination).is_multicast,
                "local_address": str(target_address.ip)}
    frame = make_frame(source, destination, protocol, 32000, p.get("destination_port", 0), marker,
                       mac(sender, sender_iface), mac(target, p["ingress"]))
    process = subprocess.Popen(["docker", "exec", target, "python3", "-u", "-c", RECEIVE, json.dumps(receiver)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready = process.stdout.readline().strip()
    if ready != "READY":
        output, error = process.communicate(timeout=8)
        raise RuntimeError({"ready": ready, "stdout": output, "stderr": error})
    send = docker(sender, ["python3", "-c", SEND, json.dumps({"interface": sender_iface, "frame": frame.hex()})])
    output, error = process.communicate(timeout=8)
    if send["returncode"] or process.returncode:
        raise RuntimeError({"sender": send, "receiver": {"stdout": output, "stderr": error, "returncode": process.returncode}})
    result = json.loads(output.strip())
    return {"case_id": case["case_id"], "at": now(), "target": target,
            "sender": sender, "sender_interface": sender_iface, "ingress": p["ingress"],
            "source": source, "destination": destination, "protocol": protocol,
            "receiver_kind": "egress packet socket" if forwarded else "local raw IP socket after INPUT",
            "frame_hex": frame.hex(), "sender_result": send, "result": result}
