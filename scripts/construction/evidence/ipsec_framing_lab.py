#!/usr/bin/env python3
"""Observe a canonical IPsec UDP guard in an isolated pair of Linux namespaces."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def checksum(data):
    if len(data) % 2:
        data += bytes(1)
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def udp_packet(port, payload, ihl=5, source_port=40000):
    header = bytearray.fromhex('4500000000010000401100000afb00010afb0002')
    header[0] = 0x40 + ihl
    header.extend(bytes([1]) * (4 * (ihl - 5)))
    header[2:4] = struct.pack('!H', len(header) + 8 + len(payload))
    header[10:12] = struct.pack('!H', checksum(bytes(header)))
    return bytes(header) + struct.pack('!HHHH', source_port, port, 8 + len(payload), 0) + payload


def ike(size=28):
    data = bytearray(size)
    data[17] = 0x20
    data[24:28] = struct.pack('!I', size)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    parser.add_argument('--bytecode', type=Path)
    parser.add_argument('--send')
    parser.add_argument('--options', action='store_true')
    parser.add_argument('--source-port-framing', action='store_true')
    args = parser.parse_args()
    if args.send:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.sendto(bytes.fromhex(args.send), ('10.251.0.2', 0))
        return
    args.output.mkdir(parents=True, exist_ok=False)
    commands = []
    def run(command, optional=False):
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        commands.append({'id': 'framing-%04d' % len(commands), 'at': now(), 'command': command,
            'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode and not optional:
            raise RuntimeError(result.stderr)
        return result.stdout
    cases = []
    started = now()
    names = ['tdnfr%d-%d' % (os.getpid(), index) for index in [0, 1]]
    created = []
    try:
        for name in names:
            run(['ip', 'netns', 'add', name])
            created.append(name)
        run(['ip', 'link', 'add', 'f0', 'type', 'veth', 'peer', 'name', 'f1'])
        for index in [0, 1]:
            name = names[index]
            port = 'f%d' % index
            run(['ip', 'link', 'set', port, 'netns', name])
            run(['ip', '-n', name, 'addr', 'add', '10.251.0.%d/24' % (index + 1), 'dev', port])
            run(['ip', '-n', name, 'link', 'set', port, 'up'])
            run(['ip', '-n', name, 'link', 'set', 'lo', 'up'])
        prefix = ['ip', 'netns', 'exec', names[1], 'iptables']
        program = args.bytecode.read_text().strip()
        run(prefix + ['-A', 'INPUT', '-p', 'udp', '-m', 'bpf', '--bytecode', program, '-j', 'ACCEPT'])
        run(prefix + ['-A', 'INPUT', '-p', 'udp', '-j', 'DROP'])
        run(['ip', 'netns', 'exec', names[1], 'iptables-save'])
        run(['uname', '-a'])
        values = [('short500', 500, b'\xff', False), ('short4500', 4500, b'\xff', False),
            ('ike500', 500, ike(), True), ('ike500large', 500, ike(256), True),
            ('ike4500', 4500, bytes(4) + ike(), True),
            ('esp4500', 4500, bytes.fromhex('0102030400000001'), True),
            ('zero4500', 4500, bytes(8), False), ('wronglength500', 500, ike() + b'x', False),
            ('wronglength4500', 4500, bytes(4) + ike() + b'x', False),
            ('wrongversion500', 500, ike()[:17] + b'\x10' + ike()[18:], False),
            ('wrongport', 501, ike(), False)]
        cases_to_send = [(name, port, payload, expected, 5) for name, port, payload, expected in values]
        if args.options:
            cases_to_send.extend([('ike500-options6', 500, ike(), True, 6),
                ('ike500-options15', 500, ike(), True, 15),
                ('ike4500-options6', 4500, bytes(4) + ike(), True, 6),
                ('malformed500-options6', 500, b'\xff', False, 6)])
        for name, port, payload, expected, ihl in cases_to_send:
            run(prefix + ['-Z', 'INPUT'])
            raw = udp_packet(40000, payload, ihl, source_port=port) if args.source_port_framing else udp_packet(port, payload, ihl)
            send = ['ip', 'netns', 'exec', names[0], sys.executable, str(Path(__file__).resolve()), '--send', raw.hex()]
            run(send)
            time.sleep(.08)
            counters = run(prefix + ['-L', 'INPUT', '-n', '-v', '-x'])
            rows = [line.split() for line in counters.splitlines() if line.split() and line.split()[0].isdigit() and ('ACCEPT' in line or 'DROP' in line)]
            accepted, dropped = int(rows[0][0]), int(rows[1][0])
            cases.append({'name': name, 'at': now(), 'ipHex': raw.hex(), 'expectedAccepted': expected,
                'acceptedPackets': accepted, 'droppedPackets': dropped, 'counterObservation': commands[-1]['id']})
            if (accepted, dropped) != ((1, 0) if expected else (0, 1)):
                raise RuntimeError('Kernel result differs for ' + name)
    finally:
        for name in reversed(created):
            run(['ip', 'netns', 'del', name], optional=True)
        (args.output / 'observations.json').write_text(json.dumps({'startedAt': started, 'endedAt': now(), 'commands': commands, 'cases': cases}, indent=2) + '\n')
        (args.output / 'bytecode.txt').write_text(args.bytecode.read_text())
        (args.output / 'collector.py').write_text(Path(__file__).read_text())
        manifest = {'files': [{'path': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(args.output.iterdir()) if p.is_file()]}
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'cases': len(cases), 'passed': True}))


if __name__ == '__main__':
    main()
