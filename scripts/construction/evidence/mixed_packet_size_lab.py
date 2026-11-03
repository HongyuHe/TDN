#!/usr/bin/env python3
"""Measure MACsec, standalone L2TPv3 and outer ESP sizing in an isolated lab."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

import manual_pairing_lab as pairing


SIZES = [1228, 1359, 1360, 1361, 1414, 1415, 1468, 1469, 1500, 1501, 4028]
PORTS = [(node + site, port) for site in ['A', 'B'] for node, port in [
    ('H', 'red'), ('I', 'red'), ('I', 'macsec0'), ('I', 'gray'),
    ('E', 'innerframes'), ('E', 'l2tpeth0'), ('E', 'uplink'),
    ('O', 'gray'), ('O', 'black'), ('F', 'outside')]]


def capture(interface):
    channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    channel.bind((interface, 0))
    print(json.dumps({'ready': True, 'interface': interface, 'at': pairing.utc(),
                      'monotonic_ns': time.monotonic_ns()}), flush=True)
    while True:
        frame, address = channel.recvfrom(131072)
        if len(frame) < 14 or frame[12:14] not in [b'\x08\x00', b'\x88\xe5']:
            continue
        print(json.dumps({'interface': interface, 'at': pairing.utc(),
            'monotonic_ns': time.monotonic_ns(), 'packet_type': address[2],
            'frame_hex': frame.hex(), 'frame_bytes': len(frame),
            'sha256': hashlib.sha256(frame).hexdigest()}), flush=True)


class SizingLab(pairing.Lab):
    def matrix(self, phase):
        observers = []
        paths = []
        try:
            for node, port in PORTS:
                path = self.root / (phase + '--' + node + '--' + port + '.jsonl')
                stream = path.open('x')
                command = ['ip', 'netns', 'exec', self.prefix + node, sys.executable,
                    str(Path(__file__).resolve()), '--capture-interface', port]
                process = subprocess.Popen(command, stdout=stream, stderr=subprocess.PIPE, text=True)
                observers.append((process, stream, node, port, path, command))
                paths.append(path)
            deadline = time.monotonic() + 8
            while not all(path.stat().st_size for path in paths):
                if any(process.poll() is not None for process, *_ in observers):
                    raise RuntimeError('Mixed sizing observer exited before readiness')
                if time.monotonic() > deadline:
                    raise RuntimeError('Mixed sizing observer readiness timeout')
                time.sleep(.05)
            for node, port in PORTS:
                self.run(['ip', '-j', '-d', 'link', 'show', 'dev', port], node)
                self.run(['ethtool', '-k', port], node)
            for node in ['IA', 'IB', 'EA', 'EB', 'OA', 'OB']:
                self.run(['nstat', '-az'], node)
                self.run(['ip', '-j', '-4', 'route', 'show', 'table', 'all'], node)
                self.run(['sysctl', 'net.ipv4.ip_no_pmtu_disc', 'net.ipv4.route.min_pmtu'], node)
            for source, destination in [('HA', '10.2.0.2'), ('HB', '10.1.0.2')]:
                for mode in ['do', 'dont']:
                    for size in SIZES:
                        before = []
                        for node in ['IA', 'IB', 'EA', 'EB', 'OA', 'OB']:
                            self.run(['iptables-save', '-c'], node)
                            before.append(self.commands[-1]['id'])
                        start = time.monotonic_ns()
                        result = self.run(['ping', '-n', '-c', '1', '-W', '1', '-M', mode,
                            '-s', str(size - 28), '-p', 'a1b2c3d4', destination], source, False)
                        observation = self.commands[-1]['id']
                        end = time.monotonic_ns()
                        after = []
                        for node in ['IA', 'IB', 'EA', 'EB', 'OA', 'OB']:
                            self.run(['iptables-save', '-c'], node)
                            after.append(self.commands[-1]['id'])
                        self.size_cases.append({'phase': phase, 'source': source,
                            'destination': destination, 'mode': mode, 'source_ip_bytes': size,
                            'observation': observation, 'returncode': result.returncode,
                            'start_ns': start, 'end_ns': end, 'filters_before': before,
                            'filters_after': after})
            for node in ['IA', 'IB', 'EA', 'EB', 'OA', 'OB']:
                self.run(['nstat', '-az'], node)
        finally:
            for process, stream, node, port, path, command in observers:
                process.terminate()
                _, stderr = process.communicate(timeout=5)
                stream.close()
                self.size_observers.append({'phase': phase, 'device': node, 'interface': port,
                    'command': command, 'returncode': process.returncode, 'stderr': stderr,
                    'file': path.name, 'stopped_by_collector': True})

    def state(self, label):
        original = super().state(label)
        if label != 'stable-before':
            return original
        self.size_cases = []
        self.size_observers = []
        self.matrix('before')
        for node in ['OA', 'OB']:
            self.run(['iptables', '-I', 'FORWARD', '1', '-o', 'black', '-m', 'length',
                '--length', '1447:65535', '-j', 'DROP'], node)
            self.run(['iptables', '-I', 'OUTPUT', '1', '-o', 'black', '-m', 'length',
                '--length', '1501:65535', '-j', 'DROP'], node)
        self.matrix('outer-guard')
        for node in ['IA', 'IB']:
            self.run(['iptables', '-I', 'FORWARD', '1', '-o', 'macsec0', '-m', 'length',
                '--length', '1361:65535', '-j', 'DROP'], node)
        self.matrix('inner-and-outer-guard')
        return super().state('sizing-after')

    def finish(self, error=None):
        (self.root / 'sizing.json').write_text(json.dumps({
            'schema': 'mixed-packet-sizing/v1', 'sizes': SIZES,
            'cases': getattr(self, 'size_cases', []),
            'observers': getattr(self, 'size_observers', []),
            'scope': 'AF_PACKET namespace observations with actual configured offloads. '
                     'Manual SAs; no IKE/MKA authentication claim. The three phases preserve '
                     'original, outer admission guard, and inner plus outer admission guards.'}, indent=2) + '\n')
        (self.root / 'mixed-sizing.source.py').write_bytes(Path(__file__).read_bytes())
        super().finish(error)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output')
    parser.add_argument('--capture-interface')
    args = parser.parse_args()
    if args.capture_interface:
        capture(args.capture_interface)
    else:
        pairing.Lab = SizingLab
        pairing.pairing(args.output, 'macsec', 'ipsec', standalone=True)
