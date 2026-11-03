#!/usr/bin/env python3
"""Observe source fragmentation and encrypted packet sizes on a native MSC path."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def capture(interface, duration):
    channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    channel.bind((interface, 0))
    channel.settimeout(.2)
    print(json.dumps({'ready': True, 'interface': interface, 'at': now(), 'monotonic_ns': time.monotonic_ns()}), flush=True)
    end = time.monotonic() + duration
    while time.monotonic() < end:
        try:
            frame, address = channel.recvfrom(131072)
        except socket.timeout:
            continue
        if len(frame) < 34 or frame[12:14] != b'\x08\x00' or frame[23] not in [1, 50]:
            continue
        packet = frame[14:]
        length = int.from_bytes(packet[2:4], 'big')
        flags = int.from_bytes(packet[6:8], 'big')
        print(json.dumps({'interface': interface, 'at': now(), 'monotonic_ns': time.monotonic_ns(),
            'packet_type': address[2], 'frame_hex': frame.hex(), 'frame_bytes': len(frame),
            'ip_bytes': length, 'ip_header_bytes': (packet[0] & 15) * 4, 'protocol': packet[9],
            'source': socket.inet_ntoa(packet[12:16]), 'destination': socket.inet_ntoa(packet[16:20]),
            'ip_id': int.from_bytes(packet[4:6], 'big'), 'df': bool(flags & 0x4000),
            'mf': bool(flags & 0x2000), 'fragment_offset': (flags & 8191) * 8,
            'ip_sha256': hashlib.sha256(packet[:length]).hexdigest()}), flush=True)
    channel.close()


def experiment(args):
    args.output.mkdir(parents=True, exist_ok=False)
    spec = json.loads(args.spec.read_text())
    declared = {d['id']: d for d in spec['devices']}
    ports = [value.split(':', 1) for value in args.ports]
    if args.source not in declared or any(d not in declared or p not in {i['name'] for i in declared[d]['interfaces']} for d, p in ports):
        raise ValueError('Experiment device/interface is not declared')
    commands, processes, files, cases = [], [], [], []
    started = now()

    def run(command, kind, timeout=20):
        start = now()
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        row = {'id': 'size-%04d' % len(commands), 'kind': kind, 'command': command,
            'started_at': start, 'ended_at': now(), 'returncode': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}
        commands.append(row)
        return row

    try:
        pids = {}
        for device, interface in ports:
            if device not in pids:
                row = run(['docker', 'inspect', '-f', '{{.State.Pid}}', device], 'namespace')
                if row['returncode']:
                    raise ValueError('Cannot identify experiment namespace')
                pids[device] = int(row['stdout'])
            command = ['nsenter', '-t', str(pids[device]), '-n', sys.executable,
                str(Path(__file__).resolve()), '--capture-interface', interface, '--duration', '120']
            path = args.output / (device + '--' + interface + '.jsonl')
            stream = path.open('w')
            process = subprocess.Popen(command, stdout=stream, stderr=subprocess.PIPE, text=True)
            processes.append((process, stream, device, interface, command))
            files.append(path)
        deadline = time.monotonic() + 5
        while not all(path.stat().st_size for path in files):
            if time.monotonic() > deadline:
                raise RuntimeError('Packet observers did not become ready')
            time.sleep(.05)
        for device, interface in ports:
            run(['docker', 'exec', device, 'ip', '-j', '-d', 'link', 'show', 'dev', interface], 'interface-mtu')
            run(['nsenter', '-t', str(pids[device]), '-n', 'ethtool', '-k', interface], 'offload')
        for device in pids:
            run(['docker', 'exec', device, 'nstat', '-az'], 'counters-before')
            run(['docker', 'exec', device, 'ip', '-j', '-4', 'route', 'show', 'table', 'all'], 'routes')
            run(['docker', 'exec', device, 'sysctl', 'net.ipv4.ip_no_pmtu_disc',
                'net.ipv4.tcp_mtu_probing', 'net.ipv4.route.min_pmtu'], 'pmtu')
        for mode, size in [('do', 1292), ('do', 1293), ('dont', 1293), ('dont', 4000), ('do', 1200)]:
            filters_before = [run(['docker', 'exec', device, 'iptables-save', '-c'], 'filters-before')['id'] for device in pids]
            before = time.monotonic_ns()
            row = run(['docker', 'exec', args.source, 'ping', '-n', '-c', '2', '-W', '2',
                '-M', mode, '-s', str(size), '-p', 'a1b2c3d4', args.destination], 'probe', 10)
            finish = time.monotonic_ns()
            filters_after = [run(['docker', 'exec', device, 'iptables-save', '-c'], 'filters-after')['id'] for device in pids]
            cases.append({'mode': mode, 'icmp_payload_bytes': size, 'source_ip_bytes': size + 28,
                'start_ns': before, 'end_ns': finish, 'observation': row['id'],
                'filters_before': filters_before, 'filters_after': filters_after})
        for device in pids:
            run(['docker', 'exec', device, 'nstat', '-az'], 'counters-after')
    finally:
        for process, stream, device, interface, command in processes:
            process.terminate()
            _, stderr = process.communicate(timeout=5)
            stream.close()
            commands.append({'id': 'size-%04d' % len(commands), 'kind': 'packet-observer',
                'device': device, 'interface': interface, 'command': command,
                'returncode': process.returncode, 'stderr': stderr,
                'output': device + '--' + interface + '.jsonl', 'stopped_by_collector': True})
        (args.output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        (args.output / 'cases.json').write_text(json.dumps({'source': args.source, 'destination': args.destination,
            'cases': cases, 'started_at': started, 'ended_at': now(),
            'scope': 'AF_PACKET observations in the container network namespaces; offloads remain as configured. The capture does not claim physical-NIC post-offload serialization.'}, indent=2) + '\n')
        (args.output / 'spec.json').write_text(json.dumps(spec, indent=2) + '\n')
        shutil.copy2(__file__, args.output / 'collector.source.py')
        entries = [{'path': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}
                   for p in sorted(args.output.iterdir()) if p.is_file()]
        (args.output / 'manifest.json').write_text(json.dumps({'schema': 'native-packet-sizing/v1',
            'configuration_id': args.output.name, 'files': entries}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--capture-interface')
    parser.add_argument('--duration', type=float, default=45)
    parser.add_argument('--spec', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--source')
    parser.add_argument('--destination')
    parser.add_argument('--ports', nargs='+')
    args = parser.parse_args()
    if args.capture_interface:
        capture(args.capture_interface, args.duration)
    else:
        experiment(args)
