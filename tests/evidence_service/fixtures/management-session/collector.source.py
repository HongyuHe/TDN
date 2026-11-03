#!/usr/bin/env python3
"""Capture an AW-initiated HTTPS connection and rejected Outer-side attempts."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


CAPTURE = '''import socket,time,json,sys
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('gray',0))
print(json.dumps({'ready':True}),flush=True)
while True:
 b,a=s.recvfrom(65535)
 if len(b)>34 and b[12:14]==bytes.fromhex('0800') and b[23]==6:
  print(json.dumps({'monotonic_ns':time.monotonic_ns(),'interface':a[0],'packet_type':a[2],'frame_hex':b.hex()}),flush=True)
'''

SERVER = '''import socket,ssl,json,time,sys
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(sys.argv[1],sys.argv[2])
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.31.0.2',443));s.listen(1)
print(json.dumps({'ready':True}),flush=True)
r,a=s.accept()
with c.wrap_socket(r,server_side=True) as t:
 request=t.recv(4096)
 print(json.dumps({'event':'request','peer':a,'local':t.getsockname(),'monotonic_ns':time.monotonic_ns(),'bytes_hex':request.hex()}),flush=True)
 response=b'HTTP/1.1 200 OK\\r\\nContent-Length: 3\\r\\n\\r\\nOK\\n';t.sendall(response)
 print(json.dumps({'event':'response','monotonic_ns':time.monotonic_ns(),'bytes_hex':response.hex()}),flush=True)
 time.sleep(4)
'''

CLIENT = '''import socket,ssl,json,time,sys
c=ssl.create_default_context(cafile=sys.argv[1]);s=socket.socket();s.settimeout(5);s.bind(('10.31.0.1',41000));s.connect(('10.31.0.2',443))
with c.wrap_socket(s,server_hostname='outer.msc.test') as t:
 request=b'GET /status HTTP/1.1\\r\\nHost: outer.msc.test\\r\\n\\r\\n';t.sendall(request)
 print(json.dumps({'event':'request','peer':t.getpeername(),'local':t.getsockname(),'monotonic_ns':time.monotonic_ns(),'bytes_hex':request.hex()}),flush=True)
 response=t.recv(4096)
 print(json.dumps({'event':'response','monotonic_ns':time.monotonic_ns(),'bytes_hex':response.hex()}),flush=True)
 assert response.endswith(b'OK\\n')
 time.sleep(3)
'''

UNSOLICITED = '''import socket,json,time
s=socket.socket();s.settimeout(1);s.bind(('10.31.0.2',42000));start=time.monotonic_ns()
result=s.connect_ex(('10.31.0.1',443));print(json.dumps({'event':'unsolicited_connect','start_ns':start,'end_ns':time.monotonic_ns(),'result':result,'source':'10.31.0.2','source_port':42000,'destination':'10.31.0.1','destination_port':443}));assert result!=0
'''

UNBOUND_REPLY = '''import socket,struct,json,time,hashlib
def checksum(b):
 if len(b)%2:b+=b'\\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b));n=(n>>16)+(n&65535);n+=(n>>16);return (~n)&65535
src=socket.inet_aton('10.31.0.2');dst=socket.inet_aton('10.31.0.1');payload=b'v31-unbound-reply'
tcp=struct.pack('!HHLLBBHHH',443,41001,77,99,5<<4,0x18,4096,0,0)+payload
cs=checksum(src+dst+struct.pack('!BBH',0,6,len(tcp))+tcp);tcp=tcp[:16]+struct.pack('!H',cs)+tcp[18:]
ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),31,0,64,6,0,src,dst);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
packet=ip+tcp;s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW);sent=0;error=None
try:sent=s.sendto(packet,('10.31.0.1',0))
except OSError as exc:error=exc.errno
print(json.dumps({'event':'unbound_reply_attempt','monotonic_ns':time.monotonic_ns(),'packet_hex':packet.hex(),'sha256':hashlib.sha256(packet).hexdigest(),'sent_bytes':sent,'errno':error}))
assert error in [None,1]
'''


def collect(root):
    root.mkdir(parents=True, exist_ok=False)
    private = root.parent / (root.name + '-private')
    private.mkdir(mode=0o700, exist_ok=False)
    prefix = 'tdnv31s-'
    commands, processes, handles = [], [], []
    error = None

    def run(argv, device=None, required=True):
        command = (['ip', 'netns', 'exec', prefix + device] if device else []) + argv
        start = time.monotonic_ns()
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        commands.append({'id': 'cmd-%04d' % len(commands), 'device': device, 'command': command,
            'start_ns': start, 'end_ns': time.monotonic_ns(), 'returncode': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr})
        if required and result.returncode:
            raise RuntimeError(str(command) + ': ' + result.stderr)
        return commands[-1]

    def launch(name, program, device, extra=()):
        path = root / (name + '.py')
        path.write_text(program)
        handle = (private / (name + '.jsonl')).open('w')
        handles.append(handle)
        argv = ['ip', 'netns', 'exec', prefix + device, 'python3', '-u', str(path), *map(str, extra)]
        process = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT)
        processes.append(process)
        commands.append({'id': 'cmd-%04d' % len(commands), 'device': device, 'command': argv,
            'start_ns': time.monotonic_ns(), 'kind': 'spawn', 'pid': process.pid})
        return process

    def wait_record(name, needle):
        for _ in range(100):
            if needle in (private / (name + '.jsonl')).read_text():
                return
            time.sleep(.05)
        raise RuntimeError('Missing record from ' + name)

    def state(label):
        result = {}
        for device in ['AW', 'OUTER']:
            result[device] = {key: run(argv, device) for key, argv in [
                ('interfaces', ['ip', '-j', '-d', 'addr']), ('routes', ['ip', '-j', 'route']),
                ('filters', ['iptables-save', '-c']), ('conntrack', ['conntrack', '-L', '-p', 'tcp', '-o', 'extended'])]}
        (root / (label + '.json')).write_text(json.dumps(result, indent=2) + '\n')

    try:
        run(['uname', '-a'])
        run(['openssl', 'version'])
        for node in ['AW', 'OUTER']:
            run(['ip', 'netns', 'add', prefix + node])
            run(['ip', 'link', 'set', 'lo', 'up'], node)
        run(['ip', 'link', 'add', 'session-aw', 'type', 'veth', 'peer', 'name', 'session-outer'])
        for node, name, address in [('AW', 'session-aw', '10.31.0.1/30'), ('OUTER', 'session-outer', '10.31.0.2/30')]:
            run(['ip', 'link', 'set', name, 'netns', prefix + node])
            run(['ip', 'link', 'set', name, 'name', 'gray'], node)
            run(['ip', 'addr', 'add', address, 'dev', 'gray'], node)
            run(['ip', 'link', 'set', 'gray', 'up'], node)
            for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
                run(['iptables', '-P', chain, 'DROP'], node)
            for chain in ['INPUT', 'OUTPUT']:
                run(['iptables', '-A', chain, '-i' if chain == 'INPUT' else '-o', 'lo', '-j', 'ACCEPT'], node)
                run(['iptables', '-A', chain, '-p', 'tcp', '-m', 'conntrack', '--ctstate', 'ESTABLISHED', '-j', 'ACCEPT'], node)
            chain = 'OUTPUT' if node == 'AW' else 'INPUT'
            run(['iptables', '-A', chain, '-s', '10.31.0.1', '-d', '10.31.0.2', '-p', 'tcp', '--dport', '443', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'ACCEPT'], node)
            for chain in ['INPUT', 'OUTPUT']:
                run(['iptables', '-A', chain, '-j', 'DROP'], node)
        certificate, key = private / 'server.pem', private / 'server.key'
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '1', '-subj', '/CN=outer.msc.test', '-addext', 'subjectAltName=DNS:outer.msc.test', '-keyout', str(key), '-out', str(certificate)])
        shutil.copy2(certificate, root / 'server.pem.public')
        for node in ['AW', 'OUTER']:
            launch('capture-' + node, CAPTURE, node)
            wait_record('capture-' + node, 'ready')
        server = launch('server', SERVER, 'OUTER', [certificate, key])
        wait_record('server', 'ready')
        client = launch('client', CLIENT, 'AW', [certificate])
        wait_record('client', 'response')
        state('established')
        client.wait(timeout=8)
        server.wait(timeout=8)
        if client.returncode or server.returncode:
            raise RuntimeError('HTTPS exchange failed')
        state('before-negative')
        run(['python3', '-c', UNSOLICITED], 'OUTER')
        state('after-unsolicited')
        run(['python3', '-c', UNBOUND_REPLY], 'OUTER')
        time.sleep(.2)
        state('after-unbound-reply')
    except Exception as exc:
        error = str(exc)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        for handle in handles:
            handle.close()
        for path in sorted(private.glob('*.jsonl')):
            row = run(['cat', str(path)], required=False)
            (root / path.name).write_text(row['stdout'])
        for node in ['AW', 'OUTER']:
            run(['ip', 'netns', 'delete', prefix + node], required=False)
        shutil.rmtree(private)
        (root / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        shutil.copy2(__file__, root / 'collector.source.py')
        evidence = {'schema': 'management-session/v1', 'configuration_id': root.name,
            'runtime_backend': 'isolated-linux-netns-https', 'error': error,
            'devices': [{'id': 'AW', 'role': 'gray-workstation', 'namespace': prefix + 'AW'},
                        {'id': 'OUTER', 'role': 'outer-management-endpoint', 'namespace': prefix + 'OUTER'}],
            'scope': 'Observed management connection semantics; no encryption-tunnel or product-certification claim.'}
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        files = [{'path': str(p.relative_to(root)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}
                 for p in sorted(root.rglob('*')) if p.is_file()]
        (root / 'manifest.json').write_text(json.dumps({'schema': 'management-session/v1',
            'configuration_id': root.name, 'error': error, 'files': files,
            'captured_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}, indent=2) + '\n')
    if error:
        raise RuntimeError(error)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    collect(parser.parse_args().output)
