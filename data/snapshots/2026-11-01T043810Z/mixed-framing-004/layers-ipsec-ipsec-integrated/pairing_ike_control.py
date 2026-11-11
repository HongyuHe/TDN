"""Allow and test correctly framed peer IKE through manually provisioned MSC layers."""
import hashlib
import json
from pathlib import Path
import subprocess
import time


def install(lab, inner, outer):
    if inner != 'ipsec':
        return
    source=Path(__file__)
    lab.code_hashes[source.name]=hashlib.sha256(source.read_bytes()).hexdigest()
    (lab.root/source.name).write_bytes(source.read_bytes())
    program=source.with_name('ipsec-udp-framing-bytecode.txt').read_text().strip()
    (lab.root/'ipsec-udp-framing-bytecode.txt').write_text(program+'\n')
    guard=['-p','udp','-m','multiport','--dports','500,4500','-m','bpf','--bytecode',program]
    for node,local,remote in [('IA','10.11.0.1','10.21.0.1'),('IB','10.21.0.1','10.11.0.1')]:
        for chain,first,second in [('INPUT',remote,local),('OUTPUT',local,remote)]:
            lab.run(['iptables','-A',chain,'-i' if chain=='INPUT' else '-o','gray','-s',first,'-d',second,*guard,'-j','ACCEPT'],node)
    outside='black' if outer=='ipsec' else 'macsec0'
    for node,local,remote in [('OA','10.11.0.1','10.21.0.1'),('OB','10.21.0.1','10.11.0.1')]:
        for incoming,outgoing,first,second,direction in [('gray',outside,local,remote,'out'),(outside,'gray',remote,local,'in')]:
            cmd=['iptables','-A','FORWARD','-i',incoming,'-o',outgoing,'-s',first,'-d',second,*guard]
            if outer=='ipsec':cmd+=['-m','policy','--dir',direction,'--pol','ipsec','--mode','tunnel','--reqid','200']
            lab.run(cmd+['-j','ACCEPT'],node)
    checks=[]
    valid=bytearray(28);valid[17]=32;valid[24:28]=(28).to_bytes(4,'big')
    for payload,expected in [(bytes(valid),True),(b'\xff',False)]:
        server="import socket,json;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1);s.bind(('10.21.0.1',500));print('ready',flush=True)\ntry:\n b,a=s.recvfrom(4096);print(json.dumps({'receivedHex':b.hex(),'peer':a}))\nexcept socket.timeout:print(json.dumps({'timeout':True}))"
        command=['ip','netns','exec',lab.prefix+'IB','python3','-u','-c',server]
        started=time.monotonic_ns();process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if process.stdout.readline().strip()!='ready':raise RuntimeError('IKE test receiver failed')
        sender="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.11.0.1',500));print(s.sendto(bytes.fromhex('"+payload.hex()+"'),('10.21.0.1',500)))"
        sent=lab.run(['python3','-c',sender],'IA',False);sent_id=lab.commands[-1]['id']
        stdout,stderr=process.communicate(timeout=3);received=json.loads(stdout)
        oid='cmd-%04d'%len(lab.commands)
        lab.commands.append({'id':oid,'command':command,'device_id':'IB','returncode':process.returncode,'stdout':stdout,'stderr':stderr,'start_monotonic_ns':started,'end_monotonic_ns':time.monotonic_ns()})
        actual=received.get('receivedHex')==payload.hex()
        checks.append({'payloadHex':payload.hex(),'expectedReceived':expected,'received':actual,'senderObservation':sent_id,'receiverObservation':oid,'senderReturncode':sent.returncode})
        if actual!=expected:raise RuntimeError('Peer IKE admission differs')
    scope_path=lab.root/'boundary-policy-scope.json'
    scope=json.loads(scope_path.read_text());scope['Additional_peer_IKE']='Exact same-level Inner IPv4 UDP500/4500 allowance uses canonical IKEv2/UDP-ESP framing. Outer IPsec forwarding retains reqid200. Actual peer admission is tested; no IKE authentication claim.';scope_path.write_text(json.dumps(scope,indent=2)+'\n')
    (lab.root/'ike-allowance-checks.json').write_text(json.dumps({'checks':checks,'scope':'Actual same-level peer UDP framing admission; manual SAs still make no IKE authentication claim.'},indent=2)+'\n')
