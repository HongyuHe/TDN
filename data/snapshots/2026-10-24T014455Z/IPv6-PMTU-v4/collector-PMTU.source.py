#!/usr/bin/env python3
"""Observe dynamic IPv6 PMTU on an owned ESP tunnel path."""
import argparse,hashlib,json,os,select,socket,struct,subprocess,time
from pathlib import Path
from family_execution_v9 import Lab,utc
def data(size):return bytes((i*29+7)%256 for i in range(size))
def sha(value):return hashlib.sha256(value).hexdigest()
def capture(a):
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd));s.bind((a.interface,0));s.setblocking(False);end=time.monotonic()+9;records=[]
    while time.monotonic()<end:
        if not select.select([s],[],[],.1)[0]:continue
        frame,meta=s.recvfrom(65535);p=frame[14:]
        if len(p)<40:continue
        r={'at':utc(),'packet_type':meta[2],'source':socket.inet_ntop(socket.AF_INET6,p[8:24]),'destination':socket.inet_ntop(socket.AF_INET6,p[24:40]),'next_header':p[6],'payload_length':struct.unpack('!H',p[4:6])[0],'ip_total_length':40+struct.unpack('!H',p[4:6])[0]}
        if p[6]==58 and len(p)>=48:
            r.update({'icmpv6_type':p[40],'icmpv6_code':p[41]})
            if p[40]==2:
                r['advertised_mtu']=struct.unpack('!I',p[44:48])[0]
                if len(p)>=88:r['quoted_header']={'source':socket.inet_ntop(socket.AF_INET6,p[56:72]),'destination':socket.inet_ntop(socket.AF_INET6,p[72:88]),'next_header':p[54]}
        if p[6]==50 and len(p)>=48:r.update({'spi':struct.unpack('!I',p[40:44])[0],'esp_sequence':struct.unpack('!I',p[44:48])[0]})
        records.append(r)
    Path(a.output).write_text(json.dumps({'interface':a.interface,'namespace':os.readlink('/proc/self/ns/net'),'records':records},indent=2)+'\n')
def server(a):
    s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind(('fd72:2::2',43101));s.settimeout(7);seen=[]
    try:
        b,peer=s.recvfrom(65535);seen.append({'bytes':len(b),'sha256':sha(b),'matches_public_pattern':b==data(len(b))});s.sendto(b'owned-pmtu-ack',peer)
    except socket.timeout:pass
    Path(a.output).write_text(json.dumps({'at':utc(),'received':seen},indent=2)+'\n')
def sender(a):
    s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.setsockopt(socket.IPPROTO_IPV6,23,2);s.setsockopt(socket.IPPROTO_IPV6,25,1);s.connect(('fd72:2::2',43101));s.settimeout(1);events=[];initial=s.getsockopt(socket.IPPROTO_IPV6,24)
    for attempt in range(3):
        try:n=s.send(data(1400));events.append({'attempt':attempt,'send_bytes':n})
        except OSError as e:events.append({'attempt':attempt,'send_error':e.errno,'error':str(e)})
        time.sleep(.7)
        while True:
            try:
                b,control,flags,address=s.recvmsg(65535,2048,socket.MSG_ERRQUEUE|socket.MSG_DONTWAIT);decoded=[]
                for level,kind,value in control:
                    if level==socket.IPPROTO_IPV6 and kind==25 and len(value)>=16:
                        err,origin,typ,code,pad,info,extra=struct.unpack('=IBBBBII',value[:16]);decoded.append({'errno':err,'origin':origin,'type':typ,'code':code,'info':info,'data':extra})
                events.append({'attempt':attempt,'error_queue':decoded,'quoted_payload_bytes':len(b)})
            except (BlockingIOError,TimeoutError):break
        events.append({'attempt':attempt,'socket_path_mtu':s.getsockopt(socket.IPPROTO_IPV6,24)})
    n=s.send(data(1200))
    try:ack=s.recv(2048).decode()
    except OSError as e:ack=str(e)
    Path(a.output).write_text(json.dumps({'at':utc(),'initial_path_mtu':initial,'final_path_mtu':s.getsockopt(socket.IPPROTO_IPV6,24),'events':events,'valid_send_bytes':n,'valid_sha256':sha(data(1200)),'ack':ack},indent=2)+'\n')
def main(a):
    lab=Lab(a.output,'IPv6-PMTU-v4');lab.prefix='tcv3pm4-';script=str(Path(__file__).resolve());children=[];lab.code_hashes={'ipv6_pmtu_v4.py':sha(Path(__file__).read_bytes()),'family_execution_v9.py':sha(Path(__file__).with_name('family_execution_v9.py').read_bytes())}
    (lab.root/'collector-PMTU.source.py').write_bytes(Path(__file__).read_bytes())
    def start(node,args):
        cmd=['ip','netns','exec',lab.prefix+node,'python3',script,*args];p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);children.append(p);lab.commands.append({'id':'async-%04d'%len(lab.commands),'at':utc(),'command':cmd,'pid':p.pid});return p
    try:
        for node,role in [('HA','Red-source'),('IA','VPN-A'),('R','Black-router'),('IB','VPN-B'),('HB','Red-destination')]:lab.node(node,role,node[-1])
        for link in [('HA','red','IA','red','fd72:1::2/64','fd72:1::1/64','Red'),('IA','wire','R','left','fd72:10::1/64','fd72:10::2/64','Black'),('R','right','IB','wire','fd72:20::1/64','fd72:20::2/64','Black'),('IB','red','HB','red','fd72:2::1/64','fd72:2::2/64','Red')]:lab.link(*link)
        for node,iface in [('IA','wire'),('R','left')]:lab.run(['ip','link','set',iface,'mtu',1600],node)
        for node,iface in [('R','right'),('IB','wire')]:lab.run(['ip','link','set',iface,'mtu',1400],node)
        for node,dst,via in [('HA','fd72:2::/64','fd72:1::1'),('HB','fd72:1::/64','fd72:2::1'),('IA','fd72:2::/64','fd72:10::2'),('IA','fd72:20::2/128','fd72:10::2'),('IB','fd72:1::/64','fd72:20::1'),('IB','fd72:10::1/128','fd72:20::1')]:lab.route(node,dst,via)
        lab.esp('IA','IB','fd72:10::1','fd72:20::2','fd72:1::/64','fd72:2::/64',321,'representative-IPv6-ESP')
        for node in ['IA','IB']:
            for tool in ['iptables','ip6tables']:lab.run([tool,'-P','FORWARD','DROP'],node)
            for inside,outside,direction in [('red','wire','out'),('wire','red','in')]:lab.run(['ip6tables','-A','FORWARD','-i',inside,'-o',outside,'-m','policy','--dir',direction,'--pol','ipsec','--reqid',321,'-j','ACCEPT'],node)
        from gateway_header_policy_v5 import install
        install(lab,['IA','IB']);lab.run(['uname','-a']);lab.state('before');lab.run(['ip','-6','route','get','fd72:2::2'],'HA')
        for node,iface,label in [('HA','red','Red-source'),('IA','wire','sender-Black'),('R','right','router-egress'),('IB','red','Red-destination')]:start(node,['--role','capture','--interface',iface,'--output',str(lab.root/(label+'.json'))])
        start('HB',['--role','server','--output',str(lab.root/'receiver.json')]);time.sleep(.3);start('HA',['--role','sender','--output',str(lab.root/'sender.json')])
        for p in children:
            stdout,stderr=p.communicate(timeout=13);lab.commands.append({'id':'async-end-%04d'%len(lab.commands),'at':utc(),'pid':p.pid,'returncode':p.returncode,'stdout':stdout,'stderr':stderr});assert p.returncode==0,stderr
        lab.run(['ip','-6','route','get','fd72:2::2'],'HA');lab.run(['ip','-6','route','get','fd72:20::2'],'IA');lab.state('after')
        source=json.loads((lab.root/'sender.json').read_text());received=json.loads((lab.root/'receiver.json').read_text())['received'];captures=[x for p in lab.root.glob('*.json')if p.name in['Red-source.json','sender-Black.json','router-egress.json','Red-destination.json']for x in json.loads(p.read_text())['records']]
        for name,result in [('actual-ICMPv6-PTB',any(x.get('icmpv6_type')==2 for x in captures)),('dynamic-source-PMTU-lowered',source['final_path_mtu']<source['initial_path_mtu']),('valid-protected-payload',bool(received)and received[0]['bytes']==1200 and received[0]['matches_public_pattern']and source['ack']=='owned-pmtu-ack')]:lab.probes.append({'id':name,'expected_result':True,'observed_result':result})
        (lab.root/'scope.json').write_text(json.dumps({'scope':'Owned supplemental Linux namespace IPv6 ESP path with manually provisioned SAs. Actual ICMPv6 PTB headers, error queue, socket PMTU and route cache transitions are retained. The smaller public payload is verified by size/hash and protected return acknowledgement. No production authority or every PMTU condition is inferred.','payload_generator':'byte[i]=(29*i+7) mod256','preservation':'Only newly named namespaces, routes, SAs, MTUs and filters are changed and removed after collection.'},indent=2)+'\n')
        for name in ['ipv6_pmtu_v4.py','family_execution_v9.py']:(lab.root/(name+'.source')).write_bytes(Path(__file__).with_name(name).read_bytes())
        lab.finish()
    except Exception as exc:
        for p in children:
            if p.poll()is None:p.terminate()
        lab.finish(str(exc))
p=argparse.ArgumentParser();p.add_argument('--role',default='main',choices=['main','capture','server','sender']);p.add_argument('--output',required=True);p.add_argument('--interface');a=p.parse_args();{'main':main,'capture':capture,'server':server,'sender':sender}[a.role](a)
