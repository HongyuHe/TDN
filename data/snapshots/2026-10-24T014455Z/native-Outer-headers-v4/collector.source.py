import argparse,hashlib,json,socket,struct,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--device-prefix',default='ND');p.add_argument('--profile-name',default='native-os-diversity-v3');a=p.parse_args();root=Path(a.root);out=root/'exports/native-Outer-headers-v4';out.mkdir();records=[];error=None
def utc():return datetime.now(timezone.utc).isoformat()
def run(argv,check=True):
 r=subprocess.run(list(map(str,argv)),text=True,capture_output=True,timeout=30);records.append({'id':'header3-%04d'%len(records),'started_at':utc(),'command':list(map(str,argv)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr[-2000:])
 return r
def ex(node,argv,check=True):return run(['docker','exec',node,*argv],check)
def ns(node,argv,check=True):
 pid=run(['docker','inspect','--format','{{.State.Pid}}',node]).stdout.strip();return run(['nsenter','--target',pid,'--net',*argv],check)
def snapshot(node,label):
 for cmd in [['uname','-a'],['ip','-d','-j','link'],['ip','-j','address'],['ip','-j','rule'],['ip','-j','-6','rule'],['ip','-j','route','show','table','all'],['ip','-j','-6','route','show','table','all'],['iptables-save','-c'],['ip6tables-save','-c'],['ip','xfrm','state','list','nokeys'],['ip','xfrm','policy'],['sysctl','net.ipv4.conf.all.accept_source_route','net.ipv6.conf.all.disable_ipv6']]:
  ex(node,cmd);records[-1]['phase']=label
 ns(node,['nft','-j','list','ruleset']);records[-1]['phase']=label
sender="""import socket,struct,sys,time,json
iface,smac,dmac,src,dst,options=sys.argv[1:];opt=bytes([1,1,0,0])if options=='yes'else b'';payload=b'owned-public-header-filter-control';udp=struct.pack('!HHHH',500,500,8+len(payload),0)+payload;header=struct.pack('!BBHHHBBH4s4s',69+len(opt)//4,0,20+len(opt)+len(udp),43003,0,222,17,0,socket.inet_aton(src),socket.inet_aton(dst))+opt;total=sum(struct.unpack('!%dH'%(len(header)//2),header));total=(total&65535)+(total>>16);total=(total&65535)+(total>>16);header=header[:10]+struct.pack('!H',(~total)&65535)+header[12:];frame=bytes.fromhex(dmac.replace(':',''))+bytes.fromhex(smac.replace(':',''))+bytes.fromhex('0800')+header+udp;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind((iface,0))
for i in range(3):s.send(frame);time.sleep(.05)
print(json.dumps({'sent':3,'source':src,'destination':dst,'IHL':len(header),'ttl':222,'UDP_source':500,'UDP_destination':500,'scope':'Raw injection from the actual adjacent firewall namespace. The claimed peer IP is explicit and is not treated as authenticated origin.'}))
"""
try:
 spec=json.loads((root/'scripts/profiles'/(a.profile_name+'.json')).read_text());outers=[d for d in spec['devices']if d['role']=='outer'];assert len(outers)==2
 run(['uname','-a']);run(['cat','/proc/sys/kernel/random/boot_id']);run(['cat','/sys/class/dmi/id/product_uuid']);run(['nft','--version'])
 for d in outers:
  node=d['id'];assert node.startswith(a.device_prefix+'_');neighbor=a.device_prefix+'_OF_'+node.split('_')[-1]
  run(['docker','inspect','--format','{{.Id}} {{.Image}} {{.State.Pid}} {{.HostConfig.NetworkMode}}',node]);snapshot(node,'before')
  mac=json.loads(ex(node,['ip','-j','link','show','black']).stdout)[0]['address'];peer_mac=json.loads(ex(neighbor,['ip','-j','link','show','inside']).stdout)[0]['address'];src=d['tunnel']['remote'];dst=d['tunnel']['local']
  for mode,target in [('yes',dst),('no','239.192.0.1')]:ex(neighbor,['python3','-c',sender,'inside',peer_mac,mac,src,target,mode]);records[-1]['phase']='before-diagnostic'
  ex(node,['iptables-save','-c']);ns(node,['nft','-j','list','ruleset'])
  old=ns(node,['nft','list','table','inet','tdn_outer_headers_v3'],False);assert old.returncode!=0,'Owned policy table already exists'
  rules='add table inet tdn_outer_headers_v3\nadd chain inet tdn_outer_headers_v3 ingress { type filter hook prerouting priority -450; policy accept; }\nadd chain inet tdn_outer_headers_v3 egress { type filter hook output priority -450; policy accept; }\nadd rule inet tdn_outer_headers_v3 ingress ip hdrlength > 5 counter drop comment "PF10_IPv4_options_ingress"\nadd rule inet tdn_outer_headers_v3 egress ip hdrlength > 5 counter drop comment "PF10_IPv4_options_egress"\nadd rule inet tdn_outer_headers_v3 ingress iifname "black" ip daddr 224.0.0.0/4 counter drop comment "PF9_IPv4_multicast"\nadd rule inet tdn_outer_headers_v3 ingress iifname "black" ip6 daddr ff00::/8 counter drop comment "PF9_IPv6_multicast"\n'
  policy=out/(node+'-policy.nft');policy.write_text(rules);ns(node,['nft','-f',str(policy)])
  for mode,target,label in [('yes',dst,'IPv4-options'),('no','239.192.0.1','IPv4-external-multicast')]:
   before=json.loads(ns(node,['nft','-j','list','table','inet','tdn_outer_headers_v3']).stdout);ex(neighbor,['python3','-c',sender,'inside',peer_mac,mac,src,target,mode]);after=json.loads(ns(node,['nft','-j','list','table','inet','tdn_outer_headers_v3']).stdout)
   def count(obj,comment):
    rows=[x['rule']for x in obj['nftables']if'rule'in x and x['rule'].get('comment')==comment];assert len(rows)==1
    return next(v['counter']['packets']for v in rows[0]['expr']if'counter'in v)
   comment='PF10_IPv4_options_ingress'if mode=='yes'else'PF9_IPv4_multicast';delta=count(after,comment)-count(before,comment);records[-1].update(probe=label+'-'+node,expected_result='three-packets-dropped',observed_result='three-packets-dropped'if delta==3 else'counter-mismatch',drop_counter_delta=delta);assert delta==3
  snapshot(node,'after')
 for source,dest in [(a.device_prefix+'_R_A1','10.2.1.10'),(a.device_prefix+'_R_B1','10.1.1.10')]:
  r=ex(source,['ping','-n','-c','3','-W','1',dest],False);records[-1].update(probe='protected-data-'+source,expected_result='delivered',observed_result='delivered'if r.returncode==0 else'no-reply');assert r.returncode==0
except Exception as exc:error=str(exc)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':utc(),'records':records,'error':error,'scope':['Two actual native ND IPsec Outers receive early nftables IPv4-options rejection on ingress/output and IP multicast rejection on Black ingress. Hook priority-450 precedes IPv4/IPv6 defragmentation at-400 in the documented implementation-family contract. Effective JSON rules, all route/filter/interface/XFRM state and worker/container bindings are retained.','Raw IPv4 option and multicast controls originate in each actual adjacent Outer Firewall namespace with the claimed remote peer IP. Each exact early rejection counter must increase by three; useful protected traffic must pass both directions. Before diagnostics and effective rule counters are retained without asserting successful application delivery.','PF10 is the selected IPv4 objective. PF9 applies to external multicast. IPv6 multicast policy is effective, but these IPv4 native deployments retain their actual IPv6-disabled external interfaces; no active IPv6 packet-counter test is claimed. No IKE or arbitrary Red protocol-only exception bypasses the header rules.','Root, Docker and namespace policy installation remain trusted laboratory controls. The helper leaves its selected hardening in place. Full IPv6/native coverage and future administrative changes remain separate.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'controls':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
