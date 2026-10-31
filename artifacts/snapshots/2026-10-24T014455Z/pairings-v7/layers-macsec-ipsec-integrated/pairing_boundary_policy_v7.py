import hashlib,json,time
from pathlib import Path

def install(lab,inner,outer,standalone):
 lab.code_hashes['pairing_boundary_policy_v7.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();(lab.root/'pairing_boundary_policy_v7.py').write_bytes(Path(__file__).read_bytes());peer_gray='10.21.0.1'if inner=='ipsec'else'10.60.0.2';local_gray='10.11.0.1'if inner=='ipsec'else'10.60.0.1';diagnostics=[]
 for target in [peer_gray,local_gray]:lab.route('HA',target+'/32','10.1.0.1')
 lab.start_headers()
 for target,label in [(peer_gray,'peer-Inner-Gray'),(local_gray,'local-Inner-Gray')]:
  r=lab.run(['ping','-n','-c','2','-W','1','-s','64',target],'HA',False);diagnostics.append({'label':label,'source':'10.1.0.2','destination':target,'observation_id':lab.commands[-1]['id'],'returncode':r.returncode,'scope':'Diagnostic delivery result. Actual egress/header observations determine whether protection was bypassed.'})
 udp="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.1.0.2',500));s.sendto(b'owned-Red-UDP500-boundary-probe',('"+peer_gray+"',500));print('sent legitimate Red source UDP500 to peer Inner Gray')"
 lab.run(['python3','-c',udp],'HA');time.sleep(.2);lab.state('pre-filter-bypass');(lab.root/'bypass-before.json').write_text(json.dumps({'diagnostics':diagnostics,'peer_gray':peer_gray,'local_gray':local_gray,'udp_observation_id':next(r['id']for r in reversed(lab.commands)if r.get('device_id')=='HA'and r['command'][-1:]==[udp])},indent=2)+'\n')
 names=[n['id']for n in lab.nodes if n['id']not in ['HA','HB']]
 for node in names:
  for ipt in ['iptables','ip6tables']:
   for chain in ['INPUT','OUTPUT','FORWARD']:lab.run([ipt,'-P',chain,'DROP'],node)
   for chain in ['INPUT','OUTPUT']:lab.run([ipt,'-A',chain,'-i'if chain=='INPUT'else'-o','lo','-j','ACCEPT'],node)
 for node,local_red,peer_red,local_ip,peer_ip in [('IA','10.1.0.0/24','10.2.0.0/24','10.11.0.1','10.21.0.1'),('IB','10.2.0.0/24','10.1.0.0/24','10.21.0.1','10.11.0.1')]:
  port='gray'if inner=='ipsec'else'macsec0'
  for i,o,s,d,direction in [('red',port,local_red,peer_red,'out'),(port,'red',peer_red,local_red,'in')]:
   cmd=['iptables','-A','FORWARD','-i',i,'-o',o,'-s',s,'-d',d]
   if inner=='ipsec':cmd+=['-m','policy','--dir',direction,'--pol','ipsec','--reqid','100']
   lab.run(cmd+['-j','ACCEPT'],node)
  if inner=='ipsec':
   for chain,s,d in [('INPUT',peer_ip,local_ip),('OUTPUT',local_ip,peer_ip)]:lab.run(['iptables','-A',chain,'-i'if chain=='INPUT'else'-o','gray','-s',s,'-d',d,'-p','esp','-j','ACCEPT'],node)
 outer_port='black'if outer=='ipsec'else'macsec0'
 if inner=='macsec':
  ends=['EA','EB']if standalone else['OA','OB'];encips=['10.11.0.1','10.21.0.1']if standalone else(['10.90.0.1','10.90.0.2']if outer=='macsec'else['10.11.0.2','10.21.0.2'])
  physical={n:json.loads(lab.run(['ip','-j','link','show','gray'],n).stdout)[0]['address']for n in ['IA','IB']}
  for endpoint,index in zip(ends,[0,1]):
   lab.run(['ebtables','-P','FORWARD','DROP'],endpoint)
   for i,o,source in [('innerframes','l2tpeth0',physical[['IA','IB'][index]]),('l2tpeth0','innerframes',physical[['IB','IA'][index]])]:lab.run(['ebtables','-A','FORWARD','-i',i,'-o',o,'-p','0x88e5','-s',source,'-j','ACCEPT'],endpoint)
   port='uplink'if standalone else outer_port
   for chain,source,destination in [('INPUT',encips[1-index],encips[index]),('OUTPUT',encips[index],encips[1-index])]:
    cmd=['iptables','-A',chain,'-i'if chain=='INPUT'else'-o',port,'-s',source,'-d',destination,'-p','udp','--sport','1701','--dport','1701']
    if not standalone and outer=='ipsec':cmd+=['-m','policy','--dir','in'if chain=='INPUT'else'out','--pol','ipsec','--reqid','200']
    lab.run(cmd+['-j','ACCEPT'],endpoint)
 for node,index in [('OA',0),('OB',1)]:
  if inner=='ipsec' or standalone:
   ips=['10.11.0.1','10.21.0.1'];protocol='esp'if inner=='ipsec'else'udp'
   for i,o,s,d,direction in [('gray',outer_port,ips[index],ips[1-index],'out'),(outer_port,'gray',ips[1-index],ips[index],'in')]:
    cmd=['iptables','-A','FORWARD','-i',i,'-o',o,'-s',s,'-d',d,'-p',protocol]
    if protocol=='udp':cmd+=['--sport','1701','--dport','1701']
    if outer=='ipsec':cmd+=['-m','policy','--dir',direction,'--pol','ipsec','--reqid','200']
    lab.run(cmd+['-j','ACCEPT'],node)
  if outer=='ipsec':
   ips=['192.0.2.1','192.0.3.1']
   for chain,s,d in [('INPUT',ips[1-index],ips[index]),('OUTPUT',ips[index],ips[1-index])]:lab.run(['iptables','-A',chain,'-i'if chain=='INPUT'else'-o','black','-s',s,'-d',d,'-p','esp','-j','ACCEPT'],node)
 if outer=='macsec':
  lab.run(['ebtables','-F','FORWARD'],'BF');lab.run(['ebtables','-P','FORWARD','DROP'],'BF')
  for chain in ['INPUT','OUTPUT']:lab.run(['ebtables','-P',chain,'DROP'],'BF')
  for source,i,o in [('OA','p1','p2'),('OB','p2','p1')]:
   mac=json.loads(lab.run(['ip','-j','link','show','black'],source).stdout)[0]['address'];lab.run(['ebtables','-A','FORWARD','-i',i,'-o',o,'-p','0x88e5','-s',mac,'-j','ACCEPT'],'BF')
 lab.ping('HA',peer_gray,'no_reply','legitimate-Red-to-peer-Gray-rejected');lab.ping('HA',local_gray,'no_reply','legitimate-Red-to-local-Gray-rejected');lab.run(['python3','-c',udp],'HA')
 (lab.root/'boundary-policy-scope.json').write_text(json.dumps({'runtime_backend':'supplemental Linux namespaces/static manual SAs','defaults':'Every nonhost namespace has INPUT/OUTPUT/FORWARD DROP for IPv4 and IPv6. Existing explicit Black ESP forwarding permits remain.','Inner_IPsec':'Interface and Red-subnet source/destination bounds plus matching reqid100 policy. Local ESP only on Gray with exact peer addresses. No Red ICMP/UDP500 exception.','Inner_MACsec':'Forwarded Red subnet pairs cross macsec0 only. Actual controlled-port encryption settings remain independently checked. Bridge forwarding allows only MACsec EtherType from the known Inner MAC in the required direction.','Outer_IPsec':'Forwarded exact Inner-ESP or encapsulator UDP1701 endpoints require reqid200 policy. Integrated L2TP is a local UDP endpoint and requires its matching incoming/outgoing Outer policy. Outer ESP is bound to its Black peer addresses/direction.','Outer_MACsec':'Actual macsec0 is the sole protected forwarding port. The bridge Black boundary allows only known-source MACsec frames in the exact port direction.','Control_scope':'Static manual SA fixtures need no IKE/EAPOL control exception. L2TP UDP1701 is bound to its actual component endpoints and interface directions. ARP neighbor exchange inside MACsec remains encrypted. No arbitrary Red packet is exempt by protocol alone.'},indent=2)+'\n')
