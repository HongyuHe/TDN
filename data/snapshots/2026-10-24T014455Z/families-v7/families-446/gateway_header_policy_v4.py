import hashlib,json,time
from pathlib import Path
def install(lab,nodes):
 for node in nodes:
  lab.run(['ip6tables','--version'],node)
  lab.run(['ip6tables','-t','raw','-N','EVA6_IMMEDIATE'],node)
  for protocol in [6,17,50,58]:
   lab.run(['ip6tables','-t','raw','-A','EVA6_IMMEDIATE','-m','u32','--u32','4>>8&0xFF='+str(protocol),'-j','RETURN'],node)
  lab.run(['ip6tables','-t','raw','-A','EVA6_IMMEDIATE','-j','DROP'],node)
  for hook in ['PREROUTING','OUTPUT']:
   lab.run(['ip6tables','-t','raw','-I',hook,'1','-j','EVA6_IMMEDIATE'],node)
  lab.run(['ip6tables-save','-c'],node)
 time.sleep(2)
 for node in nodes:
  for link in lab.links:
   endpoints=link['endpoints'];addresses=link['addresses']
   found=False
   for i,endpoint in enumerate(endpoints):
    if endpoint.split(':')[0]!=node or not addresses[i] or ':' not in addresses[i]:continue
    peer=endpoints[1-i].split(':')[0]
    if not addresses[1-i] or ':' not in addresses[1-i]:continue
    lab.ping(peer,addresses[i].split('/')[0],'delivered','permitted-ICMPv6-adjacent-'+node)
    found=True
    break
   if found:break
 lab.code_hashes['gateway_header_policy_v4.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
 (lab.root/'gateway_header_policy_v4.py').write_bytes(Path(__file__).read_bytes())
 (lab.root/'header-policy.json').write_text(json.dumps({'source_clauses':['MSC-PF-12'],'devices':nodes,'hooks':['raw/PREROUTING','raw/OUTPUT'],'field':'Immediate IPv6 Next Header at byte 6 of IPv6 header','allowed_values':[6,17,50,58],'scope':'Every VPN gateway in the supplemental family fixture, including gateways with no configured global IPv6 address. The profile supports allowed TCP, UDP, ESP and ICMPv6 immediate values. No arbitrary upper-layer match is substituted. Source multicast and IPv4 options clauses are separate controls.'},indent=2)+'\n')
