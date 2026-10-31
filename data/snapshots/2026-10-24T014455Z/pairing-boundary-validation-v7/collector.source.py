import hashlib,json
from pathlib import Path
from datetime import datetime,timezone
base=Path('artifacts/snapshots/2026-10-24T014455Z');run=Path('artifacts/construction/2026-10-24T014455Z');root=base/'pairings-v7';out=base/'pairing-boundary-validation-v7';out.mkdir();checks=[]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for d in sorted(root.iterdir()):
 if not d.is_dir():continue
 m=json.loads((d/'manifest.json').read_text())
 for row in m['files']:assert sha(d/row['path'])==row['sha256'],str(d/row['path'])
 for name,h in m['code_hashes'].items():
  target=d/('collector.source.py'if name=='pairing_execution_v7.py'else name);assert sha(target)==h
 o=json.loads((d/'evidence.json').read_text());assert o['error']is None and len(o['probes'])==6;assert all(p['expected_result']==p['observed_result']for p in o['probes'])
 bad=[];states={}
 for phase in ['pre-filter-bypass','stable-before','stable-after']:
  state=json.loads((d/(phase+'.json')).read_text());states[phase]={'devices':len(state),'state_command_refs':sum(len(v)for v in state.values())}
  for device,fields in state.items():
   for name,value in fields.items():
    if isinstance(value,dict)and value.get('returncode',0)!=0:bad.append([phase,device,name,value['returncode']])
   if phase!='pre-filter-bypass'and device not in ['HA','HB']:
    for family in ['filters4','filters6']:
     text=fields[family]['value'];assert all(':'+chain+' DROP'in text for chain in ['INPUT','OUTPUT','FORWARD']),(d,device,family)
 assert not bad,bad
 before=json.loads((d/'bypass-before.json').read_text());target=before['peer_gray'];counts={}
 for phase in [1,2,3]:
  count={}
  for f in d.glob('phase-'+str(phase)+'-headers-*.json'):
   h=json.loads(f.read_text());assert h['parse_or_capacity_errors']==0
   device=f.stem.split('-')[-1];frames=h['frames']
   count[device]={'frames':len(frames),'legitimate_source_to_peer_gray_cleartext_egress':sum(x['packet_type']==4 and x['headers'].get('ipv4',{}).get('source')=='10.1.0.2'and x['headers'].get('ipv4',{}).get('destination')==target for x in frames)}
  counts[str(phase)]=count
 if 'ipsec-ipsec'in d.name or 'ipsec-macsec'in d.name:
  assert counts['1']['IA']['legitimate_source_to_peer_gray_cleartext_egress']>0
  assert counts['1']['OA']['legitimate_source_to_peer_gray_cleartext_egress']>0
 assert counts['2']['IA']['legitimate_source_to_peer_gray_cleartext_egress']==0
 checks.append({'path':str(d),'manifest_sha256':sha(d/'manifest.json'),'controls':len(o['probes']),'collection_interval':[o['started_at'],o['ended_at']],'states':states,'header_counts':counts,'before_delivery_diagnostics':before['diagnostics']})
assert len(checks)==6
scope=['All six supplemental namespace pairings preserve pre-repair state and field-only bypass observations, then strict IPv4/IPv6 INPUT/OUTPUT/FORWARD default DROP with explicit source/destination/interface/policy permits. Useful bidirectional traffic, Inner-loss denial, restoration and two legitimate-source Gray-destination denials pass36 controls.','The two IPsec-Inner cases confirm actual cleartext HA-source peer-Gray packets on IA and OA egress before repair. Peer ping failure does not hide that emission counterexample. Phase2 contains repaired negative and useful traffic; the same cleartext target tuple is absent from IA egress.','MACsec uses actual controlled ports, exact Red-subnet forwarding and direction/source-bound MACsec-only bridge permits. Local L2TP1701 endpoints have explicit component/direction bindings. Static manual SAs need no IKE or EAPOL exception; arbitrary Red ICMP or UDP500 receives no protocol-only exception.','All complete before/after link, bridge, namespace, route/rule, filter, TC, encapsulation, MACsec and XFRM observations remain. The hardened field parser preserves public headers only. Manual SAs, supplemental static routing and bounded collection intervals do not establish native FRR/OVS, MKA authentication or physical separation.','Earlier pairings-v5 remains unchanged and supplies the published pre-repair deployment counterexample. The new helper source is the replayable repair for these six fixtures.']
(out/'validation.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'checks':checks,'scope':scope},indent=2)+'\n');(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':p.name,'sha256':sha(p)}for p in out.iterdir()if p.is_file()]},indent=2)+'\n')
response={'id':'C-PAIRING-FILTER-006','request_id':'C-PAIRING-FILTER-006','at':datetime.now(timezone.utc).isoformat(),'status':'ready-six-boundary-repairs-with-before-counterexamples','groups':['RG-007','RG-008','RG-015','RG-029','RG-030','RG-035'],'bundle_paths':[str(root),str(out)],'checks':checks,'scope':scope}
(run/'responses/C-PAIRING-FILTER-006.json').write_text(json.dumps(response,indent=2)+'\n');print(json.dumps({'response':str(run/'responses/C-PAIRING-FILTER-006.json'),'cases':len(checks),'controls':sum(x['controls']for x in checks)}))
