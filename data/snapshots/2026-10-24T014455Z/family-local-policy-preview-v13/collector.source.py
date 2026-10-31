from pathlib import Path
import hashlib,json
from datetime import datetime,timezone

base=Path('artifacts/snapshots/2026-10-24T014455Z')
run=Path('artifacts/construction/2026-10-24T014455Z')
root=base/'families-v13/families-444'
out=base/'family-local-policy-preview-v13'
out.mkdir()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
manifest=json.loads((root/'manifest.json').read_text())
for row in manifest['files']:assert sha(root/row['path'])==row['sha256']
evidence=json.loads((root/'evidence.json').read_text())
assert evidence['error']is None
assert all(p['expected_result']==p['observed_result']for p in evidence['probes'])
checks={}
for phase in ['before-local-policy','after-local-policy','reduced-MTU','stable-before','temporary-black-icmp-denial','stable-after']:
    state=json.loads((root/(phase+'.json')).read_text())
    checks[phase]={'devices':len(state),'fields':sum(len(fields)for fields in state.values())}
    for node in ['IA','IB','OA','OB']:
        for family in ['filters4','filters6']:
            text=state[node][family]['value']
            if phase!='before-local-policy':assert all(':'+chain+' DROP'in text for chain in ['INPUT','OUTPUT','FORWARD'])
    if phase in ['stable-before','stable-after']:
        for node in ['IA','IB','OA','OB']:
            rules=json.loads(state[node]['nft']['value'])
            assert any(v.get('chain',{}).get('table')=='EVA_SOURCE_V13'and v['chain'].get('prio')==-460 for v in rules['nftables'])
scope=[
'Family444 is ready for early defensive-policy/model review. Seven remaining combinations are still collecting and are not claimed available by this preview.',
'The copied-payload weak-host response is an untested hypothesis. The automated cybersecurity risk check stopped the earlier turn; no operation-specific rejection was visible. No crafted/forged response experiment or loader-injection probe was retried. New collectors contain only ordinary assigned-address connectivity and owned policy changes.',
'Both-family INPUT/OUTPUT/FORWARD default DROP; exact SA-peer and interface-bound local ESP; exact adjacent endpoint/interface ICMP types; scoped hop-limit255 neighbor discovery. Source validation in prerouting at-460 precedes the existing immediate-IPv6-header gate at-450 and documented defragmentation priority-400. Inbound decapsulated peer source ranges additionally require incoming XFRM reqid100/200.',
'The temporary Black-ICMP denial has its own full state phase. The DROP is removed before ordinary adjacent restoration and the final stable-after capture. Outer Black MTU is1400 only in the explicitly reduced-MTU phase and returns to1500 before the ordinary baseline captures. Learned route PMTU metrics remain observable.',
'All26 finite controls match. Ordinary1350-byte data encounters received IPv4 fragmentation-needed errors from its actual adjacent Inner at MTU1290;1100-byte data delivers both directions. The original ping output and route lookups are retained. No packet-body quote parser or universal quoted-body provenance claim is supplied.',
'An error quote containing an already protected ESP body retains the protection of those copied bytes. A plaintext echo or quote must retain its Red origin and required protection in the execution model. Exact adjacent error permits alone do not establish that body-level fact. Complete local and early-hook state supports Construction review of that distinction.',
'Actual contemporaneous worker/kernel/boot/hardware UUID and namespace identities are included. The backend is supplemental Linux namespaces/static SAs, not native FRR/OVS or IKE authentication. Original families-v9 and the v10 test-rule ordering failure remain preserved.'
]
(out/'validation.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'manifest_sha256':sha(root/'manifest.json'),'controls':len(evidence['probes']),'phases':checks,'scope':scope},indent=2)+'\n')
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':p.name,'sha256':sha(p)}for p in out.iterdir()if p.is_file()]},indent=2)+'\n')
response={'id':'C-GENERATED-RESPONSE-008-v13-preview','request_id':'C-GENERATED-RESPONSE-008','status':'ready-one-family-defensive-policy-seven-pending','groups':['RG-007','RG-008','RG-029','RG-030','RG-035','RG-038'],'bundle_paths':[str(root),str(base/'families-v10/families-444'),str(out)],'scope':scope}
(run/'responses/C-GENERATED-RESPONSE-008-v13-preview.json').write_text(json.dumps(response,indent=2)+'\n')
print(json.dumps({'response':str(run/'responses/C-GENERATED-RESPONSE-008-v13-preview.json'),'controls':len(evidence['probes'])}))
