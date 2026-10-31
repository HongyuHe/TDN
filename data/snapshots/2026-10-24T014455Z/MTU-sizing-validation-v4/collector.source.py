import hashlib,json,re
from pathlib import Path
from datetime import datetime,timezone
base=Path('artifacts/snapshots/2026-10-24T014455Z')
run=Path('artifacts/construction/2026-10-24T014455Z')
out=base/'MTU-sizing-validation-v4';out.mkdir()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def verify(root):
    manifest=json.loads((root/'manifest.json').read_text())
    for row in manifest['files']:
        path=root/row['path'];assert sha(path)==row['sha256']
        if path.suffix in['.json','.py','.conf','.nft','.log']:
            assert not re.search(rb'-----BEGIN (?:EC |RSA |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]+-----END ',path.read_bytes())
    for name,value in manifest['code_hashes'].items():
        path=root/('collector.source.py'if name.startswith('mtu_sizing_')else name)
        assert sha(path)==value,(name,value)
    return manifest
checks=[]
selected=[base/'MTU-sizing-v3/layers-ipsec-ipsec-integrated',base/'MTU-sizing-v4/layers-macsec-ipsec-standalone']
for root in selected:
    verify(root)
    obj=json.loads((root/'evidence.json').read_text());assert obj['error']is None
    assert len(obj['probes'])==6 and all(p['expected_result']==p['observed_result']for p in obj['probes'])
    phases={}
    for phase in [1,2,3]:
        frames=[]
        for node in ['OA','OB']:
            capture=json.loads((root/('phase-'+str(phase)+'-headers-'+node+'.json')).read_text())
            assert capture['parse_or_capacity_errors']==0
            frames.extend(row for row in capture['frames']if row['interface']=='black'and row['packet_type']==4 and row['headers'].get('ipv4',{}).get('protocol')==50)
        phases[str(phase)]={'Outer_Black_IP_frames':len(frames),'IP_lengths':sorted({row['headers']['ipv4']['total_length']for row in frames}),'fragmented_frames':sum(bool(row['headers']['ipv4']['fragment_field']&0x3fff)for row in frames)}
    assert phases['2']['Outer_Black_IP_frames']>0 and phases['2']['fragmented_frames']==0
    assert max(phases['2']['IP_lengths'])<=1400
    checks.append({'path':str(root),'manifest_sha256':sha(root/'manifest.json'),'controls':6,'collection_interval':[obj['started_at'],obj['ended_at']],'header_phases':phases,'settings':json.loads((root/'sizing-scope.json').read_text())['settings']})
failed=base/'MTU-sizing-v3/layers-macsec-ipsec-standalone';verify(failed)
failure=json.loads((failed/'evidence.json').read_text())
assert [p['id']for p in failure['probes']if p['expected_result']!=p['observed_result']]==['sized-restoration']
scope=[
'Only already-present local outputs are validated and published. No remote command, packet experiment, cleanup or retry is executed by this publication helper.',
'MSC-SR-23 concerns configured IPv4 external Gray packet MTU or IPv6 PMTU with Outer path sizing considered. Optional MSC-IR-2 concerns external MACsec frame sizing or IPv6 PMTU. The selected IPv4 cases configure Red IP MTU1100, Inner Gray carrier MTU1200 and Outer Black MTU1400; the MACsec case also sets plaintext macsec0 MTU1100 and standalone encapsulator uplinks1200.',
'Both selected paths deliver1072-byte ICMP payloads in both directions. IPv4/ICMP adds28 bytes, reaching the configured1100-byte Red packet.1073-byte payloads are rejected at that configured size boundary. Actual Outer Black ESP headers show no fragmentation during the sized maximum-payload phase and lengths at most1400. Actual captured lengths are retained rather than inferred from a constant overhead alone.',
'The IPsec case passes six controls. The original MACsec v3 case passes maximum-size/useful/loss controls but fails restoration because taking macsec0 down removes its dependent route. The v4 helper explicitly restores that route and all six controls match. Original failed bytes/configuration and both before/after collections remain preserved.',
'Only ordinary assigned-address kernel pings were generated in these completed experiments. Field-only captures retain public packet headers, lengths and fragment metadata. No payload or ciphertext body is serialized. Manual static SAs, supplemental namespaces and fixed algorithm/frame settings remain explicit.',
'The observations support the selected configured-size geometry and finite boundary controls. Every accepted size, alternate padding/algorithm, other L2TP cookie, jumbo frame, arbitrary Ethernet format, future configuration and native backend require their own formal assumptions or evidence. The separate IPv6-PMTU-v4 bundle supplies the active IPv6 transition; this IPv4 sizing response does not replace it.'
]
(out/'validation.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'checks':checks,'preserved_failure':{'path':str(failed),'manifest_sha256':sha(failed/'manifest.json'),'mismatch':'sized-restoration'},'scope':scope},indent=2)+'\n')
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':p.name,'sha256':sha(p)}for p in out.iterdir()if p.is_file()]},indent=2)+'\n')
response={'id':'MTU-SIZING-v4','status':'ready-two-selected-IPv4-geometries-with-preserved-restoration-failure','groups':['RG-033'],'bundle_paths':[str(base/'MTU-sizing-v3'),str(base/'MTU-sizing-v4'),str(out)],'checks':checks,'scope':scope}
(run/'responses/MTU-SIZING-v4.json').write_text(json.dumps(response,indent=2)+'\n')
print(json.dumps({'response':str(run/'responses/MTU-SIZING-v4.json'),'checks':checks}))
