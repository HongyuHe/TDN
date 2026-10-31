from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
base=Path('artifacts/snapshots/2026-10-24T014455Z')
run=Path('artifacts/construction/2026-10-24T014455Z')
root=base/'utility-v4';out=base/'utility-fresh-replay-validation-v4';out.mkdir()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
checks=[]
for d in sorted(root.iterdir()):
    if not d.is_dir():continue
    manifest=json.loads((d/'manifest.json').read_text())
    for row in manifest['files']:assert sha(d/row['path'])==row['sha256']
    for name,value in manifest['code_hashes'].items():
        actual=d/name
        if not actual.is_file()and name=='matrix_lab.py':actual=d/'matrix_lab.py'
        assert actual.is_file()and sha(actual)==value,(name,value)
    obj=json.loads((d/'evidence.json').read_text())
    assert obj['error']is None
    assert all(p['expected_result']==p['observed_result']for p in obj['probes'])
    if d.name=='cds-log':
        events=[json.loads(line)for line in (d/'SIEM-service.log').read_text().splitlines()if line.startswith('{')]
        decisions=[json.loads(line)for line in (d/'CDS-service.log').read_text().splitlines()if line.startswith('{')]
        assert len(events)==1 and events[0]['event']['severity']=='warning'
        assert [r['accepted']for r in decisions]==[True,False]
    checks.append({'path':str(d),'manifest_sha256':sha(d/'manifest.json'),'controls':len(obj['probes']),'collection_interval':[obj['started_at'],obj['ended_at']],'case':json.loads((d/'case.json').read_text())})
assert len(checks)==8
scope=[
'Eight utility configurations completed in a fresh worker root with parameterized namespace prefix and case selector. All retained finite controls match. The CDS relay additionally delivers the single accepted warning event and rejects the malformed command-shaped record. These are isolated test events and no external message is sent.',
'Exact utility, matrix and routing dependency bytes are included in every leaf. The public command is sudo python3 RUN_ROOT/scripts/utility_variants_v4.py --root RUN_ROOT --namespace-prefix u4review- --case all. --case also selects each of the eight individual configurations. Existing output/private directories and used namespace prefixes are refused.',
'Stage utility_variants_v4.py plus v3/matrix_lab.py and v3/routing_variants.py into one scripts directory, flattening the two dependency names. The worker needs Linux namespaces/XFRM, iproute2, iptables, ebtables, OpenSSL and Python3. Root is required for owned namespaces and static test SAs. Private certificates/keys are generated below RUN_ROOT/private and excluded from all copied exports.',
'The runtime backend is supplemental Linux namespaces/static routes. Native FRR/OVS deployments remain preserved. Optional central management, VLAN management and software log relay remain separate from independent MSC data-path claims.',
'This closes the retained fresh-replay route for those eight configurations and nine representative rows. It does not establish other-CP compliance, approved CDS membership, alternate-egress approval, actual personnel, complete administrative controls or all packet executions. Old utility-v3 observations remain unchanged.'
]
(out/'validation.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'checks':checks,'scope':scope},indent=2)+'\n')
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':p.name,'sha256':sha(p)}for p in out.iterdir()if p.is_file()]},indent=2)+'\n')
response={'id':'UTILITY-FRESH-REPLAY-v4','status':'ready-eight-configurations-nine-case-rows','groups':['RG-051','RG-055','RG-056','RG-075'],'bundle_paths':[str(root),str(out)],'checks':checks,'scope':scope}
(run/'responses/UTILITY-FRESH-REPLAY-v4.json').write_text(json.dumps(response,indent=2)+'\n')
print(json.dumps({'response':str(run/'responses/UTILITY-FRESH-REPLAY-v4.json'),'controls':sum(r['controls']for r in checks)}))
