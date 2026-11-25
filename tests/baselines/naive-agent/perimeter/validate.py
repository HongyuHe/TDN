"""Validate the additional firewall applications against the retained paired evidence."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time

from run import HERE, ROOT, SOURCE, digest, write


def audit(target):
    source=target/'TrustAudit.lean'
    source.write_text((target/'FirewallCompliance.lean').read_text()+
        '\n#print axioms TDN.Experiments.FirewallSnapshot.snapshot_outer_firewall_local_service_admission\n')
    p=subprocess.run([str(Path.home()/'.elan/bin/lake'),'env','lean','--json',str(source)],
        cwd=ROOT,capture_output=True,text=True,timeout=180)
    (target/'trust-audit.jsonl').write_text(p.stdout)
    assert p.returncode==0, p.stdout[-2000:]
    messages=[json.loads(s) for s in p.stdout.splitlines() if s.startswith('{')]
    declaration=[m['data'] for m in messages if 'depends on axioms:' in m.get('data','')]
    assert len(declaration)==1, declaration
    values=re.search(r'depends on axioms:\s*\[([^]]*)\]',declaration[0],re.S)[1]
    axioms=[v.strip() for v in values.split(',') if v.strip()]
    allowed={'propext','Classical.choice','Quot.sound','Lean.ofReduceBool'}
    assert all(a in allowed or '._native.native_decide.ax_' in a for a in axioms),axioms
    return {'case':target.name,'returncode':p.returncode,'axioms':axioms,
            'compiler_trusted':True,'sourceSHA256':digest(source),'logSHA256':digest(target/'trust-audit.jsonl')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run',type=Path)
    args=parser.parse_args()
    root=args.run
    recorded=json.loads((root/'sources.json').read_text())
    for path,expected in recorded['files'].items():
        assert digest(ROOT/path)==expected, path
    results=json.loads((root/'results.json').read_text())
    assert len(results)==10
    rows=[]
    for n in range(1,6):
        network=f'net-{n:02}'
        clean=json.loads((root/(network+'-clean')/'result.json').read_text())
        fault=json.loads((root/(network+'-MSC-PF-22')/'result.json').read_text())
        assert clean['status']=='accepted' and clean['returncode']==0 and not clean['errors']
        assert not clean['rejected_rules']
        assert fault['status']=='rejected' and len(fault['errors'])==1
        assert len(fault['rejected_rules'])==2
        assert all('is false' in e['data'] for e in fault['errors'])
        for result in [clean,fault]:
            folder=root/result['case']
            assert result['inputSHA256']==digest(folder/'input.json')
            assert result['sourceSHA256']==digest(folder/'FirewallCompliance.lean')==digest(HERE/'FirewallCompliance.lean')
            source=SOURCE/('controls/'+network if result==clean else 'cases/'+network+'-MSC-PF-22')
            provenance=json.loads((folder/'provenance.json').read_text())
            assert provenance['snapshotSHA256']==digest(source/'snapshot/native/snapshot.json')
            manifest=json.loads((source/'snapshot/native/manifest.json').read_text())
            assert manifest['convergence']['consistent'] and not manifest['collection_failures']
            if result==fault:
                original=json.loads((source/'lean/result.json').read_text())
                assert original['status']=='accepted_by_Lean'
                live=json.loads((source/'public/oracle/single-fault'/(network+'.json')).read_text())
                assert len(live['records'])==1 and live['records'][0]['violated']
        old=json.loads((root/clean['case']/'input.json').read_text())
        new=json.loads((root/fault['case']/'input.json').read_text())
        assert old['controls']==new['controls'] and old['firewalls']==new['firewalls']
        assert old['coverage']==new['coverage']
        assert {json.dumps(r,sort_keys=True) for r in fault['full_rejected_rules']} - {json.dumps(r,sort_keys=True) for r in clean['full_rejected_rules']} == {json.dumps(r,sort_keys=True) for r in fault['rejected_rules']}
        findings=[]
        for iface,(direction,(hook,rule)) in fault['rejected_rules']:
            assert iface.endswith(':outside') and hook in ['input','output']
            assert {'protocol':{'name':'tcp'}} in rule['atoms']
            findings.append({'interface':iface,'direction':direction,'hook':hook,'rule':rule})
        assert {r['hook'] for r in findings}=={'input','output'}
        rows.append({'network':network,'clean':'accepted','fault':'rejected',
            'clean_seconds':clean['seconds'],'fault_seconds':fault['seconds'],
            'checked_black_ifaces':old['coverage']['checkedBlackIfaces'],
            'http_findings':findings,'additional_forward_guard_failures':len(clean['full_rejected_rules'])})
    with ThreadPoolExecutor(max_workers=2) as pool:
        audits=list(pool.map(audit,[root/(f'net-{n:02}-clean') for n in range(1,6)]))
    baseline=json.loads((SOURCE/'scoring.json').read_text())['summary']
    summary={'at':datetime.now(timezone.utc).isoformat(),'status':'passed','clean_controls':5,
        'rejected_faulty_snapshots':5,'additional_distinct_faults':5,
        'original_detected':baseline['detected'],'combined_confirmed_detections':baseline['detected']+5,
        'supported_combined_confirmed_detections':baseline['supported_detected']+5,
        'formal_applications':10,'native_toolchain_trusted':True,
        'seconds_sum':sum(r['seconds'] for r in results),'rows':rows,'trust_audits':audits,
        'scope':'Existing Outer Firewall theorem applied to native INPUT and OUTPUT acceptance on Black data interfaces. A general checked lemma transfers acceptance from the full imported deployment. FORWARD-rule diagnostics are retained separately.',
        'immutable_original_run':str(SOURCE.relative_to(ROOT)),
        'all_95_other_cases':'Their original proof results are retained; the new firewall application was run on five PF-22 cases and five clean controls.'}
    write(root/'validation.json',summary)
    print(json.dumps({k:summary[k] for k in ['status','clean_controls','rejected_faulty_snapshots','combined_confirmed_detections']}))


if __name__=='__main__':
    main()
