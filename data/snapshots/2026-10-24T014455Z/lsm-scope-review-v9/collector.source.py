import hashlib,json
from pathlib import Path
from datetime import datetime,timezone

base=Path('artifacts/snapshots/2026-10-24T014455Z')
run=Path('artifacts/construction/2026-10-24T014455Z')
out=base/'lsm-scope-review-v9'
out.mkdir()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
checks=[]
for name in ['lsm-gateway-v7','lsm-gateway-v8','lsm-mount-flags-v9']:
    root=base/name
    manifest=json.loads((root/'manifest.json').read_text())
    for row in manifest['files']:
        assert sha(root/row['path'])==row['sha256']
    source=root/'collector.source.py'
    if not source.exists():
        source=Path('scripts/construction/evidence/lsm_gateway_v7.py')
        assert sha(source)==manifest['collector_sha256']
        (out/'lsm_gateway_v7.exact-source.py').write_bytes(source.read_bytes())
    assert sha(source)==manifest['collector_sha256']
    obj=json.loads((root/'observations.json').read_text())
    probes=[{k:r.get(k)for k in ['probe','expected_result','observed_result']}for r in obj['records']if'probe'in r]
    clean=[{'command':r['command'],'returncode':r['returncode']}for r in obj['records']if r.get('command',[])[:3]==['docker','rm','-f']]
    assert clean and all(r['returncode']==0 for r in clean)
    checks.append({'bundle_path':str(root),'manifest_sha256':sha(root/'manifest.json'),'error':obj['error'],'probes':probes,'cleanup':clean})
scope=[
'Historical artifacts are preserved and summarized without rerunning their experiments. The automated cybersecurity risk check stopped the previous turn; no operation-specific rejection was visible. The coordinator subsequently prohibited retrying crafted/forged response packets and loader-injection probes or equivalent methods.',
'The v7 attempt ended when docker cp rejected a read-only container filesystem. Six direct immutable-executable, profile-transition and non-gateway key-open checks matched. Its collector bytes are attached now only after matching the original manifest hash; that attachment is a later source-recovery supplement.',
'The v8 before-policy loader hypothesis was not demonstrated on either peer. Both attempts failed to map the shared object. They are two mismatches against an exploratory expected counterexample, not confirmed vulnerabilities. No private key contents were read or exported.',
'The v8 hardened profile used environment-scrubbing Px transitions and constrained executable mappings. Both gateway status checks, both useful IKEv2/IPsec directions, SA-loss denial and six original boundary controls matched. Those observations do not demonstrate that the profile change caused the earlier mapping failures.',
'The v9 mount supplement used a separate fresh fixture and found read-only root with noexec tmpfs at /run,/tmp,/dev/shm. The supplement is not a contemporaneous readback of the removed v8 containers.',
'All owned disposable containers have successful recorded docker rm cleanup. Full historical policies, public test configurations and source hashes remain. These supplemental AppArmor observations do not establish native ND or FreeBSD mandatory confinement, universal interface access controls, host-root isolation, hardware tamper resistance or approved-product status.',
'The historical helpers containing prohibited probe steps are not a current replay entry point. Future allowed work is read-only effective policy collection, defensive policy review and ordinary assigned-address interoperability. No blocked action is retried.'
]
(out/'review.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'checks':checks,'scope':scope},indent=2)+'\n')
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':p.name,'sha256':sha(p)}for p in out.iterdir()if p.is_file()]},indent=2)+'\n')
response={'id':'LSM-SCOPE-REVIEW-v9','status':'ready-historical-partial-and-unconfirmed-results','groups':['RG-009','RG-011','RG-041'],'bundle_paths':[c['bundle_path']for c in checks]+[str(out)],'checks':checks,'scope':scope}
(run/'responses/LSM-SCOPE-REVIEW-v9.json').write_text(json.dumps(response,indent=2)+'\n')
print(json.dumps({'response':str(run/'responses/LSM-SCOPE-REVIEW-v9.json'),'bundles':len(checks)+1}))
