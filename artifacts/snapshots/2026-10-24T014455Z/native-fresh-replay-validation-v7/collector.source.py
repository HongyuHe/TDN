import hashlib,json
from pathlib import Path
from datetime import datetime,timezone
run=Path('artifacts/construction/2026-10-24T014455Z');base=Path('artifacts/snapshots/2026-10-24T014455Z');controller=base/'native-fresh-replay-v7';worker=base/'native-fresh-replay-v7-worker';out=base/'native-fresh-replay-validation-v7';out.mkdir()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
checks=[]
for manifest in [controller/'manifest.json',*sorted(worker.glob('*/manifest.json'))]:
 m=json.loads(manifest.read_text());files=m['files']
 for row in files:
  target=manifest.parent/row['path'];assert target.is_file()and sha(target)==row['sha256'],str(target)
 o=json.loads((manifest.parent/'observations.json').read_text());assert not o.get('error'),str(manifest)
 probes=[r for r in o.get('records',[])if'expected_result'in r];assert all(r.get('expected_result')==r.get('observed_result')for r in probes)
 assert all(r.get('status')not in ['failed','not-ready']for r in o.get('records',[]))
 checks.append({'path':str(manifest.parent),'manifest_sha256':sha(manifest),'records':len(o.get('records',[])),'controls':len(probes),'error':o.get('error')})
c=json.loads((controller/'observations.json').read_text());assert c['execute']and len(c['jobs'])==13
for row in c['sources']:
 assert sha(Path(row['staged_path']))==row['staged_sha256']
for source in ['replay_v7.py','profiles/replay-native-freebsd-v7.json']:
 dest=out/Path(source).name;dest.write_bytes((Path('scripts/construction/evidence')/source).read_bytes())
(out/'validation.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'checks':checks,'completed_jobs':13,'controller_source_sha256':sha(out/'replay_v7.py'),'source_binding':'All exact transformed staged sources match the controller source records. Worker source hashes refer to those transformed bytes. Each worker bundle file matches its retained manifest.','scope':['Fresh isolated NQ deployment on pc22 with FRR/OVS and actual FreeBSD/Botan Inners. Linux Outers use native Docker components. Existing NC/ND/MW deployments remain separate.','The13 selected jobs include bootstrap, build, native integration, DNS IPv4/IPv6, CBC, certificate events, scheduled reauthentication, independent Red clocks, abrupt power/startup/audit persistence and PF interface flags. Separate supplemental or Linux Outer VM experiments are not silently included.','Guest SSH/charon start automatically after the power events. Explicit IKE resets and CHILD initiation in the power driver are preserved. No automatic SA recovery or full76-group compliance follows.']},indent=2)+'\n')
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':str(p.relative_to(out)),'sha256':sha(p)}for p in sorted(out.rglob('*'))if p.is_file()]},indent=2)+'\n')
response={'id':'NATIVE-FRESH-REPLAY-v7','at':datetime.now(timezone.utc).isoformat(),'status':'ready-thirteen-jobs-complete','bundle_paths':[str(controller),str(worker),str(out)],'checks':checks,'scope':json.loads((out/'validation.json').read_text())['scope']}
(run/'responses/NATIVE-FRESH-REPLAY-v7.json').write_text(json.dumps(response,indent=2)+'\n');print(json.dumps({'response':str(run/'responses/NATIVE-FRESH-REPLAY-v7.json'),'manifests':len(checks),'controls':sum(x['controls']for x in checks)}))
