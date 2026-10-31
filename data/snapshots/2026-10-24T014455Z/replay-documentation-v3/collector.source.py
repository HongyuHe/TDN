import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
run=Path('artifacts/construction/2026-10-24T014455Z');base=Path('artifacts/snapshots/2026-10-24T014455Z');old=base/'replay-documentation-v3';new=base/'replay-documentation-v4';old.mkdir();new.mkdir()
current=Path('scripts/construction/evidence')
old_paragraph='Stage eap_tls_v17.py and eap_delay_lab_v17.py together, with the recorded repaired build under RUN_ROOT/hostap-pq-delay. The container uses host privileges to create only the named supplemental fixtures. Its actual image ID, OpenSSL version and namespace identities must remain in the collection. Forward v17 rejects the three-second delayed data. Reverse v17 still accepts it. Both carry ordinary and 100 ms traffic. The reverse delay behavior remains an actionable implementation gap. No complete EAP delay-compliance claim follows.'
new_paragraph='Stage v3/eap_tls_v18.py and v3/eap_delay_lab_v18.py together as RUN_ROOT/scripts/eap_tls_v18.py and eap_delay_lab_v18.py. The final binaries are under RUN_ROOT/hostap-pq-delay-auth. First preserve and build the full official-source patches and configs in hostap-pq-delay-build-v4, then apply hostap_auth_lowest_pn_v5.py. The final helper clones the prior source, wires the missing authenticator receive-PN setter and rebuilds hostapd inside the recorded image. Both final binary paths and hashes appear in the v18 collection. The container uses host privileges to create only the named supplemental fixtures. Both arrangements and both traffic directions reject three-second delayed data, accept the 100 ms control and restore useful traffic. All 16 controls pass. The v17 reverse failure remains preserved. Complete IEEE normative conformance and nonzero replay-window or replacement-SA behavior remain separate.'
expected=json.loads((run/'responses/RUNTIME-IMAGES-AND-REPLAY-DOCS-v3.json').read_text())['documentation_sha256']
for path in ['README.md','REPLAY.md','profiles/README.md']:
    source=current/path;t=source.read_text();previous=t
    if path=='README.md':previous=t.replace('Objective EAP with repaired delay behavior | v3/eap_tls_v18.py and v3/eap_delay_lab_v18.py; OpenSSL 3.5.5 container and final authenticator callback required; all 16 checks pass','Objective EAP and current delay attempt | v3/eap_tls_v17.py and v3/eap_delay_lab_v17.py; correct OpenSSL container runtime required; reverse delay gap remains')
    if path=='REPLAY.md':
        assert new_paragraph in t
        previous=t.replace(new_paragraph,old_paragraph).replace('--name tcv3-eap-delay-v18','--name tcv3-eap-delay-v17').replace('scripts/eap_tls_v18.py','scripts/eap_tls_v17.py')
    previous_bytes=previous.encode();assert hashlib.sha256(previous_bytes).hexdigest()==expected[str(source)],path
    for root,data in [(old,previous_bytes),(new,source.read_bytes())]:
        target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
for root in [old,new]:
    (root/'collector.source.py').write_bytes(Path(__file__).read_bytes())
    (root/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'version_scope':'v3 exact bytes recovered by reversing the explicit EAP-only revision and verified against the already published v3 SHA-256; v4 captures the current EAP v18 revision.','files':[{'path':str(f.relative_to(root)),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in root.rglob('*')if f.is_file()]},indent=2)+'\n')
paths=[old,new];response={'at':datetime.now(timezone.utc).isoformat(),'status':'public-documentation-revision-delivered','groups':[],'bundle_paths':[str(p)for p in paths],'checks':[{'path':str(p),'manifest_sha256':hashlib.sha256((p/'manifest.json').read_bytes()).hexdigest()}for p in paths],'scope':['The v3 exact documentation bytes match all three previously published hashes. The v4 immutable capture updates objective EAP to the tested v18 callback repair. Mutable README paths may evolve; those captures retain each published revision.','Native replay v6 passed ten selected jobs and preserves FRR/OVS. Persistent guest startup, Linux Outer correction, supplemental protocols and four-worker construction retain their stated independent scope and unfinished combined replay work.'],'supersedes_current_documentation_only':str(run/'responses/RUNTIME-IMAGES-AND-REPLAY-DOCS-v3.json')}
p=run/'responses/REPLAY-DOCUMENTATION-v4.json';p.write_text(json.dumps(response,indent=2)+'\n')
with(run/'requests_responses.jsonl').open('a')as f:f.write(json.dumps({'at':response['at'],'actor':'evidence','event':'response','path':str(p)})+'\n')
print(json.dumps({'response':str(p),'prior_hashes_match':True}))
