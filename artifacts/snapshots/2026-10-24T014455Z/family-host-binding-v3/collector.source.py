import argparse,hashlib,json,subprocess
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/family-host-binding-v3';out.mkdir();records=[]
def run(cmd):
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=20);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':cmd,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});return r
for cmd in [['hostname','-f'],['date','-u','--iso-8601=ns'],['uname','-a'],['uname','-r'],['uname','-v'],['cat','/proc/version'],['cat','/proc/sys/kernel/random/boot_id'],['cat','/sys/class/dmi/id/product_uuid'],['cat','/proc/uptime'],['grep','^btime','/proc/stat'],['readlink','/proc/self/ns/net'],['ip6tables','--version'],['nft','--version'],['modinfo','nf_defrag_ipv6'],['modinfo','nf_conntrack'],['modinfo','nf_tables']]:run(cmd)
leaves=[]
for name in ['444','446','464','466','644','646','664','666']:
    path=root/'exports/families-v9'/('families-'+name);m=json.loads((path/'manifest.json').read_text());sources=[]
    for f in m['files']:
        data=(path/f['path']).read_bytes();assert hashlib.sha256(data).hexdigest()==f['sha256']
        if f['path']in['collector.source.py','gateway_header_policy_v4.py','gateway_header_policy_v5.py','family_forward_policy_v3.py','early-header-policy.json']:sources.append({'path':f['path'],'sha256':f['sha256']})
    leaves.append({'path':str(path),'manifest_sha256':hashlib.sha256((path/'manifest.json').read_bytes()).hexdigest(),'started_at':m['started_at'],'ended_at':m['ended_at'],'collector_sha256':m['code_sha256'],'source_bindings':sources,'stat_uid':path.stat().st_uid,'filesystem_mtime_ns':path.stat().st_mtime_ns})
contemporaneous=[]
for name in ['data-fragments-v4','data-fragments-v5']:
    path=root/'exports'/name
    for r in json.loads((path/'commands.json').read_text()):
        if r.get('command')in[['uname','-a'],['cat','/proc/version']]:contemporaneous.append({'bundle':name,'commands_sha256':hashlib.sha256((path/'commands.json').read_bytes()).hexdigest(),'manifest_sha256':hashlib.sha256((path/'manifest.json').read_bytes()).hexdigest(),'record':r})
o={'at':datetime.now(timezone.utc).isoformat(),'runtime_backend':'Supplemental Linux network namespaces and static XFRM on the clnode176 worker','controller_execution_binding':{'declared_by':'Evidence Agent, from its executed SSH collection command','host_argument':'hy@clnode176.clemson.cloudlab.us','executed_command':['sudo','python3',str(root/'scripts/family_execution_v9.py'),'--output',str(root/'exports/families-v9'),'--families','all'],'scope':'The controller host argument identifies the worker used for all eight sequential collections. The contemporaneous leaf collection intervals and source hashes are immutable; later supplementary records are labelled separately.'},'family_leaves':leaves,'contemporaneous_kernel_observations':contemporaneous,'fresh_supplementary_worker_observations':records,'limitations':['The family v9 leaves did not directly collect a boot ID or uname. Their immutable hashes are retained and the gap is not rewritten away.','Fresh boot ID, hardware UUID, uptime and kernel/build observations are supplementary. They are distinguished from the actual same-run kernel records in the fragment collections. Uptime/btime can support continuity under ordinary trusted-host and clock assumptions, not independent historical attestation.','Official upstream Linux v6.8 references explain the implementation family and hook constants. No byte identity with Ubuntu distribution kernel sources or binaries is asserted.']}
(out/'observations.json').write_text(json.dumps(o,indent=2)+'\n');(out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'leaves':len(leaves),'contemporaneous_kernel_records':len(contemporaneous),'fresh_records':len(records)}))
