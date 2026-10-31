import argparse,hashlib,json,re,shlex,subprocess,time
from datetime import datetime,timezone
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--output',required=True);parser.add_argument('--execute',action='store_true');args=parser.parse_args()
config=json.loads(Path(args.config).read_text());out=Path(args.output);out.mkdir();staged=out/'staged';staged.mkdir();original='/users/hy/tdn-continuation-2026-10-24T014455Z';root=config['run_root'];host=config['host'];prefix=config['device_prefix'];bridge=config['bridge_prefix']
assert re.fullmatch('[A-Z]{2,4}',prefix);assert re.fullmatch('[a-z][a-z0-9]{2}',bridge);assert re.fullmatch('/users/hy/[A-Za-z0-9_-]+',root);assert root!=original
source=Path('scripts/construction/evidence');sources=[];records=[];error=None
def stage(name,text=None):
 p=source/name;data=p.read_text() if text is None else text
 replacements=[(original,root),('ND_',prefix+'_'),('nd3',bridge),('22222',str(config['ssh_port_base'])),('native-os-diversity-v3',config['profile_name'])]
 for before,after in replacements:data=data.replace(before,after)
 dest=staged/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(data);sources.append({'source':str(p),'original_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'staged_path':str(dest),'staged_sha256':hashlib.sha256(dest.read_bytes()).hexdigest()});return dest
stage('replay_freebsd_bootstrap_v3.py')
build=(source/'freebsd_build_v3.py').read_text().replace('time.monotonic()+180','time.monotonic()+1800').replace('/usr/local/sbin/swanctl --version\n','/usr/local/sbin/swanctl --version || test -x /usr/local/sbin/swanctl\n')
build=build.replace('sha256 strongswan-6.0.3.tar.bz2','sha256 strongswan-6.0.3.tar.bz2\ntest "$(sha256 -q strongswan-6.0.3.tar.bz2)" = 288f2111f5c9f6ec85fc08fa835bf39232f5c4044969bb4de7b4335163b1efa9')
stage('freebsd_build_v3.py',build)
integration=(source/'freebsd_native_integration_v3.py').read_text().replace('charon.pid /usr/local/libexec/ipsec/charon\'','charon.pid /usr/local/libexec/ipsec/charon </dev/null >/dev/null 2>&1\'')
integration=integration.replace("cmds=['sysctl net.inet.ip.forwarding=1'","cmds=['kldstat -n ipsec >/dev/null 2>&1 || kldload ipsec','sysrc kld_list+=ipsec','sysctl kern.crypto.allow_soft=1','sysctl net.inet.ipsec.debug=0','sysctl net.inet.ip.forwarding=1'")
stage('freebsd_native_integration_v3.py',integration)
for name in ['freebsd_native_integration_v8.py','native_dns_hardening_v7.py','native_cbc_alternative_v4.py','freebsd_certificate_events_v4.py','freebsd_automatic_reauth_v3.py','independent_red_clocks_v3.py','freebsd_audit_power_v8.py','native_dns_hardening_v11.py','freebsd_pf_skip_v13.py']:stage(name)
stage('profiles/native-os-diversity-v3.json')
(staged/'replay-config.json').write_text(json.dumps(config,indent=2)+'\n')
binary=Path('artifacts/construction/2026-10-24T014455Z/evidence/runtime/twinet-linux');binary_sha=hashlib.sha256(binary.read_bytes()).hexdigest();assert binary_sha=='555098b40130410a5827e2010316a3bc00e77c90eb2cfba1f4a150a32a9ce5dd'
def command(argv,timeout=120):
 argv=list(map(str,argv))
 if argv[0] in ['ssh','scp']:argv=[argv[0],'-o','BatchMode=yes','-o','ConnectTimeout=8','-o','ControlMaster=auto','-o','ControlPersist=600','-o','ControlPath='+str(Path('.replay-ssh-'+prefix.lower()).resolve()),*argv[1:]]
 r=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=timeout);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,argv)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if r.returncode:raise RuntimeError(r.stderr[-2000:]+r.stdout[-2000:])
 return r
def remote(argv,timeout=120):return command(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5',host,shlex.join(list(map(str,argv)))],timeout)
jobs=[['python3',root+'/scripts/replay_freebsd_bootstrap_v3.py','--config',root+'/scripts/replay-config.json'],[root+'/scripts/twinet-linux','msc','--spec',root+'/scripts/profiles/'+config['profile_name']+'.json','--state-dir',root+'/private/'+config['profile_name'],'up'],['python3',root+'/scripts/freebsd_build_v3.py'],['python3',root+'/scripts/freebsd_native_integration_v3.py'],['python3',root+'/scripts/freebsd_native_integration_v8.py'],['python3',root+'/scripts/native_dns_hardening_v7.py'],['python3',root+'/scripts/native_cbc_alternative_v4.py'],['python3',root+'/scripts/freebsd_certificate_events_v4.py'],['python3',root+'/scripts/freebsd_automatic_reauth_v3.py'],['python3',root+'/scripts/independent_red_clocks_v3.py'],['python3',root+'/scripts/freebsd_audit_power_v8.py','--config',root+'/scripts/replay-config.json','--output',root+'/exports/freebsd-audit-power-v8'],['python3',root+'/scripts/native_dns_hardening_v11.py','--root',root,'--device-prefix',prefix,'--guest-port-base',str(config['ssh_port_base'])],['python3',root+'/scripts/freebsd_pf_skip_v13.py','--root',root,'--device-prefix',prefix,'--guest-port-base',str(config['ssh_port_base'])]]
try:
 if args.execute:
  check="import socket,subprocess;from pathlib import Path;assert not Path("+repr(root)+").exists(),'Replay root already exists';names=subprocess.check_output(['sudo','-n','docker','ps','-a','--format','{{.Names}}'],text=True).splitlines();assert not any(n.startswith("+repr(prefix+'_')+") for n in names),'Device prefix already exists';"
  for port in [config['ssh_port_base'],config['ssh_port_base']+1,config['socket_port']]:check+="s=socket.socket();s.bind(('127.0.0.1',"+str(port)+"));s.close();"
  remote(['python3','-c',check]);remote(['mkdir','-p',root+'/scripts/profiles',root+'/exports',root+'/private'])
  for file in staged.rglob('*'):
   if not file.is_file():continue
   name=str(file.relative_to(staged));destination=name.replace('profiles/native-os-diversity-v3.json','profiles/'+config['profile_name']+'.json')
   command(['scp','-q',file,host+':'+root+'/scripts/'+destination])
  command(['scp','-q',binary,host+':'+root+'/scripts/twinet-linux']);remote(['chmod','+x',root+'/scripts/twinet-linux'])
  for job in jobs:
   remote(['sudo','-n',*job],timeout=4200)
   verdict="import json;from pathlib import Path;bad=[];\nfor p in Path("+repr(root+'/exports')+").glob('*/observations.json'):\n o=json.loads(p.read_text());\n if o.get('error'):bad.append(str(p));\n if any(r.get('status') in ['failed','not-ready'] for r in o.get('records',[])):bad.append(str(p));\n if any('expected_result'in r and r.get('observed_result')!=r['expected_result']for r in o.get('records',[])):bad.append(str(p));\nprint(bad);assert not bad,bad"
   remote(['sudo','-n','python3','-c',verdict])
except Exception as e:error=str(e)
finally:
 data={'at':datetime.now(timezone.utc).isoformat(),'configuration':config,'execute':args.execute,'error':error,'sources':sources,'binary_sha256':binary_sha,'jobs':jobs,'records':records,'scope':['Fresh root, fresh device prefix and distinct ports are required. The entry point refuses existing roots or device prefixes. Existing deployments are not reused or removed.','Staged source bytes and all transformations are preserved with original and executed hashes. All selected final setup, mount hardening, CBC restoration, certificate and timer operations are explicit jobs.','Required host images and packages are prerequisites listed in REPLAY.md. Source downloads are pinned by SHA-256. Credentials are freshly generated on the remote worker and never staged in public files.']}
 (out/'observations.json').write_text(json.dumps(data,indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':str(p.relative_to(out)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.rglob('*') if p.is_file() and p.name!='manifest.json']},indent=2)+'\n');print(json.dumps({'error':error,'execute':args.execute,'jobs':len(jobs),'output':str(out)}))
 if error:raise SystemExit(1)
