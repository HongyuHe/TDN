import argparse,base64,hashlib,json,os,shlex,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/audit-protected-offload-v5';out.mkdir();private=root/'private/audit-offload-v4';assert private.is_dir();receiver='hy@pc08.cloudlab.umass.edu';remote_root=str(root/'audit-offload-v4');records=[];error=None;key=Path('/users/hy/tdn-replay-20261024-v6/private/freebsd/management_key');port='22352'
def run(cmd,check=True,input=None,timeout=45):
 start=datetime.now(timezone.utc).isoformat();r=subprocess.run(list(map(str,cmd)),capture_output=True,text=not isinstance(input,bytes),input=input,timeout=timeout);stdout=r.stdout.decode()if isinstance(r.stdout,bytes)else r.stdout;stderr=r.stderr.decode()if isinstance(r.stderr,bytes)else r.stderr
 assert '-----BEGIN PRIVATE KEY-----'not in stdout and'-----BEGIN EC PRIVATE KEY-----'not in stdout
 records.append({'id':'offload-%04d'%len(records),'started_at':start,'ended_at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':stdout,'stderr':stderr,'input_scope':'Private issuance material sent directly over authorized SSH; bytes are not logged.'if isinstance(input,bytes)else'No private input bytes recorded. The authorized SSH session forwards its agent only while configuring the owned collector; the server public host key is pinned from an already authenticated controller connection.'})
 if check and r.returncode:raise RuntimeError(json.dumps(records[-1]))
 return r
def guest(cmd,check=True):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-i',key,'-p',port,'root@127.0.0.1',cmd],check)
def remote(cmd,check=True):return run(['ssh','-o','BatchMode=yes','-o','UserKnownHostsFile='+str(private/'known_hosts'),receiver,cmd],check)
def probe(label,command,expect):
 r=guest(command,False);passed=(r.returncode==0)if expect=='accepted'else(r.returncode!=0);records[-1].update(probe=label,expected_result=expect,observed_result=expect if passed else'contrary-result');return r
try:
 for role in ['ca','server','client','untrusted']:
  (out/(role+'.public.pem')).write_bytes((private/(role+'.pem')).read_bytes())
  run(['openssl','x509','-in',private/(role+'.pem'),'-noout','-subject','-issuer','-serial','-fingerprint','-sha256'])
 guest('mkdir -p /var/db/tdn-audit-exporter/tls; chmod 700 /var/db/tdn-audit-exporter /var/db/tdn-audit-exporter/tls')
 run(['scp','-q','-i',key,'-P',port,root/'scripts/audit-export-client-v3','root@127.0.0.1:/var/db/tdn-audit-exporter/audit-export-client'])
 for name in ['ca.pem','client.pem','client.key','untrusted.pem','untrusted.key']:run(['scp','-q','-i',key,'-P',port,private/name,'root@127.0.0.1:/var/db/tdn-audit-exporter/tls/'+name])
 guest('chmod 700 /var/db/tdn-audit-exporter/audit-export-client; chmod 600 /var/db/tdn-audit-exporter/tls/*.key; route -n add -host 198.22.255.18 10.0.2.2 || route -n get 198.22.255.18; date -u; freebsd-version -kru; ifconfig vtnet0; pfctl -si; pfctl -sr')
 marker='owned-protected-offload-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');guest('logger -p auth.notice -t tdn-audit '+marker+'; sleep 1; fsync /var/log/auth.log; cp /var/log/auth.log /var/db/tdn-audit-exporter/actual-audit-source.log; fsync /var/db/tdn-audit-exporter/actual-audit-source.log; grep -F '+marker+' /var/db/tdn-audit-exporter/actual-audit-source.log')
 common='/var/db/tdn-audit-exporter/audit-export-client --url https://198.22.255.18:43463/v1/audit --log /var/db/tdn-audit-exporter/actual-audit-source.log --ca /var/db/tdn-audit-exporter/tls/ca.pem '
 trusted=common+'--cert /var/db/tdn-audit-exporter/tls/client.pem --key /var/db/tdn-audit-exporter/tls/client.key '
 probe('actual-audit-batch-durable-ack',trusted+'--cursor /var/db/tdn-audit-exporter/cursor.json','accepted')
 probe('same-batch-idempotent-retry',trusted+'--cursor /var/db/tdn-audit-exporter/duplicate-cursor.json','accepted')
 probe('certificate-device-binding-denied',trusted+'--device Another-Device --cursor /var/db/tdn-audit-exporter/denied-cursor.json','rejected')
 probe('untrusted-client-certificate-denied',common+'--cert /var/db/tdn-audit-exporter/tls/untrusted.pem --key /var/db/tdn-audit-exporter/tls/untrusted.key --cursor /var/db/tdn-audit-exporter/untrusted-cursor.json','rejected')
 guest('test ! -e /var/db/tdn-audit-exporter/denied-cursor.json; test ! -e /var/db/tdn-audit-exporter/untrusted-cursor.json; cat /var/db/tdn-audit-exporter/cursor.json; sha256 /var/db/tdn-audit-exporter/actual-audit-source.log')
 for src,dst in [('NC_R_A1','10.2.1.10'),('NC_R_B1','10.1.1.10')]:
  r=run(['docker','exec',src,'ping','-n','-c','3','-W','1',dst],False);records[-1].update(probe='protected-data-'+src,expected_result='delivered',observed_result='delivered'if r.returncode==0 else'no_reply')
except Exception as exc:error=str(exc)
finally:
 for name in ['audit_offload_experiment_v5.py','audit_collector_v3.py','audit_export_client_v3.go']:
  f=root/'scripts'/name
  if f.exists():(out/name).write_bytes(f.read_bytes())
 binary=root/'scripts/audit-export-client-v3'
 if binary.exists():(out/'audit-export-client-v3').write_bytes(binary.read_bytes())
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'backend':'Actual NC FreeBSD InnerA source; supplemental dedicated TLS collector process on distinct pc08 worker; host root and provisioning remain trusted.','scope':['Actual auth.log bytes travel over TLS1.3 with mutual certificate authentication. Receiver binds client CN to device and offset/hash, durably fsyncs before acknowledgment, and source persists its cursor only after a matching response.','No source audit bytes, private credential files or private VM disks are exported in this public bundle. Public records retain offset/hash, marker presence and exact certificate fingerprints.','Service restart, configured capacity/backpressure, source rotation and broader retention remain separate pending tests. One-year retention and organizational adoption are not inferred.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
