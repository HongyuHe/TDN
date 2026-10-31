import argparse,base64,hashlib,json,os,signal,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/audit-collector-readback-v7';out.mkdir();records=[];error=None
def record(label,argv):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=15);records.append({'at':datetime.now(timezone.utc).isoformat(),'label':label,'command':argv,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});return r
try:
 for label,argv in [('time',['date','-u','--iso-8601=ns']),('kernel',['uname','-a']),('boot',['cat','/proc/sys/kernel/random/boot_id']),('hardware',['cat','/sys/class/dmi/id/product_uuid']),('python',['python3','--version']),('TLS',['python3','-c','import ssl;print(ssl.OPENSSL_VERSION)']),('public-certificate',['openssl','x509','-in',str(root/'private/server.pem'),'-noout','-fingerprint','-sha256','-subject','-issuer','-dates']),('listeners',['ss','-lntp'])]:record(label,argv)
 for role in ['server','budget']:
  pid=int((root/'private'/str(role+'.pid')).read_text());argv=[x.decode()for x in Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')if x]
  assert str(root/'scripts/audit_collector_v3.py')in argv
  expected=str(root/'private'/('store'if role=='server'else'budget-store'));assert expected in argv
  records.append({'at':datetime.now(timezone.utc).isoformat(),'label':role+'-owned-process','pid':pid,'argv':argv})
  if role=='budget':
   os.kill(pid,signal.SIGTERM);time.sleep(.3);records.append({'at':datetime.now(timezone.utc).isoformat(),'label':'budget-test-process-stopped','pid':pid,'remaining_state':Path('/proc/'+str(pid)+'/stat').read_text().split()[2]if Path('/proc/'+str(pid)+'/stat').exists()else'absent'})
 for store in ['store','budget-store']:
  directory=root/'private'/store;journal=directory/'audit-journal.jsonl'
  rows=[json.loads(line)for line in journal.read_text().splitlines()]if journal.exists()else[]
  records.append({'at':datetime.now(timezone.utc).isoformat(),'label':store+'-public-summary','directory_mode':oct(directory.stat().st_mode&511),'journal_mode':oct(journal.stat().st_mode&511)if journal.exists()else None,'journal_sha256':hashlib.sha256(journal.read_bytes()).hexdigest()if journal.exists()else None,'records':[{k:v for k,v in row.items()if k!='data'}for row in rows],'actual_audit_markers':[line for row in rows for line in base64.b64decode(row['data']).decode(errors='replace').splitlines()if'owned-protected-offload-'in line]})
 assert not(root/'private/budget-store/audit-journal.jsonl').exists()
 for source in ['audit_collector_v3.py']:
  (out/source).write_bytes((root/'scripts'/source).read_bytes())
except Exception as exc:error=str(exc)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':'Public identity and committed-record metadata only. Raw audit bodies and private credentials remain private. Only the positively identified separate budget test process is stopped; the primary collector remains running.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
