import argparse,base64,hashlib,json,os,signal,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();r=Path(a.root);out=r/'exports/audit-collector-reliability-v8';out.mkdir(parents=True);private=r/'private';records=[];error=None

def capture(label):
 journal=private/'store/audit-journal.jsonl';rows=[json.loads(line)for line in journal.read_text().splitlines()]if journal.exists()else[]
 records.append({'at':datetime.now(timezone.utc).isoformat(),'label':label,'journal_sha256':hashlib.sha256(journal.read_bytes()).hexdigest()if journal.exists()else None,'file_mode':oct(journal.stat().st_mode&511)if journal.exists()else None,'records':[{k:v for k,v in row.items()if k!='data'}for row in rows],'actual_audit_markers':[line for row in rows for line in base64.b64decode(row['data']).decode(errors='replace').splitlines()if'owned-protected-offload-'in line]})
try:
 capture('before-restart');pid=int((private/'server.pid').read_text());argv=[x.decode()for x in Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')if x];assert str(r/'scripts/audit_collector_v3.py')in argv and str(private/'store')in argv;os.kill(pid,signal.SIGTERM);deadline=time.monotonic()+10
 while Path('/proc/'+str(pid)).exists()and time.monotonic()<deadline:time.sleep(.1)
 #* A reparented process can remain a zombie until the supervisor reaps it.
 if Path('/proc/'+str(pid)+'/stat').exists():assert Path('/proc/'+str(pid)+'/stat').read_text().split()[2]=='Z'
 log=(private/'server-restart.log').open('w');proc=subprocess.Popen(argv,stdout=log,stderr=log,start_new_session=True);(private/'server.pid').write_text(str(proc.pid));time.sleep(.4);assert proc.poll()is None;capture('after-restart');records.append({'at':datetime.now(timezone.utc).isoformat(),'operation':'owned-service-restart','old_pid':pid,'new_pid':proc.pid,'command':argv})

except Exception as exc:error=str(exc)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':'Read-only committed journal summaries plus a positively identified owned collector restart and separately bounded store. No private credential or source audit body bytes are exported.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
