import argparse,hashlib,json,subprocess
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();config=json.loads(Path(a.config).read_text());root=Path(config['run_root']);out=root/'exports/freebsd-module-repair-v6';out.mkdir();records=[];error=None
def ssh(i,cmd,check=True):
 args=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=accept-new','-i',str(root/'private/freebsd/management_key'),'-p',str(config['ssh_port_base']+i),'root@127.0.0.1',cmd];r=subprocess.run(args,capture_output=True,text=True,timeout=90);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':args,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr)
 return r
try:
 for i in [0,1]:
  ssh(i,'kldstat; sysctl kern.crypto.allow_soft')
  ssh(i,'kldstat -n ipsec >/dev/null 2>&1 || kldload ipsec')
  ssh(i,'sysctl kern.crypto.allow_soft=1; sysrc kld_list+=ipsec')
  ssh(i,'kldstat; sysctl net.inet.ipsec.crypto_support')
  ssh(i,'/usr/local/sbin/swanctl --load-all')
 ssh(0,'/usr/local/sbin/swanctl --initiate --child protected')
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'cause':'Fresh FreeBSD kernels had IPSEC_SUPPORT stubs but no ipsec.ko loaded. PF_KEY SAD installation returned EINVAL. Explicitly load ipsec.ko and persist it in kld_list before gateway startup.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error}))
