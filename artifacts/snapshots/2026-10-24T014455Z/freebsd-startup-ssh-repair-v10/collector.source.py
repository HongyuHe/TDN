import argparse,hashlib,json,subprocess
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/freebsd-startup-ssh-repair-v10';out.mkdir();config=json.loads((root/'scripts/replay-config.json').read_text());port=str(config['ssh_port_base']);key=root/'private/freebsd/management_key';records=[];error=None
def run(cmd,check=True):
    start=datetime.now(timezone.utc).isoformat();r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=45);assert '-----BEGIN PRIVATE KEY-----'not in r.stdout;records.append({'at':start,'ended_at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
    if check and r.returncode:raise RuntimeError(r.stderr)
    return r
def ssh(cmd,check=True):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-i',key,'-p',port,'root@127.0.0.1',cmd],check)
try:
    ssh('wc -c /etc/rc.conf /usr/local/etc/rc.d/tdn_gateway; ifconfig vtnet0')
    for source,destination in [('rc.conf.restored','/etc/rc.conf'),('tdn_gateway.restored','/usr/local/etc/rc.d/tdn_gateway')]:
        file=root/'exports/freebsd-startup-repair-v9'/source;data=file.read_bytes();assert data
        (out/source).write_bytes(data);run(['scp','-q','-o','BatchMode=yes','-i',key,'-P',port,file,'root@127.0.0.1:'+destination])
    ssh('chmod 644 /etc/rc.conf; chmod 555 /usr/local/etc/rc.d/tdn_gateway; fsync /etc/rc.conf; fsync /usr/local/etc/rc.d/tdn_gateway; fsync /etc; fsync /usr/local/etc/rc.d; sync; wc -c /etc/rc.conf /usr/local/etc/rc.d/tdn_gateway')
    ssh('service netif start vtnet2 vtnet3; service routing restart; sysctl net.inet.ip.forwarding=1; service tdn_gateway start')
    ssh('/usr/local/sbin/swanctl --stats; /usr/local/sbin/swanctl --initiate --child protected')
    r=run(['docker','exec',config['device_prefix']+'_R_A1','ping','-n','-c','3','-W','1','10.2.1.10'],False);records[-1].update({'probe':'protected-data-after-startup-restoration','expected_result':'delivered','observed_result':'delivered'if r.returncode==0 else'no-reply'})
    ssh('grep -F synthetic-durable-marker-0 /var/log/auth.log')
except Exception as e:error=str(e)
finally:
    (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['Exact public startup bytes are transferred through the existing authorized guest SSH key after the normal sshd onestart console command. No password was guessed or changed.','The first console restoration sent long base64 lines through a UART and did not restore file bytes. That failed attempt remains separate. SCP transfer plus actual size/hash and explicit file/directory fsync replaces that unreliable path.','Only the owned NC guest is repaired. Hypervisor, host root and existing SSH provisioning remain trusted laboratory controls.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'probes':[{k:r[k]for k in ['probe','expected_result','observed_result']}for r in records if'probe'in r]}))
