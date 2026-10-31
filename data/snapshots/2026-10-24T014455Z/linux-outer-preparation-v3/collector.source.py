import argparse,hashlib,json,shlex,subprocess,time
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();config=json.loads(Path(a.config).read_text());root=Path(config['run_root']);out=root/'exports/linux-outer-preparation-v3';out.mkdir();private=root/'private/linux-outer';private.mkdir(mode=0o700);records=[];error=None
def run(cmd,timeout=90,check=True):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=timeout);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr[-2000:])
 return r
try:
 url='https://cloud.debian.org/images/cloud/bookworm/latest/';name='debian-12-genericcloud-amd64.qcow2'
 run(['curl','-fL','--retry','2','-o',private/'SHA512SUMS',url+'SHA512SUMS'],timeout=180)
 run(['curl','-fL','--retry','2','-o',private/name,url+name],timeout=1200)
 expected=[line.split()[0]for line in (private/'SHA512SUMS').read_text().splitlines()if line.split()[-1].lstrip('*')==name][0]
 actual=hashlib.sha512((private/name).read_bytes()).hexdigest();assert actual==expected
 (out/'SHA512SUMS.public').write_bytes((private/'SHA512SUMS').read_bytes())
 (out/'image-provenance.json').write_text(json.dumps({'retrieved_at':datetime.now(timezone.utc).isoformat(),'issuer':'Debian cloud image team','requested_url':url+name,'checksums_url':url+'SHA512SUMS','sha512':actual,'bytes':(private/name).stat().st_size,'format':'Official Debian 12 genericcloud QEMU image','scope':'HTTPS issuer image and same-origin checksum verified. No secure-boot or vendor software signature claim follows from the checksum.'},indent=2)+'\n')
 pub=run(['ssh-keygen','-y','-f',root/'private/freebsd/management_key']).stdout.strip()
 for i in [0,1]:
  disk=private/('outer-'+str(i)+'.qcow2');run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',private/name,disk,'12G'])
  seed=private/('seed-'+str(i));seed.mkdir();mac='52:54:76:08:'+str(i)+'0:10'
  user={'disable_root':False,'ssh_pwauth':False,'users':[{'name':'root','lock_passwd':True,'ssh_authorized_keys':[pub]}],'packages':['strongswan-swanctl','strongswan-charon','strongswan-pki','libstrongswan-standard-plugins','libcharon-extra-plugins','python3','iptables','iproute2','ntpsec-ntpdate'],'runcmd':[['sh','-c','systemctl disable --now strongswan-starter 2>/dev/null || true'],['touch','/root/tdn-linux-outer-ready']]}
  (seed/'user-data').write_text('#cloud-config\n'+json.dumps(user,indent=2)+'\n');(seed/'meta-data').write_text(json.dumps({'instance-id':config['device_prefix'].lower()+'-linux-outer-'+str(i),'local-hostname':config['device_prefix'].lower()+'-linux-outer-'+str(i)})+'\n')
  (seed/'network-config').write_text(json.dumps({'version':2,'ethernets':{'management':{'match':{'macaddress':mac},'dhcp4':True,'dhcp6':False}}})+'\n')
  iso=private/('seed-'+str(i)+'.iso');run(['genisoimage','-quiet','-output',iso,'-volid','cidata','-joliet','-rock',seed/'user-data',seed/'meta-data',seed/'network-config'])
  port=22452+i
  run(['qemu-system-x86_64','-name',config['device_prefix'].lower()+'-linux-outer-v3-'+str(i),'-enable-kvm','-cpu','host','-smp','2','-m','2048','-drive','file='+str(disk)+',format=qcow2,if=virtio','-drive','file='+str(iso)+',media=cdrom,readonly=on','-netdev','user,id=mgmt,hostfwd=tcp:127.0.0.1:'+str(port)+'-:22','-device','virtio-net-pci,netdev=mgmt,mac='+mac,'-display','none','-serial','file:'+str(private/('serial-'+str(i)+'.log')),'-monitor','unix:'+str(private/('monitor-'+str(i)+'.sock'))+',server,nowait','-pidfile',private/('qemu-'+str(i)+'.pid'),'-daemonize'])
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'configuration':config,'records':records,'error':error,'scope':'Preparation of two fresh actual Linux Outer kernels. Original native Outers have not been stopped or replaced during preparation. Private NoCloud credentials remain remote only; the exported public key identifies the authorized laboratory control.'},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error}))
