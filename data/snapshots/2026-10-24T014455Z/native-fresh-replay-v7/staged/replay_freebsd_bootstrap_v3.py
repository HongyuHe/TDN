import hashlib,json,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
import argparse
p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();config=json.loads(Path(a.config).read_text());root=Path(config['run_root']);base=root/'private/freebsd';out=root/'exports/replay-freebsd-bootstrap-v3';out.mkdir();base.mkdir(parents=True,mode=0o700);records=[];error=None
def run(args,timeout=120):
 r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=timeout);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,args)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if r.returncode:raise RuntimeError(r.stderr)
 return r
try:
 name='FreeBSD-14.4-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz';image=base/name;expected='d957fe56fb596280428328e78e9e4feae00dd361701caa79a061f9bd289eff67';url='https://download.freebsd.org/releases/VM-IMAGES/14.4-RELEASE/amd64/Latest/'+name
 if config.get('image_cache'):run(['cp','--reflink=auto',config['image_cache'],image])
 else:run(['curl','--fail','--location','--output',image,url],timeout=1200)
 assert hashlib.sha256(image.read_bytes()).hexdigest()==expected,'FreeBSD official image hash changed; review version before proceeding'
 run(['xz','-d','-k',image],timeout=300);run(['mv',base/name[:-3],base/'base.qcow2'])
 run(['ssh-keygen','-q','-t','ed25519','-N','','-f',base/'management_key']);pub=(base/'management_key.pub').read_text().strip()
 for i in [0,1]:
  seed=base/('seed-v2-'+str(i));seed.mkdir();instance=config['device_prefix'].lower()+'-freebsd-'+str(i)
  (seed/'meta-data').write_text('instance-id: '+instance+'\nlocal-hostname: '+instance+'\n')
  commands=['mkdir -p /root/.ssh','chmod 700 /root/.ssh','printf "%s\\n" '+repr(pub)+' > /root/.ssh/authorized_keys','chmod 600 /root/.ssh/authorized_keys','sysrc sshd_enable=YES','echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config','echo "PasswordAuthentication no" >> /etc/ssh/sshd_config','service sshd restart']
  user='#cloud-config\nhostname: '+instance+'\nssh_pwauth: false\nssh_authorized_keys:\n  - '+pub+'\nnetwork:\n  version: 2\n  ethernets:\n    vtnet0:\n      dhcp4: true\n    vtnet1:\n      dhcp4: false\n      addresses: [172.28.90.'+str(i+1)+'/30]\nruncmd:\n'+''.join('  - '+json.dumps(c)+'\n' for c in commands)
  (seed/'user-data').write_text(user);(out/('user-data-'+str(i)+'.public.yaml')).write_text(user)
  disk=base/('node-v2-'+str(i)+'.qcow2');iso=base/('seed-v2-'+str(i)+'.iso')
  run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',base/'base.qcow2',disk]);run(['genisoimage','-quiet','-output',iso,'-volid','cidata','-joliet','-rock',seed])
  args=['qemu-system-x86_64','-name',instance,'-enable-kvm','-cpu','host','-smp','2','-m','2048','-drive','file='+str(disk)+',format=qcow2,if=virtio','-drive','file='+str(iso)+',media=cdrom,readonly=on','-netdev','user,id=mgmt,hostfwd=tcp:127.0.0.1:'+str(config['ssh_port_base']+i)+'-:22','-device','virtio-net-pci,netdev=mgmt,mac='+config['mac_prefix']+':'+str(i)+'0:10','-netdev','socket,id=gray,'+('listen=127.0.0.1:'+str(config['socket_port']) if i==0 else 'connect=127.0.0.1:'+str(config['socket_port'])),'-device','virtio-net-pci,netdev=gray,mac='+config['mac_prefix']+':'+str(i)+'0:11','-display','none','-serial','file:'+str(base/('serial-v2-'+str(i)+'.log')),'-monitor','unix:'+str(base/('monitor-v2-'+str(i)+'.sock'))+',server,nowait','-pidfile',str(base/('qemu-v2-'+str(i)+'.pid')),'-daemonize'];run(args)
except Exception as e:error=str(e)
finally:
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'image_url':url,'expected_image_sha256':expected,'configuration':config},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error}))
 if error:raise SystemExit(1)
