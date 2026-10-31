import hashlib,json,subprocess,time,shlex
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-continuation-2026-10-24T014455Z');out=root/'exports/lsm-gateway-v7';out.mkdir();work=root/'private/lsm-gateway-v7';work.mkdir(mode=0o700);records=[];error=None;containers=[]
def run(args,check=True):
 r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=45)
 if '-----BEGIN PRIVATE KEY-----' in r.stdout:raise RuntimeError('Secret export refused')
 records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,args)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if check and r.returncode:raise RuntimeError(r.stderr)
 return r
def ex(name,*cmd,check=True):
 if cmd and cmd[0]=='swanctl':cmd=['sh','-c','exec '+shlex.join(list(map(str,cmd)))]
 return run(['docker','exec',name,*cmd],check)
profile='''#include <tunables/global>
profile tdn-lsm-device-v7 flags=(attach_disconnected) {
  / r,
  /** rwklm,
  /{,usr/}{bin,sbin}/** ix,
  /usr/lib/ipsec/charon px -> tdn-lsm-gateway-v7,
  /usr/sbin/swanctl px -> tdn-lsm-gateway-v7,
  audit deny /etc/swanctl/private/** rwklm,
  deny /proc/*/mem rwklm,
  deny /proc/*/fd/** rwklm,
  deny /proc/*/map_files/** rwklm,
  network,
  capability,
  signal,
  deny ptrace,
}
profile tdn-lsm-gateway-v7 flags=(attach_disconnected) {
  file,
  network,
  capability,
  signal,
  deny ptrace,
}
'''
try:
 policy=out/'apparmor.profile';policy.write_text(profile);run(['apparmor_parser','-r',policy])
 run(['openssl','req','-new','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:secp384r1','-nodes','-keyout',work/'ca.key','-out',work/'ca.pem','-days','1','-sha384','-subj','/CN=LSM-v3-Test-CA','-addext','basicConstraints=critical,CA:TRUE'])
 for i in [0,1]:
  site='A' if i==0 else 'B';name='tcv3-lsm7-'+site.lower();d=work/site
  for part in ['private','x509','x509ca']: (d/part).mkdir(parents=True)
  run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:secp384r1','-nodes','-keyout',d/'private/key.pem','-out',work/(site+'.csr'),'-sha384','-subj','/CN='+site+'.lsm.test'])
  ext=work/(site+'.ext');ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:'+site+'.lsm.test\n')
  run(['openssl','x509','-req','-in',work/(site+'.csr'),'-CA',work/'ca.pem','-CAkey',work/'ca.key','-CAcreateserial','-out',d/'x509/cert.pem','-days','1','-sha384','-extfile',ext])
  (d/'x509ca/ca.pem').write_bytes((work/'ca.pem').read_bytes());(d/'private/key.pem').chmod(0o600)
  config='''connections {
 msc {
  version = 2
  local_addrs = 10.254.31.%d
  remote_addrs = 10.254.31.%d
  proposals = aes256gcm16-prfsha384-ecp384
  reauth_time = 3h
  rekey_time = 0s
  local { auth = pubkey
   certs = cert.pem
   id = %s.lsm.test
  }
  remote { auth = pubkey
   id = %s.lsm.test
  }
  children {
   protected {
    local_ts = 10.251.%d.1/32
    remote_ts = 10.251.%d.1/32
    mode = tunnel
    esp_proposals = aes256gcm16-ecp384
    start_action = none
   }
  }
 }
}
'''%(i+1,2-i,site,'B' if i==0 else 'A',i+1,2-i)
  (d/'swanctl.conf').write_text(config);(out/(site+'.public.conf')).write_text(config);(out/(site+'.public.pem')).write_bytes((d/'x509/cert.pem').read_bytes())
  run(['docker','run','-d','--name',name,'--network','none','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--read-only','--tmpfs','/run','--tmpfs','/tmp','--security-opt','apparmor=tdn-lsm-device-v7','--mount','type=bind,src='+str(d)+',dst=/etc/swanctl,readonly','--entrypoint','sleep','twinet-msc:construction-v2','infinity']);containers.append(name)
  run(['docker','inspect','--format','{{json .HostConfig}}',name])
  ex(name,'cat','/proc/self/status')
  immutable="import os,json;result='unexpected-open';\ntry:\n fd=os.open('/usr/sbin/swanctl',os.O_WRONLY);os.close(fd)\nexcept OSError as e:result='read-only' if e.errno==30 else 'denied'\nprint(json.dumps({'gateway_executable_write':result}))"
  r=ex(name,'python3','-c',immutable);records[-1].update(probe='gateway-executable-immutable',expected_result='read-only',observed_result='read-only' if '"read-only"' in r.stdout else 'unexpected')
  escalation="from pathlib import Path;import json;result='unexpected-profile-change';\ntry:Path('/proc/self/attr/current').write_text('changeprofile tdn-lsm-gateway-v7')\nexcept PermissionError:result='denied'\nprint(json.dumps({'direct_profile_change':result}))"
  r=ex(name,'python3','-c',escalation);records[-1].update(probe='nongateway-direct-profile-change',expected_result='denied',observed_result='denied' if '"denied"' in r.stdout else 'unexpected')
  pid=run(['docker','inspect','--format','{{.State.Pid}}',name]).stdout.strip()
  host='ls7'+str(i);peer='lp7'+str(i)
  if i==0:run(['ip','link','add',host,'type','veth','peer','name',peer])
  else:host='lp70'
  run(['ip','link','set',host,'netns',pid]);ex(name,'ip','link','set',host,'name','eth0');ex(name,'ip','link','set','eth0','up');ex(name,'ip','link','set','lo','up');ex(name,'ip','addr','add','10.254.31.'+str(i+1)+'/30','dev','eth0');ex(name,'ip','addr','add','10.251.'+str(i+1)+'.1/32','dev','lo');ex(name,'ip','route','add','10.251.'+str(2-i)+'.1/32','via','10.254.31.'+str(2-i))
  ex(name,'iptables','-A','OUTPUT','-s','10.251.'+str(i+1)+'.1/32','-d','10.251.'+str(2-i)+'.1/32','-m','policy','--dir','out','--pol','ipsec','-j','ACCEPT')
  ex(name,'iptables','-A','OUTPUT','-s','10.251.'+str(i+1)+'.1/32','-d','10.251.'+str(2-i)+'.1/32','-j','REJECT')
  ex(name,'iptables-save','-c')
  run(['docker','exec','-d',name,'sh','-c','exec /usr/lib/ipsec/charon > /tmp/charon.log 2>&1']);time.sleep(.5)
  ex(name,'swanctl','--load-all')
  for cmd in [['cat','/proc/self/attr/current'],['ps','-eo','pid,comm,args'],['stat','-c','%a %U %n','/etc/swanctl/private/key.pem']]:ex(name,*cmd)
  test="import os,json;result='unexpected-open';\ntry:\n fd=os.open('/etc/swanctl/private/key.pem',os.O_RDONLY);os.close(fd)\nexcept PermissionError:result='denied'\nprint(json.dumps({'root_key_open':result}))"
  r=ex(name,'python3','-c',test);records[-1].update(probe='root-nongateway-key-open',expected_result='denied',observed_result='denied' if '"denied"' in r.stdout else 'unexpected-open')
 constructor=out/'key-open-constructor.c';constructor.write_text('#include <fcntl.h>\n#include <unistd.h>\n#include <stdio.h>\n__attribute__((constructor)) static void check(void){int fd=open("/etc/swanctl/private/key.pem",O_RDONLY);printf("owned-test-key-open=%s\\n",fd>=0?"opened":"denied");if(fd>=0)close(fd);}\n')
 run(['cc','--version']);run(['cc','-shared','-fPIC','-O2','-o',out/'key-open-constructor.so',constructor])
 (out/'apparmor-before.profile').write_text(profile)
 for name in containers:
  run(['docker','cp',out/'key-open-constructor.so',name+':/tmp/key-open-constructor.so'])
  r=ex(name,'env','LD_PRELOAD=/tmp/key-open-constructor.so','/usr/sbin/swanctl','--stats',check=False);records[-1].update(probe='before-nongateway-preload-test-key-open',expected_result='opened-counterexample',observed_result='opened-counterexample'if'owned-test-key-open=opened'in r.stdout else'not-demonstrated',scope='The constructor opens only the owned disposable fixture key and closes it without reading any bytes. The output is a boolean, not key material.')
 hardened=profile.replace(' px -> ',' Px -> ').replace('  file,','  /** rwkl,\n  /lib/** mr,\n  /usr/lib/** mr,\n  /usr/sbin/swanctl mr,\n  deny /proc/*/mem rwklm,\n  deny /proc/*/fd/** rwklm,\n  deny /proc/*/map_files/** rwklm,')
 policy.write_text(hardened);(out/'apparmor-after.profile').write_text(hardened);run(['apparmor_parser','-r',policy])
 for name in containers:
  r=ex(name,'env','LD_PRELOAD=/tmp/key-open-constructor.so','/usr/sbin/swanctl','--stats',check=False);records[-1].update(probe='after-nongateway-preload-test-key-open',expected_result='blocked-and-gateway-available',observed_result='blocked-and-gateway-available'if r.returncode==0 and'owned-test-key-open=opened'not in r.stdout else'failed',scope='Uppercase Px scrubs unsafe loader environment; gateway executable mapping is limited to immutable installed binaries/libraries. Writable run/tmp and descriptor paths cannot introduce mapped code.')
 ex(containers[0],'swanctl','--initiate','--child','protected')
 for name in containers:
  ex(name,'swanctl','--list-sas');ex(name,'ip','-s','xfrm','state','list','nokeys')
  ex(name,'sh','-c','for p in /proc/[0-9]*/comm; do if test "$(cat "$p" 2>/dev/null)" = charon; then cat "${p%/comm}/attr/current"; fi; done')
 for i,name in enumerate(containers):
  r=ex(name,'ping','-n','-I','10.251.'+str(i+1)+'.1','-c','3','-W','1','10.251.'+str(2-i)+'.1',check=False);records[-1].update(probe='confined-gateway-IPsec-data',expected_result='delivered',observed_result='delivered' if r.returncode==0 else 'no_reply')
 for name in containers:ex(name,'swanctl','--terminate','--ike','msc',check=False)
 r=ex(containers[0],'ping','-n','-I','10.251.1.1','-c','3','-W','1','10.251.2.1',check=False);records[-1].update(probe='LSM-case-SA-loss',expected_result='no_reply',observed_result='delivered' if r.returncode==0 else 'no_reply')
 run(['journalctl','-k','--since','5 minutes ago','--grep','tdn-lsm','--no-pager'],check=False)
except Exception as e:error=str(e)
finally:
 for name in containers:
  ex(name,'cat','/tmp/charon.log',check=False)
  ex(name,'sh','-c','for p in /proc/[0-9]*/comm; do if test "$(cat "$p" 2>/dev/null)" = charon; then cat "${p%/comm}/attr/current"; fi; done',check=False)
  run(['docker','rm','-f',name],check=False)
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'runtime_backend':'supplemental-Linux-Docker-IKEv2-and-host-enforced-AppArmor','scope':['Fresh owned read-only containers run actual IKEv2 gateways under explicit AppArmor profiles. The general device profile denies the private key subtree; immutable charon and swanctl executables transition to the gateway profile that can load the keys. Non-gateway root opens are tested without reading or exporting any key bytes.','The complete effective policy and executable/profile identities must support the claims. Private credential provisioning and the host root/Docker policy loader remain trusted laboratory controls. No all-interface, host administrator, hardware tamper, approved-product or universal noninterference guarantee follows from this bounded case.','Mandatory policy is supplemental and is not asserted to be installed on the separate original native profiles or FreeBSD Inners.']},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'probes':[{k:r[k] for k in ['probe','expected_result','observed_result']} for r in records if 'probe'in r]}))
