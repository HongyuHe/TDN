import concurrent.futures,hashlib,json,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-replay-20261024-v7');out=root/'exports/freebsd-botan-build-v3';out.mkdir(exist_ok=False);records=[]
script="""set -e
env ASSUME_ALWAYS_YES=yes pkg bootstrap -f
env ASSUME_ALWAYS_YES=yes pkg install -y botan3 gmake pkgconf
mkdir -p /root/tdn-freebsd-v3
cd /root/tdn-freebsd-v3
fetch -o strongswan-6.0.3.tar.bz2 https://download.strongswan.org/strongswan-6.0.3.tar.bz2
sha256 strongswan-6.0.3.tar.bz2
test "$(sha256 -q strongswan-6.0.3.tar.bz2)" = 288f2111f5c9f6ec85fc08fa835bf39232f5c4044969bb4de7b4335163b1efa9
tar -xjf strongswan-6.0.3.tar.bz2
cd strongswan-6.0.3
./configure --help > configure-help.txt
./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --disable-defaults --enable-charon --enable-swanctl --enable-vici --enable-ikev2 --enable-kernel-pfkey --enable-kernel-pfroute --enable-socket-default --enable-botan --enable-random --enable-nonce --enable-pem --enable-x509 --enable-constraints --enable-revocation --enable-pubkey --enable-pkcs1 --enable-pkcs8 --enable-counters
gmake -j2
gmake install
uname -a
pkg info botan3
/usr/local/sbin/swanctl --version || test -x /usr/local/sbin/swanctl
ldd /usr/local/lib/ipsec/plugins/libstrongswan-botan.so
"""
(out/'guest-build.sh').write_text(script)
def build(i):
 argv=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-o','ConnectTimeout=5','-i',str(root/'private/freebsd/management_key'),'-p',str(22392+i),'root@127.0.0.1']
 start=datetime.now(timezone.utc).isoformat()
 deadline=time.monotonic()+1800
 while True:
  r=subprocess.run(argv+['uname -a'],capture_output=True,text=True,timeout=12)
  if r.returncode==0:break
  if time.monotonic()>deadline:return {'guest':i,'started_at':start,'ended_at':datetime.now(timezone.utc).isoformat(),'status':'not-ready','stderr':r.stderr}
  time.sleep(5)
 r=subprocess.run(argv+['sh -s'],input=script,capture_output=True,text=True,timeout=1800)
 (out/('guest'+str(i)+'.log')).write_text(r.stdout+'\nSTDERR\n'+r.stderr)
 return {'guest':i,'command':argv+['sh -s'],'started_at':start,'ended_at':datetime.now(timezone.utc).isoformat(),'status':'passed' if r.returncode==0 else 'failed','returncode':r.returncode,'log':'guest'+str(i)+'.log'}
try:
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:records=list(pool.map(build,[0,1]))
finally:
 (out/'observations.json').write_text(json.dumps({'records':records,'source_url':'https://download.strongswan.org/strongswan-6.0.3.tar.bz2','backend':'QEMU KVM FreeBSD 14.4 guest; Botan plugin build with default plugins disabled','scope':'Build is a prerequisite. Effective loaded plugin identity and useful protected traffic remain separate checks.'},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps(records))
