import os,json,pathlib,subprocess,re
records=[]
for p in sorted(pathlib.Path('/proc').glob('[0-9]*')):
 try:
  args=p.joinpath('cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace');name=p.joinpath('comm').read_text().strip()
  if int(p.name)==os.getpid():args='[inventory collector]'
  args=re.sub(r'(?i)(password|secret|token|mka_cak)([= ]+)[^ ]+',r'\1\2[REDACTED]',args)
  records.append({'pid':int(p.name),'name':name,'command':args,'process_state':p.joinpath('stat').read_text().rsplit(') ',1)[1].split()[0]})
 except (FileNotFoundError,PermissionError):pass
out={'processes':records,'commands':[],'public_files':{},'access':[],'startup_files':{}}
for cmd in [['ss','-H','-a','-n','-p','-A','all'],['systemctl','list-unit-files','--state=enabled','--no-pager'],['ip','-j','address'],['ip','-j','route','show','table','all'],['sysctl','net.ipv4.ip_forward','net.ipv6.conf.all.forwarding','net.ipv6.conf.all.autoconf','net.ipv6.conf.default.autoconf']]:
 try:
  r=subprocess.run(cmd,text=True,capture_output=True,timeout=10);out['commands'].append({'argv':cmd,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 except Exception as e:out['commands'].append({'argv':cmd,'unavailable':str(e)})
for name in ['/etc/resolv.conf','/etc/nsswitch.conf','/etc/network/interfaces','/etc/systemd/networkd.conf','/etc/ssh/sshd_config']:
 p=pathlib.Path(name);out['public_files'][name]={'exists':p.exists(),'content':p.read_text() if p.exists() else None}
for directory in ['/etc/init.d','/etc/rc0.d','/etc/rc1.d','/etc/rc2.d','/etc/rc3.d','/etc/rc4.d','/etc/rc5.d','/etc/rc6.d','/etc/netplan','/etc/systemd/network','/etc/dhcp']:
 p=pathlib.Path(directory);out['startup_files'][directory]=[str(q) for q in p.iterdir()] if p.exists() else []
shadow={}
p=pathlib.Path('/etc/shadow')
if p.exists():
 for line in p.read_text().splitlines():
  f=line.split(':');shadow[f[0]]={'password_locked':f[1].startswith(('!','*')),'empty_password':f[1]=='','hash_exported':False}
for line in pathlib.Path('/etc/passwd').read_text().splitlines():
 f=line.split(':');out['access'].append({'user':f[0],'uid':int(f[2]),'shell':f[-1],**shadow.get(f[0],{'password_status':'unavailable'})})
print(json.dumps(out))
