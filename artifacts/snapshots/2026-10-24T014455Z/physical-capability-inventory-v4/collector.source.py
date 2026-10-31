import concurrent.futures,hashlib,json,subprocess
from datetime import datetime,timezone
from pathlib import Path
run=Path('artifacts/construction/2026-10-24T014455Z');out=Path('artifacts/snapshots/2026-10-24T014455Z/physical-capability-inventory-v4');out.mkdir()
hosts=['clnode176.clemson.cloudlab.us','clnode159.clemson.cloudlab.us','clnode163.clemson.cloudlab.us','pc08.cloudlab.umass.edu','pc22.cloudlab.umass.edu','pc16.cloudlab.umass.edu']
script="""import json,subprocess,pathlib,datetime
records=[]
def r(cmd):
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=20);records.append({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
for cmd in [['hostname'],['uname','-a'],['cat','/sys/class/dmi/id/product_uuid'],['lspci','-Dnn'],['ip','-j','-d','link','show'],['lsblk','-J','-o','NAME,TYPE,RO,FSTYPE'],['mokutil','--sb-state'],['bootctl','status','--no-pager'],['cat','/proc/cmdline'],['dpkg-query','-W','linux-image-*','shim-signed','grub-efi-amd64-signed']]:
 try:r(cmd)
 except Exception as e:records.append({'command':cmd,'error':str(e)})
for p in pathlib.Path('/sys/class/net').iterdir():
 if not(p/'device').exists():continue
 r(['ethtool','-i',p.name]);r(['ethtool',p.name]);r(['ip','-j','addr','show',p.name])
 try:port=(p/'phys_port_name').read_text().strip()
 except OSError as e:port='unavailable: '+str(e)
 records.append({'interface':p.name,'pci_device':str((p/'device').resolve()),'driver':str((p/'device/driver').resolve()),'physical_port_name':port})
records.append({'efi_present':pathlib.Path('/sys/firmware/efi').exists(),'scope':'Read-only inventory. No NIC, route, boot or existing workload configuration changes.'})
print(json.dumps(records))
"""
def worker(h):
 p=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hy@'+h,'sudo','-n','python3','-c',__import__('shlex').quote(script)],capture_output=True,text=True,timeout=120)
 f=out/(h.split('.')[0]+'.json');f.write_text(json.dumps({'host':h,'at':datetime.now(timezone.utc).isoformat(),'returncode':p.returncode,'records':json.loads(p.stdout)if p.returncode==0 else [],'stderr':p.stderr},indent=2)+'\n');return {'host':h,'returncode':p.returncode}
with concurrent.futures.ThreadPoolExecutor(max_workers=6)as pool:results=list(pool.map(worker,hosts))
(out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'hosts':results,'groups':['RG-053','RG-057','RG-073'],'scope':'Physical PCI NIC capabilities, assigned interfaces and read-only host signing/boot inventory. Link capability does not establish actual per-Red cable placement or classified physical protection.'},indent=2)+'\n')
(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n')
print(json.dumps(results))
