import argparse,hashlib,json,os,subprocess
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--worker',required=True);args=p.parse_args();root=Path(args.root);out=root/'exports'/('multiworker-'+args.worker+'-sidecar-bindings-v3');out.mkdir();records=[];error=None
def run(cmd):
 r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=30);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if r.returncode:raise RuntimeError(r.stderr)
 return r
try:
 hardware=Path('/sys/class/dmi/id/product_uuid').read_text().strip();kernel=run(['uname','-a']).stdout.strip();host=run(['hostname']).stdout.strip()
 names=run(['docker','ps','--format','{{.Names}}']).stdout.splitlines();selected=[n for n in names if n.startswith('MW_') and n.endswith('-frr')];bindings=[]
 for name in selected:
  helper=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0];target=helper['HostConfig']['NetworkMode'];assert target.startswith('container:'),target
  parent=json.loads(subprocess.check_output(['docker','inspect',target.split(':',1)[1]],text=True))[0]
  def identity(o):
   pid=o['State']['Pid'];return {'id':o['Id'],'name':o['Name'].lstrip('/'),'pid':pid,'image_id':o['Image'],'image_name':o['Config']['Image'],'labels':o['Config'].get('Labels',{}),'network_mode':o['HostConfig']['NetworkMode'],'running':o['State']['Running'],'network_namespace':os.readlink('/proc/'+str(pid)+'/ns/net'),'process_namespace':os.readlink('/proc/'+str(pid)+'/ns/pid')}
  binding={'worker':args.worker,'host':host,'hardware_uuid':hardware,'kernel':kernel,'helper':identity(helper),'parent':identity(parent)};binding['same_network_namespace']=binding['helper']['network_namespace']==binding['parent']['network_namespace'];assert binding['same_network_namespace'];bindings.append(binding)
  run(['docker','exec',name,'vtysh','-c','show version'])
 (out/'bindings.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'worker':args.worker,'host':host,'hardware_uuid':hardware,'kernel':kernel,'bindings':bindings},indent=2)+'\n')
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':'Read-only binding of actual MW FRR helpers to parent network namespaces and worker hardware. Other deployments are not changed.'},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error,'helpers':len(selected) if 'selected'in locals() else 0}))
