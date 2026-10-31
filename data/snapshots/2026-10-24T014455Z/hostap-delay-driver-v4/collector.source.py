import difflib,hashlib,json,shutil,subprocess
from pathlib import Path
from datetime import datetime,timezone
root=Path('/users/hy/tdn-continuation-2026-10-24T014455Z');out=root/'exports/hostap-delay-driver-v4';out.mkdir();tree=root/'hostap-delay-fixed/wpa_supplicant-2.12';records=[];error=None
try:
 shutil.copytree(root/'hostap-delay/wpa_supplicant-2.12',tree)
 path=tree/'src/drivers/driver_macsec_linux.c';before=path.read_text();a=before.index('static int macsec_drv_set_receive_lowest_pn(');b=before.index('\n}',a)+2;function=before[a:b];assert 'MACSEC_SA_ATTR_PN, sa->next_pn' in function
 fixed=function.replace('sa->next_pn','sa->lowest_pn');after=before[:a]+fixed+before[b:];path.write_text(after)
 (out/'driver.before.c').write_text(before);(out/'driver.after.c').write_text(after);(out/'driver.patch').write_text(''.join(difflib.unified_diff(before.splitlines(keepends=True),after.splitlines(keepends=True),fromfile='a/src/drivers/driver_macsec_linux.c',tofile='b/src/drivers/driver_macsec_linux.c')))
 work=tree/'wpa_supplicant';(out/'wpa_supplicant.config').write_bytes((work/'.config').read_bytes())
 for cmd in [['make','-j4'],['sha256sum','./wpa_supplicant'],['./wpa_supplicant','-v'],['ldd','./wpa_supplicant']]:
  r=subprocess.run(cmd,cwd=work,capture_output=True,text=True,timeout=180);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':cmd,'cwd':str(work),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  if r.returncode:raise RuntimeError(r.stderr[-2000:])
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes())
 (out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':'Original hostap Linux set_receive_lowest_pn uses the receive_sa next_pn field even though KaY has updated lowest_pn. This owned callback repair sends lowest_pn to the kernel and logs that same value. Prior bounded-Hello and PN-history patches remain in the copied owned tree. The preceding active-bit-only experiment failed to reject three-second data and remains preserved.'},indent=2)+'\n')
 (out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.iterdir() if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'error':error}))
