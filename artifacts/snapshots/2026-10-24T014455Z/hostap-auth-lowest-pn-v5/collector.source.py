import argparse,difflib,hashlib,json,shutil,subprocess,tarfile
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/hostap-auth-lowest-pn-v5';out.mkdir();target=root/'hostap-pq-delay-auth';records=[];error=None
try:
 shutil.copytree(root/'hostap-pq-delay',target);tree=target/'hostapd-2.12';file=tree/'src/ap/wpa_auth_kay.c';before=file.read_text()
 wrapper="""static int hapd_set_receive_lowest_pn(void *priv, struct receive_sa *sa)
{
 struct hostapd_data *hapd = priv;

 if (!hapd->driver->set_receive_lowest_pn)
  return -1;
 return hapd->driver->set_receive_lowest_pn(hapd->drv_priv, sa);
}


"""
 needle='static int hapd_get_transmit_next_pn(';assert needle in before;after=before.replace(needle,wrapper+needle,1)
 needle='\tkay_ctx->get_receive_lowest_pn = hapd_get_receive_lowest_pn;';assert needle in after;after=after.replace(needle,needle+'\n\tkay_ctx->set_receive_lowest_pn = hapd_set_receive_lowest_pn;',1);file.write_text(after)
 (out/'wpa_auth_kay.before.c').write_text(before);(out/'wpa_auth_kay.after.c').write_text(after);(out/'callback.patch').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/src/ap/wpa_auth_kay.c',tofile='b/src/ap/wpa_auth_kay.c')))
 (out/'hostapd.config').write_bytes((tree/'hostapd/.config').read_bytes())
 args=['docker','run','--rm','-v',str(root)+':'+str(root),'-w',str(tree/'hostapd'),'tdn-hostap-pq:20261024-v3']
 for cmd in [['make','clean'],['make','-j4'],['./hostapd','-v'],['ldd','./hostapd'],['sha256sum','./hostapd']]:
  r=subprocess.run(args+cmd,capture_output=True,text=True,timeout=300);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':args+cmd,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  if r.returncode and cmd[-1]!='-v':raise RuntimeError(r.stderr[-1000:])
 archive=root/'scripts/hostapd-2.12.tar.gz';patch=[];hashes=[]
 with tarfile.open(archive)as tar:
  for m in tar.getmembers():
   if not m.isfile()or not(m.name.endswith(('.c','.h'))or Path(m.name).name=='Makefile'):continue
   old=tar.extractfile(m).read();rel=Path(m.name).relative_to('hostapd-2.12');f=tree/rel
   if not f.is_file()or f.read_bytes()==old:continue
   new=f.read_bytes();patch.extend(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)));hashes.append({'path':str(rel),'official_sha256':hashlib.sha256(old).hexdigest(),'final_sha256':hashlib.sha256(new).hexdigest()})
 (out/'hostapd.full.patch').write_text(''.join(patch));(out/'source-hashes.json').write_text(json.dumps({'official_archive_url':'https://w1.fi/releases/hostapd-2.12.tar.gz','archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'changed':hashes},indent=2)+'\n')
except Exception as e:error=str(e)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['The official hostapd 2.12 authenticator KAY setup wires the receive-PN getter but omits the setter callback. Reverse EAP v17 logs explicitly report the missing secy operation and accept delayed data.','The owned repair forwards the existing secy set_receive_lowest_pn callback to the existing driver API using hapd->drv_priv and the same receive_sa. It adds no new packet-number interpretation; the already justified zero-window Linux setter receives the KAY-computed value.','Original v17 binaries and failed observations remain unchanged. Full standard conformance, nonzero windows and replacement-SA overlap remain separate.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'files':[{'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in out.iterdir()if p.is_file()]},indent=2)+'\n');print(json.dumps({'error':error}))
 if error:raise SystemExit(1)
