import argparse,hashlib,json,os,subprocess,tarfile
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root);out=root/'exports/twinet-source-build-v3';out.mkdir();workspace=root/'public-build/twinet-01f8-v3';workspace.mkdir(parents=True);records=[];error=None
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def command(argv,cwd=None,env=None,timeout=900):
 r=subprocess.run(argv,cwd=cwd,env=env,text=True,capture_output=True,timeout=timeout);records.append({'at':datetime.now(timezone.utc).isoformat(),'command':list(map(str,argv)),'working_directory':str(cwd)if cwd else None,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 if r.returncode:raise RuntimeError(r.stderr[-3000:])
 return r
try:
 archive=root/'public-sources/Twinet-01f8f4d-public-build-source.tar.gz';top='Twinet-01f8f4d632b779dbe78ec67992f5071dc596b00e'
 with tarfile.open(archive)as t:
  members=t.getmembers()
  for m in members:
   rel=Path(m.name);assert rel.parts[0]==top and'..'not in rel.parts and not rel.is_absolute();assert not(m.issym()or m.islnk()),'Unexpected source link'
  t.extractall(workspace,members=members)
 source=workspace/top;assert not(source/'internal/cli/kubernetes_test.go').exists();go=root/'toolchains/go/bin/go';env=dict(os.environ,GOTOOLCHAIN='local',GOPATH=str(workspace/'gopath'),GOMODCACHE=str(workspace/'modules'),GOCACHE=str(workspace/'cache'),CGO_ENABLED='0')
 command([str(go),'version'],env=env);command([str(go),'env','GOVERSION','GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN'],env=env)
 command([str(go),'mod','download'],cwd=source,env=env)
 modules=command([str(go),'list','-m','-json','all'],cwd=source,env=env);(out/'modules.json-stream').write_text(modules.stdout)
 command([str(go),'build','-trimpath','-buildvcs=false','-o',str(out/'twinet-online-build'),'./cmd/twinet'],cwd=source,env=env)
 command([str(go),'mod','vendor'],cwd=source,env=env)
 with tarfile.open(out/'twinet-vendor.tar.gz','w:gz')as t:t.add(source/'vendor',arcname='vendor')
 offline=dict(env,GOPROXY='off',GOSUMDB='off',GOMODCACHE=str(workspace/'empty-offline-modules'),GOCACHE=str(workspace/'fresh-offline-cache'))
 command([str(go),'build','-mod=vendor','-trimpath','-buildvcs=false','-o',str(out/'twinet-offline-build'),'./cmd/twinet'],cwd=source,env=offline)
 command([str(out/'twinet-offline-build'),'--help'],timeout=20)
 command([str(go),'version','-m',str(out/'twinet-offline-build')],env=env)
 for name in ['go.mod','go.sum']:(out/name).write_bytes((source/name).read_bytes())
 (out/'build-environment.json').write_text(json.dumps({'online':{k:env[k]for k in ['GOTOOLCHAIN','GOPATH','GOMODCACHE','GOCACHE','CGO_ENABLED']},'offline':{k:offline[k]for k in ['GOTOOLCHAIN','GOPATH','GOMODCACHE','GOCACHE','CGO_ENABLED','GOPROXY','GOSUMDB']},'input_source_archive_sha256':sha(archive),'online_binary_sha256':sha(out/'twinet-online-build'),'offline_binary_sha256':sha(out/'twinet-offline-build'),'vendor_archive_sha256':sha(out/'twinet-vendor.tar.gz')},indent=2)+'\n')
except Exception as exc:error=str(exc)
finally:
 (out/'collector.source.py').write_bytes(Path(__file__).read_bytes());(out/'observations.json').write_text(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'records':records,'error':error,'scope':['Build only the authorized pinned Twinet public source, with the unneeded flagged Kubernetes test fixture excluded. The source root is new and unrelated deployments remain untouched.','The retained official Go1.25.0 compiler is forced with GOTOOLCHAIN=local. The offline build uses a newly empty compiler cache and module cache, GOPROXY=off/GOSUMDB=off and the retained vendor source.','The new binary and help invocation establish buildability only. The previously tested deployment uses a separately pinned executable with its own identity; no binary equality or new deployment validation is claimed.']},indent=2)+'\n');(out/'manifest.json').write_text(json.dumps({'collector_sha256':sha(Path(__file__)),'files':[{'path':f.name,'sha256':sha(f),'bytes':f.stat().st_size}for f in out.iterdir()if f.is_file()]},indent=2)+'\n');print(json.dumps({'error':error,'records':len(records)}))
