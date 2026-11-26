"""Check restoration of a spare virtual link before using the attachment trial."""

import argparse
from pathlib import Path

from mode_lab import remote
from run_mode_trial import write
from unplug_lab import SCRIPT


REHEARSAL = """
from pathlib import Path
import json,secrets,subprocess,sys,tempfile,time
req=json.load(sys.stdin);script=req['script'];side=req.get('side','inside');nonce=secrets.token_hex(6)
if side not in ('inside','outside','gray2','gray4'):raise ValueError('Unknown rehearsal side')
ports=['s'+str(i+1) for i in range(int(side[-1]))] if side.startswith('gray') else [side]
a='tdn-link-test-a-'+nonce; b='tdn-link-test-b-'+nonce; parked='tns-'+nonce
def call(*args):
    return subprocess.check_output(list(args),text=True,stderr=subprocess.STDOUT,timeout=25)
with tempfile.TemporaryDirectory() as scratch:
    lease=Path(scratch)/'lease'; worker=None
    try:
        for n in (a,b):call('ip','netns','add',n)
        for i,port in enumerate(ports):
            peer='other'+str(i)
            call('ip','-n',a,'link','add',port,'type','veth','peer','name',peer,'netns',b)
            call('ip','netns','exec',a,'sysctl','-qw','net.ipv6.conf.'+port+'.disable_ipv6=1')
            call('ip','-n',a,'addr','add',f'192.0.2.{4*i+1}/30','broadcast',f'192.0.2.{4*i+3}','dev',port)
            call('ip','-n',a,'link','property','add','dev',port,'altname','tdn-test-'+port)
            call('ip','-n',b,'link','set',peer,'up');call('ip','-n',a,'link','set',port,'up')
        worker=subprocess.Popen(['ip','netns','exec',a,'sleep','120']);time.sleep(.3)
        lookup=\"pid=cmd(['docker','inspect','-f','{{.State.Pid}}',dev]).strip()\"
        if script.count(lookup)!=1:raise ValueError('Unknown worker namespace lookup')
        s=script.replace(lookup,'pid='+repr(str(worker.pid))).replace('/var/tmp/tdn-naive-rg-mode-lease',str(lease))
        records=[]
        for action in ('edit','restore'):
            dev={'gray2':'NT_GF_A','gray4':'NF_GF_A'}.get(side,'NT_OF_A1')
            req={'device':dev,'nonce':nonce,'ports':ports,'action':action,'recovery':'pass'}
            p=subprocess.run([sys.executable,'-c',s],input=json.dumps(req),text=True,capture_output=True)
            if p.returncode:raise RuntimeError(p.stderr[-1000:])
            records.append(json.loads(p.stdout))
        if records[0]['original']!=records[1]['restored']:raise ValueError('Restoration mismatch')
        print(json.dumps({'fixture':'two isolated namespaces with no uplink','ports':ports,'side':side,'result':'pass',
              'original':records[0]['original'],'restored':records[1]['restored']}))
    finally:
        subprocess.run(['systemctl','stop','tdn-rg-rollback-'+nonce+'.timer'],capture_output=True)
        if worker is not None:worker.terminate();worker.wait()
        for n in (a,b,parked):subprocess.run(['ip','netns','del',n],capture_output=True)
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--side", choices=("inside", "outside", "gray2", "gray4"), default="inside"
    )
    args = parser.parse_args()
    result = remote(REHEARSAL, {"script": SCRIPT, "side": args.side})
    write(args.output, result)
    print(result["result"])
