"""Run the existing native and processing collectors on each experimental network."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys


def collect(profile, root, sources):
    spec = profile['topology']
    for device in spec['devices']:
        observed = subprocess.run(['docker', 'exec', device['id'], 'ip', '-j', '-d', 'address', 'show'],
                                  capture_output=True, text=True, check=True)
        declared = {i['name'] for i in device['interfaces']}
        for iface in json.loads(observed.stdout):
            if iface['ifname'] not in declared and iface.get('linkinfo', {}).get('info_kind') == 'dummy':
                device['interfaces'].append({'name': iface['ifname'], 'zone': 'local', 'mtu': iface['mtu']})
    target = root / profile['network']
    target.mkdir(parents=True, exist_ok=False)
    spec_path = target / 'spec.json'
    spec_path.write_text(json.dumps(spec, indent=2)+'\n')
    commands = [
        [sys.executable, str(sources / 'collect_native_v2.py'), '--spec', str(spec_path),
         '--output', str(target / 'native'), '--configuration-id', profile['network'], '--run-id', 'blind-theory-01', '--platform-interface-names', 'gre0,gretap0,erspan0'],
        [sys.executable, str(sources / 'collect_processing.py'), '--spec', str(spec_path),
         '--output', str(target / 'processing')],
    ]
    results = []
    for command in commands:
        p = subprocess.run(command, capture_output=True, text=True)
        results.append({'command':command,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        (target / 'collection.json').write_text(json.dumps(results,indent=2)+'\n')
    return {'network':profile['network'],'returncodes':[r['returncode'] for r in results]}


def main():
    p=argparse.ArgumentParser();p.add_argument('--profiles',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--sources',type=Path,required=True)
    a=p.parse_args();profiles=[json.loads(f.read_text()) for f in sorted(a.profiles.glob('net-*.json'))]
    with ThreadPoolExecutor(max_workers=5) as pool:
        results=list(pool.map(lambda x:collect(x,a.output,a.sources),profiles))
    print(json.dumps(results))


if __name__=='__main__':main()
