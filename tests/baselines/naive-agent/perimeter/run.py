"""Apply the existing Outer Firewall theorem to retained one-fault snapshots."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = HERE.parent / 'runs/20261112-isolated-theory-01'
sys.path.insert(0, str(ROOT / 'mcp'))
from tdn_evidence.parsers.execution import parse_execution


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def controls_from_intent(spec, policy):
    assert policy['protocol'] == 'ospf' and policy['additional_services'] == []
    devices = {d['id']: d for d in spec['devices']}
    result = []
    for link in spec['links']:
        for side, opposite in [('a', 'b'), ('b', 'a')]:
            endpoint, peer = link[side], link[opposite]
            device, neighbor = devices[endpoint['device']], devices[peer['device']]
            if [device['role'], neighbor['role']] != policy['neighbor_roles']:
                continue
            if endpoint['interface'] != policy['firewall_interface']:
                raise ValueError('Unexpected firewall underlay interface')
            local = next(i for i in device['interfaces'] if i['name'] == endpoint['interface'])
            remote = next(i for i in neighbor['interfaces'] if i['name'] == peer['interface'])
            local_ip = int(ipaddress.ip_interface(local['address']).ip)
            remote_ip = int(ipaddress.ip_interface(remote['address']).ip)
            for hook in policy['hooks']:
                src, dst = (remote_ip, local_ip) if hook == 'input' else (local_ip, remote_ip)
                for destination in policy['destinations']:
                    result.append({'device':device['id'], 'interface':device['id']+':'+local['name'],
                        'nativeName':local['name'], 'direction':'inbound' if hook=='input' else 'outbound',
                        'hook':hook, 'source':src, 'destination':dst if destination=='adjacent-unicast-address'
                        else int(ipaddress.ip_address(destination)), 'protocol':policy['protocol']})
    if not result:
        raise ValueError('Empty declared underlay policy')
    return result


def project(bundle, controls):
    kinds = {'inner':'vpn', 'outer':'vpn', 'firewall':'outerFirewall', 'gray-firewall':'grayFirewall',
             'transport':'ordinaryGrayRouter', 'switch':'ordinaryGraySwitch', 'host':'other', 'admin':'workstation'}
    sources = {d['id']: d for d in bundle['sourceDevices']}
    originals = {i['id']:i for i in bundle['sourceInterfaces']}
    bindings = {i['portId']:i for i in bundle['ifaceBindings']}
    components = [{'id':d['id'], 'site':d['site'] or 'transport', 'kind':kinds[d['role']],
        'layer':d['role'] if d['role'] in ['inner','outer'] else None,
        'level':{'classification':d['security_level_id'] or 'infrastructure',
                 'compartments':[], 'dissemination':[], 'otherControls':[]},
        'infrastructure':True} for d in sources.values()]
    interfaces = []
    names = []
    for index, native in enumerate(bundle['ports']):
        binding = bindings[index]
        original = originals[binding['interfaceId']]
        assert bundle['deviceIds'][original['device_id']] == native['owner']
        assert original['name'] == native['name']
        addresses = [int(ipaddress.ip_address(a['local'])) for a in original['addresses']
                     if a['family']=='inet' and a.get('scope')!='host']
        if len(addresses)>1:
            raise ValueError('Interface requires explicit address expansion')
        zone = original['zone']
        assert zone in ['red','gray','black','local','management']
        interfaces.append({'id':original['id'], 'device':original['device_id'],
            'zone':'hostLocal' if zone in ('local', 'management') else zone, 'address':addresses[0] if addresses else None,
            'namespaceAddresses':[int(ipaddress.ip_address(a['local']))+(2**128 if a['family']=='inet6' else 0)
                                  for a in original['addresses'] if a['family'] in ['inet','inet6']],
            'linkAddress':None, 'physical':binding['emulatedAttachment'],
            'externalData':binding['externalDataPort'], 'managementNetwork':binding['managementNetwork'],
            'mtu':original['mtu']})
        names.append(original['id'])
    owners = {i:name for name,i in bundle['deviceIds'].items()}
    records = {'components':components, 'interfaces':interfaces, 'ifaceNames':names,
        'ownerNames':[owners.get(i,'unlisted-device') for i in range(len(bundle['devices']))],
        'policies':[], 'tunnels':[], 'pairs':[], 'masks':[], 'ipsecSizes':[],
        'nativeDevices':bundle['devices'], 'nativeIfaces':bundle['ports'],
        'routes':bundle['routes'], 'links':bundle['links'], 'bridges':bundle['bridges']}
    #* Native policies are constructed inside Lean from the complete captured device rules.
    #* The firewall theorem uses no tunnel, payload-size, endpoint-service, or ACL-mask declarations.
    firewalls = []
    for device in components:
        if device['kind'] != 'outerFirewall':
            continue
        inside = names.index(device['id']+':inside')
        neighbors = {b for a,b in bundle['links'] if a==inside}
        candidates = {interfaces[i]['device'] for i in neighbors
                      if interfaces[i]['zone']=='black' and sources[interfaces[i]['device']]['role']=='outer'}
        if len(candidates)!=1:
            raise ValueError('Expected exactly one linked Outer encryptor')
        firewalls.append({'firewall':device['id'], 'outer':candidates.pop()})
    selected = [i for i in interfaces if i['zone']=='black' and sources[i['device']]['role']=='firewall']
    assert selected and all(i['address'] is not None for i in selected)
    assert len(selected)==2*len(firewalls)
    for control in controls:
        iface=next(i for i in interfaces if i['id']==control['interface'])
        expected=control['destination'] if control['hook']=='input' and control['destination']<3758096384 else None
        if control['hook']=='output':
            expected=control['source']
        if expected is not None:
            assert iface['address']==expected
    return {'records':records, 'controls':controls, 'firewalls':firewalls,
        'internalIfaces':[i['id'] for i in selected if i['id'].endswith(':inside')],
        'coverage':{'allDevices':len(components), 'allIfaces':len(interfaces),
                    'firewalls':len(firewalls), 'checkedBlackIfaces':[i['id'] for i in selected],
                    'managementMapping':'Management interfaces retain ownership, addresses and rules; their zone is local with managementNetwork=true. The theorem selects Black data interfaces.'}}


def prepare(folder, target, controls):
    target.mkdir(parents=True, exist_ok=False)
    bundle = parse_execution(folder/'snapshot/native', folder/'snapshot/processing')
    projected = project(bundle, controls)
    write(target/'input.json', projected)
    shutil.copy2(HERE/'FirewallCompliance.lean', target/'FirewallCompliance.lean')
    write(target/'provenance.json', {'source':str(folder.relative_to(ROOT)),
        'nativeManifestSHA256':digest(folder/'snapshot/native/manifest.json'),
        'snapshotSHA256':digest(folder/'snapshot/native/snapshot.json'),
        'processingManifestSHA256':digest(folder/'snapshot/processing/manifest.json'),
        'inputSHA256':digest(target/'input.json'), 'templateSHA256':digest(HERE/'FirewallCompliance.lean')})
    return target


def check(target):
    start=datetime.now(timezone.utc).isoformat()
    clock=time.monotonic()
    p=subprocess.run([str(Path.home()/'.elan/bin/lake'),'env','lean','--json',str(target/'FirewallCompliance.lean')],
        cwd=ROOT, capture_output=True, text=True, timeout=240)
    elapsed=time.monotonic()-clock
    (target/'lean.jsonl').write_text(p.stdout)
    (target/'stderr.txt').write_text(p.stderr)
    messages=[json.loads(line) for line in p.stdout.splitlines() if line.startswith('{')]
    diagnostics=[json.loads(line.removeprefix('TDN_FIREWALL_DIAGNOSTICS:'))
                 for line in [m.get('data','').strip() for m in messages] if line.startswith('TDN_FIREWALL_DIAGNOSTICS:')]
    if len(diagnostics)!=1:
        raise ValueError('Expected one diagnostic result: '+p.stdout[-3000:])
    errors=[m for m in messages if m.get('severity')=='error']
    false_checks=bool(errors) and all('Tactic `native_decide` evaluated that the proposition' in e['data']
        and 'is false' in e['data'] for e in errors)
    result={'case':target.name, 'started_at':start, 'seconds':elapsed, 'returncode':p.returncode,
        'errors':errors,'rejected_rules':diagnostics[0], 'full_rejected_rules':[json.loads(line.removeprefix('TDN_FIREWALL_FULL_DIAGNOSTICS:')) for line in [m.get('data','').strip() for m in messages] if line.startswith('TDN_FIREWALL_FULL_DIAGNOSTICS:')][0],'status':'rejected' if false_checks else 'accepted' if p.returncode==0 else 'error',
        'inputSHA256':digest(target/'input.json'), 'sourceSHA256':digest(target/'FirewallCompliance.lean')}
    write(target/'result.json',result)
    print(json.dumps({k:result[k] for k in ['case','status','seconds']}),flush=True)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--network',choices=[f'net-{n:02}' for n in range(1,6)])
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    build=subprocess.run([str(Path.home()/'.elan/bin/lake'),'build',
        'TDN.Deployments.DeviceCheckDefaults','TDN.Deployments.Perimeter_DeviceModel',
        'TDN.Requirements.PerimeterDeviceAclChecks'],cwd=ROOT,capture_output=True,text=True)
    (args.output/'dependencies.log').write_text(build.stdout+build.stderr)
    if build.returncode:
        raise RuntimeError('Lean dependency build failed')
    write(args.output/'sources.json',{'at':datetime.now(timezone.utc).isoformat(),
        'files':{str(path.relative_to(ROOT)):digest(path)
                 for path in [*HERE.glob('*.py'),*HERE.glob('*.lean'),*HERE.glob('*.json'),
                              *sorted((ROOT/'TDN').rglob('*.lean'))]}})
    policy=json.loads((HERE/'approved-control-policy.json').read_text())
    shutil.copy2(HERE/'approved-control-policy.json',args.output/'approved-control-policy.json')
    targets=[]
    for n in range(1,6):
        network=f'net-{n:02}'
        if args.network and network!=args.network:
            continue
        clean=SOURCE/'controls'/network
        faulty=SOURCE/'cases'/(network+'-MSC-PF-22')
        intent=json.loads((clean/'snapshot/native/spec.json').read_text())
        assert intent==json.loads((faulty/'snapshot/native/spec.json').read_text())
        controls=controls_from_intent(intent,policy)
        write(args.output/'policies'/(network+'.json'), {'specSHA256':digest(clean/'snapshot/native/spec.json'),
            'policySHA256':digest(HERE/'approved-control-policy.json'), 'controls':controls})
        targets.append(prepare(clean,args.output/(network+'-clean'),controls))
        targets.append(prepare(faulty,args.output/(network+'-MSC-PF-22'),controls))
    if not args.prepare_only:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(check,targets))
        write(args.output/'results.json',results)


if __name__=='__main__':
    main()
