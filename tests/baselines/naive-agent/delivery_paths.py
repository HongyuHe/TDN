"""Replay the original permitted Red deliveries using TDN's forwarding-step checker."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from delivery_lab import intended_pairs
from measure import typecheck
from mode_lab import profile, remote
from observe_controls import HERE, NETWORKS


ROOT = HERE.parents[2]
GENERATOR = ROOT / 'scripts/construction/generate_execution_witness.py'
ROUTE_FIELDS = 'ingress egress destPrefixLow destPrefixHigh prefixLength metric tablePriority'.split()
POLICY_FIELDS = 'id tag sender receiver sourceLow sourceHigh destinationLow destinationHigh priority requiredSpi'.split()


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fields(record, names):
    return [record[name] for name in names]


def generator_input(records, native):
    policies = {}
    states = {}
    for name, index in records['deviceIds'].items():
        device = records['devices'][index]
        policies[name] = {direction: [fields(r, POLICY_FIELDS) for r in device[key]] for direction, key in [('out', 'egressPolicies'), ('in', 'ingressPolicies')]}
        states[name] = [fields(r, ('reqid', 'spi', 'sender', 'receiver')) for r in device['states']]
    return {'snapshot': str(native.resolve()), 'port_ids': records['portIds'], 'levels': records['levels'],
            'links': records['links'], 'switches': records['bridges'], 'route_gateways': records['routeGateways'],
            'routes': [fields(r, ROUTE_FIELDS) for r in records['routes']], 'policies': policies, 'states': states}


def red_iface(device):
    matches = [i for i in device['interfaces'] if i['zone'] == 'red' and i.get('address')]
    if len(matches) != 1:
        raise ValueError('Expected a designated Red host interface on ' + device['id'])
    return device['id']+':'+matches[0]['name'], int(ipaddress.ip_interface(matches[0]['address']).ip)


def clean_paths(run, network):
    declared = profile(network)
    devices = {d['id']: d for d in declared['topology']['devices']}
    records = read(run / 'controls' / (network+'-frozen') / 'forwarding/evidence.json')
    native = run / 'raw/controls' / network / 'snapshot/native'
    paths = []
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        (work/'input.json').write_text(json.dumps(generator_input(records, native)))
        for source, destination, _ in intended_pairs(declared):
            src, src_addr = red_iface(devices[source]); dst, dst_addr = red_iface(devices[destination])
            argv = [sys.executable, str(GENERATOR), str(work/'input.json'), '--module', 'TDN.Models.RecordedForwarding',
                    '--namespace', 'BenchmarkPositive', '--source-port', src, '--destination-port', dst,
                    '--trace', str(work/'trace.json'), '--records', str(work/'records.json'), '--output', str(work/'proposed.lean')]
            proposed = subprocess.run(argv, capture_output=True, text=True, timeout=90)
            if proposed.returncode:
                raise ValueError(f'Clean path generation failed for {source} to {destination}: '+proposed.stderr[-700:])
            raw = read(work/'records.json'); prefix = 'TDN.Deployments.BenchmarkPositive.witness'
            actions = raw[prefix+'Actions']; states=[raw[prefix+f'State{i}'] for i in range(len(actions)+1)]
            for state in states:
                state['authenticatedInboundPolicies'] = state.pop('authenticated')
                frame = state['frame']; frame['ingressIface'] = frame.pop('enteredIface')
            paths.append({'source':src,'destination':dst,'sourceAddress':src_addr,'destinationAddress':dst_addr,
                          'start':states[0],'steps':list(zip(actions,states[1:]))})
    if not paths or len({(p['source'],p['destination']) for p in paths}) != len(paths):
        raise ValueError('Empty or duplicated intended Red peer pairs')
    dest = run/'controls'/(network+'-approved-paths.json')
    with dest.open('x') as file:
        json.dump({'portIds':records['portIds'],'paths':paths}, file, separators=(',',':'))


def clean_management(run, network):
    devices = profile(network)['topology']['devices']
    services = []
    for device in devices:
        if device['role'] != 'gray-firewall' or not device.get('admin'):
            continue
        iface = next(i for i in device['interfaces'] if i['zone'] == 'management')
        host = next(d['id'] for d in devices if d['role']=='admin' and any(
            str(ipaddress.ip_interface(i['address']).ip)==device['admin'] for i in d['interfaces'] if i.get('address')))
        address = str(ipaddress.ip_interface(iface['address']).ip)
        services.append({'iface':device['id']+':'+iface['name'], 'sourceDevice':host, 'sourceAddress':device['admin'],
                         'destinationAddress':address, 'destinationPort':8443})
    if services:
        program = """
import json,subprocess,sys
items=json.load(sys.stdin)
for item in items:
    if (item['sourceDevice'],item['destinationAddress']) not in [('QM_AW_A99','172.30.109.20'),('QM_AW_B99','172.30.119.20')]:
        raise ValueError('Unexpected management circuit')
    sample='import socket,sys,json; s=socket.create_connection((sys.argv[1],8443),4); print(json.dumps(s.getsockname())); s.close()'
    endpoint=json.loads(subprocess.check_output(['docker','exec',item['sourceDevice'],'python3','-c',sample,item['destinationAddress']],text=True,timeout=9))
    if endpoint[0]!=item['sourceAddress']:raise ValueError('Unexpected source address')
    item['sourcePort']=endpoint[1]
print(json.dumps(items))
"""
        services = remote(program,services)
    with (run/'controls'/(network+'-management-inputs.json')).open('x') as file:
        json.dump(services,file,indent=2);file.write('\n')


def current_seals(records):
    seals = {}
    for tunnel in records['ipsecTunnelBindings']:
        if not (tunnel['senderInstalled'] and tunnel['receiverInstalled'] and tunnel['senderPolicies'] and tunnel['receiverPolicies']):
            continue
        seal = tunnel['seal']
        key = (seal['tag'],seal['sender'],seal['receiver'])
        seals.setdefault(key,set()).add(seal['association'])
    return seals


def bind_state(state, original_names, current_ids, seals):
    state = deepcopy(state)
    frame = state['frame']
    state['iface'] = current_ids[original_names[state['iface']]]
    frame['ingressIface'] = current_ids[original_names[frame['ingressIface']]]
    for layer in frame['encapLayers']:
        seal = layer['authentication']; candidates = seals.get((seal['tag'],seal['sender'],seal['receiver']),set())
        if candidates and seal['association'] not in candidates:
            seal['association'] = min(candidates)
    state['authenticated'] = state.pop('authenticatedInboundPolicies')
    frame['enteredIface'] = frame.pop('ingressIface')
    return state


def check(run, network, records_file, output):
    records = read(records_file); approved = read(run/'controls'/(network+'-approved-paths.json'))
    original_names = {index:name for name,index in approved['portIds'].items()}; ids = records['portIds']
    seals = current_seals(records); demands = []; paths = []
    members = {d['id']:d for d in profile(network)['topology']['devices']}
    for src,dst,_ in intended_pairs(profile(network)):
        source,sa = red_iface(members[src]); dest,da = red_iface(members[dst])
        demands.append({'sourceIface':ids[source],'destinationIface':ids[dest],'sourceAddress':sa,'destinationAddress':da})
    absent = set(records['validation']['snapshot'].get('ipv4_link_observations', {}).get('absent_interfaces', []))
    for p in approved['paths']:
        if any(original_names[index] in absent for state in [p['start'], *(s for _,s in p['steps'])]
               for index in (state['iface'],state['frame']['ingressIface'])):
            continue
        demand = {'sourceIface':ids[p['source']],'destinationIface':ids[p['destination']],
                  'sourceAddress':p['sourceAddress'],'destinationAddress':p['destinationAddress']}
        paths.append({'demand':demand,'start':bind_state(p['start'],original_names,ids,seals),
                      'steps':[(a,bind_state(s,original_names,ids,seals)) for a,s in p['steps']]})
    data = {k:records[k] for k in ('devices','ports','routes','links','bridges')}
    services=[]
    for s in read(run/'controls'/(network+'-management-inputs.json')):
        services.append({'iface':ids[s['iface']],'sourceAddress':int(ipaddress.ip_address(s['sourceAddress'])),
                         'destinationAddress':int(ipaddress.ip_address(s['destinationAddress'])),
                         'sourcePort':s['sourcePort'],'destinationPort':s['destinationPort']})
    data.update(demands=demands,paths=paths,managementServices=services)
    source = HERE/'DeliveryPathChecks.lean'
    return typecheck(source,output,data,set(source.read_text().splitlines()))


def check_trial(run, network, trial):
    registration = read(run/'delivery-protocol.json')
    if any(digest(run/path)!=expected for path,expected in registration['control_files_sha256'].items()):
        raise ValueError('An intended delivery or management reference changed')
    if digest(HERE/'DeliveryPathChecks.lean')!=registration['clean_proofs'][network]['source_sha256']:
        raise ValueError('The proof program differs from its clean control')
    records = trial/'tdn-full/forwarding/evidence.json'
    if not records.is_file():
        result = {'status':'input_unavailable','reason':'The evidence importer did not produce a forwarding model for this snapshot.'}
    else:
        try:
            result = check(run,network,records,trial/'delivery-check')
        except (ValueError, KeyError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            result = {'status':'input_unavailable','reason':str(exc)}
    (trial/'delivery-check-status.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def register(run):
    clean = {}; inputs = {}; pairs = {}; transitions = {}
    for n in NETWORKS:
        proof = read(run/'controls'/(n+'-delivery-check')/'result.json')
        if proof['status']!='pass':
            raise ValueError('Missing positive delivery control for '+n)
        clean[n] = {k:proof[k] for k in ('source_sha256','evidence_sha256')}
        for suffix in ('-approved-paths.json','-management-inputs.json'):
            p=run/'controls'/(n+suffix);inputs[str(p.relative_to(run))]=digest(p)
        selection=read(run/'controls'/(n+'-approved-paths.json'))['paths']
        pairs[n]=len(selection);transitions[n]=sum(len(p['steps']) for p in selection)
    result={'registered_at':datetime.now(timezone.utc).isoformat(),'clean_proofs':clean,'control_files_sha256':inputs,
            'sources_sha256':{str(p.relative_to(ROOT)):digest(p) for p in (HERE/'DeliveryPathChecks.lean',HERE/'delivery_paths.py',GENERATOR,ROOT/'TDN/Models/RecordedForwarding.lean')},
            'allowed_pairs':pairs,'forwarding_steps':transitions,
            'selection':'Positive paths were generated on the three registered clean captures, before the first forwarding-denial trial. Each proved delivery starts at an authorized Red source and ends at the designated same-network peer. Legitimate public association identifiers can be rebound to the same tunnel endpoints after rekeying.',
            'earlier_trials':'The existing isolated mode trials are replayed against their retained snapshots with this same proof. Original six-check timings remain available separately.'}
    with (run/'delivery-protocol.json').open('x') as file:
        file.write(json.dumps(result,indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path); parser.add_argument('network',nargs='?',choices=NETWORKS)
    parser.add_argument('--register',action='store_true')
    parser.add_argument('--generate-clean',action='store_true')
    parser.add_argument('--collect-management',action='store_true')
    parser.add_argument('--records',type=Path); parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.register:register(args.run)
    if not args.network and (args.generate_clean or args.collect_management or args.records):parser.error('Select a network')
    if args.generate_clean:clean_paths(args.run,args.network)
    if args.collect_management:clean_management(args.run,args.network)
    if args.records and args.output:
        result=check(args.run,args.network,args.records,args.output)
        print(args.network,result['status'],result['typecheck_ns'],[e['data'][:200] for e in result['errors']][:3])
