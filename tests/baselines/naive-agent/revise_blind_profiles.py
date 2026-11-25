"""Replace disruptive transport-mode injections before freezing the blind trial."""
import json
from pathlib import Path
from common import BASE, now, write_json

run = BASE / 'runs/20261112-blind-theory-01'
requirements = json.loads((run / 'requirements.json').read_text())
replacements = {
    'MSC-IR-1': ('MSC-PF-5', 'gray', 'For all Inner Encryption Component interfaces connected to a Gray Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, IPsec, MKA, MACsec, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.', 45),
    'MSC-OR-1': ('MSC-PF-3', 'black', 'For all Outer VPN Gateway interfaces connected to a Black Network, traffic filtering rules must be applied to both inbound and outbound traffic, such that only IKE, ESP, and control plane protocols (as defined in this CP) approved by organization-defined policy are allowed.', 44),
}
records = []
for path in sorted((run / 'original-profiles').glob('net-*.json')):
    profile = json.loads(path.read_text())
    for case in profile['mutations']:
        previous = case['requirement']
        if previous not in replacements:
            case['validated'] = False
            continue
        requirement, iface, quote, page = replacements[previous]
        device = next(d for d in profile['topology']['devices'] if d['id'] == case['device'])
        destination = next(i['address'].split('/')[0] for i in device['interfaces'] if i['name'] == iface)
        case.update(case_id=profile['network'] + '-' + requirement, requirement=requirement,
                    operation='allow_packet', description='Accept a GRE data packet on the external interface.',
                    parameters={'chain': 'INPUT', 'ingress': iface, 'destination': destination, 'protocol': 'gre'},
                    validated=False)
        records.append({'network': profile['network'], 'removed': previous, 'replacement': requirement,
                        'reason': 'ESP transport with subnet selectors prevented CHILD SA establishment and masked unrelated faults. Restore tunnel mode and add an independently observable external GRE allowance.'})
        requirements[requirement] = {'page': page, 'text': quote}
    write_json(run / 'profiles' / path.name, profile)
for old in replacements:
    requirements.pop(old)
write_json(run / 'requirements.json', requirements)
write_json(run / 'fault-design-revision.json', {'at': now(), 'changes': records, 'distinct_requirement_targets_per_network': 20})
