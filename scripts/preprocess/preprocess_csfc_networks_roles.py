#!/usr/bin/env python3
"""Build evidence-linked network and device-role views for the MSC CP."""
import argparse
import json
import re
from pathlib import Path

from reconcile_csfc_extraction import apply_mappings, write_networks, write_requirement_links

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'artifacts/extraction'
NETWORKS = OUT / 'networks'
ROLES = OUT / 'roles'


def write(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')


def norm(text):
    return re.sub(r'\s+', ' ', text).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--networks-only', action='store_true', help='Regenerate networks and their role-instance projection without rebuilding the role inventory.')
    args = parser.parse_args()
    units = [json.loads(line) for line in (OUT / 'source/source_index.jsonl').read_text().splitlines()]
    by_id = {u['source_id']: u for u in units}

    def pages(u):
        return {loc['page'] for loc in u['locations']}

    def select(page_numbers, terms=None):
        return [u for u in units if pages(u) & set(page_numbers) and (terms is None or any(t.lower() in u['text'].lower() for t in terms))]

    def refs(page_numbers, terms=None):
        return [u['source_id'] for u in select(page_numbers, terms)]

    def quote(us):
        return [{'source_id': u['source_id'], 'text': u['text']} for u in us]

    def fact(text, source_ids, basis='source_stated'):
        return {'text': text, 'basis': basis, 'source_ids': source_ids}

    role_specs = [
        ('solution-component', 'Solution Component', r'(?:MSC |CSfC )?Solution Components?', 'Generic component category to which the CP assigns solution-wide requirements.'),
        ('encryption-component', 'Encryption Component', r'Encryption Components?', 'Generic VPN Gateway or MACsec Device category.'),
        ('inner-encryption', 'Inner Encryption Component', r'Inner Encryption Components?', 'Terminates the inner encryption layer.'),
        ('outer-encryption', 'Outer Encryption Component', r'Outer Encryption Components?', 'Terminates the outer encryption layer.'),
        ('vpn-gateway', 'VPN Gateway', r'(?:IPsec )?VPN Gateways?|VPN Components?', 'Generates IPsec encryption tunnels.'),
        ('inner-vpn', 'Inner VPN Gateway', r'Inner VPN Gateways?', 'VPN Gateway serving the inner encryption layer.'),
        ('outer-vpn', 'Outer VPN Gateway', r'Outer VPN Gateways?', 'VPN Gateway serving the outer encryption layer.'),
        ('macsec-device', 'MACsec Device', r'MACsec Devices?|MACsec Ethernet Encryptors', 'Generates MACsec encryption tunnels.'),
        ('inner-macsec', 'Inner MACsec Device', r'Inner MACsec Devices?', 'MACsec Device serving the inner encryption layer.'),
        ('outer-macsec', 'Outer MACsec Device', r'Outer MACsec Devices?', 'MACsec Device serving the outer encryption layer.'),
        ('firewall', 'Firewall', r'(?:Traffic Filtering )?Firewalls?', 'Traffic filtering component category.'),
        ('outer-firewall', 'Outer Firewall', r'Outer Firewalls?', 'Filters traffic between the Black Network and Outer Encryption Component.'),
        ('gray-firewall', 'Gray Firewall', r'Gray Firewalls?', 'Filters Gray Network traffic between encryption components and management components.'),
        ('inner-firewall', 'Inner Firewall', r'Inner Firewalls?', 'Located between the Inner Encryption Component and Red Network; requirements may come from another CP.'),
        ('aw', 'Administrative Workstation', r'Administrative Workstations?|Management Workstations?|\bAWs?\b|\bMW\b', 'Maintains, monitors, and controls component security functions; may be physical or virtual.'),
        ('red-aw', 'Red Administrative Workstation', r'Red (?:Administrative Workstation|AW)s?', 'Administers Inner Encryption Components, Inner Firewall, and Red Management Services.'),
        ('gray-aw', 'Gray Administrative Workstation', r'Gray (?:Administrative Workstation|AW)s?', 'Administers Outer Encryption Components, Gray Firewall, and Gray Management Services.'),
        ('black-aw', 'Black Administrative Workstation', r'Black AWs?', 'Mentioned to prohibit Black AW management of Gray components; no positive MSC assignment is supplied.'),
        ('management-component', 'Management component', r'(?:Management|management) (?:Service )?[Cc]omponents?|administration components|management devices', 'Generic component providing management functions; exact realization depends on the stated role.'),
        ('red-management', 'Red Management Services', r'Red Management Services?|Red Administration Management Components', 'Aggregate services for secure inner-layer administration and Red Network monitoring.'),
        ('gray-management', 'Gray Management Services', r'Gray Management Services?', 'Aggregate services for secure Gray Network administration and monitoring.'),
        ('siem', 'Security Information and Event Management', r'Security Information and Event Management|\bSIEMs?\b', 'Collects and analyzes log data and provides alerts.'),
        ('red-siem', 'Red SIEM', r'Red SIEMs?|RED SECURITY INFORMATION AND EVENT MANAGEMENT', 'Collects Red-side logs and flow data; may receive Gray logs through an approved CDS.'),
        ('gray-siem', 'Gray SIEM', r'Gray SIEMs?|GRAY SECURITY INFORMATION AND EVENT MANAGEMENT', 'Collects Gray-side logs; explicitly not a mandatory component.'),
        ('authentication-server', 'Authentication Server', r'(?:MSC )?Authentication Servers?|\bASs?\b', 'Supports EAP-TLS mutual authentication between MACsec Devices.'),
        ('supplicant', 'Supplicant', r'\bsupplicant\b', 'MACsec Device authentication function; each device performs both supplicant and authenticator functions.'),
        ('authenticator', 'Authenticator', r'\bauthenticator\b', 'MACsec Device authentication function; distinct from the Authentication Server.'),
        ('key-server', 'Key Server', r'Key Servers?', 'MACsec Device designated to distribute Secure Association Keys to its peer.'),
        ('ca', 'Certification Authority', r'Certification Authorit(?:y|ies)|Certificate Authority|\bCAs?\b', 'Issues certificates; preserve CA role separately from human CA Administrators.'),
        ('inner-ca', 'Inner CA', r'Inner CAs?', 'CA associated with Inner Encryption Components.'),
        ('outer-ca', 'Outer CA', r'Outer CAs?', 'CA associated with Outer Encryption Components.'),
        ('local-ca', 'Locally run CA', r'locally run CAs?', 'Locally operated CA placement/management specialization.'),
        ('enterprise-ca', 'Enterprise CA', r'enterprise CAs?', 'Enterprise CA that need not be managed by the Solution Owner.'),
        ('root-ca', 'Root CA', r'Root CAs?', 'Root CA is given as an example of a trust anchor in certificate-chain provisioning; the document does not make the terms exact synonyms.'),
        ('signing-ca', 'Signing CA', r'signing CAs?', 'Certificate-signing CA role mentioned in provisioning and trust-chain setup.'),
        ('kgs', 'Key Generation Solution', r'Key Generation Solutions?|\bKGS\b', 'Generates pre-shared CAKs and associated CKNs.'),
        ('encapsulation-device', 'Encapsulation/Decapsulation Device', r'Encapsulation/\s*Decapsulation Device|standalone device|standalone router or switch', 'Encapsulates inner MACsec traffic when the selected encryption component lacks that feature.'),
        ('router', 'Router', r'\brouters?\b', 'Generic routing device; retain specializations and context rather than equating all routers.'),
        ('gray-router', 'Gray Network router', r'ordinary router|router/switch', 'Selects a redundant Outer Encryption Component in the availability example.'),
        ('screening-router', 'Screening router', r'screening router', 'Optional Black Network packet filter outside the MSC Solution boundary.'),
        ('customer-edge-router', 'Customer Edge Router', r'Customer Edge Router', 'Example of an existing Black Network screening router.'),
        ('switch', 'Switch', r'\bswitch\b|router/switch', 'Device alternative for standalone encapsulation or Gray infrastructure forwarding; switching as an activity is not an instance.'),
        ('cds', 'Cross Domain Solution', r'cross domain solution|\bCDS\b', 'Controlled interface across security domains, including transfer of Gray logs to a Red SIEM.'),
        ('cdp', 'CRL Distribution Point', r'CRL Distribution Point|\bCDPs?\b', 'Web server hosting a CRL for VPN Gateways to download.'),
        ('ocsp-responder', 'OCSP Responder', r'OCSP Responders?', 'Certificate status responder used for revocation checking.'),
        ('ips', 'Intrusion Prevention System', r'Intrusion Prevention Systems?|\bIPSs?\b', 'Optional product-selection category in MSC-PS-5.'),
        ('aw-host', 'Host/server for AW virtual machines', r'physical host/server|hosts/servers|Hosts/servers', 'Physical host/server used to host management or AW virtual machines; restrictions preserve dedicated functions.'),
        ('virtual-machine', 'Virtual Machine', r'Virtual Machines?|\bVMs?\b', 'Virtual implementation form for management services and AWs.'),
        ('physical-workstation', 'Physical workstation', r'physical workstation|separate workstations|workstations used', 'Physical implementation form; may host an AW or another explicitly separated function.'),
        ('enrollment-server', 'Enrollment server', r'enrollment(?: or provisioning)? servers|enrollment,', 'Enrollment function mentioned in restrictions on cohosting management functions.'),
        ('provisioning-server', 'Provisioning server', r'provisioning servers|provisioning,', 'Provisioning function that must be separated from AW functions.'),
        ('certificate-registration', 'Certificate registration component', r'certificate registrations|CA registration|certificate registration', 'Certificate-registration function separated from AW functions; exact product is unspecified.'),
        ('registration-authority', 'Registration Authority', r'Registration Authorit(?:y|ies)|\bRA\b', 'Mixed hardware, software, and personnel authority collecting and submitting certificate information; device realization is unspecified.'),
        ('trusted-time-source', 'Trusted time source', r'trusted time source', 'Trusted time source on the Red Network for Red components or on the Gray Management Network for Gray components.'),
        ('dns-server', 'DNS server', r'DNS server', 'Server referenced through configured DNS server addresses; not assigned an explicit deployment location.'),
        ('control-plane-service', 'Control plane network service', r'Network services provided by control plane|network services provided by control plane', 'Inside-network service category; NTP is an example rather than a new named device instance.'),
        ('third-party-server', 'Third-party server', r'third.party server', 'External server contact category blocked or disabled for Outer Encryption Components.'),
        ('end-user-device', 'End user device', r'end user devices?', 'Device category in combined CSfC solutions referenced by MSC-SR-13.'),
        ('high-assurance-encryptor', 'High Assurance encryptor', r'High Assurance encryptor', 'Example approved protection for remote administration; not equated to an MSC encryption component.'),
        ('government-product', 'NSA-certified Government-off-the-Shelf product', r'Government-off-the-Shelf products|NSA-certified product', 'Alternative approved egress product in the MSC-SR-14 footnote.'),
        ('locally-managed-device', 'Locally Managed Device', r'Locally Managed Device', 'Management-mode role defined by a hardwired AW connection.'),
        ('remotely-managed-device', 'Remotely Managed Device', r'Remotely Managed Device', 'Management-mode role defined by methods other than a local hardwired AW connection.'),
        ('auxiliary-network-device', 'Auxiliary network device', r'auxiliary network devices', 'Generic supporting device category in Security Administrator duties.'),
        ('authentication-service', 'Infrastructure authentication service', r'authentication service', 'Service used for access to infrastructure components under MSC-GD-27; not assumed identical to the MACsec AS.'),
        ('network-administration-device', 'Network administration device', r'network administration device', 'Generic administrative device wording in MSC-DM-7; correspondence with AW is not explicitly defined.'),
        ('infrastructure-component', 'Infrastructure component', r'infrastructure components?|infrastructure hardware', 'Generic infrastructure category in password, authentication-service, inventory, and inspection requirements.'),
        ('network-device', 'Network device', r'network devices?', 'Generic device category used in DNS-service restrictions and protocol discussion.'),
        ('perimeter-device', 'Perimeter device', r'perimeter device', 'Outer Encryption Component placement facet when no Outer Firewall is present.'),
        ('key-management-component', 'Key and certificate management component', r'KEY AND CERTIFICATE MANAGEMENT COMPONENTS', 'Component category whose detailed requirements are relocated to separate annexes.'),
    ]
    role_specs.extend([
        ('trust-anchor-ca', 'Trust Anchor CA', r'Trust Anchor CA', 'CA whose certificate is installed as the trust anchor under MSC-VG-4; Root CA remains a separately preserved example rather than an exact alias.'),
        ('password-generator', 'Approved password generator', r'(?:approved )?password generator', 'Generates passwords as recommended by MSC-GD-21; the document does not specify a hardware or software realization.'),
        ('log-repository', 'Log and status repository', r'similar repository', 'Receives logs and status information as an alternative to a SIEM; its implementation is unspecified.'),
        ('testing-equipment', 'Testing equipment', r'testing equipment', 'Equipment available for gray-box testing inside and outside the developed solution; no particular product is specified.'),
        ('testing-software', 'Testing software', r'testing software', 'Software available for gray-box testing inside and outside the developed solution; no particular product is specified.'),
        ('ike-initiator', 'IKEv2 initiator', r'\binitiator\b', 'Protocol endpoint role that sends the initiator messages in the described IKE_SA_INIT exchange. The source does not identify Bob or Alice as that endpoint.'),
        ('ike-responder', 'IKEv2 responder', r'\bresponder\b', 'Protocol endpoint role that sends the responder messages in the described IKE_SA_INIT exchange. The source does not identify Bob or Alice as that endpoint.'),
    ])
    roles = []
    mentions = []
    unresolved = []
    for slug, name, pattern, description in role_specs:
        rid = 'ROLE-' + slug
        rg = re.compile(pattern, re.I)
        hits = []
        for u in units:
            for m in rg.finditer(u['text']):
                if slug in {'ike-initiator', 'ike-responder'} and not u['source_id'].endswith(':p027:u008.s002'):
                    continue
                if slug == 'authentication-server' and m.group().lower() == 'as':
                    if m.group() != 'AS':
                        continue
                if slug == 'router' and ('Protocol Router Network' in u['text'] or 'RFC' in u['text'] and 'Router' not in u['text']):
                    continue
                if slug in {'ca','kgs'} and u['text'][m.end():].lstrip().startswith('Administrator'):
                    continue
                mention = {'mention_id': f'RM-{len(mentions)+1:05}', 'role_id': rid, 'source_id': u['source_id'], 'source_wording': m.group(), 'text_start': m.start(), 'text_end': m.end(), 'basis': 'source_stated', 'context': u['text']}
                mentions.append(mention)
                hits.append(mention)
        ids = list(dict.fromkeys(h['source_id'] for h in hits))
        aliases = sorted(set(h['source_wording'] for h in hits))
        role = {'role_id': rid, 'preferred_name': name, 'source_wording': aliases, 'aliases': aliases, 'description': {'text': description, 'basis': 'interpretation_for_review', 'source_ids': ids}, 'source_ids': ids, 'evidence': quote([by_id[sid] for sid in ids]), 'instance_policy': 'A role category, not a named device instance. A device may have several supported roles.', 'status': 'evidence_linked_semantic_review_separate' if ids else 'unresolved_no_indexed_mention'}
        if slug in {'ike-initiator', 'ike-responder'}:
            role['role_kind'] = 'protocol_endpoint_role'
        elif slug in {'red-management','gray-management','management-component'}:
            role['role_kind'] = 'aggregate_component_service_role'
        elif slug == 'registration-authority':
            role['role_kind'] = 'mixed_authority_role'
            role['uncertainty'] = 'The glossary includes individuals as well as hardware/software. Only the hardware/software function is within the device-role inventory.'
        elif slug in {'locally-managed-device','remotely-managed-device','virtual-machine','physical-workstation','aw-host'}:
            role['role_kind'] = 'management_or_realization_facet'
        else:
            role['role_kind'] = 'device_or_service_role'
        if slug == 'aw':
            role['alias_qualification'] = 'The change history explicitly renames Management Workstation to Administrative Workstation. MW remains in Appendix B; historical wording is retained.'
        if not ids:
            unresolved.append({'role_id': rid, 'reason': 'No direct text match; requires source/OCR review.'})
        roles.append(role)
    role_by_id = {r['role_id']: r for r in roles}

    figure_pages = [10,12,14,15,17,18,19,20,22,28]
    crops = json.loads((NETWORKS / 'crop_manifest.json').read_text())
    figure_refs = {}
    for i,p in enumerate(figure_pages,1):
        fs = [u for u in select([p]) if u.get('unit_type') in {'figure','figure_ocr','figure_label','figure_region'} or u.get('figure_number') == i]
        captions = [u for u in select([p]) if u.get('prose_kind') == 'figure_caption' or u.get('unit_type') == 'figure_caption']
        figure_refs[i] = [u['source_id'] for u in fs + captions]
        if not figure_refs[i]:
            figure_refs[i] = refs([p], [f'Figure {i}'])
        crops[i-1].update({'source_ids': figure_refs[i], 'review_status': 'visually_inspected', 'review_method': 'Agent viewed the final 200 dpi crop pixels using view_image.', 'review_result': 'Complete image border, labels, any legend, and full caption retained and readable.', 'review_scope': 'No external configuration or compliance assessment.'})

    examples=[]

    def blocks(page, numbers):
        return {f'p{page:03}:u{number:03}' for number in numbers}

    setup_blocks={
        1:blocks(10,range(4,8))|blocks(11,[5,7])|blocks(23,[2]),
        2:blocks(12,[3])|blocks(23,[2,3,4,5,7,8]),
        3:blocks(14,[1,2,4,6,7,8,9]),
        4:blocks(15,[2,4,5]),
        5:blocks(15,[7])|blocks(16,[1,2,4,5,6]),
        6:blocks(17,[3,4,5,6])|blocks(18,[1,2,4,5])|blocks(24,[5,6]),
        7:blocks(18,[7])|blocks(19,range(3,11))|blocks(25,[7]),
        8:blocks(19,[7,8,9,10])|blocks(20,[2])|blocks(25,[7])|blocks(42,[4]),
        9:blocks(21,[7,8])|blocks(22,[2])|blocks(35,[9]),
        10:blocks(26,[13])|blocks(27,range(1,12))|blocks(28,[2]),
    }

    def block_key(u):
        return ':'.join(u['source_id'].split(':')[1:]).split('.s')[0]

    def setup_unit(u):
        return bool(u['text']) and u['unit_type'] in {'sentence','trailing_text','table_row'} and u.get('prose_kind') not in {'figure_caption','table_caption'}

    def example(n, title, ps, requirements, kind='topology'):
        support = [u for u in select(ps) if setup_unit(u) and (n not in setup_blocks or block_key(u) in setup_blocks[n])]
        e = {'example_id': f'NET-{n:03}', 'title': title, 'kind': kind, 'figure_numbers': [n] if n<=10 else [], 'source_ids': list(dict.fromkeys([u['source_id'] for u in support] + figure_refs.get(n,[]))), 'setup_passages': quote(support), 'setup_passage_scope': 'Complete source units from the indicated discussion pages are retained to preserve qualifications; some adjacent context is included.', 'devices': [], 'networks': [], 'aggregates': [], 'links': [], 'interfaces': [], 'sites_and_boundaries': [], 'shared_components': [], 'facts': [], 'requirement_links': [], 'compliance': {}, 'unknowns': [], 'open_issues': [], 'status':'evidence_linked_semantic_review_separate'}
        if n<=10:
            e['figure_crops']=[crops[n-1]]
        else:
            e['figure_crops']=[]
        examples.append(e)
        return e

    def device(e, suffix, name, roles, location, basis='visual_interpretation'):
        did=e['example_id']+'-'+suffix
        source=figure_refs.get(int(e['example_id'][-3:]),e['source_ids'])
        e['devices'].append({'device_id':did,'name':name,'name_kind':'source_label' if e['kind']!='textual_configuration' else 'role_category_in_partial_configuration', 'location':location,'role_ids':['ROLE-'+r for r in roles], 'basis':basis,'source_ids':source,'instance_note':'Analyst ID distinguishes repeated source labels; it is not a source-provided hostname. A textual configuration role does not assert a specific deployed instance.'})
        return did

    def network(e,suffix,name,zone,location,basis='visual_interpretation'):
        nid=e['example_id']+'-'+suffix
        e['networks'].append({'network_id':nid,'name':name,'zone':zone,'location':location,'basis':basis,'source_ids':figure_refs.get(int(e['example_id'][-3:]),e['source_ids'])})
        return nid

    def link(e,a,b,kind='drawn_connection',text=None,basis='visual_interpretation',sources=None):
        e['links'].append({'endpoints':[a,b],'kind':kind,'description':text or 'Line visibly connects the indicated endpoints.', 'basis':basis,'source_ids':sources or figure_refs.get(int(e['example_id'][-3:]),e['source_ids']), 'unknowns':[]})

    titles=['Two encryption tunnels across an untrusted network','Public Internet as Black transport','Two independently managed sites','Central Management Site and Remote Site','Two networks at the same security level','Networks at different security levels','MACsec encapsulation at the outer component internal interface','MACsec encapsulation by a separate device','Redundant Outer Encryption Components','CNSA 2.0 IKEv2 peer exchange']
    psets=[[10,11,23],[12,23],[14],[15],[15,16,17],[17,18,24],[18,19,25],[19,20,25,42],[21,22,35],[26,27,28]]
    reqsets=[['MSC-PS-6','MSC-PS-7','MSC-PS-11'],['MSC-SR-12','MSC-PF-22','MSC-PS-12'],['MSC-SR-2','MSC-VG-15','MSC-AA-2'],['MSC-DM-4','MSC-DM-5','MSC-MD-6'],['MSC-SR-16','MSC-PF-17','MSC-VG-15'],['MSC-SR-7','MSC-SR-8','MSC-PF-23','MSC-PF-28','MSC-PF-32'],['MSC-MD-13'],['MSC-MD-13','MSC-PF-1','MSC-PF-2'],['MSC-SR-7','MSC-SR-16','MSC-OR-8'],['MSC-VG-19','MSC-VG-20','MSC-VG-21']]
    for n in range(1,11):
        e=example(n,titles[n-1],psets[n-1],reqsets[n-1], 'protocol_exchange' if n==10 else 'topology')
        if n==10:
            a=device(e,'bob','Bob',['vpn-gateway'],'left')
            b=device(e,'alice','Alice',['vpn-gateway'],'right')
            for exchange in ['IKE_SA_INIT Proposal (CNSA 1.0)','IKE_INTERMEDIATE Proposal (ML-KEM)','IKE_AUTH Exchange (ML-DSA)','ESP Traffic']:
                link(e,a,b,'protocol_exchange',exchange)
            e['unknowns'].append('The exchange does not assign Bob or Alice to the inner or outer encryption layer.')
            continue
        black=network(e,'black','Public Internet as Black Network' if n==2 else 'Black Network','Black','between sides')
        count=2 if n in {5,9} else 3 if n==6 else 1
        named=n in {3,4,5,6,9}
        all_inner={}
        all_outer={}
        for side in ['A','B']:
            loc=f'Site {side}' if named else ('left side' if side=='A' else 'right side')
            e['sites_and_boundaries'].append(fact(f'{loc}: '+('site label is present; dashed outline is shown.' if named else 'no source-provided site name.'),figure_refs[n],'visual_interpretation'))
            outer=[]
            for j in range(2 if n==9 else 1):
                out=device(e,f'{side}-outer-{j+1}','Outer Encryption Component',['outer-encryption','encryption-component'],loc+(' upper' if j==0 and n==9 else ' lower' if n==9 else ''))
                outer.append(out)
                if n==2:
                    fw=device(e,f'{side}-outer-fw','Outer Firewall',['outer-firewall','firewall'],loc)
                    link(e,out,fw)
                    link(e,fw,black)
                else:
                    link(e,out,black)
            all_outer[side]=outer
            hub=None
            if n==5:
                hub=network(e, f'{side}-gray-data', 'Gray Data Network', 'Gray', loc)
                link(e, hub, outer[0], 'shared_gray_segment', 'The figure labels the branching segment Gray Data Network.')
            elif n==6:
                hub=device(e,f'{side}-gray-fw','Gray Firewall',['gray-firewall','firewall'],loc)
                link(e,hub,outer[0])
            elif n==9:
                hub=device(e,f'{side}-router','Router',['router','gray-router'],loc)
                for out in outer:
                    link(e,hub,out)
            all_inner[side]=[]
            for j in range(count):
                role=['inner-encryption','encryption-component']
                label='Inner Encryption Component'
                if n in {7,8}:
                    role+=['macsec-device','inner-macsec']
                    label='MACsec Device'
                inn=device(e,f'{side}-inner-{j+1}',label,role,loc+(f' Network {j+1}' if count>1 else ''))
                all_inner[side].append(inn)
                redname='Red Network'
                if n==5:
                    redname=f'Network {j+1} Secret (US Only)'
                if n==6:
                    redname=['Network 1 Top Secret','Network 2 Secret (US Only)','Network 3 Secret (Coalition)'][j]
                if n==9:
                    redname=['Network 1 Secret (US Only)','Network 2 Secret (Coalition)'][j]
                red=network(e,f'{side}-red-{j+1}',redname,'Red',loc)
                link(e,red,inn)
                if n==8:
                    enc=device(e,f'{side}-encap','Encapsulation/Decapsulation Device',['encapsulation-device'],loc)
                    link(e,inn,enc)
                    link(e,enc,outer[0])
                else:
                    link(e,inn,hub or outer[0],text='Drawn Gray-side connection; branching line denotes shared Gray connectivity.' if count>1 else None)
                if n==3 or n in {4,5} and side=='A' or n==6:
                    mg=device(e,f'{side}-red-management-{j+1}','Red Management Services',['red-management','management-component'],loc+(f' Network {j+1}' if count>1 else ''))
                    link(e,mg,red,'management_network_connection')
            if n==3 or n in {4,5} and side=='A' or n==6:
                mg=device(e,f'{side}-gray-management','Gray Management Services',['gray-management','management-component'],loc)
                link(e,mg,hub if n==6 else outer[0],'management_network_connection')
            if count>1:
                e['shared_components'].append(fact(f'{loc} shares '+('the Gray Firewall and one Outer Encryption Component among three inner components.' if n==6 else 'a router and two Outer Encryption Components among two inner components.' if n==9 else 'one Outer Encryption Component among two inner components.'),figure_refs[n],'visual_interpretation'))
        if n in {1,3}:
            for role, ds in [('inner',all_inner),('outer',all_outer)]:
                link(e,ds['A'][0],ds['B'][0],'encryption_tunnel',f'{role.capitalize()} encryption tunnel described in prose.','source_stated',refs([10] if n==1 else [14],['tunnel','encrypted twice']))
        if n==1:
            e['facts'].append(fact('The explicit untrusted-network requirement supplies the Outer Firewall omitted from Figure 1. It is located at the MSC edge and connects to the Black Network.',refs([23],['untrusted network','located at the edge'])))
        if n==2:
            e['facts'].append(fact('An Outer Firewall is required between an untrusted Black Network such as the Public Internet and the Outer Encryption Component.',refs([12,23],['Outer Firewall'])))
            e['interfaces'].append(fact('Outer Encryption Component external interface connects to Outer Firewall internal interface when the Black Network is the Public Internet.',refs([23],['external interface','internal interface'])))
        if n==3:
            e['facts'].append(fact('Each site manages its own components. Management traffic does not cross the Black Network. Local or enterprise CAs may be used; peers must have required trust and revocation information.',refs([14],['managed sites','CAs','management traffic','certificates'])))
        if n in {4,5}:
            e['facts'].append(fact('Site A is the central management site and Site B is remote; additional sites may follow the remote-site design.',refs([15,16],['Central Management','Remote Site','additional site']), 'source_stated' if n==5 else 'visual_interpretation'))
            e['facts'].append(fact('Remote management traversing the Black Network is encrypted at least twice. Gray central management refers to the Enterprise Gray annex.',refs([15],['management traffic','Enterprise Gray'])))
            e['unknowns'].append('The figures do not enumerate all AW, CA, AS, SIEM, or KGS instances behind aggregate management-services symbols.')
        if n==5:
            e['facts'].append(fact('Both Network 1 and Network 2 are Secret U.S.-only; the prose allows their singly encrypted traffic over the Gray Network without additional security controls in place.',refs([16],['Network 1','Network 2','same security level'])))
            e['open_issues'].append({'issue_id':'NET-005-security-level-wording','description':'The same-security-level subsection also says "Two Inner Encryption Components for networks of different security levels". Retain the wording without silently correcting its scope.','source_ids':refs([16],['different security levels'])})
        if n==6:
            e['facts'].append(fact('Gray Firewalls filter paths among inner components of different security levels; Outer Encryption Component filtering is still required.',refs([17,18],['filter','Gray Firewall'])))
        if n in {7,8}:
            e['facts'].append(fact('Inner MACsec traffic needs encapsulation before outer encryption. No single encapsulation protocol is mandated; L2TPv3 and Ethernet over MPLS are examples.',refs([19,25],['encapsulat','Layer 2 Tunneling','Ethernet over'])))
            if n==7:
                e['interfaces'].append(fact('Encapsulation/Decapsulation arrows point to the Gray-facing internal interface of each Outer Encryption Component.',figure_refs[n],'visual_interpretation'))
            else:
                e['interfaces'].append(fact('Standalone device internal interface connects to the Inner MACsec Device; external interface connects to the Outer Encryption Component.',refs([19],['internal interface','external interface'])))
                e['open_issues'].append({'issue_id':'NET-008-encapsulation-scope','description':'PDF p19 and §5.5 require all Solution Component requirements for the standalone device. PDF p20 says the additional step falls outside the MSC Solution boundary and highly recommends DM/port filtering. MSC-MD-13 expressly applies §11.1. The source tension is unresolved.','source_ids':refs([19,20,25,42],['standalone','outside the boundary','additional step','MSC-MD-13'])})
        if n==9:
            e['facts'].append(fact('Two outer tunnels connect upper and lower pairs; ordinary Gray routers select outbound outer components. Management components are omitted for clarity.',refs([21],['outer encryption tunnels','ordinary router','Management components'])))
            for j in range(2):
                link(e,all_outer['A'][j],all_outer['B'][j],'encryption_tunnel','Upper/lower pair outer tunnel.','source_stated',refs([21],['outer encryption tunnels','upper pair','lower pair']))
            e['facts'].append(fact('MSC-SR-7 supplies the Gray Firewall requirement omitted from Figure 9: every physical Gray path between Inner components for different security levels includes a Gray Firewall.',refs([35],['MSC-SR-7'])))
            e['unknowns'].append('The failover mechanism and the number and exact attachment points of the textually required Gray Firewalls are unspecified.')

    def textual_structure(e, n):
        d = {x['role_ids'][0].removeprefix('ROLE-'): x['device_id'] for x in e['devices']}
        e['configurations'] = []
        def net(slug, name, zone):
            return network(e, slug, name, zone, 'Placement described by the cited configuration.', 'source_stated')
        def relation(a, b, description, kind='stated_relationship', condition=None):
            link(e, a, b, kind, description, 'source_stated', e['source_ids'])
            if condition:
                e['links'][-1]['condition'] = condition
        def configuration(name, meaning):
            e['configurations'].append({'name': name, 'meaning': meaning, 'basis': 'source_stated', 'source_ids': e['source_ids']})
        def interface(text):
            e['interfaces'].append(fact(text, e['source_ids']))
        def site(text):
            e['sites_and_boundaries'].append(fact(text, e['source_ids']))
        if n == 11:
            for inner, outer in [('IPsec','IPsec'),('IPsec','MACsec'),('MACsec','IPsec'),('MACsec','MACsec')]:
                configuration(inner + '/' + outer, {'inner_tunnel': inner, 'outer_tunnel': outer, 'outer_MACsec_point_to_point': outer == 'MACsec'})
            relation(d['inner-encryption'], d['outer-encryption'], 'The inner tunnel is nested inside the outer tunnel; physical intermediary devices are unspecified.', 'encryption_layer_order')
        elif n == 12:
            data = net('gray-data', 'Gray Data Network', 'Gray')
            management = net('gray-management-network', 'Gray Management Network', 'Gray')
            relation(d['gray-aw'], management, 'Gray AW is a Gray management component.', 'network_placement')
            relation(d['gray-management'], data, 'Management-network components administer data-network components.', 'logical_administration')
            interface('Data and management traffic require physical and cryptographic separation; VLAN separation alone is insufficient.')
        elif n == 13:
            unclassified = net('unclassified', 'Unclassified network treated as a Red Network for CP requirements', 'Unclassified')
            relation(unclassified, d['inner-encryption'], 'The unclassified network must be behind its own Inner Encryption Component.', 'behind_component')
            relation(d['inner-encryption'], d['outer-encryption'], 'Its inner component is behind the shared outer component.', 'encryption_layer_order')
        elif n == 14:
            gray = net('gray', 'Gray Network', 'Gray')
            red = net('red', 'Red Network', 'Red')
            relation(d['gray-management'], d['cds'], 'Gray log data is transferred through an approved CDS.', 'logical_log_transfer')
            relation(d['cds'], d['red-siem'], 'The Red SIEM receives the transferred Gray log data.', 'logical_log_transfer')
            relation(d['red-siem'], red, 'The receiving SIEM is located in the Red Network.', 'network_placement')
        elif n == 15:
            black = net('black', 'Black Network', 'Black')
            relation(black, d['screening-router'], 'Screening filters packets from the Black Network before they reach an Outer Encryption Component.', 'packet_path')
            relation(d['screening-router'], d['outer-encryption'], 'Screened packets continue toward the Outer Encryption Component.', 'packet_path')
            configuration('Existing screening router', 'The screening router could be part of an existing Black Network; a Customer Edge Router is an example of that same role.')
            configuration('Added screening router', 'The screening router could be added between Outer Encryption Components and existing Black Network components.')
            e['devices'][1]['alternative_role_of'] = d['screening-router']
            site('The screening router belongs to the Black Network and is outside the MSC Solution boundary.')
        elif n == 16:
            configuration('Physical AW', 'An AW can be a physical workstation, subject to restrictions on additional uses.')
            configuration('Virtual AW', 'An AW can be a VM on a physical host/server, subject to the stated hosting and separation restrictions.')
            relation(d['aw-host'], d['virtual-machine'], 'The physical host/server hosts the AW VM in the virtual-AW alternative.', 'hosting', 'Virtual AW implementation selected')
            e['devices'][2]['alternative_realization_of'] = d['aw']
            e['devices'][3]['alternative_realization_of'] = d['aw']
        elif n == 17:
            gray = net('gray-management-network', 'Gray Management Services local LAN or VLAN', 'Gray')
            relation(d['gray-aw'], d['outer-encryption'], 'A direct physical serial cable is the explicit local-management example.', 'direct_physical_connection', 'Direct local management alternative')
            configuration('Same-site LAN or VLAN', 'The Gray AW resides in Gray Management Services at the same site as the Outer Encryption Component; the stated exception concerns CNSA Suite algorithms.')
            relation(d['gray-aw'], gray, 'Same-site Gray AW resides in Gray Management Services.', 'network_placement', 'Same-site LAN or VLAN alternative')
            e['devices'][2]['facet_of'] = d['outer-encryption']
            interface('Serial cable is the stated direct physical interface example; the document supplies no serial port identifier.')
            site('The same-site example locates the Gray AW and Outer Encryption Component at one site. It does not grant a general plaintext-management exception.')
        elif n == 18:
            red = net('red', 'Red Network', 'Red')
            relation(red, d['government-product'], 'One approved egress path may use an NSA-certified product.', 'physical_egress_path')
            aggregate = e['example_id'] + '-csfc-solution'
            e['aggregates'].append({'aggregate_id': aggregate, 'name': 'CSfC Solution conforming to a CP', 'kind': 'solution_aggregate', 'basis': 'source_stated', 'source_ids': e['source_ids']})
            e['devices'] = [device for device in e['devices'] if device['device_id'] != d['solution-component']]
            relation(red, aggregate, 'Another egress path may use a whole CSfC Solution conforming to a CP; the passage does not reduce that solution to one device.', 'physical_egress_path')
            site('The footnote permits both egress paths at the same site.')
        elif n == 19:
            configuration('Combined data-in-transit solution', 'If another CSfC data-in-transit solution includes end-user devices, its Inner Firewall requirements must be followed.')
            configuration('Combined solution Gray Firewall', 'A Gray Firewall may be required by the other CP. The paragraph does not specify a complete combined topology.')
            red = net('red', 'Red Network', 'Red')
            relation(red, d['inner-firewall'], 'When deployed, the Inner Firewall is between the Red Network and Inner Encryption Component.', 'conditional_component_placement', 'Inner Firewall deployed under companion CP requirements')
            relation(d['inner-firewall'], d['inner-encryption'], 'The Inner Firewall faces the Inner Encryption Component on the other side of the stated placement.', 'conditional_component_placement', 'Inner Firewall deployed under companion CP requirements')
            site('The MSC text supplies Inner Firewall placement. Additional requirements and topology details of the combined deployment depend on the companion CP.')
        elif n == 20:
            configuration('Parallel redundancy', 'Redundant components may be added in parallel if every redundant component follows applicable CP requirements.')
            configuration('Multiple inner components', 'When multiple inner components share an outer component, they must be in parallel.')
            relation(d['inner-encryption'], d['outer-encryption'], 'Multiple instances of the inner role can share the outer component in parallel.', 'shared_component_arrangement')
            e['shared_components'].append(fact('The outer component may be shared by multiple inner components; no instance count or failover configuration is supplied.', e['source_ids']))
        elif n == 21:
            net('black', 'Black Network', 'Black')
            net('red', 'Red Network', 'Red')
            configuration('Existing routing protocols', 'Existing GRE, MPLS or OSPF use in the Black and/or Red Network may continue with AO approval.')
            site('The text places routing-protocol use in Black and/or Red Networks. It does not identify a particular router location or connection.')
        elif n == 22:
            for zone in ['Red','Gray','Black']:
                nid = net(zone.lower(), zone + ' Network', zone)
                configuration(zone + ' IP version', {'network_id': nid, 'allowed_choices': ['IPv4','IPv6'], 'independent_of_other_networks': True})
        elif n == 23:
            relation(d['ca'], d['vpn-gateway'], 'A CA processes the VPN Gateway CSR and issues its device certificate.', 'certificate_issuance')
            relation(d['ca'], d['macsec-device'], 'A CA issues the device certificate in the certificate-based MACsec alternative.', 'certificate_issuance', 'Certificate-based MACsec selected')
            relation(d['authentication-server'], d['macsec-device'], 'The AS and each MACsec Device mutually authenticate for EAP-TLS negotiation.', 'mutual_authentication', 'Certificate-based MACsec selected')
            relation(d['kgs'], d['macsec-device'], 'A Security Administrator obtains the symmetric key from an NSA-approved KGS and applies it to the component.', 'out_of_band_key_provisioning', 'MACsec PSK alternative selected')
            configuration('Independent sites', 'Each site may use locally run or enterprise CAs and must ensure required peer signing certificates and revocation information are available. MACsec CAK peers use the same CAK.')
            configuration('Central site', 'At least separate inner and outer CAs are needed when applicable. For MACsec EAP-TLS the CAs and AS are at the central site; the stated PSK alternative for one layer does not require a CA for that layer.')
            site('Provisioning occurs out of band in a physically secured area. The authentication server must not connect to both Gray and/or Red Networks; the source wording is retained without inventing a topology.')
        elif n == 24:
            gray = net('gray', 'Gray Network', 'Gray')
            relation(d['inner-encryption'], gray, 'Gray interfaces of inner components can use separate address ranges for each supported Red Network.', 'interface_addressing')
            interface('Separate address ranges are an example addressing scheme supporting source/destination filtering. Actual ranges are unspecified.')
        elif n == 25:
            gray = net('gray-data', 'Gray Data Plane', 'Gray')
            relation(d['cdp'], gray, 'A CDP may be located on the Gray data plane under the stated filtering arrangement.', 'network_placement')
            relation(d['ocsp-responder'], gray, 'An OCSP responder is the stated alternative revocation service.', 'network_placement')
            relation(d['inner-vpn'], d['cdp'], 'The component can exchange HTTP revocation traffic with the CDP/OCSP responder according to its applicable filter rules.', 'logical_revocation_traffic')
            e['links'][-1]['transit_filter_component_ids'] = [d['outer-vpn']]
            interface('MSC-PF-15 requires the Outer Encryption Component Gray interfaces to allow HTTP traffic between Inner VPN Gateways and CDP/OCSP responders. The Outer component is a filtering/transit component in that rule, not a stated revocation endpoint.')
            interface('Filtering rules constrain HTTP revocation traffic; the row descriptions retain the exact component/interface conditions.')
        elif n == 26:
            red = net('red', 'Red Network', 'Red')
            gray = net('gray-management-network', 'Gray Management Network', 'Gray')
            configuration('Red time source', {'network_id': red, 'requirement': 'MSC-SR-3', 'meaning': 'Components on the Red Network synchronize to a trusted time source on the Red Network.'})
            configuration('Gray time source', {'network_id': gray, 'requirement': 'MSC-SR-4', 'meaning': 'Components on the Gray Network synchronize to a trusted time source on the Gray Management Network.'})
            relation(d['inner-encryption'], d['trusted-time-source'], 'Red component time synchronization uses its Red Network trusted time source.', 'time_synchronization')
            relation(d['outer-encryption'], d['trusted-time-source'], 'Gray component time synchronization uses its Gray Management Network trusted time source; the role reference does not assert the same device as the Red source.', 'time_synchronization')
        elif n == 27:
            relation(d['aw'], d['high-assurance-encryptor'], 'The High Assurance encryptor is an example of NSA-approved protection for remote administration.', 'protected_management_path', 'High Assurance encryptor alternative selected')
            relation(d['high-assurance-encryptor'], d['solution-component'], 'Remote management reaches the managed component through the chosen approved protection.', 'protected_management_path', 'High Assurance encryptor alternative selected')
            configuration('Other approved CP solution', 'An approved CP is another example of NSA-approved protection. The exact remote management network topology is unspecified.')

    textual_specs=[
        (11,'Four layering configurations',[18,19],['MSC-MD-13'],['table-1'], 'Table 1 permits inner/outer IPsec/IPsec, IPsec/MACsec, MACsec/IPsec, and MACsec/MACsec. Outer MACsec cases are point to point.', ['vpn-gateway','macsec-device','inner-encryption','outer-encryption']),
        (12,'Separated Gray data and management networks',[13,30,49],['MSC-DM-25'],['Gray Data Network','Gray Management Network','MSC-DM-25'],'Data and management networks may be separate; management components administer data-network components.', ['gray-aw','gray-management','outer-encryption','gray-firewall']),
        (13,'Unclassified network behind its own inner component',[16],['MSC-SR-16'],['unclassified network'],'An unclassified network can share an outer component if it has its own inner component and meets requirements as a Red Network.', ['inner-encryption','outer-encryption']),
        (14,'Gray logs transferred to Red SIEM through CDS',[11,25,30,36],['MSC-SR-22'],['CDS','Gray SIEM','Red SIEM'],'An approved CDS can support Gray log transfer to a Red SIEM.', ['gray-management','red-siem','cds']),
        (15,'Screening router on the Black Network',[26],[],['screening router','Customer Edge Router'],'An optional screening router filters Black Network packets before they reach outer components; it is outside the MSC Solution.', ['screening-router','customer-edge-router','outer-encryption']),
        (16,'Dedicated physical and virtual administrative workstations',[30,47,49],['MSC-DM-1','MSC-DM-2','MSC-DM-23','MSC-DM-24','MSC-DM-28'],['physical host/server','physical workstation','MSC-DM-1','MSC-DM-2','MSC-DM-23','MSC-DM-24','MSC-DM-28'],'AWs may be physical or virtual, with stated cohosting restrictions.', ['aw','aw-host','virtual-machine','physical-workstation']),
        (17,'Local Gray AW direct or same-site management',[30],['MSC-DM-8'],['serial cable','same LAN','same site'],'A direct serial cable is the local encryption exception. A same-site Gray AW example does not need CNSA Suite algorithms because its traffic does not traverse an untrusted network.', ['gray-aw','outer-encryption','locally-managed-device']),
        (18,'Alternative approved egress alongside the MSC Solution',[36],['MSC-SR-14'],['egress path','Government-off','NSA-certified'],'A site may have both an NSA-certified-product egress and an egress through a CP-conforming CSfC solution.', ['government-product','solution-component']),
        (19,'Combining MSC with another CSfC solution',[25,35,36],['MSC-SR-11','MSC-SR-13'],['MSC-SR-11','MSC-SR-13','other CSfC CPs'],'Combined deployments may inherit Gray Firewall or Inner Firewall requirements from the other CP.', ['gray-firewall','inner-firewall','end-user-device','inner-encryption']),
        (20,'Parallel components for load or availability',[21,22,24,25],['MSC-SR-16'],['load balanc','multiple Outer','multiple Inner','redundant'],'Parallel components and load-balancing or standby designs are permitted subject to stated requirements; implementation mechanisms are outside scope.', ['inner-encryption','outer-encryption','gray-firewall']),
        (21,'Existing Black and Red routing protocols',[21],['MSC-OR-8'],['Generic','Routing Encapsulation','already used','OSPF'],'Existing GRE, MPLS, or OSPF use may continue in Black/Red networks with AO approval.', []),
        (22,'Independent IPv4 or IPv6 choice by network',[21],[],['IPv4','IPv6'],'Red, Gray, and Black Networks can independently use IPv4 or IPv6.', []),
        (23,'Certificate or CAK authentication variants',[14,15,20,26,29,30],['MSC-MD-3','MSC-MD-14','MSC-AA-1','MSC-AA-2'],['CAK','CAs','certificates','Authentication Server','AS','KGS'],'Independent and central site designs describe certificate, CAK, CA, AS, and KGS options; exact assignments depend on the chosen layer.', ['ca','inner-ca','outer-ca','authentication-server','kgs','macsec-device','vpn-gateway']),
        (24,'Separate address ranges on Gray interfaces',[23],['MSC-PF-17'],['separate address ranges'],'The source gives separate address ranges for each Red Network inner component as an addressing-scheme example supporting filtering.', ['inner-encryption','outer-encryption']),
        (25,'Revocation service on the Gray data plane',[35,45,46,47],['MSC-SR-8','MSC-PF-15','MSC-PF-25'],['MSC-SR-8','MSC-PF-15','MSC-PF-25'],'Requirements describe CDP/OCSP placement on the Gray data plane and HTTP revocation-check traffic through filtering components.', ['cdp','ocsp-responder','inner-vpn','outer-vpn','gray-firewall']),
        (26,'Trusted control-plane services on inside networks',[35],['MSC-SR-1','MSC-SR-3','MSC-SR-4'],['MSC-SR-1','MSC-SR-3','MSC-SR-4'],'Control-plane services such as NTP belong on the corresponding inside network; the Red trusted time source is on the Red Network and the Gray trusted time source is on the Gray Management Network.', ['control-plane-service','trusted-time-source','inner-encryption','outer-encryption']),
        (27,'Remote administration through approved protection',[48],['MSC-DM-8'],['MSC-DM-8'],'Remote AW administration uses an NSA-approved solution; a CP or High Assurance encryptor is given as an example.', ['aw','high-assurance-encryptor','solution-component']),
    ]
    textual_register=[]
    for n,title,ps,rs,terms,desc,rids in textual_specs:
        e=example(n,title,ps,rs,'textual_configuration')
        selected=[u for u in select(ps) if setup_unit(u) and (u.get('table_key') in terms or any(re.search(r'(?<![A-Za-z0-9-])' + re.escape(t) + r'(?![A-Za-z0-9-])', u['text']) if t.startswith('MSC-') else t.lower() in u['text'].lower() for t in terms))]
        selected_blocks={block_key(u) for u in selected}
        if n == 23:
            selected_blocks = blocks(14,[6,7]) | blocks(15,[2]) | blocks(20,[6,7,8,9]) | blocks(26,[6]) | blocks(29,[10,11,12,13]) | blocks(30,[1])
        support=[u for u in units if setup_unit(u) and block_key(u) in selected_blocks]
        e['source_ids']=[u['source_id'] for u in support]
        e['setup_passages']=quote(support)
        e['setup_passage_scope']='Complete prose blocks or table rows selected by the explicit example or configuration wording; raw originals remain in the source index.'
        e['facts']=[fact(desc,e['source_ids'])]
        for rid in rids:
            device(e,rid,role_by_id['ROLE-'+rid]['preferred_name'],[rid],'Placement only as stated in setup passages.','source_stated')
        textual_structure(e, n)
        if n==17:
            e['open_issues'].append({'issue_id':'NET-017-distinct-exceptions','description':'The direct-connection exception to management encryption and the same-site exception to CNSA Suite algorithms are separate statements, not a general same-site plaintext permission.','source_ids':e['source_ids']})
        textual_register.append({'textual_example_id':f'TEXT-{n-10:03}','title':title,'example_ids':[e['example_id']],'source_ids':e['source_ids'],'disposition':'extracted','basis':'source_stated'})
    excluded_examples=[
        ([12,13],['Examples of control plane','For example, requirements'],'Protocol examples and time-synchronization requirement explanation supply context but do not describe an additional deployment.'),
        ([59],['For example','Certificate Policy'],'Certificate Policy glossary example concerns business transactions, not an MSC network.'),
    ]
    for ps,terms,reason in excluded_examples:
        ids=refs(ps,terms)
        textual_register.append({'textual_example_id':f'TEXT-X{len(textual_register)+1:03}','source_ids':ids,'disposition':'excluded','reason':reason,'example_ids':[]})
    cue_register=[]
    for u in units:
        if not re.search(r'\bexamples?\b|such as|e\.g\.|i\.e\.',u['text'],re.I):
            continue
        mapped=[e['example_id'] for e in examples if u['source_id'] in e['source_ids']]
        cue_register.append({'source_id':u['source_id'],'text':u['text'],'example_ids':mapped,'disposition':'represented_in_context' if mapped else 'excluded_as_no_additional_network','reason':'Mapped source discussion is retained with the network records.' if mapped else 'The passage gives a protocol, setting, personnel privilege, glossary, or requirement example without another network arrangement.'})
    figures=[]
    for n,p in enumerate(figure_pages,1):
        figures.append({'figure_id':f'FIG-{n:02}','figure_number':n,'page':p,'example_ids':[f'NET-{n:03}'],'source_ids':figure_refs[n],'disposition':'extracted_as_protocol_example' if n==10 else 'extracted_as_topology','subfigures':[], 'review_status':'visually_inspected','crop':crops[n-1]})

    human_patterns=r'Security Administrator|Auditor|Integrator|Solution Owner|Authorizing Official|CA Administrator|Key Generation Solution Administrator|Black Network Administrator|Information System Security Officer'
    excluded=[]
    for u in units:
        for m in re.finditer(human_patterns,u['text'],re.I):
            excluded.append({'source_id':u['source_id'],'source_wording':m.group(),'reason':'Human or organizational responsibility, not a device role.','disposition':'excluded_personnel_role'})
    for u in units:
        if 'backup storage medium' in u['text']:
            excluded.append({'source_id': u['source_id'], 'source_wording': 'backup storage medium', 'reason': 'The passage names a storage asset for off-loaded audit data. It does not assign a device or service function. The requirement remains in the requirement inventory.', 'disposition': 'excluded_storage_asset'})
    excluded.append({'source_ids':refs([59,60,61],['Central Management Site','Remote Site','Independently Managed Site']), 'source_wording':'Central Management Site; Remote Site; Independently Managed Site','reason':'Site management arrangements are recorded in network examples, not treated as devices.','disposition':'excluded_site_role'})
    instances=[{'example_id':e['example_id'],**d} for e in examples for d in e['devices']]
    used={r for d in instances for r in d['role_ids']}
    missing=used-set(role_by_id)
    assert not missing,missing
    for e in examples:
        e['setup_passage_scope']='Relevant complete source prose blocks and contextualized rows are quoted. Figure labels, captions, headings, and empty image units remain supporting references rather than setup quotations.'
        e['role_ids']=sorted({r for d in e['devices'] for r in d['role_ids']})
    apply_mappings(examples)
    validation={'status':'evidence_linked_semantic_review_separate','source_unit_count_scanned':len(units),'pages_scanned':list(range(1,67)),'figure_count':len(figures),'figure_count_expected':10,'topology_figure_count':9,'protocol_figure_count':1,'example_record_count':len(examples),'network_record_count':sum(e['kind']=='topology' for e in examples),'configuration_record_count':sum(e['kind']=='textual_configuration' for e in examples),'protocol_exchange_record_count':sum(e['kind']=='protocol_exchange' for e in examples),'role_count':len(roles),'role_mention_count':len(mentions),'unresolved_role_count':len(unresolved),'all_example_roles_present':not missing,'all_crops_visually_inspected':all(c['review_status']=='visually_inspected' for c in crops),'independent_semantic_review':'See validation/plan_audit and validation/final_status.json; producer checks do not grant semantic approval.','limitations':['Role mention matching is evidence indexing after manual document review, not a proof that every semantic role was recognized.','Source inconsistencies are retained as open issues.'],'memory_use':'Prior memory prompted checking encapsulation boundary wording; all recorded source facts were reverified against this PDF.'}
    for collection in [roles,examples,figures,textual_register]:
        for record in collection:
            for sid in record.get('source_ids',[]):
                assert sid in by_id,sid
    for e in examples:
        for q in e['setup_passages']:
            assert q['text']==by_id[q['source_id']]['text']
    write(NETWORKS/'examples.json',examples)
    write(NETWORKS/'figure_register.json',figures)
    write(NETWORKS/'textual_example_register.json',textual_register)
    write(NETWORKS/'textual_cue_register.json',cue_register)
    write(NETWORKS/'crop_manifest.json',crops)
    write(NETWORKS/'validation.json',validation)
    write(NETWORKS/'revisions.json',[{'finding_id':'ROOT-NET-001','finding':'Page-wide setup selection included unrelated legal prose and empty figure units.','resolution':'Replaced figure-example page selection with explicit relevant paragraph-block selections. Setup quotations now contain only nonempty prose or table rows. Textual examples retain complete matching paragraphs, excluding headings, captions, and figure units.','status':'resolved','affected_example_ids':[e['example_id'] for e in examples],'verification':'Every setup quote equals its source-index unit; NET-001 excludes p009:u018.s003, p010:u002.s001-003, and p010:u011.'}])
    write(ROLES/'instances.json',instances)
    if not args.networks_only:
        write(ROLES/'roles.json',roles)
        write(ROLES/'unresolved.json',unresolved)
        write(ROLES/'exclusions.json',excluded)
        (ROLES/'mentions.jsonl').write_text(''.join(json.dumps(m,ensure_ascii=False)+'\n' for m in mentions))
        write(ROLES/'validation.json',validation)
    write_networks(examples)
    write_requirement_links(examples)
    if args.networks_only:
        print(json.dumps(validation, indent=2))
        return
    lines=['# Device-role inventory','','Source interpretation and scope questions remain documented. Independent semantic review and current readiness are reported in the [plan audit](../validation/plan_audit/) and [current status](../validation/final_status.json).','','[Explore the ontology hierarchy](ontology.md), [open the interactive visualization](ontology.html), or [download the OWL export](ontology.owl). Subtype edges and documented associations preserve distinct meanings and retain source evidence.', '', 'The inventory preserves generic categories, specialized roles, aggregate services, and management or realization facets. Repeated named instances are recorded separately in instances.json. Personnel roles are excluded in exclusions.json.','']
    for role in roles:
        lines += [f'## {role["role_id"]}: {role["preferred_name"]}','','Kind: '+role['role_kind']+'.','',role['description']['text']+' [Interpretation for review.]','','Source wording: '+', '.join(role['source_wording'])+'.','']
        if role.get('uncertainty'):
            lines += [role['uncertainty'],'']
        for q in role['evidence']:
            lines += [f'`{q["source_id"]}`','', '> '+q['text'],'']
    (ROLES/'roles.md').write_text('\n'.join(lines))
    print(json.dumps(validation,indent=2))


if __name__ == '__main__':
    main()
