"""Render reviewed-by-author requirement selections against the frozen source index.

Selections are explicit semantic annotations from a complete reading of the PDF.
The script does not discover obligations by keywords and does not construct proofs.
"""

import collections
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'artifacts/extraction/requirements'
INDEX = ROOT / 'artifacts/extraction/source/source_index.jsonl'
SOURCES = [json.loads(line) for line in INDEX.read_text().splitlines()]
BY_ID = {r['source_id']: r for r in SOURCES}
DOC = SOURCES[0]['document_id']
BY_REQ = {r['requirement_id']: r for r in SOURCES if r.get('requirement_id')}
GROUPS = []


def select(spec):
    found = []
    for token in spec.split():
        if token.startswith('table-'):
            matches = [r for r in SOURCES if r.get('table_key') == token and r['unit_type'] == 'table_row']
        else:
            span = re.fullmatch(r'(p\d{3}):u(\d{3})-u(\d{3})', token)
            if span:
                prefixes = [f'{DOC}:{span[1]}:u{i:03d}' for i in range(int(span[2]), int(span[3]) + 1)]
            else:
                prefixes = [f'{DOC}:{token}']
            matches = [r for r in SOURCES if any(r['source_id'] == p or r['source_id'].startswith(p + '.') for p in prefixes)]
        if not matches:
            raise ValueError(f'Unknown source selector: {token}')
        found.extend(r['source_id'] for r in matches)
    return list(dict.fromkeys(found))


def reqs(spec):
    result = []
    for token in spec.split():
        prefix, nums = token.split(':')
        for item in nums.split(','):
            bounds = [int(x) for x in item.split('-')]
            for n in range(bounds[0], bounds[-1] + 1):
                rid = f'MSC-{prefix}-{n}'
                if rid not in BY_REQ:
                    raise ValueError(rid)
                result.append(rid)
    return result


def passage(sid, kind):
    r = BY_ID[sid]
    return {'source_id': sid, 'text': r['text'], 'unit_type': r['unit_type'],
            'locations': r['locations'], 'evidence_role': kind,
            'quotation_basis': 'Exact indexed text; only documented source-index whitespace normalization and corrections apply.'}


def add(number, slug, title, statement, applicability, rows='', prose='', context='', force='Mandatory for the stated applicability.', notes=(), alternatives=()):
    if isinstance(notes, str):
        notes = (notes,)
    if isinstance(alternatives, str):
        alternatives = (alternatives,)
    original = reqs(rows)
    primary = [BY_REQ[x]['source_id'] for x in original] + select(prose)
    primary = sorted(set(primary), key=lambda sid: BY_ID[sid]['document_order'])
    context_ids = select(context)
    for sid in list(primary) + list(context_ids):
        r = BY_ID[sid]
        context_ids.extend(r.get('table_title_source_ids', []))
        context_ids.extend(r.get('header_source_ids', []))
        context_ids.extend(r.get('applicable_note_source_ids', []))
    for rid in original:
        r = BY_REQ[rid]
        context_ids.extend(r.get('table_title_source_ids', []))
        context_ids.extend(r.get('header_source_ids', []))
        context_ids.extend(r.get('applicable_note_source_ids', []))
    context_ids = sorted(set(context_ids) - set(primary), key=lambda sid: BY_ID[sid]['document_order'])
    force_rows = []
    for rid in original:
        r = BY_REQ[rid]
        cells = {c['column']: c['text'] for c in r.get('logical_cells', r['cells'])}
        if not r.get('logical_cells') and r.get('row_fragments'):
            cells = {col: ' '.join(frag_cell['text'] for frag in r['row_fragments'] for frag_cell in frag['cells'] if frag_cell['column'] == col and frag_cell['text']) for col in range(1, 5)}
        force_rows.append({'original_requirement_id': rid, 'source_id': r['source_id'],
                           'threshold_objective_verbatim': cells.get(3, ''),
                           'alternatives_verbatim': cells.get(4, ''),
                           'description_verbatim': cells.get(2, ''),
                           'field_provenance': 'Indexed logical_cells, or ordered column-preserving concatenation of indexed row_fragments cells.'})
    text_all = ' '.join(BY_ID[sid]['text'] for sid in primary + context_ids)
    xrefs = sorted(set(re.findall(r'MSC-[A-Z]{2}-\s*\d+', text_all)))
    GROUPS.append({'group_id': f'RG-{number:03d}', 'title': title,
                   'original_requirement_ids': original, 'source_ids': primary,
                   'requirement_passages': [passage(sid, 'requirement_or_immediate_qualification') for sid in primary],
                   'applicability': applicability,
                   'document_force': {'interpretation': force, 'table_rows': force_rows,
                                      'semantics_source_ids': select('p031:u009-u014')},
                   'alternative_logic_interpretation': list(alternatives),
                   'qualifications_and_exceptions': list(notes),
                   'context_source_ids': context_ids,
                   'context_passages': [passage(sid, 'definition_qualification_or_illustration') for sid in context_ids],
                   'cross_references_verbatim_tokens': xrefs,
                   'theorem_name': f'msc_{slug}',
                   'theorem_statement': statement,
                   'theorem_statement_status': 'AI interpretation for later formalization; exactly one encompassing top-level target; no proof constructed.',
                   'theorem_target_count': 1,
                   'review_status': 'See validation/review and validation/plan_audit for independent findings and current artifact hashes.',
                   'evidence_and_provability': 'Unknown until later model and evidence design; retained independently of current emulation capabilities.',
                   'open_issue_ids': []})


#* Compliance, product selection, and high-level architecture.
add(1, 'applicable_requirements_and_policy', 'Applicable requirements and policy precedence',
    'An MSC implementation provides the functions needed by its selected capabilities and satisfies every applicable threshold requirement or its stated objective alternative, together with applicable CNSS and local policy; CP requirements take precedence over conflicting local policy.',
    'Every implementation and its selected capabilities; Solution Owner, customer, and Authorizing Official.',
    'SR:6', 'p008:u007 p009:u002 p013:u010 p031:u009-u014 p056:u003',
    force='Mandatory compliance; preferred Objective variants are encouraged; optional capabilities need not be selected.',
    notes=('The term security level includes classification, compartments, dissemination controls, and other controls.', 'External CNSS policy content is not imported into the extraction.', 'Feedback and conflict reporting in §2 use request/should wording, not table T=O requirement strength.'))
add(2, 'validated_configuration_and_modification', 'Validated configuration and component modification',
    'Every Solution Component uses its NIAP-certified evaluated configuration, and an actual modification has the NIAP statement required by the CSfC PMO. Consultation with the vendor and NIAP continuity process is recommended for a proposed modification.',
    'All Solution Components and customers or Integrators modifying them.', 'PS:16', 'p008:u004-u005',
    force='Evaluated configuration and NIAP statement are required; pre-modification consultation is recommended.',
    notes=('Configuration changes outside the evaluated configuration and OEM-code changes, including code signing, are stated revalidation triggers.', 'The source does not guarantee that a modification will retain certification.'))
add(3, 'listed_product_eligibility', 'Product eligibility on the CSfC Components List',
    'Selected VPN Gateways, MACsec Devices, firewalls, and Authentication Servers belong to their specified CSfC product lists; selecting the optional IPS capability requires the IPS list, and NIAP certification alone does not establish list eligibility.',
    'Product selection for VPN Gateways, MACsec Devices, firewalls, ASs, and optional IPSs.',
    'PS:1-3,5,17', 'p010:u009 p011:u001.s002 p022:u005 p032:u023-u024 p059:u009',
    force='T=O for listed mandatory device categories; MSC-PS-5 is Objective/Optional.',
    notes=('Eligibility depends on the listed product model and version.', 'The CP prohibits protecting classified data with a single commercial product; the approved CP composition is required.', 'Contacting a vendor to seek listing is encouragement, not evidence that the product is eligible.'))
add(4, 'implementation_diversity', 'Independent product, operating-system, and cryptographic implementations',
    'Inner and Outer Encryption Components satisfy manufacturer or NSA-approved product independence, use different operating systems beyond service-pack or version differences, and use independent cryptographic libraries; any Gray Firewall also satisfies the specified independence relationship with Inner Encryption Components.',
    'Inner/Outer pairs and any Gray Firewall paired with Inner Encryption Components.', 'PS:6-8,10',
    alternatives=('Manufacturer independence and NSA-determined same-manufacturer product independence are disjunctive choices, not cumulative requirements.',))
add(5, 'physically_distinct_security_components', 'Physical separation of security components',
    'Inner and Outer Encryption Components use distinct physical devices, and the required firewalls and encryption components use separate devices with no device serving more than one of the specified functions.',
    'Inner/Outer Encryption Components; required Outer, Gray, and Inner firewalls.', 'PS:11-12',
    'p023:u005 p024:u001.s002 p024:u006.s001 p025:u006.s002',
    notes=('The prose includes a required Inner Firewall, while PS-12 enumerates Outer and Gray Firewalls.',))
add(6, 'supply_chain_assessment', 'Product Supply Chain Threat Assessment',
    'Every selected component undergoes the organization’s AO-approved Product Supply Chain Threat Assessment so that mitigations are determined for its intended application.',
    'Every selected component and the procuring organization.', 'PS:15', 'p032:u025',
    notes=('CNSSD 505 is a referenced external dependency; no assessment outcome is assumed.'))
add(7, 'nested_layer_protection', 'Two independent encryption layers and allowed tunnel pairings',
    'Every protected data flow across the untrusted Black Network passes through independent Inner then Outer encryption and the reverse decryption sequence using the IPsec/MACsec pairings in Table 1; each layer terminates on its matching encryption components, and Outer MACsec configurations are limited to point-to-point use.',
    'Protected data-plane packets or frames crossing the Black Network and directly communicating sites.',
    prose='p010:u005-u007 p012:u006 p014:u002 p018:u007 p022:u004',
    context='table-1 p010:u008 p010:u011 p011:u005.s001 p011:u007.s001 p012:u003.s001 p059:u008 p060:u004 p060:u008 p061:u004',
    force='Architectural requirements and permitted alternatives; Table 1 enumerates four permitted layer combinations.',
    notes=('Figures illustrate arrangements and do not prove compliance.', 'The blanket statement about all Black-Network communications is qualified elsewhere by permitted control-plane traffic; it must not erase those explicit exceptions.'))
add(8, 'security_level_connectivity', 'Connectivity restricted to the same security level',
    'Red Networks communicate through MSC only within the same security level, and Inner VPN Gateways authenticate and establish tunnels only for Red Networks of that level; multiple levels can share Outer infrastructure while each Red or included unclassified network retains its own Inner Encryption Component and applicable Red-network protections.',
    'Red Networks, included unclassified networks, Inner Encryption Components, and shared Outer infrastructure.',
    'VG:15', 'p010:u004 p011:u005.s002 p011:u005.s003 p011:u005.s004 p015:u007 p016:u001 p017:u003',
    context='p061:u009', force='Mandatory separation and conditional permission to share infrastructure.',
    notes=('Security level is richer than a classification label.', 'No limit on the number of levels is stated; Outer MACsec remains point-to-point under RG-007.'))
add(9, 'gray_network_classification_boundary', 'Gray-network control and classification boundary',
    'The Solution Owner or a trusted third party controls the Red and Gray Networks, and the MSC design is inapplicable if the classification authority classifies exposed Gray information that the design does not protect with two encryption layers.',
    'Solution Owner, classification authority, Red/Gray Networks and exposed Gray metadata.',
    prose='p011:u005.s005 p011:u007 p011:u008', context='p060:u008',
    force='Architectural ownership condition and explicit prohibition on implementing the design under the stated classification determination.',
    notes=('The text distinguishes singly encrypted classified payload from Gray information such as addresses; the exact classification decision remains external.'))
add(10, 'independently_managed_sites', 'Independently managed site administration and trust',
    'In the independently managed design, each site administers its own Encryption Components without management traffic crossing the Black Network, maintains interoperable peers, and provides the appropriate cross-site CA signing and revocation information or shared CAK for each communicating encryption relationship.',
    'Sites choosing independent management and their certificate or CAK trust relationships.',
    prose='p013:u012 p014:u004 p014:u006-u009', context='p014:u001 p014:u003 p014:u011 p060:u010',
    force='Conditional design requirements and permission to use locally managed or enterprise CAs.',
    notes=('The AS wording “both Gray and/or Red Networks” is retained without silently resolving its ambiguity; RG-024 includes the one-site AS table constraint.', 'Cross-site trust does not override per-layer or per-security-level CA separation.'))
add(11, 'centrally_managed_sites', 'Central management, CA placement, and intersite protection',
    'In the central-management design, the central personnel administer and key the sites with interoperable components, separate Inner and Outer CA functions, central CAs and an AS for certificate-based MACsec, and the required protection of management traffic across sites; enterprise CAs are preferred when available.',
    'Centrally managed sites, central administrators, CAs, AS, and intersite management traffic.',
    prose='p015:u002 p015:u004-u005', context='p015:u003 p015:u009 p059:u010 p061:u007',
    force='Conditional design requirements; enterprise-CA use is recommended; a PSK-authenticated layer may omit its CA.',
    notes=('Central Gray management depends on the external CSfC Enterprise Gray Implementation Requirements Annex.', 'The prose states at least two CAs and then allows a PSK layer without a CA; the exception remains explicit.', 'At least two encryption layers protect management traffic on the Black Network; local exceptions are in RG-046.'))
add(12, 'security_level_key_and_management_separation', 'Separate authentication and management for security levels',
    'Distinct Red security levels have separate CAs, CAKs, and management devices for their Inner Encryption Components so that components at different levels cannot mutually authenticate; same-level designs may elect the additional filtering controls described for multiple levels.',
    'Inner Encryption Components and management services for multiple Red security levels.',
    prose='p016:u002 p016:u004-u006', context='p061:u009',
    force='Mandatory separation across levels; additional same-level security is permitted.',
    notes=('CA and CAK clauses apply to the chosen authentication method, not to a requirement to deploy both methods.', 'Figure 5 is an illustration and does not establish complete compliance.'))
add(13, 'gray_firewall_path_coverage', 'Gray Firewalls on all paths needing level separation',
    'All Gray-network paths between Inner Encryption Components for different security levels, and the specified paths between Gray management services and lower-level Inner components, include Gray Firewalls that block the prohibited flows; Outer filtering remains required even when standalone Gray Firewalls are present.',
    'Multi-level Gray networks, AWs, locally run CAs, CDP/OCSP services, and Inner/Outer Encryption Components.',
    'SR:7-8', 'p017:u004-u005 p018:u001-u005 p024:u005 p024:u006.s002 p024:u006.s003',
    context='p018:u009 p060:u009 p061:u009',
    notes=('Gray AWs and locally run CAs are grouped with the highest Red security level in §4.2.2.2.', 'SR-8 refers to different security levels while the prose specifies lower-than-highest targets; both scopes are retained.', 'The word “typically” in §5.3 does not cancel the all-path requirements.'))
add(14, 'gray_addressing_for_level_filtering', 'Gray addressing supports security-level filtering',
    'Gray addresses and address ranges distinguish security levels so that the specified packet filters can admit only intended same-level Inner peers and reject cross-level paths.',
    'Address assignment on Gray interfaces and rules on Outer Encryption Components and Gray Firewalls.',
    prose='p017:u006 p023:u010', context='p018:u005 p061:u009',
    notes=('The §5.2 sentence says to prevent same-security-level communication, conflicting with the same-level allowances elsewhere; the theorem target is provisional and the conflict remains open.'))
add(15, 'macsec_encapsulation', 'MACsec encapsulation and standalone encapsulator obligations',
    'Inner MACsec traffic, and MACsec traffic crossing an IP network, receives encapsulation before Outer encryption without premature MACsec decryption; an unsupported built-in encapsulation feature requires a correctly connected standalone encapsulator, and its applicable Solution Component obligations are resolved explicitly from the conflicting source passages.',
    'Inner MACsec Devices, Outer Encryption Components, and any standalone encapsulation/decapsulation router or switch.',
    'MD:13', 'p019:u007-u010 p020:u002 p025:u007',
    context='p019:u011 p019:u013 p020:u001 p020:u011 p060:u003 p061:u002',
    force='Encapsulation is required; any AO-approved encapsulation protocol is permitted. The extent of standalone-device obligations is disputed by the source.',
    notes=('§4.2.3 and §5.5 require all Solution Component requirements, but the paragraph below Figure 8 places the step outside the boundary and highly recommends DM/port filtering.', 'MSC-MD-13 explicitly requires Solution Component treatment for §11.1.', 'No exemption or precedence rule is invented. The final formal target needs a documented interpretation decision.'))
add(16, 'macsec_optional_clear_vlan_and_xpn', 'Permitted MACsec clear VLAN tags and XPN',
    'A MACsec implementation may expose the VLAN ID tag and may use XPN when its device supports those features, while retaining the other applicable MACsec protection requirements.',
    'MACsec Devices supporting clear VLAN ID tags or extended packet numbers.',
    prose='p020:u003-u004', context='table-9', force='Conditional permissions, not requirements to enable the features.',
    notes=('The source discusses high speeds of 100 GB/s or higher; the extracted permission does not impose a new speed threshold.',))
add(17, 'mutual_device_authentication_and_npe', 'Mutual authentication and Non-Person Entity certificates',
    'Inner peers and Outer peers mutually authenticate using the method appropriate to VPN or MACsec, and every issued device authentication certificate for those components is a Non-Person Entity certificate.',
    'Peer encryption devices and all authentication certificates issued to them.',
    prose='p020:u006 p020:u009.s001 p023:u007 p025:u004',
    notes=('Detailed certificate validation, MACsec alternatives, and key handling are separate theorem groups.',))
add(18, 'cnss_algorithm_policy', 'CNSS algorithm-policy requirements and choices',
    'The solution satisfies the §2 algorithm-policy choices for confidentiality, authentication, key establishment, integrity, and objective software/firmware signing, respecting the listed threshold and objective alternatives and the detailed protocol tables.',
    'Protection of National Security Systems up to Top Secret using this CP.',
    prose='p009:u003-u015',
    force='The paragraph says required; authentication/key establishment distinguish Threshold and Objective; signing is Objective.',
    notes=('Only the algorithms stated in the supplied PDF are represented.', 'Detailed protocol tables include additional parameters and choices, including DH group 16; §2 is not silently substituted for those tables.'))

#* Cryptographic protocol requirements and alternatives.
add(19, 'ipsec_algorithm_profile_choice', 'IPsec CNSA profile and post-quantum exchange sequence',
    'Each VPN tunnel follows either the threshold CNSA 1.0 proposal profile or the corresponding CNSA 2.0 objective profile, whose initial IKE_SA_INIT uses a size-bounded CNSA 1.0 exchange and whose encrypted IKE_INTERMEDIATE uses ML-KEM-1024 with the specified IKE extensions and Table 7 algorithms outside the initial exchange.',
    'Inner and Outer VPN Gateways and every IPsec connection using the selected CNSA profile.',
    'VG:1,19-21', 'p026:u013 p027:u001-u011 p028:u002',
    context='table-6 table-7 p028:u001 p028:u008',
    force='MSC-VG-1 is Threshold; MSC-VG-19/20/21 are the corresponding Objective profile. Current objective status is distinct from prospective future requirements.',
    alternatives=('Interpret the “MSC-VG-19, MSC-VG-20, and MSC-VG-21” alternative as the three-part CNSA 2.0 profile, not as three independently sufficient substitutes.',),
    notes=('Referenced RFCs and drafts remain external dependencies; no external version is silently substituted.', 'Figure 10 supports the exchange ordering and does not prove a protocol implementation.'))
add(20, 'vpn_certificate_authentication', 'VPN certificate loading and authentication checks',
    'VPN Gateways authenticate during IKE using unique device certificates and the corresponding CA chain through its trust anchor, reject revoked or expired certificates, and either do not use preinstalled default/self-signed/proprietary certificates or remove them under the objective alternative.',
    'Every VPN Gateway and its IKE authentication.', 'VG:2-4,6-8', 'p020:u007',
    force='T=O for certificate loading and checks; non-use is Threshold and removal is Objective. RFC 8784 PSK augmentation is permitted.',
    alternatives=('MSC-VG-2 or MSC-VG-3 governs preinstalled certificates; the two rows must not be represented as mandatory simultaneous branches.',),
    notes=('CRL, OCSP, and similar mechanisms are permitted ways to check revocation.', 'RFC 8784 PSKs supplement certificates and depend on the Symmetric Key Management Annex.'))
add(21, 'vpn_private_key_confinement', 'VPN private-key access confinement',
    'A VPN Gateway private key is inaccessible through an interface, and the optional objective Mandatory Access Control policy permits only that VPN Gateway to access its key.',
    'Stored VPN private keys and optional access-control policy.', 'VG:5,17',
    force='MSC-VG-5 is T=O; MSC-VG-17 is Objective/Optional.')
add(22, 'ike_version_and_encryption_modes', 'IKEv2 and IKE/ESP encryption-mode alternatives',
    'Every VPN Gateway uses IKEv2 and selects a permitted IKE encryption mode and a permitted ESP encryption mode: CBC at threshold or GCM at objective, with HMAC integrity when ESP CBC is selected.',
    'All VPN Gateways, IKE encryption, and ESP encryption.', 'VG:9-12,18',
    force='IKEv2 is T=O. IKE and ESP each have their own independent Threshold/Objective choice.',
    alternatives=('IKE: MSC-VG-10 or MSC-VG-18.', 'ESP: MSC-VG-11 or MSC-VG-12.'))
add(23, 'vpn_sa_lifetimes_and_reauthentication', 'VPN SA lifetimes and reauthentication',
    'Every VPN Gateway configures an IKE SA lifetime of at most 24 hours and an ESP SA lifetime of at most 8 hours, and reauthenticates its tunnel peer before rekeying an IKE SA.',
    'All VPN Gateways and established IKE/ESP Security Associations.', 'VG:13-14,16')
add(24, 'macsec_authentication_choice_and_as', 'MACsec authentication alternatives and AS scope',
    'MACsec peers authenticate using either PSK CAKs or certificate-based EAP-TLS; the certificate branch uses an AS for mutual device-certificate authentication, each MACsec device acts as supplicant and authenticator, and the AS obeys the stated one-site and Red/Gray network connection restrictions.',
    'MACsec Devices; the AS when certificate-based authentication is selected.',
    'MD:3,14 AA:1-2', 'p020:u008 p026:u006.s001 p026:u006.s002 p026:u006.s003',
    context='p014:u007.s005',
    force='MSC-MD-3 and MSC-MD-14 are both marked Threshold alternatives. AA-1 and AA-2 are T=O within certificate-based MACsec.',
    alternatives=('Choose MSC-MD-3 CAK authentication or MSC-MD-14 EAP-TLS authentication; do not relabel EAP-TLS as Objective.',),
    notes=('The AS may connect to only one site’s network; §4.2.1.1 additionally uses ambiguous “both Gray and/or Red Networks” wording.',))
add(25, 'macsec_encryption_and_key_wrap', 'MACsec encryption and key wrapping algorithms',
    'MACsec Devices use 256-bit AES Key Wrap for key distribution and 256-bit AES GCM for MACsec protection with the algorithms specified in Table 9.',
    'MACsec data encryption and key distribution.', 'MD:1-2', context='table-9')
add(26, 'macsec_eap_tls_profile_choice', 'MACsec EAP-TLS CNSA profile alternatives',
    'Certificate-authenticated MACsec Devices and their AS use either the Table 10 CNSA 1.0 EAP-TLS suite or the objective Table 11 CNSA 2.0 suite, with ML-KEM-1024, ML-DSA-87, and TLS 1.3 in the CNSA 2.0 branch.',
    'MACsec Devices and AS participating in EAP-TLS.', 'AA:3-4',
    'p026:u006.s004 p026:u006.s005 p028:u004', context='table-10 table-11',
    force='AA-3 is Threshold and AA-4 is Objective; prose future migration statements do not make the Objective branch universally mandatory in this version.',
    alternatives=('Select MSC-AA-3 or MSC-AA-4 as the corresponding cipher-suite profile.',))
add(27, 'macsec_key_generation_and_server', 'MACsec key generation, key-server selection, and rollover',
    'MACsec CKNs come from an NSA-approved KGS and are at least 16 bytes. The applicable CAK-generation constraint remains provisional for the EAP-TLS branch because the source states both MSK derivation and KGS generation of all CAKs; the PSK branch uses the stated approved-KGS generation. Each pair sets the prescribed key-server values with the central site serving when present, and fallback CAKs are disabled.',
    'MACsec CAKs/CKNs and each pair forming a MACsec tunnel.', 'MD:5-6,15',
    'p020:u009.s002 p029:u012', context='p020:u008.s003 p020:u008.s004 p020:u008.s005 p060:u013',
    notes=('Key Server value is 0 for the server and 1 for the other device.', 'External key-management details are not reconstructed from relocated rows.'))
add(28, 'macsec_protection_parameters', 'MACsec mandatory protection parameters',
    'MACsec Devices enable MKA data-delay protection, set lifetime and hello timeouts to 6.0 and 2.0 seconds, set the replay window to 2 or the lowest value possible for the Black Network, encrypt all external data traffic, set confidentiality offset to zero, and operate in must-secure mode.',
    'All MACsec Devices and their external data ports.', 'MD:7-10,12,16',
    notes=('The replay-window clause retains its network-dependent qualification; no fixed value of 2 is imposed when the source permits another minimum.', 'MD-10 and MD-16 overlap but are both preserved.'))
add(29, 'inner_tunnel_no_bypass', 'Inner encryption and decryption cannot be bypassed',
    'Inner VPN Gateways use ESP tunnel mode with an associated IP tunneling protocol; Inner Encryption Components never bypass encryption from Red to Gray or decryption from Gray to Red and never permit split tunneling, using Mandatory Access Control in each selected objective branch.',
    'Inner Encryption Components, their Red/Gray interfaces, and all corresponding traffic.',
    'IR:1,3-7', 'p025:u006.s001 p061:u010', context='p060:u005 p060:u012',
    force='Tunnel mode and no split tunneling are T=O; each bypass direction has a Threshold rule or Objective Mandatory Access Control implementation.',
    alternatives=('Red-to-Gray: MSC-IR-3 or MSC-IR-4.', 'Gray-to-Red: MSC-IR-5 or MSC-IR-6.'))
add(30, 'outer_tunnel_no_bypass', 'Outer encryption and decryption cannot be bypassed',
    'Outer VPN Gateways use ESP tunnel mode; Outer Encryption Components accept already-encrypted Gray traffic except permitted control-plane traffic, never bypass encryption to Black or decryption from Black, and never permit split tunneling, using Mandatory Access Control in each selected objective branch.',
    'Outer Encryption Components and Gray/Black interface traffic.', 'OR:1-7',
    'p024:u002.s001', context='p060:u005 p060:u012 p061:u010',
    force='OR-1/4/7 are T=O; OR-2/3 and OR-5/6 are Threshold/Objective alternatives.',
    alternatives=('Gray-to-Black encryption: MSC-OR-2 or MSC-OR-3.', 'Black ingress decryption: MSC-OR-5 or MSC-OR-6.'),
    notes=('OR-4 expressly excepts control-plane traffic; that exception must survive the encompassing theorem.',))
add(31, 'encryption_component_routing_limits', 'Routing and switching limits on Encryption Components',
    'Outer Encryption Components do not implement routing protocols or routing functionality as stated in the prose, while permitted firewall infrastructure supplies dynamic routing; Inner Encryption Components do not switch or route for other Encryption Components.',
    'Outer internal/external interfaces and Inner Encryption Components.', 'OR:8 SR:17',
    'p013:u006.s005 p013:u006.s006 p013:u006.s007 p013:u006.s008 p023:u011',
    notes=('Routing between protected domains remains prohibited by RG-029 and RG-030; the prose’s broad “routing functionality” requires review against infrastructure routing descriptions.',))
add(32, 'transec_conditions', 'TRANSEC under the stated deployment conditions',
    'TRANSEC is enabled under the applicable Public-Internet and MACsec-to-Outer-Firewall conditions once the conflicting prose and objective-table requirement strength are resolved explicitly.',
    'Outer Encryption Components using the Public Internet or a MACsec external interface connected to an Outer Firewall.',
    'OR:9', 'p023:u008.s004', context='p061:u011',
    force='§5.2 says must for Public Internet. MSC-OR-9 is Objective with a blank Alternatives cell for a MACsec interface connected to an Outer Firewall.',
    notes=('The differing requirement strength and conditions are retained as an open source conflict; a blank Alternatives cell is not silently changed to Optional.',))
add(33, 'packet_size_configuration', 'Packet sizing to control fragmentation',
    'Gray Firewall/Encryption Component external packet sizes satisfy the required IPv4 MTU or IPv6 PMTU configuration, and the optional Inner interface objective sizes packets or frames with the Black Network and Outer Component limits in view.',
    'External interfaces of Gray Firewalls and Encryption Components; optional Inner interface sizing objective.',
    'SR:23 IR:2', force='SR-23 is T=O; IR-2 is Objective/Optional. “Should consider” clauses remain recommendations.',
    notes=('The source distinguishes avoiding fragmentation in SR-23 from reducing fragmentation in IR-2.',))

#* Network filtering and management.
add(34, 'outer_firewall_placement', 'Outer Firewall placement for untrusted Black transport',
    'An MSC solution using an untrusted Black network such as the Public Internet places an Outer Firewall between that network and the Outer Encryption Component, with the stated internal and external connections.',
    'Untrusted Black transport and Public-Internet deployments.', 'SR:12',
    'p012:u003.s005 p023:u002 p023:u008.s001 p023:u008.s002 p023:u008.s003',
    context='p012:u004 p012:u010',
    notes=('The prose uses the broader “untrusted network such as Public Internet” condition; SR-12 explicitly names Public Internet.',))
add(35, 'boundary_interface_filtering', 'Permitted protocols and peers at encryption and firewall boundaries',
    'Outer VPN Black interfaces permit IKE/ESP and approved control traffic, Outer MACsec Black interfaces permit MACsec PDUs and approved control traffic, and Inner Gray interfaces permit the listed tunnel/control protocols in both directions. Inner Red interfaces permit only addresses and ports associated with Red services. A required Outer Firewall applies its protocol allowlist, with its external interface using the local Outer Encryption Component as the permitted destination and its internal interface using that local component as the permitted source, subject to the stated control-plane allowances. Packets leaving the Outer Encryption Component make connections only to the remote Outer Encryption Component or other intended device.',
    'All Outer Black interfaces, Inner Gray interfaces and Red service interfaces, and required Outer Firewalls.',
    'PF:3-5,22 OR:10', 'p023:u003-u004 p023:u009 p025:u005',
    notes=('Multiple external tunnel interfaces are allowed, but each obeys port filtering.', 'The §5.1 prose lists IPsec/MACsec while PF-22 also names IKE/MKA and approved control traffic; retain the table’s detailed allowances.', 'Inner internal interfaces permit only addresses and ports associated with Red services.'))
add(36, 'minimal_interface_exposure', 'Minimal network-interface exposure',
    'Each Solution Component restricts every network interface to the smallest possible address ranges, ports, and protocols and disables every unused network interface.',
    'All network interfaces of all Solution Components.', 'PF:1-2')
add(37, 'outer_third_party_services', 'Outer-component third-party contact restrictions',
    'Every service or feature enabling an Outer Encryption Component to contact a third-party server is blocked at threshold or disabled at objective.',
    'Outer Encryption Component features, including manufacturer-server contact.', 'PF:6-7',
    force='Threshold blocking or corresponding Objective disabling.',
    alternatives=('MSC-PF-6 or MSC-PF-7.',))
add(38, 'ip_header_and_multicast_filtering', 'IP header and multicast filtering',
    'Outer Encryption Components drop external multicast, VPN Gateways admit only the specified IPv4 Protocol or IPv6 Next Header values, and the selected IPv4 Outer-IPsec objective drops packets containing IP options.',
    'External Outer traffic; all VPN Gateways according to deployed IP version.', 'PF:9-12',
    'p021:u004.s004', force='PF-9/11/12 are T=O; PF-10 is Objective with a blank Alternatives cell.',
    notes=('PF-10 has no stated threshold alternative; its blank table cell remains visible for review.',))
add(39, 'outer_gray_interface_policy', 'Outer Gray-interface allowlist and default denial',
    'Outer Gray interfaces admit the specified same-level Inner tunnel traffic, approved management/control traffic, and conditional revocation HTTP; restrict management initiation to Gray AWs except Outer logging/authentication; enforce source reachability and peer addressing; and deny traffic outside PF-8, PF-13, PF-15, and PF-19.',
    'Gray interfaces of Outer Encryption Components; HTTP clause applies when CDP/OCSP is on the Gray data plane.',
    'PF:8,13,15,17-20', context='p060:u001 p061:u009 p023:u010',
    notes=('The source’s same-level permit rules conflict with §5.2’s same-level prevention sentence.', 'PF-17’s address-only restriction must be reconciled with explicit management/control and revocation exceptions, rather than erasing those exceptions.', 'The PF-20 reference list is preserved exactly.'))
add(40, 'gray_firewall_allowlist', 'Gray Firewall allowlist and cross-level denial',
    'A required Gray Firewall permits the listed same-level tunnel, revocation HTTP, physical-management-port, and control-plane traffic; enforces peer address and source-reachability restrictions; denies traffic outside the enumerated exceptions; and blocks traffic between Inner VPN Gateways of different classification levels.',
    'Required Gray Firewalls and their data/management interfaces.', 'PF:23,25,27-32',
    context='p030:u006 p060:u001 p060:u009 p061:u009',
    notes=('PF-32 says classification levels, while other clauses use the broader security-level definition; both are retained.', 'PF-28 address restrictions coexist with the explicit management/control/HTTP exceptions.', 'HTTP beyond revocation checking is blocked.'))
add(41, 'control_plane_policy_and_services', 'Control-plane approval, defaults, and service location',
    'Control-plane services reside inside the relevant encryption layer; unapproved protocols are blocked or disabled; necessary standards-conformant Layer 2 protocols are permitted, Layer 3 defaults to disabled unless AO policy allows it, and Red/Gray multicast and existing routing protocols follow their stated AO conditions. Networks may independently select IPv4 or IPv6, and appropriate protocols may be selected where the CP does not specify one.',
    'Control-plane services and protocols, Red/Gray/Black networks, and Solution Owner/AO approvals.',
    'SR:1', 'p013:u006.s001 p013:u006.s002 p013:u006.s003 p013:u006.s004 p013:u007 p021:u003 p021:u004.s001 p021:u004.s002 p021:u004.s003 p021:u005 p056:u011',
    context='p012:u008 p013:u001-u005',
    force='Mandatory service placement, approval restrictions, and Layer-3 default; conditional protocol permissions.',
    notes=('Red, Gray, and Black can independently use IPv4 or IPv6 unless a specific clause says otherwise.', 'The general absence of a prescribed protocol does not override specific IPsec, revocation, or Outer-routing restrictions.'))
add(42, 'trusted_time_synchronization', 'Layer-specific trusted time synchronization',
    'Inner Encryption Components and Red Management Services synchronize to a trusted Red time source, while Outer Encryption Components, Gray Management Services, and any Gray Firewall synchronize to a trusted source in the Gray Management Network.',
    'Encryption Components and layer-specific management services; Gray Firewall when present.',
    'SR:3-4', context='p013:u006.s002 p013:u006.s003',
    notes=('No specific synchronization protocol or technique is required by the source.',))
add(43, 'defaults_dns_and_boot_configuration', 'Default credentials, DNS, and remote bootstrap',
    'Solution Components change or remove default access-control values, specify DNS server addresses or disable DNS services, and disable automatic remote boot-time configuration; the optional objective disables network-device DNS lookup.',
    'All Solution Components and network-device DNS lookup.', 'SR:5,19-21',
    force='SR-5/20/21 are T=O; SR-19 is Objective/Optional.',
    notes=('Specified DNS servers and disabled DNS are alternatives in SR-20.',))
add(44, 'layered_administrative_separation', 'Layer-specific administration and management-plane separation',
    'Each component has adequate AW administration, with at least one Red AW and one Gray AW; Inner/Red and Outer/Gray management use their respective networks and distinct AWs, dedicated management interfaces, and the stated physical, cryptographic, and ACL separation from data traffic; Gray Management has no direct connection to NIPRNet or another unclassified network not dedicated to CSfC administration.',
    'All AWs, Solution Components, and Red/Gray management and data planes.',
    'SR:18 DM:3-6,17,25',
    'p011:u005.s006 p011:u005.s007 p011:u009.s003 p011:u009.s005 p011:u009.s006 p011:u009.s007 p012:u001.s002 p013:u008 p024:u010 p026:u002 p030:u003.s001 p030:u003.s002 p030:u005 p030:u006',
    force='Mandatory administrative separation; administrative functionality may be distributed across the AW set.',
    notes=('Physical and cryptographic separation in §4.1.4 and the minimum Gray Firewall ACL separation in DM-25 apply together. The minimum ACL condition does not waive the stronger separation conditions.', 'Control-plane traffic has no general separation requirement unless specified.', 'Gray management attachment is to the required Gray Firewall or otherwise the Outer Component.'))
add(45, 'dedicated_and_hardened_aws', 'Dedicated, protected, hardened Administrative Workstations',
    'Physical AWs and AW virtual machines use the stated dedicated hardware/VM boundaries, reside in protected facilities, exclude prohibited functions and non-CSfC uses, follow vendor and organizational hardening/patching policy, and power off when unused.',
    'Physical AWs, AW VMs, and their hosts/servers.', 'DM:1-2,23-24,26-28',
    'p030:u004',
    notes=('§6.2 prohibits AW hosts from hosting provisioning/enrollment/registration/SIEM VMs. DM-24 requires separate workstations or VMs for those functions. Both restrictions apply: a separate VM must also respect the AW host restriction.', 'No provisioner or SIEM function is silently assigned to an AW.'))
add(46, 'secure_management_transport', 'Management transport protection and local exceptions',
    'Solution Components are managed securely through an AW over an NSA-approved remote solution or locally; management addresses are minimized, network management uses the listed secure protocols, direct physical local management has its stated exception, and Black-network management receives two approved encryption layers with the local LAN/VLAN qualification retained.',
    'All administrative and monitoring traffic, local direct connections, same-LAN/VLAN traffic, and remote Black transport.',
    'DM:7-8', 'p012:u007 p024:u002.s002 p030:u007',
    context='p015:u004 p060:u014 p061:u006',
    notes=('§5.2 broadly says Gray AW traffic must include two layers, while §6.2 gives local and LAN/VLAN qualifications.', 'The LAN/VLAN exception most immediately follows the Black-network two-layer sentence; it is not silently interpreted as permission for all same-LAN management to be plaintext.', 'The same-site example says CNSA algorithms are unnecessary there; listed secure protocols remain separately stated.'))
add(47, 'administrator_authentication', 'Administrator authentication and individual credentials',
    'Security Administrators authenticate before administrative functions, using CNSA certificates under the objective alternative; each AW administrator has unique credentials without group accounts, and the optional NIST SP 800-63 objective applies when selected.',
    'Security Administrators, Solution Component administration, and AW accounts.', 'DM:9-10,13,29',
    force='DM-9/10 are Threshold/Objective alternatives; DM-29 is T=O; DM-13 is Objective/Optional.',
    alternatives=('MSC-DM-9 or MSC-DM-10.',))
add(48, 'authorized_initial_provisioning', 'Authorized provisioning and initial certificate requests',
    'The Solution Owner identifies authorized Security Administrators, who provision components out of band in a secured area before first use, initiate the required CSRs, deliver them to the appropriate Inner or Outer CA, and install unique signed certificates with their chains; AWs interacting with the Outer VPN CA reside on Gray.',
    'Initial provisioning of VPN and certificate-based MACsec components and their administrators.',
    'DM:11-12,14', 'p029:u008 p029:u010-u011 p029:u013 p030:u001',
    notes=('Installing an initial CRL is permitted rather than universally mandated by the provisioning prose.', 'The certificate-based MACsec paragraph calls the inner device an “Inner VPN Gateway”; the source wording is retained as a terminology issue.', 'PSK provisioning is covered by RG-027.'))
add(49, 'personnel_clearance', 'Personnel clearance and Outer administration',
    'Security Administrators, Auditors, and Integrators hold the highest protected-data clearance, subject to the stated Black Network Administrator exception, and Outer administrators meet the highest Red classification at the Outer Component’s site.',
    'Security Administrators, Auditors, Integrators, Black Network Administrators, and Outer Component administration.',
    'DM:22 RB:1',
    notes=('The site-scoped Outer rule and solution-scoped personnel rule remain separately visible.',))
add(50, 'siem_collection_alerting_and_protection', 'SIEM placement, collection, alerting, and log transport',
    'Deployed Red and Gray SIEM functions collect the stated component logs and flow data and provide the specified alerts. Log transport is recommended to use SSHv2, TLS 1.2 or later, IPsec, or MACsec encryption. Gray functions may move to a Red SIEM through an approved CDS, and a Gray SIEM is optional.',
    'Deployed SIEMs, source components, and approved CDS-based Gray-to-Red monitoring.',
    prose='p011:u009.s004 p024:u008.s001 p024:u008.s002 p024:u008.s003 p024:u012 p025:u001 p025:u011 p026:u004 p030:u003.s003',
    force='Conditional configuration descriptions; log encryption is stated as should; Gray SIEM deployment is explicitly optional.',
    notes=('Red SIEM mandatory status is not established merely by its description.', 'The Continuous Monitoring Annex supplies additional monitoring obligations not present in this PDF.'))
add(51, 'cross_domain_solution_conditions', 'Cross Domain Solution approval conditions',
    'Any CDS used in the solution adheres to DoDI 8540.01 and the DISN Connection Process Guide and is on the National Cross Domain Strategy Management Office CDS Baseline.',
    'Any deployed CDS, including SIEM-log transfer use.', 'SR:22', context='p060:u002',
    notes=('The three external conditions are conjunctive; their external contents are not reproduced.',))
add(52, 'physical_protection_access_and_disposal', 'Physical protection, authorized access, and disposal',
    'Solution Components other than the stated Outer Firewall exception receive the highest required classified physical protection, only authorized cleared or escorted personnel gain physical access, MACsec configuration copies receive CAK-level protection, and components are disposed of as classified unless AO-approved declassification procedures apply.',
    'Solution hardware, MACsec configuration files and physical access/disposal operations.',
    'GD:1-3 SR:9 MD:11', 'p011:u009.s002 p022:u006 p024:u008.s004',
    notes=('GD-1 includes the highest level in interconnected MSC solutions; the narrower prose is not substituted for that clause.', 'The Outer Firewall exception is attached to physical-protection classification; no blanket exception from every handling clause is inferred.'))
add(53, 'shared_outer_interface_topology', 'Parallel Inner components and distinct Outer internal interfaces',
    'Inner Encryption Components sharing an Outer Encryption Component are arranged in parallel, and that Outer Component has a unique physical internal interface for each Red Network without VLAN trunking of multiple enclaves.',
    'A site with multiple Red Networks or multiple Inner Encryption Components sharing an Outer Component.',
    'SR:10,16', context='p015:u007')
add(54, 'site_interoperability', 'Interoperable components across communicating sites',
    'Every pair of sites that needs to communicate selects interoperable components for each tunnel, with interoperability testing recommended despite product-list eligibility.',
    'Communicating sites and their Inner and Outer tunnels.', 'SR:2',
    'p011:u001.s003 p011:u001.s004', context='p014:u006 p015:u002',
    force='Interoperability is T=O; testing in §4 is recommended.')
add(55, 'combined_cp_firewalls', 'Firewall requirements when combining capability packages',
    'When MSC is combined with another CSfC solution, a required Gray Firewall is included and any Inner Firewall requirements imposed by a combined data-in-transit/end-user-device CP are followed; the standalone MSC CP does not itself require an Inner Firewall.',
    'Solutions combining MSC with other CSfC capability packages.', 'SR:11,13', 'p025:u009',
    notes=('Applicable companion-CP requirements remain external dependencies.',))
add(56, 'approved_red_egress_paths', 'Approved physical paths out of Red Networks',
    'Every physical path leaving a Red Network uses a conforming MSC solution or an AO-approved data-in-transit protection solution, allowing the stated coexistence of an NSA-certified product path and a CP-conforming CSfC path.',
    'All Red-network egress paths.', 'SR:14',
    notes=('The source footnote permits parallel government-certified and CSfC protected egress paths; it does not authorize unprotected paths.',))
add(57, 'patches_virus_updates_and_tempest', 'Operational security updates and TEMPEST policy',
    'Solution Components receive virus updates as required by policy and the AO, security-critical patches are tested then applied according to policy and this CP, local policy specifies patch installation, and components comply with local TEMPEST policy.',
    'All components and their patch/update operation.', 'SR:15 GD:22-24',
    context='p054:u008 p056:u013')
add(58, 'inventory_and_baseline_configuration', 'Hardware inventory and available baseline configuration',
    'Every hardware component is tracked by the AO-approved inventory process as part of a CSfC solution, and the Security Administrator maintains a baseline configuration available to the Auditor.',
    'All hardware and component configurations.', 'GD:25-26')
add(59, 'procurement_purpose_nondisclosure', 'Procurement documentation excludes classified-protection purpose',
    'Acquisition and procurement documentation omits the equipment purpose, including its use to protect classified information.',
    'Acquisition and procurement records for solution equipment.', 'GD:4')
add(60, 'compliance_audits', 'Annual and NSA-authorized compliance audits',
    'The Solution Owner permits and fully cooperates with NSA-authorized compliance audits, the AO ensures an annual audit against the latest CP as part of re-registration, and the AO receives and reviews the results.',
    'Solution Owner, AO, annual renewal, and authorized audit requests.', 'GD:5-7', 'p056:u009',
    notes=('Inspection, testing, observation, and interviewing are non-exhaustive audit methods.',))
add(61, 'registration_and_version_updates', 'Registration, approval, annual renewal, and version updates',
    'Before operational use the customer obtains NSA registration approval and submits the complete registration package and AO compliance matrix, then renews annually and updates changed registration information; new-version compliance follows an explicitly resolved deadline preserving both the table and §13.3 statements.',
    'All customers using CSfC on NSS; Solution Owner and AO; initial use and changes/renewals.',
    'GD:8-12', 'p008:u008 p008:u009 p009:u001 p056:u007 p057:u014 p058:u001 p058:u002',
    notes=('GD-11 says compliance at next registration renewal, whereas §13.3 says six months from notification and re-registration. Neither deadline is silently discarded.', 'Top Secret solutions are considered case by case.', 'The annual validity starts from approval.', 'The registration acknowledgement describes approval; no artifact here is an actual registration approval.'))
add(62, 'audit_log_retention_and_continuity', 'Audit retention, storage monitoring, backup, and continuity',
    'Audit data is retained for at least one year, remaining capacity is assessed quarterly, frequent backups occur, incident-reporting guidance is documented, and the organization maintains an audit continuity plan covering capacity warnings, long-term offload, overflow response, and power events.',
    'Audit storage, Security Administrators, and the implementing organization.', 'GD:13-20',
    context='p059:u003 p059:u004',
    notes=('The source gives no numeric backup frequency beyond “frequently”; no interval is invented.',))
add(63, 'infrastructure_authentication_choice', 'Infrastructure authentication alternatives',
    'Infrastructure components use either threshold passwords containing at least 112 random bits or the objective authentication service on their respective network/domain, with an approved password generator recommended for the password branch.',
    'All infrastructure components and their access mechanisms.', 'GD:21,27',
    force='Threshold password requirement or Objective domain authentication service; password-generator use is recommended.',
    alternatives=('MSC-GD-21 or MSC-GD-27.',),
    notes=('The external Key Management Annex Appendix A is a dependency; no password-generation algorithm is invented.',))
add(64, 'incident_reporting', 'Incident triggers, required report fields, and reporting deadline',
    'For every reportable incident under RP-3 through RP-15, the Solution Owner reports the confirmed incident within 24 hours of detection through the stated NSA channel and supplies at least all RP-2 fields, treating unexplained activity as malicious unless known non-malicious and preserving the Black-connectivity exception.',
    'Solution Owners, AO reporting duties, and incidents affecting the solution.', 'RP:1-15',
    'p052:u011-u013 p056:u012', context='p060:u015',
    notes=('The trigger is the disjunction of RP-3 through RP-15, not a requirement that every condition occur.', 'RP-13 excludes connectivity issues associated with the Black Network.', 'RP-1 says confirmed incidents while the malicious definition includes unexplained activity; reporting certainty must not be tightened silently.', 'Local incident procedures remain in force; the CP adds its reporting obligations.'))
add(65, 'separation_of_personnel_roles', 'Separation of administrative and auditing personnel',
    'Different people perform Security Administrator and Auditor roles, different administrators manage Inner/Red and Outer/Gray components, and optional Mandatory Access Control role definitions apply when selected; customers may also require Red/Gray separation among Integrator personnel.',
    'Security Administrators, Auditors, and optional Integrator-role separation.', 'RB:2,5,11',
    'p026:u011', force='RB-2/5 are T=O; RB-11 is Objective/Optional; Integrator separation is a customer permission.')
add(66, 'training_and_hardware_inspection', 'Personnel training and physical tamper inspections',
    'Security Administrators and Auditors meet local IA training requirements, and administrators periodically inspect infrastructure hardware for tampering or unauthorized physical changes.',
    'Security Administrators, Auditors, and infrastructure hardware.', 'RB:3,6',
    notes=('“Periodically” is preserved without inventing an interval.',))
add(67, 'predisposal_key_revocation', 'Revocation or CAK destruction before disposal',
    'Security Administrators initiate the certificate-revocation or CAK-destruction process before disposal of any Solution Component.',
    'Any Solution Component scheduled for disposal and its administrators.', 'RB:8',
    notes=('Initiating the applicable process is the exact stated timing obligation; completion criteria belong to external key-management requirements.',))
add(68, 'security_administrator_duties', 'Security Administrator operational duties',
    'Security Administrators maintain, monitor, and control solution security, apply critical updates, document/report incidents, support integration and maintenance logistics with necessary escorts, defend auxiliary network devices, and maintain CP-version compliance according to GD-11.',
    'Security Administrators for the solution and auxiliary network devices.',
    prose='p054:u007-u012',
    notes=('The role may also be called Information System Security Officer.', 'The listed duties are non-exhaustive.', 'Version-transition conflict remains in RG-061.'))
add(69, 'auditor_duties_and_access', 'Auditor review duties and access boundary',
    'The Auditor reviews administrator actions and audit events for compromise, manages audit log data, documents and reports incidents, develops and reports a System Audit Capability Survey, and is authorized access only to Inner and Outer administration components.',
    'Auditor role and audit/administration systems.', prose='p054:u013-u016',
    notes=('The duties are stated as non-exhaustive.',))
add(70, 'integrator_permitted_duties', 'Optional Integrator involvement and duty scope',
    'A customer may engage an external Integrator to implement the CP, with the possible duties of acquiring products, configuring the solution, documenting/testing/maintaining it, and responding to incidents, subject to the applicable CP obligations.',
    'Customers choosing an external Integrator and that Integrator’s assigned duties.',
    prose='p055:u001-u005', force='Optional engagement and non-exhaustive possible duties; no mandatory Integrator role is invented.')
add(71, 'ao_authorization_and_lifecycle_control', 'AO authorization evidence and lifecycle control',
    'The customer obtains security assessment and authorization using the referenced risk information and provides the results and NSA Risk Assessment to the AO. A customer wanting a solution variant contacts its NSA External Engagement Representative to determine how to obtain approval. The AO verifies proper implementation, maintains lifecycle configuration/update control, and ensures that certificate/CAK revocation information is updated on all Solution Components after compromise.',
    'Customer, testing/assessment team, AO, proposed variants, and compromise response.',
    prose='p056:u002 p056:u005-u006 p056:u008 p056:u010 p056:u013 p057:u012',
    context='p059:u005 p061:u008',
    force='Stated customer/AO obligations, must for risk-assessment delivery, and should for obtaining the risk document through the stated route.',
    notes=('The NSA Risk Assessment is external and not included; its findings are not inferred.', 'The AO’s formal approval is not replaced by a theorem or by the source figures.'))
add(72, 'solution_testing_and_evidence', 'Whole-solution testing and preserved results',
    'The implementing organization tests every security feature and operational capability, executes all Testing Annex tests, documents the baseline and discrepancies, uses Black- and Gray-Box tests, checks that local requirements do not impair security, retains test artifacts, and delivers the final report to the AO, with two-person testing recommended.',
    'The entire solution and all §5 components; implementing organization and test team.',
    'TR:1', 'p056:u004 p056:u015-u016 p057:u001-u007',
    context='p059:u007 p060:u007',
    force='TR-1 and explicit must clauses are mandatory; two-person testing and some methodology clauses are recommendations.',
    notes=('The Testing Annex is an external dependency, so its individual tests are not invented.', 'The minimum baseline record includes model/serial numbers, software versions, and configuration settings.'))
add(73, 'software_firmware_signature_choice', 'Objective software and firmware signing algorithms',
    'When the software/firmware signing objective is selected, every Solution Component uses one of the Table 2 approved algorithms and its stated parameters; one permitted algorithm is sufficient for the requirement.',
    'All Solution Components, including firewalls, VPN Gateways, and Authentication Servers, under the objective branch.',
    'SR:24', 'p028:u006 p029:u001', context='table-2',
    force='MSC-SR-24 is Objective/Optional in this version; future implementation dates are not inferred.',
    alternatives=('LMS, XMSS, or ML-DSA-87; the algorithms are alternatives, not three simultaneous obligations.',),
    notes=('LMS SHA-256/192 is recommended in Table 2; all approved parameters are stated.', 'The source says migration timelines may change.'))
add(74, 'redundant_component_permission', 'Redundant component and load-balancing permission',
    'An implementation may add parallel redundant encryption components or multiple compliant firewalls for failover or throughput only while every added security component meets its applicable CP requirements; the shown infrastructure router carries only the explicitly stated CP scope.',
    'Optional redundant Inner/Outer Encryption Components, Gray Firewalls, and the Figure 9 router/switch.',
    prose='p021:u007-u008 p022:u002 p024:u003 p024:u006.s004 p025:u003',
    context='p022:u001 p022:u009', force='Conditional permission; automatic high availability and failover design are not guaranteed by this CP.',
    notes=('§4.4 says the ordinary Gray router/switch has no CP security requirements; an encapsulating router/switch has a different treatment in RG-015.', 'A picture of redundant tunnels does not establish complete compliance or implemented failover.'))
add(75, 'additional_control_permissions', 'Optional additional controls and screening-router scope',
    'An implementation may add the stated risk-reducing controls, including a screening router on the Black Network; the router is outside the MSC Solution boundary and optional annex components receive only the scope expressly stated by the source.',
    'Optional screening router, existing Black infrastructure, and optional key-management-annex components.',
    prose='p022:u007 p026:u010', force='Permissions with explicit component-scope limitations.',
    notes=('The scope statement is not a general exemption for other routers or all annex-related components.',))
add(76, 'cp_user_legal_undertaking', 'CP user legal undertaking and disclaimer',
    'Use of the CP is associated with the source’s disclaimer and user undertaking to hold harmless and indemnify the U.S. Government, its agents, and employees for the listed claims; any formal representation must preserve the stated scope and receive legal-domain review.',
    'The CP user and the legal undertaking in §3, not network packet behavior.',
    prose='p009:u017-u018 p010:u002',
    force='Legal disclaimer and contractual undertaking, separate from T/O technical compliance.',
    notes=('Retained because the plan does not exclude process or non-network obligations.', 'No legal validity or enforceability is established by this interpretation; a legal-domain model is unresolved.'))


#* Source conflicts are explicit review blockers rather than invented precedence.
ISSUES = [
    ('REQ-I01', ['RG-015'], 'Standalone encapsulator boundary and requirement strength conflict', 'p019:u009 p020:u002 p025:u007', ['MSC-MD-13'],
     '§4.2.3 and §5.5 require all Solution Component obligations; below Figure 8 the encapsulation step is outside the solution with DM/PF highly recommended; MD-13 mandates §11.1 treatment. Resolve applicability without silently deleting any passage.'),
    ('REQ-I02', ['RG-014', 'RG-039', 'RG-040'], 'Same-level filtering sentence conflicts with the permitted peers', 'p023:u010 p018:u005', ['MSC-PF-13', 'MSC-PF-17', 'MSC-PF-23', 'MSC-PF-28'],
     '§5.2 says to prevent same-security-level communication. Other provisions allow same-level tunnels and prohibit different-level communication. The original words remain uncorrected.'),
    ('REQ-I03', ['RG-046', 'RG-011'], 'Management encryption and local exceptions', 'p024:u002.s002 p030:u007 p015:u004', ['MSC-DM-8'],
     'Broad two-layer Gray-management wording coexists with direct physical-management exceptions, LAN/VLAN qualification, and a same-site CNSA exemption. The scope of each exception needs a formal applicability decision.'),
    ('REQ-I04', ['RG-032'], 'TRANSEC requirement strength and applicability differ', 'p023:u008.s004', ['MSC-OR-9'],
     'Public-Internet prose says must, while OR-9 is Objective for MACsec connected to an Outer Firewall and has a blank Alternatives cell.'),
    ('REQ-I05', ['RG-061'], 'New-version compliance deadline conflict', 'p058:u002.s004', ['MSC-GD-11'],
     '§13.3 specifies six months from notification; GD-11 specifies the next registration renewal. No precedence is supplied.'),
    ('REQ-I06', ['RG-045'], 'AW physical-host exclusivity versus separate-VM wording', 'p030:u004', ['MSC-DM-23', 'MSC-DM-24', 'MSC-DM-28'],
     '§6.2 prohibits the AW host from hosting enrollment/provisioning/registration/SIEM VMs. DM-24 refers to separate workstations or VMs. The host-level scope must remain visible.'),
    ('REQ-I07', ['RG-044'], 'Physical/cryptographic separation and minimum logical separation', 'p013:u008 p030:u005 p030:u006', ['MSC-DM-25'],
     '§4.1.4 requires physical and cryptographic data/management separation and says VLAN alone is insufficient; DM-25 states at least logical separation by Gray Firewall ACL. Retain both requirements.'),
    ('REQ-I08', ['RG-024'], 'AS connection scope wording', 'p014:u007.s005', ['MSC-AA-2'],
     'The prose says AS must not connect to both Gray and/or Red Networks; AA-2 says only one site’s network. Network/layer/site cardinality needs a source-faithful formal definition.'),
    ('REQ-I09', ['RG-039', 'RG-040'], 'Gray address-only restrictions and explicit non-tunnel exceptions', '', ['MSC-PF-17', 'MSC-PF-19', 'MSC-PF-20', 'MSC-PF-25', 'MSC-PF-27', 'MSC-PF-28', 'MSC-PF-30', 'MSC-PF-31'],
     'Only-peer-address rules must be interpreted with the separately enumerated management/control/revocation allowances; blindly conjoining unqualified allowlists would lose allowed traffic.'),
    ('REQ-I10', ['RG-038'], 'Objective table row has no Alternative marker', '', ['MSC-PF-10'],
     'PF-10 is Objective with a blank Alternatives cell despite §8.1 describing optional objectives as marked Optional. Preserve the blank and seek review.'),
    ('REQ-I11', ['RG-048'], 'MACsec provisioning paragraph uses VPN terminology', 'p029:u013', [],
     'The certificate-based MACsec paragraph names the Inner VPN Gateway CSR. Do not silently correct the quotation; identify the intended device in later formalization.'),
    ('REQ-I12', ['RG-007', 'RG-011', 'RG-075'], 'External annex dependencies are not supplied', 'p020:u009.s003 p026:u008 p031:u003 p031:u005 p031:u007', [],
     'Key management, symmetric key management, continuous monitoring, enterprise Gray implementation, and testing annex contents are outside the supplied PDF. Relocation markers are preserved in background, with referents; their substantive obligations cannot be recovered here.'),
    ('REQ-I13', ['RG-076'], 'Legal-domain interpretation remains unreviewed', 'p009:u017-u018', [],
     'The legal undertaking is retained as a non-network obligation. Its formal applicability and any legal meaning need dedicated review; the extraction makes no enforceability claim.'),
    ('REQ-I14', ['RG-007', 'RG-074', 'RG-019'], 'Figures and protocol examples do not prove compliance', 'p010:u008 p022:u002 p028:u002', [],
     'All figures are source illustrations. Their presence is not a complete compliance statement, implementation test, or theorem proof.'),
    ('REQ-I15', ['RG-024', 'RG-027'], 'EAP-TLS CAK derivation and blanket KGS generation wording', 'p020:u008.s003 p020:u009.s002', [],
     'The authentication prose derives a CAK from the EAP-TLS MSK, then says all CAKs and CKNs must be generated by an NSA-approved KGS. The applicability of the KGS requirement to the certificate-derived branch must be resolved without changing either quotation.'),
]


#* These background decisions follow individual inspection, not keyword classification.
BACKGROUND_ANNOTATIONS = [
    ('p008:u002-u003', 'Program introduction and scope motivation; no additional standalone obligation beyond the grouped CP requirements.', False),
    ('p011:u001.s005 p011:u001.s006', 'Optional request for assistance obtaining vendor contact information; not a product eligibility or operational-compliance condition.', False),
    ('p011:u003 p011:u009.s001 p012:u003.s002 p012:u003.s003 p012:u003.s004', 'Network terminology and component inventory context; Red/Gray/Black obligations are represented in RG-007 through RG-014.', False),
    ('p020:u009.s003 p031:u007', 'External Key Management and Symmetric Key Management Annex dependency and scope statement; substantive annex contents were not supplied.', False),
    ('p031:u003.s001', 'Purpose of continuous monitoring; detailed obligations were relocated to the external Continuous Monitoring Annex.', False),
    ('p032:u002', 'Explains the MSC requirement-identifier syntax and the table of digraphs; no independent implementation requirement.', False),
    ('p033:u002', 'Security rationale for the product-independence requirements already grouped in RG-004.', False),
    ('p034:u011', 'Introduces the component-configuration stage; detailed configuration/provisioning obligations are preserved in the requirement groups.', False),
    ('p034:u013 p037:u005 p040:u004 p042:u015 p043:u009 p044:u011 p047:u013 p050:u010 p054:u006 p055:u006', 'Section or table introduction pointing to the fully preserved normative rows or role descriptions; no additional clause is omitted.', False),
    ('p019:u001 p029:u002 p032:u003 p037:u006 p037:u012 p040:u005 p040:u009 p040:u015', 'Table title split by the literal-period rule; table contents and their contextual headers retain the substantive meaning.', False),
]


REVISIONS = [
    {'review_finding_id': 'REV-REQ-001', 'group_ids': ['RG-002'], 'resolution': 'Reworded the theorem target so proposed-modification vendor/NIAP consultation remains recommended; the evaluated-configuration and actual-modification NIAP-statement requirements remain mandatory.', 'status': 'addressed_pending_reviewer_confirmation'},
    {'review_finding_id': 'REV-REQ-002', 'group_ids': ['RG-024', 'RG-027'], 'resolution': 'Retained the MSK-derived CAK versus all-CAKs-from-KGS tension as REQ-I15. Made RG-027 explicitly provisional for EAP-TLS CAK sourcing and attached the derivation source as context.', 'status': 'source_conflict_retained_open'},
    {'review_finding_id': 'REV-REQ-003', 'group_ids': ['RG-071'], 'resolution': 'Assigned variant-related NSA contact to the customer and retained the AO responsibilities in separate sentences.', 'status': 'addressed_pending_reviewer_confirmation'},
    {'review_finding_id': 'REV-REQ-004', 'group_ids': ['RG-035'], 'resolution': 'Separated the Outer Firewall destination/source rules for the local Outer Encryption Component from MSC-OR-10 connections to the remote Outer Encryption Component or other intended device.', 'status': 'addressed_pending_reviewer_confirmation'},
    {'review_finding_id': 'RG-050-force-refinement', 'group_ids': ['RG-050'], 'resolution': 'Reworded the theorem target to say log encryption is recommended, preserving the source should rather than implying mandatory transport selection.', 'status': 'addressed_pending_reviewer_confirmation'},
]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    issues = []
    scope_notes = {'evidence_scope_notes': [], 'domain_review_scope': [], 'resolved_interpretations': []}
    for iid, gids, title, selectors, rids, detail in ISSUES:
        sids = select(selectors) + [BY_REQ[r]['source_id'] for r in rids]
        record = {'issue_id': iid, 'group_ids': gids, 'title': title, 'source_ids': list(dict.fromkeys(sids)),
                  'status': 'open_source_interpretation_or_scope_issue', 'detail': detail,
                  'severity': 'scope_limitation' if iid == 'REQ-I12' else 'interpretation_blocker'}
        category = None
        if iid in {'REQ-I06', 'REQ-I07'}:
            category = 'resolved_interpretations'
            record.update(status='resolved_by_cumulative_applicability', severity='resolved', blocks_formalization=False)
            if iid == 'REQ-I06':
                record.update(title='AW host and VM restrictions apply together', resolution='Separate service VMs must also respect the AW host restriction. Distinct VMs do not authorize provisioning, enrollment, registration, or SIEM VMs on an AW-dedicated host.')
            else:
                record.update(title='Physical, cryptographic, and ACL separation apply together', resolution='The minimum logical separation required by DM-25 does not waive the physical and cryptographic separation in §4.1.4. The conditions can be imposed together.')
        elif iid == 'REQ-I13':
            category = 'domain_review_scope'
            record.update(status='legal_formalization_unreviewed', severity='domain_review_scope', blocks_formalization_for=['RG-076'], blocks_unrelated_groups=False)
        elif iid == 'REQ-I14':
            category = 'evidence_scope_notes'
            record.update(status='acknowledged_limit', severity='evidence_scope', blocks_formalization=False, detail='Figures and protocol examples support source-grounded, clause-specific requirement assessments. Implementation tests and theorem proofs require later evidence and models. That ordinary evidence boundary does not prevent extracting the requirements illustrated by an example.')
        if category:
            scope_notes[category].append(record)
        else:
            issues.append(record)
        for g in GROUPS:
            if g['group_id'] in gids:
                if category:
                    g.setdefault('scope_note_ids', []).append(iid)
                else:
                    g['open_issue_ids'].append(iid)
    owners = collections.defaultdict(list)
    for g in GROUPS:
        for sid in g['source_ids'] + g['context_source_ids']:
            owners[sid].append(g['group_id'])
    annotations = {sid: (reason, uncertain) for spec, reason, uncertain in BACKGROUND_ANNOTATIONS for sid in select(spec)}
    background = []
    for r in SOURCES:
        sid, typ = r['source_id'], r['unit_type']
        if sid in owners:
            continue
        rid = r.get('requirement_id')
        text = r['text']
        p = r['locations'][0]['page']
        uncertain = False
        dependency = None
        if sid in annotations:
            reason, uncertain = annotations[sid]
            if sid in select('p020:u009.s003 p031:u007'):
                dependency = text
        elif rid and 'relocated' in text:
            reason = 'Relocated requirement marker; substantive obligation is in the named external annex, whose content was not supplied.'
            dependency = next((c['text'] for c in r['cells'] if c['column'] == 2), text)
        elif rid and 'Withdrawn' in text:
            reason = 'Explicitly withdrawn requirement identifier; no active theorem target is inferred.'
        elif rid:
            raise ValueError(f'Active numbered requirement has no group: {rid}')
        elif typ in ('front_matter', 'page_furniture', 'heading', 'table_header'):
            reason = {'front_matter': 'Front matter or navigation record; retained for complete document coverage.',
                      'page_furniture': 'Printed page furniture; not a standalone obligation.',
                      'heading': 'Structural heading supplies document context without an independent obligation.',
                      'table_header': 'Structural table header; retained individually and referenced by contextualized rows.'}[typ]
        elif typ in ('figure', 'figure_label'):
            reason = 'Figure or figure label retained as illustrative evidence; the network artifact records its topology and scoped requirement-group assessments.'
        elif typ == 'table_row':
            if r.get('table_key') == 'revision-history':
                reason = 'Revision-history description; historical changes do not independently restate current requirement strength.'
            elif p >= 62:
                reason = 'Acronym expansion or bibliographic reference; no external requirements are imported.'
            elif r.get('table_key') == 'table-3':
                reason = 'Requirement-designator index and external-annex navigation; not a substantive requirement row.'
            else:
                reason = 'Contextual table material retained for semantic review; no standalone obligation identified in the complete-document reading.'
                uncertain = True
        elif p >= 59:
            reason = 'Glossary definition retained for reuse across theorem groups; no additional standalone obligation identified.'
        elif p <= 7:
            reason = 'Front-matter navigation or historical information; no current standalone obligation.'
        elif 'relocated' in text or 'moved to' in text or 'Requirements are found' in text:
            reason = 'External-annex relocation notice; the missing annex is an explicit dependency rather than an inferred obligation.'
            dependency = text
        elif re.match(r'^(Figure|Table) \d+\.', text) or ('u' in sid and (text.startswith('MSC Solution') or text.startswith('Approved CNSA'))):
            reason = 'Caption or table-reference context; the corresponding figure/table supplies the substantive evidence.'
        else:
            reason = 'Descriptive, navigational, or explanatory context from the complete-document reading; retained individually for the independent background review.'
            uncertain = True
        record = {'source_id': sid, 'text': text, 'unit_type': typ, 'locations': r['locations'],
                  'reason': reason, 'uncertain_classification': uncertain,
                  'original_requirement_id': rid, 'external_dependency': dependency}
        background.append(record)
    original_map = {rid: g['group_id'] for g in GROUPS for rid in g['original_requirement_ids']}
    for r in background:
        if r['original_requirement_id']:
            original_map[r['original_requirement_id']] = 'BG-001'
    assert len(original_map) == len(BY_REQ)
    assert len({g['group_id'] for g in GROUPS}) == len(GROUPS)
    assert len({g['theorem_name'] for g in GROUPS}) == len(GROUPS)
    active_ids = [rid for g in GROUPS for rid in g['original_requirement_ids']]
    assert len(active_ids) == len(set(active_ids))
    assert all(re.fullmatch(r'[a-z][a-z0-9_]*', g['theorem_name']) for g in GROUPS)
    assert all(g['theorem_target_count'] == 1 and g['theorem_statement'] for g in GROUPS)
    assert all(p['text'] == BY_ID[p['source_id']]['text'] for g in GROUPS for p in g['requirement_passages'] + g['context_passages'])
    for g in GROUPS:
        for row in g['document_force']['table_rows']:
            indexed = BY_ID[row['source_id']]
            if indexed.get('logical_cells'):
                columns = {c['column']: c['text'] for c in indexed['logical_cells']}
                assert row['description_verbatim'] == columns[2]
                assert row['threshold_objective_verbatim'] == columns[3]
                assert row['alternatives_verbatim'] == columns[4]
            assert all(sid in g['context_source_ids'] or sid in g['source_ids'] for sid in indexed.get('applicable_note_source_ids', []))
    assigned = set(owners) | {r['source_id'] for r in background}
    assert assigned == set(BY_ID)
    meta = {'schema_version': '1.0', 'document_id': DOC, 'document_sha256': SOURCES[0]['document_sha256'],
            'source_index_sha256': hashlib.sha256(INDEX.read_bytes()).hexdigest(),
            'status': 'incomplete_open_source_issues_independent_review_reported_separately',
            'ready_for_downstream_formalization': False,
            'semantic_method': 'Read all 66 original baseline PDF pages, inspect selected rendered ambiguity pages, manually group by meaning, retain prose permissions and exceptions, and mechanically reproduce indexed quotations.',
            'quotation_policy': 'Exact indexed text with indexed normalization/correction policy; raw extraction stays in source_index.jsonl. Every period is an extraction boundary, including abbreviations and section numbers.',
            'proof_policy': 'One proposed encompassing top-level Lean theorem per group. No Lean code or proofs are constructed.',
            'force_policy': 'T=O is required when applicable; Threshold/Objective alternatives are choices; Optional objectives are not universally mandatory; unlabeled prose retains its own wording and may impose obligations.',
            'definitions_policy': 'Context passages and Appendix A background units remain shared references; quoted descriptive clauses do not become unconditional mandates merely because they occur in a group.',
            'reviewed_source_pages': list(range(1, 67)),
            'rendered_source_pages_inspected': [20, 23, 30, 42, 58],
            'original_requirement_id_to_group_id': dict(sorted(original_map.items()))}
    (OUT / 'groups.json').write_text(json.dumps({**meta, 'groups': GROUPS, 'open_issues': issues, **scope_notes}, ensure_ascii=False, indent=2) + '\n')
    (OUT / 'background.json').write_text(json.dumps({**meta, 'group_id': 'BG-001', 'title': 'Background and external dependencies',
                                                  'theorem_name': None, 'theorem_statement': None,
                                                  'theorem_target_count': 0, 'source_units': background}, ensure_ascii=False, indent=2) + '\n')
    (OUT / 'original_requirement_map.json').write_text(json.dumps(dict(sorted(original_map.items())), indent=2) + '\n')
    (OUT / 'revisions.json').write_text(json.dumps({'revision_scope': 'Requirement-producer responses to independent semantic findings', 'revisions': REVISIONS}, ensure_ascii=False, indent=2) + '\n')
    lines = ['# Requirement groups', '', f'Document: `{DOC}`. Source interpretation and scope questions remain unresolved. See the [plan audit](../validation/plan_audit/independent_review.md), [historical review](../validation/review/review.md), and [current status](../validation/final_status.json).', '',
             f'{len(GROUPS)} groups each target one encompassing top-level Lean theorem. No proofs are constructed. The source quotation and AI interpretation fields remain separate.', '',
             'Threshold and Objective alternatives are choices within the stated applicability. Optional objectives are not unconditional requirements. Figures can illustrate satisfaction of selected clauses. Whole-solution implementation compliance requires further evidence.', '']
    for g in GROUPS:
        lines += [f'<a id="{g["group_id"].lower()}"></a>', '', f"## {g['group_id']}: {g['title']}", '', f"Original requirement IDs: {', '.join(g['original_requirement_ids']) or 'Prose-only'}.", '',
                  f"**Applicability:** {g['applicability']}", '', f"**Requirement strength and applicability:** {g['document_force']['interpretation']}", '',
                  f"**Single theorem target:** `{g['theorem_name']}`", '', f"**AI interpretation for later formalization:** {g['theorem_statement']}", '']
        if g['alternative_logic_interpretation']:
            lines += ['**Alternative logic:**', ''] + [f'- {s}' for s in g['alternative_logic_interpretation']] + ['']
        if g['qualifications_and_exceptions']:
            lines += ['**Qualifications and exceptions:**', ''] + [f'- {s}' for s in g['qualifications_and_exceptions']] + ['']
        if g['open_issue_ids']:
            lines += ['Open issues: ' + ', '.join(g['open_issue_ids']) + '.', '']
        if g.get('scope_note_ids'):
            lines += ['Scope or resolved-interpretation notes: ' + ', '.join(g['scope_note_ids']) + '.', '']
        lines += ['**Verbatim indexed evidence:**', '']
        for p in g['requirement_passages']:
            pages = ', '.join(str(x['page']) for x in p['locations'])
            lines += [f"- `{p['source_id']}` (PDF page {pages}):", '', f"> {p['text']}", '']
        if g['document_force']['table_rows']:
            lines += ['**Original Threshold/Objective designation and alternatives:**', '', '| Requirement | Threshold / Objective | Alternative |', '| --- | --- | --- |']
            lines += [f"| {r['original_requirement_id']} | {r['threshold_objective_verbatim'] or '(blank)'} | {r['alternatives_verbatim'] or '(blank)'} |" for r in g['document_force']['table_rows']]
            lines += ['']
        if g['context_passages']:
            lines += ['**Shared context, definitions, and illustrations:**', '']
            for p in g['context_passages']:
                lines += [f"- `{p['source_id']}`: {p['text'] or '[Image-only figure; see source location and network artifact.]'}"]
            lines += ['']
    lines += ['## Open interpretation issues', '']
    for i in issues:
        lines += [f"### {i['issue_id']}: {i['title']}", '', i['detail'], '', 'Groups: ' + ', '.join(i['group_ids']) + '.', '',
                  'Sources: ' + ', '.join(f'`{sid}`' for sid in i['source_ids']) + '.', '']
    for category, notes in scope_notes.items():
        lines += ['## ' + category.replace('_', ' ').capitalize(), '']
        for note in notes:
            lines += [f"### {note['issue_id']}: {note['title']}", '', note.get('resolution', note['detail']), '', 'Groups: ' + ', '.join(note['group_ids']) + '.', '', 'Status: ' + note['status'] + '.', '', 'Sources: ' + ', '.join(f'`{sid}`' for sid in note['source_ids']) + '.', '']
    (OUT / 'requirement_groups.md').write_text('\n'.join(lines))
    bg = ['# BG-001: Background and external dependencies', '', 'The background group has no theorem target. Every entry preserves its individual indexed source ID, exact text, placement reason, and uncertainty flag.', '',
          'Relocated requirements remain external dependencies. Withdrawn rows remain historical identifiers. Uncertain descriptive classifications must be inspected by the independent reviewer.', '']
    for r in background:
        bg += [f"## {r['source_id']}", '', f"Type: {r['unit_type']}. Uncertain classification: {'yes' if r['uncertain_classification'] else 'no'}.", '',
               r['reason'], '', f"> {r['text'] or '[Image-only figure; see source location.]'}", '']
        if r['external_dependency']:
            bg += [f"External dependency: {r['external_dependency']}", '']
    (OUT / 'background.md').write_text('\n'.join(bg))
    report = {'status': 'pass', 'scope': 'Mechanical checks only; not semantic approval.',
              'source_index_sha256': meta['source_index_sha256'], 'source_units': len(SOURCES),
              'groups': len(GROUPS), 'theorem_targets': len(GROUPS), 'background_source_units': len(background),
              'assigned_source_units': len(assigned), 'unassigned_source_units': [],
              'indexed_quotation_mismatches': [], 'all_original_requirement_ids_mapped': len(original_map),
              'logical_cell_description_force_alternative_mismatches': [],
              'missing_applicable_table_notes': [],
              'active_requirement_rows_in_groups': sum(len(g['original_requirement_ids']) for g in GROUPS),
              'background_requirement_rows': sum(bool(r['original_requirement_id']) for r in background),
              'background_relocated_requirement_rows': sum(bool(r['original_requirement_id']) and 'relocated' in r['text'] for r in background),
              'background_withdrawn_requirement_rows': sum(bool(r['original_requirement_id']) and 'Withdrawn' in r['text'] for r in background),
              'figure_labels_in_background': sum(r['unit_type'] == 'figure_label' for r in background),
              'uncertain_background_units': sum(r['uncertain_classification'] for r in background),
              'open_issues': len(issues), 'semantic_review_status': 'See validation/review and validation/plan_audit; producer checks do not grant semantic approval.',
              'ready_for_downstream_formalization': False}
    (OUT / 'mechanical_validation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
