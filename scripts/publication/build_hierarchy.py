"""Build the standalone, offline theorem hierarchy from the exported Lean dependencies."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re
import shlex
import subprocess
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / '.lavish'
ASSETS = ROOT / 'scripts/publication/hierarchy'
VERSION = 'v' + (ROOT / 'THEORY_VERSION').read_text().strip()
SOURCE = HERE / 'theorem-hierarchy/proof-map.json'
OUT = HERE / 'theorem-hierarchy.html'
LAYOUT_VERSION = 3
raw = json.loads(SOURCE.read_text())
assert raw['metadata']['version'] == VERSION, 'Rebuild the proof map for the current theory version.'
nodes = raw['nodes']

#* Descriptions explain the declaration's actual role; the boxes retain its Lean name.
MEANINGS = {
    'snapshot_public_internet_RG034': 'Proves RG-034 for the selected imported topology. The Public Internet is marked as untrusted, declared attachments have graph paths, each Outer connects through an Outer Firewall to Black, every Outer-to-Black path crosses a firewall, and each Outer has the required Gray-side connection.',
    'inside_outside_placement': 'Checks that each Outer has an inside connection to an Outer Firewall whose outside connection reaches a Black node.',
    'outer_firewall_waypointing': 'Proves that every finite path from an Outer encryptor to Black visits an Outer Firewall in the imported graph.',
    'gray_internal_connected': 'Provides a Gray path from every Outer encryptor to a Gray Firewall. The witnesses may pass through Gray switches.',
    'outer_local_cut': 'Checks that every edge with both endpoints outside the Outer Firewall set connects nodes with the same region label.',
    'outer_start_clear': 'Checks that every Outer endpoint is outside the Outer Firewall set.',
    'outer_sides_differ': 'Checks that every Outer endpoint has a different region label from every Black endpoint.',
    'waypointing_of_edge_invariant': 'Uses label preservation along paths to prove that endpoints with different labels cannot be joined by a path avoiding the specified firewalls.',
    'waypoint_free_path_preserves_region': 'Proves by induction that a path avoiding firewalls keeps its starting region label when each permitted edge preserves that label.',
    'cross_level_waypointing': 'Proves that every path in the selected Gray graph between Inners at different security levels visits a Gray Firewall.',
    'cross_level_gray_waypointing': 'Proves that every path in the selected Gray graph between Inners at different security levels visits a Gray Firewall.',
    'local_cut': 'Checks that each Gray edge avoiding the firewall set preserves the assigned connected-region label.',
    'gray_local_cut': 'Checks that each Gray edge whose endpoints are outside the Gray Firewall set preserves the assigned region label.',
    'start_clear': 'Checks that the selected starting endpoints are outside the firewall set.',
    'inner_start_clear': 'Checks that the starting Inner encryptors are outside the Gray Firewall set.',
    'sides_differ': 'Checks that the selected endpoints at different levels have different connected-region labels.',
    'gray_sides_differ': 'Checks that Inner endpoints at different security levels have different Gray region labels.',
    'concrete_bypass': 'Provides a particular Gray path between different levels that avoids the Gray Firewall. Each edge of that witness is checked against the imported graph.',
    'snapshot_RG038': 'Proves the selected protocol, multicast and IPv4-options requirements for every packet accepted by the imported gateway filters.',
    'all_header_certificates': 'Checks the required protocol, multicast and header-length conditions on every applicable allow rule in the imported gateway records.',
    'header_certificates_suffice': 'Combines the local rule checks into the RG-038 conclusion for every accepted modeled packet at every listed gateway.',
    'accepted_protocol': 'Proves that a packet accepted by the filter uses an allowed protocol when every allow rule contains the required protocol condition.',
    'accepted_header_words': 'Proves that an accepted packet has the required IPv4 header length when every allow rule enforces that length.',
    'accepted_external_unicast': 'Proves that accepted traffic arriving on the external interface has a destination outside the specified multicast range.',
    'allowed_has_matching_allow': 'Proves that an accepted packet in a default-deny rule list matched an allow rule. The proof follows the list one rule at a time.',
    'default_deny_sound': 'Proves a property of every accepted packet by showing that each matching allow rule implies that property.',
    'matching_atom': 'Proves that a packet matching a whole rule satisfies every individual condition stored in that rule.',
    'guarded_rule_protects': 'Shows that a packet matching a rule with the required protection conditions also satisfies the corresponding packet-protection condition.',
    'forwarding_policy_protects': 'Combines the required conditions on all allow rules with default denial to prove protection for every accepted packet crossing the modeled boundary.',
    'accepted_tcp_is_bounded': 'Shows that an accepted TCP packet satisfies the explicitly allowed peer, port and direction conditions for the exception.',
    'http_exception_0_bounded': 'Checks the peer, port and direction restrictions of the first imported HTTP exception.',
    'http_exception_1_bounded': 'Checks the peer, port and direction restrictions of the second imported HTTP exception.',
    'rejects_outside_allowlist': 'Shows that a packet matching no allow rule is denied by the default-deny evaluator.',
    'snapshot_loaded_configuration_RG022': 'Checks every loaded IKE version, IKE encryption mode and ESP proposal against the selected RG-022 alternatives.',
    'step_preserves_layers': 'Shows that one operation in the protected-payload model preserves the required protection layers for the destination zone.',
    'forwarding_preserves_layers': 'Uses induction to preserve the required protection layers across any finite sequence of modeled operations.',
    'step_preserves_level': 'Shows that one modeled operation leaves the payload’s security level unchanged.',
    'forwarding_preserves_level': 'Shows that any finite sequence of modeled operations leaves the payload’s security level unchanged.',
    'black_has_two_layers': 'Concludes that a modeled payload reaching Black has an Outer layer around an Inner layer, assuming the initial state has the required layer structure.',
    'inner_delivery_same_level': 'Shows that modeled Inner decryption delivers the payload at an endpoint assigned the payload’s security level.',
    'underlay_path_simulates_overlay_path': 'Turns a sequence of detailed steps into a sequence of modeled steps, given a proof that every detailed step maps to an allowed modeled step.',
    'concrete_black_protection': 'Transfers the two-layer Black conclusion to a detailed execution whose steps have been connected to the protected-payload model.',
    'effect_preserves_shape': 'Checks that each safe operation changes the protection-layer list to the shape required by the destination zone.',
    'checked_edge_preserves_layers': 'Uses one edge’s safety proof and its layer operation to preserve the required protection-layer structure.',
    'checked_machine_preserves_layers': 'Proves that every finite execution preserves the protection layers when all listed machine edges satisfy the local safety condition.',
    'deadline_elapsed_bound': 'Derives an elapsed-time bound from a reporting time that lies between detection and the permitted deadline.',
    'all_eight_declared_family_choices': 'Checks that the imported mechanism cases include all eight declared IPv4/IPv6 choices across Red, Gray and Black.',
    'all_four_declared_layer_pairings': 'Checks that the imported cases include the four IPsec/MACsec choices for the Inner and Outer layers.',
    'each_case_has_positive_traffic': 'Checks that each imported mechanism case has the required recorded successful traffic witness.',
    'captured_source_figure_six_levels': 'Checks that the imported level records contain the security-label set selected from source Figure 6.',
    'matching_mka_outcome': 'Checks the recorded successful MKA outcome when the peers have matching key material.',
    'mismatched_mka_outcome': 'Checks the recorded refusal outcome for the MKA trial with mismatched key material.',
    'eap_authentication_without_successful_data_probe': 'Checks the retained EAP trial results, including authentication and the unsuccessful protected-data attempts.',
    'observed_objective_exchange_sequence': 'Checks the required message types and ordering in the recorded objective IKE exchange.',
    'recorded_headers_fit_without_ip_fragmentation': 'Checks the recorded IP packet sizes against the path MTU and verifies the recorded absence of IP fragmentation.',
    'observed_credentials_and_configured_hash_constraints': 'Checks the captured public credentials and the explicit authentication hash constraints.',
    'observed_capabilities_distinguish_request_and_response': 'Checks the recorded capability lists for the two message directions: [2,3,4,5] in the selected request records and [3] in the response records.',
    'selected_authentication_uses_sha384': 'Checks that the selected recorded authentication signatures use SHA384.',
    'recorded_sha256_refusal_and_sha384_recovery': 'Checks the retained negative SHA256 authentication outcome and the successful SHA384 recovery outcome.',
    'observed_good_crl_authentication_exchanges': 'Checks the recorded certificate-authentication exchanges with the supplied valid revocation information.',
    'observed_revocation_status_pairs': 'Checks the retained certificate-status request and response records.',
    'recorded_ospf_neighbors_and_routes': 'Checks the recorded OSPF neighbor and route counts used by the routing experiments.',
    'no_recorded_encryptor_process_has_known_routing_name': 'Checks the captured encryptor process names against the importer’s explicit list of known routing-daemon names.',
    'observed_ntp_replies_without_clock_adjustment': 'Checks the saved NTP response observations and their recorded clock-adjustment flags.',
    'every_recorded_component_has_specified_dns_server': 'Checks that every imported component’s resolver record contains the specified DNS server.',
    'recorded_root_passwords_locked': 'Checks the captured root-account password-lock flags.',
    'recorded_macsec_selected_flags': 'Checks the imported MACsec settings selected for the experiment.',
    'required_hello_disables_source_delay_flag': 'Shows that the required hello interval makes the pinned source’s delay-protection expression false.',
    'full_RG028_fails_under_source_flag_correspondence': 'Derives a failure of the complete RG-028 condition when the device flag is assumed to follow the inspected source expression.',
    'source_timer_constants': 'Checks the hello and lifetime constants retained from the inspected MKA implementation source.',
    'source_derived_test_kek_width': 'Checks the key-encryption-key width derived for the retained test configuration.',
    'recorded_manual_redundancy_probe_outcomes': 'Checks the outcomes of the recorded manually selected redundant-path trials.',
    'recorded_relay_both_branches': 'Checks the recorded outcomes for both selected relay configurations.',
    'observed_inner_peers_have_same_full_declared_level': 'Checks that the observed Inner peer pairs have equal complete declared security labels.',
    'recorded_logical_domain_outcomes': 'Checks the captured traffic results against the expectations for the distinct logical Red networks.',
    'recorded_host_and_guest_tls_use': 'Checks the retained TLS request outcomes from the physical-host and guest-workstation trials.',
    'recorded_tls_outcomes': 'Checks the recorded successful and refused TLS attempts for the selected administration paths.',
    'supplemental_tls_recorded_outcomes': 'Checks the recorded TLS attempt outcomes in the supplemental service experiments.',
    'recorded_probe_expectations': 'Checks that each imported probe’s observed outcome matches its declared expected outcome.',
    'recorded_probe_outcomes': 'Checks the listed probe outcomes recorded for the selected network.',
    'positive_and_negative_witnesses': 'Checks that the retained trials contain both the selected successful and refused traffic examples.',
    'useful_and_negative_probe_witnesses': 'Checks that the retained probes include the selected successful traffic and negative-test witnesses.',
    'both_test_branches_present': 'Checks that the retained experiment records include both required branches of the test.',
    'outage_and_restoration_witnesses': 'Checks the recorded traffic witnesses during the outage and after restoration.',
    'edges': 'The finite list of directed device-to-device edges imported from the observed virtual links.',
    'edge': 'The edge test: a pair of devices is related exactly when it occurs in the imported edge list.',
    'grayEdges': 'The imported directed edges belonging to the Gray part of the topology.',
    'grayEdge': 'Tests whether a pair of devices appears in the imported Gray edge list.',
    'outerNodes': 'The identifiers assigned to Outer encryptors in this imported graph.',
    'innerNodes': 'The identifiers assigned to Inner encryptors in this imported graph.',
    'blackNodes': 'The identifiers selected as Black transport endpoints for this graph.',
    'firewallNodes': 'The identifiers assigned to the Outer Firewalls that the path proof requires.',
    'grayFirewallNodes': 'The identifiers assigned to the Gray Firewalls that the path proof requires.',
    'firewall': 'Tests membership in the imported Outer Firewall list.',
    'grayFirewall': 'Tests membership in the imported Gray Firewall list.',
    'outerSide': 'Assigns each device the connected-region number computed after excluding Outer Firewall nodes.',
    'side': 'Assigns the connected-region number used by the path proof after excluding the selected firewall nodes.',
    'graySide': 'Assigns a connected-region number after excluding Gray Firewall nodes.',
    'level': 'Assigns the imported security-level identifier to a device.',
    'Node': 'The finite type of device identifiers for this imported graph.',
    'insideAttachments': 'The imported pairs connecting an Outer encryptor to an Outer Firewall’s inside interface.',
    'outsideAttachments': 'The imported pairs connecting an Outer Firewall’s outside interface to Black.',
    'gateways': 'The gateway records used by RG-038, including the applicable IP versions, external interface and ordered filter chains.',
    'loadedVPNModePolicies': 'The imported lists of IKE versions, IKE modes and ESP proposals associated with each loaded connection.',
    'HeaderCertificate': 'The sufficient conditions checked on a gateway’s allow rules: permitted protocols, external multicast exclusion and the selected IPv4 header-length condition.',
    'RequiresIpsecPolicyMatch': 'Requires a rule to name the inside and outside interfaces and require an IPsec policy match in the corresponding direction.',
    'InboundGuard': 'The required conditions for traffic arriving through the selected protected boundary.',
    'OutboundGuard': 'The required conditions for traffic leaving through the selected protected boundary.',
    'ProtocolGuard': 'Requires the rule to contain a protocol condition naming one of the permitted protocols.',
    'UnicastGuard': 'Requires rule conditions that exclude external traffic addressed to the specified multicast range.',
    'evaluate': 'Evaluates an ordered rule list using the first matching rule, or the fallback verdict if no rule matches.',
    'toFilter': 'Converts a typed packet rule into the predicate-and-verdict form consumed by the general filter evaluator.',
    'holds': 'Evaluates one packet condition against the packet’s fields.',
    'Avoiding': 'The step relation that uses a graph edge and requires its destination to be outside the specified firewall set.',
    'Safe': 'The local rule for a boundary operation: forwarding stays in the same zone, and adding or removing protection crosses the matching Red/Gray/Black boundary.',
    'Shape': 'The required layer-list shape for a zone: empty in Red, Inner in Gray, and Outer around Inner in Black.',
    'MatchesZoneEncryptionPolicy': 'States that a modeled payload has the protection-layer list required by its current Red, Gray or Black zone.',
    'StackEffect': 'Describes how one operation leaves, adds to or removes from the protection-layer list.',
    'SimulatesOverlayStep': 'Requires every detailed step to map to an allowed step in the protected-payload model.',
    'Step': 'The allowed one-step transitions of the protected-payload model, including encryption, transit and decryption.',
    'WithinDeadline': 'Requires the report time to lie between detection and detection plus the allowed delay.',
    'SecurityLevel': 'A security label containing classification, compartments, dissemination restrictions and other controls.',
    'State': 'A modeled payload’s zone, location, security level and protection-layer list.',
    'Network': 'The configured relationships used by the payload model: endpoint levels, Inner and Outer peers, links and permitted mechanism pairings.',
    'TunnelSAStamp': 'Records an IPsec protection-layer identifier, the installed association’s SPI, and its sender and receiver addresses.',
    'TunnelHeader': 'One protection layer in the Red/Gray/Black architecture model, with its Inner/Outer role, endpoints, and IPsec or MACsec mechanism.',
    'DataPlaneModel': 'Supplies the forwarding tables, ordered firewall rules, IPsec policies and installed associations, interfaces, bridges, and links used by the packet model.',
    'IpsecPolicy': 'An IPsec policy with source and destination selectors, tunnel endpoints, priority, and an optional required SPI.',
    'InstalledSA': 'An installed IPsec security association identified by its local reqid, wire SPI, and tunnel endpoints.',
    'FibRoute': 'A forwarding entry with ingress and egress interfaces, destination-address bounds, prefix length, metric, and policy-table priority.',
    'SelectedFibRoute': 'Selects an applicable route by policy-table priority, longest destination prefix, and lowest metric.',
    'PerHopEncapConditions': 'The conditions on routing, filtering, encapsulation, bridging, and links that preserve the expected protection layers through each permitted step.',
    'EncapStackConsistent': 'The packet has the expected protection layers for its interface and processing stage.',
    'ForwardsAlongTrace': 'States that the supplied sequence of permitted packet-processing steps connects the initial and final packet states. The statement applies to any model supplied as its argument.',
    'EncapHeaderLayer': 'Pairs the tunnel association metadata with the saved inner header so decryption can restore that header.',
    'matchesPacket': 'Tests one firewall condition against the packet fields.',
    'Layer': 'The two possible protection-layer roles: Inner and Outer.',
    'Zone': 'The region assigned by the model. Architectural interface zones include Red, Gray, Black and local.',
    'Mechanism': 'The two protection mechanisms represented by the model: IPsec and MACsec.',
    'Operation': 'The boundary operations: forward, add Inner, add Outer, remove Inner and remove Outer protection.',
    'Edge': 'A modeled boundary step with a source zone, destination zone and operation.',
    'Packet': 'The packet fields used by the filtering model, including addressing, protocol, interfaces and policy information.',
    'Rule': 'One ordered firewall rule, containing its packet conditions and verdict.',
    'MatchCondition': 'One condition in a firewall rule, such as an address range, protocol, interface or required protection-policy identifier.',
    'Verdict': 'The modeled allow or deny result of a filter rule.',
    'GatewayHeaderPolicy': 'A gateway’s applicability flags, external interface and ordered chains for the header-filtering proof.',
    'VPNModePolicy': 'A gateway identifier together with its lists of offered IKE versions, IKE modes and ESP proposals.',
    'ESPModeProposal': 'One offered ESP encryption mode and whether it includes HMAC integrity.',
    'CipherMode': 'The encryption-mode choices distinguished by the configuration model: CBC, GCM and other.',
    'Frame': 'The Ethernet-frame fields represented by the bridge-filter model.',
    'msc_outer_firewall_placement': 'Defines RG-034 as the required external connections, firewall traversal for every Outer-to-Black path, and the conditional internal Gray connection.',
    'msc_ip_header_and_multicast_filtering': 'Defines RG-038 for a nonempty gateway inventory: accepted packets obey the applicable protocol, external multicast and IPv4-options restrictions.',
    'msc_ike_version_and_encryption_modes': 'Defines RG-022 by checking every loaded IKE version, IKE mode and ESP proposal against the permitted alternatives.',
    'msc_vpn_sa_lifetimes_and_reauthentication': 'Combines the IKE and ESP lifetime bounds with earlier peer reauthentication for every listed IKE-rekey event.',
    'msc_macsec_encryption_and_key_wrap': 'Requires AES Key Wrap with a 256-bit key and AES-GCM data protection with a 256-bit key for every listed MACsec device.',
    'msc_macsec_protection_parameters': 'Combines the MACsec delay, timer, replay-window, encryption, confidentiality-offset and must-secure requirements.',
    'msc_encryption_components_routing_restrictions': 'States the restrictions on routing behavior performed by the listed Inner and Outer encryption components.',
    'msc_trusted_time_synchronization': 'States the required trusted time source and synchronization conditions for the listed components.',
    'msc_baseline_configuration_hardening': 'States the configured DNS, default-setting removal and remote-boot requirements for the listed components.',
    'msc_defaults_dns_and_boot_configuration': 'Requires changes or removal for the listed original defaults, the stated DNS configuration alternative, and disabled automatic remote boot. The selected DNS-lookup objective adds its own condition.',
    'DNSAddress': 'An IPv4 or IPv6 address used to identify a configured DNS server.',
    'chain': 'The bridge rule list permitting ARP, IPv4 ESP, and the directed HTTP request and response exceptions between the selected client and server.',
    'Accepts': 'States that evaluating the ordered typed rules with a default-deny verdict accepts the packet.',
}

DATA_MEANINGS = {
    'cases':'the selected mechanism cases and their traffic observations', 'probes':'the captured traffic attempts and their expected and observed outcomes',
    'logicalProbes':'traffic outcomes between the declared logical Red networks', 'peerLevels':'observed Inner peer pairs with their complete declared security labels',
    'capturedLevels':'the security labels collected for the selected source example', 'matchingMKA':'the matching-key MKA trial', 'mismatchedMKA':'the mismatched-key MKA trial',
    'objectiveExchange':'the message observations for the objective IKE exchange', 'headers':'the captured IP/IKE packet-header records', 'pathMTU':'the path MTU used in the packet-size check',
    'credentials':'the captured public credential metadata', 'advertisedCapabilities':'the signature-capability lists recorded in the two message directions',
    'selectedSignatures':'the algorithms selected in the recorded authentication exchanges', 'trial':'the retained authentication trial and recovery outcomes',
    'caExchanges':'the captured certificate-authentication exchanges', 'revocationStatuses':'the recorded revocation-status requests and responses',
    'ntpReplies':'the recorded NTP requests, replies and clock-adjustment flags', 'resolverConfigurations':'the imported resolver settings for the components',
    'rootAccess':'the observed root-account access flags', 'macsecSettings':'the selected captured MACsec settings', 'eapResults':'the EAP authentication and subsequent delivery attempts',
    'awSamples':'the workstation TLS trials', 'tlsSamples':'the captured TLS request outcomes', 'samples':'the observations used by the theorem in this module',
    'ospfCounts':'the recorded OSPF neighbor and route counts', 'encryptorProcesses':'the process names observed on encryptors', 'routingNames':'the explicit list of known routing-daemon names',
    'redundancyProbes':'the traffic probes for the manual redundant-path experiments', 'relayCounts':'the recorded outcomes for the two relay branches',
    'helloMs':'the MKA hello interval in milliseconds', 'boundedHelloMs':'the bounded hello interval used by the inspected source expression',
    'lifetimeMs':'the MKA lifetime in milliseconds', 'sourceDelayFlag':'the delay-protection expression taken from the inspected MKA source',
    'sourceDerivedKekBits':'the key-encryption-key width derived for the retained test',
    'multicast4Low':'the lower address bound of the IPv4 multicast range', 'multicast4High':'the upper address bound of the IPv4 multicast range',
    'multicast6Low':'the lower address bound of the IPv6 multicast range', 'multicast6High':'the upper address bound of the IPv6 multicast range',
}


def describe(node):
    short = node['short']
    if node.get('description'):
        return node['description']
    qualified = {
        'TDN.DataPlaneForwarding.State': 'A packet’s interface, processing stage, frame, and authenticated incoming IPsec policy identifiers.',
        'TDN.DataPlaneForwarding.Frame': 'The packet header, payload identity, source security domain, saved encapsulation layers, and entry interface.',
        'TDN.DataPlaneForwarding.Step': 'One permitted routing, filtering, IPsec, bridging, transmission, or delivery operation, with the conditions required for that operation.',
        'TDN.MultiProtocolForwarding.Config': 'The combined forwarding model: IP processing plus MACsec interfaces, carriers, bridges, physical links, and header processing.',
        'TDN.MultiProtocolForwarding.State': 'The current interface and processing stage of a possibly nested IPsec/MACsec frame, together with entry and authentication information.',
        'TDN.MultiProtocolForwarding.Step': 'One permitted operation in the combined IPsec, MACsec, carrier, Ethernet, and IP forwarding model.',
        'TDN.LayeredFrame.Frame': 'A packet body that can contain nested IPsec, MACsec, and carrier layers, with payload identity and any saved visible headers.',
    }
    if node['name'] in qualified:
        return qualified[node['name']]
    for group in raw['groups']:
        if node['name'] == group['formal']:
            return group['target']
    if short in MEANINGS and short not in {'State', 'Step', 'Safe', 'Shape', 'SecurityLevel', 'Packet', 'Config', 'holds', 'evaluate'}:
        return MEANINGS[short]
    if node.get('doc'):
        return node['doc']
    if short in {'State', 'Step', 'Safe', 'Shape', 'SecurityLevel', 'Packet', 'Config', 'holds', 'evaluate'}:
        return 'Defines ' + short + ' in ' + node['name'].rsplit('.', 1)[0] + '. Its fields or conditions are shown at the linked source location.'
    if short in MEANINGS:
        return MEANINGS[short]
    if short in DATA_MEANINGS:
        return 'Records ' + DATA_MEANINGS[short] + '.'
    if short.startswith('chain_'):
        match = re.match(r'chain_(.+)_filters([46])_(INPUT|FORWARD|OUTPUT)(?:_(guarded|protects))?$', short)
        if match:
            device, version, hook, result = match.groups()
            what = f'{device}’s IPv{version} {hook} chain'
            if result == 'guarded':
                return f'Checks that every allow rule in {what} has the required boundary-protection conditions.'
            if result == 'protects':
                return f'Proves the selected boundary-protection condition for every packet accepted by {what}.'
            return f'The imported ordered rules for {what}.'
    #* Source comments are used only when they describe the declaration immediately below.
    lines = (ROOT / node['path']).read_text().splitlines()
    prefix = '\n'.join(lines[max(0, node['line']-15):node['line']-1])
    comment = re.search(r'/--\s*([^/]*?)\s*-/\s*$', prefix, re.S)
    if comment:
        return ' '.join(comment[1].split())
    if node['kind'] == 'structure':
        fields = re.findall(r'^\s*([a-zA-Z][\w]*)\s*:', node['source'], re.M)
        if fields:
            return 'A record with fields for ' + ', '.join(fields[:6]) + (', and additional fields.' if len(fields)>6 else '.')
    names = {
        'RecordedNTPReplies':'the recorded NTP response and clock-adjustment conditions',
        'RecordedCertificateExchanges':'the required recorded certificate-authentication outcomes',
        'RecordedHeadersFitWithoutIPFragmentation':'the packet-size, MTU and IP-fragmentation conditions on the listed headers',
        'TLSRecordedOutcomes':'the expected outcomes of the recorded TLS attempts',
        'ExpectedProbeOutcomes':'agreement between each probe’s expected and observed outcome',
        'EachCaseHasUsefulTraffic':'a successful traffic witness for each listed mechanism case',
        'HasSourceFigureSixLevels':'the presence of the required security-label set from source Figure 6',
        'ObservedMatchingMKASuccess':'the recorded matching-key MKA success conditions',
        'ObservedMismatchedMKARefusal':'the recorded mismatched-key MKA refusal conditions',
        'ObservedObjectiveSequence':'the required sequence of recorded objective IKE messages',
        'MACsecSelectedFlags':'the selected MACsec settings recorded by the experiment',
    }
    if short in names:
        return 'Defines ' + names[short] + '.'
    words = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', short).replace('_', ' ').lower()
    if node['kind'] in {'lemma', 'theorem'}:
        return ('Checks ' if node['decide'] else 'Proves ') + words + '. The source link gives the exact statement and assumptions.'
    return 'Defines ' + words + ' for the model in ' + Path(node['path']).stem + '.'


def direct(node):
    return list(dict.fromkeys(node['proofs'] + node['definitions']))


def minimal_definitions(name):
    #* Omit an unfolded duplicate when another displayed input definition already contains it.
    candidates = [n for n in nodes[name]['definitions'] if nodes[n]['kind'] in {'def', 'abbrev'}]
    reachable = {}
    for candidate in candidates:
        visited = set()
        todo = list(nodes[candidate]['definitions'])
        while todo:
            item = todo.pop()
            if item in visited or item not in nodes:
                continue
            visited.add(item)
            todo.extend(nodes[item]['definitions'])
        reachable[candidate] = visited
    return [n for n in candidates if not any(n in reachable[c] for c in candidates if c != n)]


def tree_graph(root, definitions, formal=None, relationship=None, clause=None, backing_proofs=()):
    members = set()
    edges = []
    relation_kinds = {}
    parents = {name for name in [formal, clause] if name and name != root}
    if backing_proofs:
        parents.add(root)
    def visit(name):
        if name in members:
            return
        members.add(name)
        node = nodes[name]
        if node['kind'] in {'theorem', 'lemma'}:
            children = node['proofs']
            if definitions and (node['decide'] or not children):
                children = list(dict.fromkeys(children + minimal_definitions(name)))
        elif name == root and backing_proofs:
            children = list(backing_proofs)
            for child in children:
                relation_kinds[(name, child)] = 'proves-specification'
        elif name == root:
            children = list(dict.fromkeys(node['proofs'] + minimal_definitions(name)))
        else:
            children = []
        for child in children:
            if child != name and child not in parents:
                edges.append((name, child))
                visit(child)
    visit(root)
    top = root
    if clause and clause != root and clause != formal:
        members.add(clause)
        edges.insert(0, (clause, root))
        relation_kinds[(clause, root)] = 'proves-clause'
        top = clause
    if formal and formal != root:
        members.add(formal)
        edges.insert(0, (formal, top))
        relation_kinds[(formal, top)] = 'clause-specification' if top == clause else relationship
        top = formal
    order = sorted(members)
    ids = {name: f'n{i}' for i, name in enumerate(order)}
    depth = {top: 0}
    for _ in range(len(members)):
        changed = False
        for parent, child in edges:
            if parent in depth and depth.get(child, -1) < depth[parent]+1:
                depth[child] = depth[parent]+1
                changed = True
        if not changed:
            break
    else:
        raise ValueError('Dependency cycle: ' + root)
    labels = {}
    dot = ['digraph G {', 'graph [rankdir=TB, nodesep=0.20, ranksep=0.48, margin=0, pad=0.12, splines=polyline, ordering=out];', 'node [shape=box, fontname="Courier", fontsize=12, margin="0.14,0.10"];']
    for name in order:
        short = nodes[name]['short']
        labels[name] = textwrap.wrap(short, width=29, break_long_words=True, break_on_hyphens=False) or [short]
        #* Prefer line breaks after underscores while retaining the exact declaration name.
        labels[name] = []
        current = ''
        for piece in re.findall(r'[^_]+_?|_', short):
            if len(current + piece) > 29 and current:
                labels[name].append(current)
                current = ''
            for part in textwrap.wrap(piece, 29, break_long_words=True, break_on_hyphens=False):
                if len(current + part) > 29:
                    labels[name].append(current)
                    current = part
                else:
                    current += part
        if current:
            labels[name].append(current)
        label = '\n'.join(labels[name])
        dot.append(f'{ids[name]} [label={json.dumps(label)}];')
    for rank in sorted(set(depth.values())):
        dot.append('{rank=same; ' + ';'.join(ids[n] for n in order if depth[n] == rank) + ';}')
    for a,b in edges:
        dot.append(f'{ids[a]} -> {ids[b]};')
    dot.append('}')
    process = subprocess.run(['dot', '-Tplain'], input='\n'.join(dot), text=True, capture_output=True, check=True)
    layout = {'nodes': [], 'edges': [], 'top': top}
    reverse = {i:n for n,i in ids.items()}
    scale = 78
    for line in process.stdout.splitlines():
        parts = shlex.split(line)
        if parts[0] == 'graph':
            layout['width'] = float(parts[2])*scale + 24
            layout['height'] = float(parts[3])*scale + 24
        elif parts[0] == 'node':
            name = reverse[parts[1]]
            layout['nodes'].append({'id': name, 'x':float(parts[2])*scale+12, 'y':layout['height']-12-float(parts[3])*scale, 'w':float(parts[4])*scale, 'h':float(parts[5])*scale, 'lines':labels[name], 'rank':depth[name]})
        elif parts[0] == 'edge':
            count = int(parts[3])
            coords = [float(n) for n in parts[4:4+count*2]]
            points = [[coords[i]*scale+12,layout['height']-12-coords[i+1]*scale] for i in range(0,len(coords),2)]
            a, b = reverse[parts[1]], reverse[parts[2]]
            kind = relation_kinds.get((a, b), 'dependency')
            layout['edges'].append({'from':a, 'to':b, 'points':points, 'kind':kind})
    return layout


register_path = raw['metadata']['register_path']
register_lines = (ROOT / register_path).read_text().splitlines()
for group in raw['groups']:
    group['registerLine'] = next(i for i,s in enumerate(register_lines,1) if f'"rg_id": "{group["id"]}"' in s)
    if group['formal'] is None:
        group.update(specifications=[], specificationProofs={}, choices=[])
        continue
    #* Related specifications come from the actual statements of the group's proof dependencies.
    proof_names, pending = set(), list(group['roots'])
    specifications = {group['formal'], *group.get('partialSpecifications', [])}
    while pending:
        name = pending.pop()
        if name in proof_names:
            continue
        proof_names.add(name)
        pending.extend(nodes[name]['proofs'])
        specifications.update(n for n in nodes[name]['statementDefinitions']
                              if n.startswith('TDN.Requirements.') and nodes[n]['short'].startswith('msc_') and nodes[n]['kind'] in {'def', 'abbrev'} and nodes[n]['canonicalName'] != nodes[group['formal']]['canonicalName'])
    group['specifications'] = [group['formal']] + sorted(specifications - {group['formal']})
    group['specificationProofs'] = {spec: sorted(name for name in proof_names
        if nodes[name]['canonicalHead'] == nodes[spec]['canonicalName']) for spec in group['specifications']}
    group['choices'] = list(dict.fromkeys(group['roots'] + group['specifications'] +
        [name for names in group['specificationProofs'].values() for name in names]))
roots = sorted({n for g in raw['groups'] for n in g['choices']})
jobs = [(g, n, mode) for g in raw['groups'] for n in g['choices'] for mode in [False, True]]


def build_layout(job):
    group, name, mode = job
    relationship = 'clause-specification' if name in group['specifications'] else 'proves-instance' if name in group['scopes'] else 'supports-target'
    conclusion = next((spec for spec in group['specifications'] if nodes[name]['canonicalHead'] == nodes[spec]['canonicalName']), nodes[name]['conclusionHead'])
    clause = conclusion if conclusion in group['specifications'] and conclusion != group['formal'] else None
    backing_proofs = group['specificationProofs'].get(name, [])
    return group['id'] + '|' + name + ('|data' if mode else '|proof'), tree_graph(name, mode, group['formal'], relationship, clause, backing_proofs)


if '--render-only' in sys.argv:
    previous = json.loads((HERE / 'theorem-hierarchy/build-validation.json').read_text())
    assert previous['source_sha256'] == hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert previous.get('layout_version') == LAYOUT_VERSION, 'Rebuild layouts before using --render-only.'
    embedded = re.search(r'<script id="hierarchy-data" type="application/json">(.*?)</script>', OUT.read_text(), re.S)
    layouts = json.loads(embedded[1])['layouts']
else:
    with ThreadPoolExecutor(max_workers=6) as pool:
        layouts = dict(pool.map(build_layout, jobs))
visible = {n['id'] for graph in layouts.values() for n in graph['nodes']}
all_details = set(visible)
for name in visible:
    all_details.update(direct(nodes[name]))
    all_details.update(nodes[name]['statementDefinitions'])
details = {name: {k:node[k] for k in ['name','short','path','line','kind','decide','proofs','definitions','statementDefinitions','libraries','conclusionHead','canonicalHead','canonicalName']} | {'description':describe(node)} for name,node in nodes.items()}
payload = {'groups':raw['groups'],'nodes':details,'layouts':layouts,'root':str(ROOT),'registerPath':register_path,
    'metadata':raw['metadata'], 'statusLabels':{
    'review_pass':'Complete conditional proof: review passed',
    'deferred':'Complete proof deferred',
    'outside_selected_scope':'Outside selected proof scope'}}
template = (ASSETS / 'template.html').read_text().replace('__THEORY_VERSION__', VERSION)
script = (ASSETS / 'app.js').read_text()
css = (ASSETS / 'style.css').read_text()
result = template.replace('/*__STYLE__*/',css).replace('/*__SCRIPT__*/',script).replace('__DATA__',json.dumps(payload,ensure_ascii=False,separators=(',',':')).replace('</','<\/'))
OUT.write_text(result)
(HERE / 'theorem-hierarchy/build-validation.json').write_text(json.dumps({'layout_version':LAYOUT_VERSION,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'artifact_sha256':hashlib.sha256(OUT.read_bytes()).hexdigest(),'groups':len(raw['groups']),'roots':len(roots),'layouts':len(layouts),'visible_declarations':len(visible),'source':'Current compiled ' + VERSION + ' Lean dependency export','design':'Existing TDN report light palette; compact top-down SVG layout','metadata':raw['metadata']},indent=2)+'\n')
print(json.dumps({'artifact':str(OUT),'bytes':OUT.stat().st_size,'groups':len(raw['groups']),'layouts':len(layouts),'visible_declarations':len(visible)}))

subprocess.run([sys.executable, str(ROOT / "scripts/publication/export_pages.py"), "--page", "hierarchy"], check=True)
