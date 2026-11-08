from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from source_paths import source_path,output_path
from reconcile_dependencies import reconcile
from refresh_contributions import refresh

root=Path.cwd()
p=output_path("theorem_register.json")
data=json.loads(p.read_text())
requests=json.loads((output_path("evidence_requests.json")).read_text())
responses=json.loads((source_path("evidence_responses")).read_text())
response_map={r.get("request_id",r.get("id")):r for r in responses["requests"]}
for request in requests["requests"]:
    if request["request_id"] in response_map:
        response=response_map[request["request_id"]]
        request["response"]=response
        request["status"]=response["status"]
(output_path("evidence_requests.json")).write_text(json.dumps(requests,indent=2,ensure_ascii=False)+"\n")
external={1,2,3,4,5,6,9,21,45,49,51,52,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,74,76}
formal={31:"TDN.Targets.msc_encryption_component_routing_limits",42:"TDN.Targets.msc_trusted_time_synchronization",43:"TDN.Targets.msc_defaults_dns_and_boot_configuration",22:"TDN.Targets.msc_ike_version_and_encryption_modes",23:"TDN.Targets.msc_vpn_sa_lifetimes_and_reauthentication",25:"TDN.Targets.msc_macsec_encryption_and_key_wrap",28:"TDN.Targets.msc_macsec_protection_parameters",34:"TDN.Targets.msc_outer_firewall_placement",38:"TDN.Targets.msc_ip_header_and_multicast_filtering"}
generic={
7:["TDN.black_has_two_layers","TDN.concrete_black_protection","TDN.Boundary.checked_machine_preserves_layers"],
8:["TDN.execution_preserves_level","TDN.inner_delivery_same_level"],
13:["TDN.Waypointing.waypointing_of_edge_invariant"],
23:["TDN.Temporal.deadline_elapsed_bound"],
29:["TDN.PacketPolicy.forwarding_policy_protects","TDN.Boundary.checked_machine_preserves_layers"],
30:["TDN.PacketPolicy.forwarding_policy_protects","TDN.Boundary.checked_machine_preserves_layers"],
34:["TDN.Waypointing.waypointing_of_edge_invariant"],
35:["TDN.Filter.default_deny_sound"],
39:["TDN.Filter.rejects_outside_allowlist"],
40:["TDN.Filter.rejects_outside_allowlist","TDN.Waypointing.waypointing_of_edge_invariant"],
64:["TDN.Temporal.deadline_elapsed_bound"]}
specific={
1:"Applicable CNSS/local policy and capability-compliance evidence are external; no conjunction over all requirements is assumed as a premise.",
2:"No NIAP evaluated-configuration baseline or modification statement was supplied; software configuration capture cannot certify it.",
3:"No dated authoritative product-list membership for actual lab products was supplied.",
4:"Evidence reports shared Linux kernel, image and strongSwan implementation. The recorded emulation lacks required OS/implementation diversity; no physical-world theorem is inferred from a label.",
5:"Evidence reports co-resident containers on one host. Virtual namespace separation does not meet the distinct-physical-device requirement.",
6:"AO-approved supply-chain assessments and mitigations are unavailable.",
7:"Generic finite-execution layer preservation is checked, but implementation independence, full Linux refinement and all technology pairings remain unresolved.",
8:"Observed same-level positive/cross-level negative probes and a generic label-preservation result are bounded partial evidence. Authentication exclusion and complete all-path behavior remain open.",
9:"Trusted organizational control and classification-authority decisions about exposed Gray information are external.",
10:"Independent management and method-specific cross-site trust require separately scoped management evidence; data-path evidence cannot discharge them.",
11:"Central management evidence, external Gray annex scope, CA/PSK qualifications and unresolved source issues remain necessary.",
12:"Actual method-specific CA/CAK and management separation and cross-level authentication refusal require dedicated observations.",
13:"The observed virtual Gray graph has a checked all-path firewall separator between differing declared levels. Management endpoints and prohibited-flow semantics remain separate clauses; physical-world claims require the declared graph abstraction and observation trust.",
14:"The same-level-prevention sentence conflicts with explicit same-level allowances; no emulation resolves authorial intent.",
15:"Encapsulation ordering and standalone device scope require MACsec evidence and authoritative resolution of conflicting scope passages.",
16:"Feature permission is conditional on device support and remaining protection duties; no blanket compliance follows from enabling clear VLAN or XPN.",
17:"Established certificate-based IPsec sessions provide partial evidence, while mutual authentication traces, NPE semantics and MACsec alternatives remain open.",
18:"Observed classical suites cannot establish all source algorithm-purpose choices, external CNSS policy, and objective alternatives.",
19:"The baseline has classical established sessions. Full offered proposals and the joint PQ extension/order/size obligations remain unproved.",
20:"Public listings show identities and CRL presence. Chain validation, actual revocation/expiry rejection and preinstalled-certificate alternatives remain unproved.",
21:"A sanitized snapshot cannot establish key inaccessibility through every interface; optional MAC policy semantics remain absent.",
22:"A Lean-checked negotiated-subset instance covers eight IKEv2/GCM records; ER-013 requests complete loaded proposals for the full configuration-level target. The claim is bounded to collected sessions and does not establish all future negotiations or offered configurations.",
23:"The full target is encoded. ESP hard-lifetime records and configured reauthentication intervals are distinguishable; an interval is not silently treated as an IKE hard lifetime. Rekey ordering still needs events/refinement.",
24:"PSK/EAP-TLS, dual supplicant/authenticator roles and AS one-site restrictions require MACsec evidence; the source AS scope ambiguity remains open.",
25:"Both algorithm obligations are encoded. MACsec data-plane encryption does not alone establish AES Key Wrap distribution.",
26:"Both complete EAP-TLS suites require actual AS/device negotiation; a manually installed MACsec key cannot witness EAP-TLS.",
27:"KGS provenance is externally unavailable; key-server priorities, fallback state and the EAP-TLS CAK-generation conflict remain separate obligations.",
28:"All six clauses are encoded, including minimum-feasible replay qualification. Kernel MACsec settings do not by themselves witness MKA timers or data-delay protection.",
29:"Eight-chain work yields four Inner IPv4 FORWARD lemmas and matching installed XFRM checks. Complete input/output/local paths, associated tunneling protocol, split-path exclusion, selected MAC branches and Linux refinement remain open.",
30:"Four Outer IPv4 FORWARD lemmas and installed XFRM checks are checked. Control exceptions, already-encrypted Gray input, local traffic, split paths, objective MAC and Linux refinement remain open.",
31:"Route tables alone cannot prove absence of routing processes or resolve the broad routing-function wording; per-component forwarding duties remain unproved.",
32:"TRANSEC requirement strength and trigger conditions conflict; no optional interpretation is invented.",
33:"Interface MTUs are observed, but complete path overhead/PMTU and source-specific avoidance versus reduction obligations remain unproved.",
34:"The complete Public-Internet branch is encoded and checked on observed virtual adjacency, including Outer internal Gray connectivity through switches and oriented external firewall attachments. Raw namespace/kind completeness is checked. Hashed representative transport intent ER-014 is pending; no actual public Internet connection or physical independence is claimed.",
35:"All baseline filter tokens translate. Generic first-match soundness is checked, but complete source allowlists, red services, intended peers and control approvals still need clause-level certificates.",
36:"Smallest-possible exposure requires an operational-needs/minimality model; a restrictive observed policy alone is insufficient.",
37:"A broad third-party feature inventory and blocked-versus-disabled choice remain unproved; sampled destinations cannot establish all feature behavior.",
38:"Family-specific rule syntax is translated. Full multicast/header/objective scope and inactive-family evidence remain separate; ER-012 tracks IPv6 applicability.",
39:"Default-denial reasoning is available, while management/control/revocation allowances, ingress reachability and the source address-exception conflict remain unresolved.",
40:"Default-denial and graph-separator lemmas are available. Full same-level allow behavior, HTTP/control exceptions, physical management ports and source conflict remain unresolved.",
41:"Actual AO/control policy, service placement and selected family/default behavior require explicit evidence beyond observed rules.",
42:"Trusted layer-specific time sources and synchronization events are not established by topology or clock output.",
43:"Default credential changes, DNS and bootstrap disablement require explicit configuration observations; absent fields are unknown.",
44:"The data-path baseline deliberately has no management profile. Source management duties remain unproved and separately scoped.",
45:"AW hardware/facility/use/hardening/shutdown duties require management and external temporal evidence.",
46:"Secure management transport and local exceptions require separately collected paths and source clarification.",
47:"Per-person administrative authentication and optional NIST/certificate branches require identity/action evidence and external policy.",
48:"Authorized secured provisioning before first use and CSR delivery require events/external records; installed certificates alone are insufficient.",
49:"Personnel clearances and Black-administrator exception scope are external evidence unavailable to the lab.",
50:"SIEM optionality is retained; deployed collection/alerts/CDS behavior and recommended transport need a selected management case.",
51:"CDS baseline membership and external policy compliance are unavailable; a simulated relay is insufficient.",
52:"Physical protection, personnel access, classified configuration copies and disposal/declassification require external records.",
53:"Virtual topology can show parallel placement, but unique physical ifaces and absence of physical enclave trunking require physical evidence.",
54:"Successful same-level baseline traffic supports interoperability for those observed sessions; all required pairings/implementations remain open.",
55:"Combined-CP applicability and external Inner Firewall requirements were not supplied; no blanket exemption is inferred.",
56:"All physical Red egress paths and AO-approved alternative protection are external/physical obligations not covered by a virtual subset.",
57:"Patch testing/application, antivirus and TEMPEST obligations depend on external policy and history unavailable in a short run.",
58:"An emulation device list is not an AO-approved hardware inventory or auditor-accessible baseline process.",
59:"Procurement documents and their disclosure contents were not supplied.",
60:"Annual/NSA-authorized audits and AO receipt/review are historical organizational actions unavailable to snapshots.",
61:"Operational registration/renewal evidence is unavailable, and the conflicting version-update deadlines remain unresolved.",
62:"One-year audit retention, quarterly capacity assessments and continuity duties cannot be inferred from a short collection interval.",
63:"Password entropy provenance or an actual same-domain authentication service requires explicit evidence; string length is not entropy.",
64:"The numeric deadline lemma is checked. Actual incident triggers, detection/report events, required fields and exceptions need external process evidence.",
65:"Containers do not establish distinct human administrators/auditors or their role assignments.",
66:"Training and periodic physical tamper inspections require personnel/event records.",
67:"Disposal ordering needs actual revocation/CAK-destruction initiation events and disposal times.",
68:"The non-exhaustive administrator duties require external operational records and source-specific assignment scope.",
69:"Auditor duties, survey/report actions and authorized access boundaries require organizational evidence.",
70:"Integrator engagement is optional; absence of a recorded engagement neither proves assigned duties nor creates a mandatory role.",
71:"Risk assessment, AO authorization, variant contact and lifecycle/compromise actions require external records.",
72:"The official Testing Annex was not supplied. Lab probes do not substitute for all annex tests, organizational records and AO delivery.",
73:"Objective selection and actual software/firmware signature algorithms with Table 2 parameters remain unobserved.",
74:"Redundant-component permission retains every applicable security obligation; a redundant topology does not establish full compliance or availability.",
75:"Screening-router and annex boundaries remain source-specific, with an unresolved annex-scope issue.",
76:"Legal undertaking scope requires legal-domain review and actual external evidence; no legal validity is inferred from Lean."
}
import_report_path=output_path("baseline-import.json")
import_report=json.loads(import_report_path.read_text()) if import_report_path.exists() else None
for group in data["groups"]:
    number=int(group["group_id"].split("-")[1])
    group["requirement_strength"]=group.pop("document_force",group.get("requirement_strength"))
    group["status"]="unresolved_interpretation" if group["open_issue_ids"] else "unavailable_evidence" if number in external else "conditional_results" if number in generic else "unresolved_proof_construction"
    group["established"]=False
    group["formal_definition"]=formal.get(number)
    group["formalization_status"]="encompassing_proposition_encoded_unproved" if number in formal else "semantic_plan_recorded_full_proposition_not_yet_encoded"
    group["lean_theorems"]=generic.get(number,[])
    group["disposition_reason"]=specific[number]
    group["remaining_construction_work"]=["Construct or complete the encompassing proposition with the registered quantifiers: "+group["proposed_formal_meaning"],"Discharge each applicable clause without collapsing alternatives or source qualifications."]
    group["evidence_needs"]=[r["request_id"] for r in requests["requests"] if group["group_id"] in r["group_ids"]]
    group["evidence_responses"]=[response_map[rid] for rid in group["evidence_needs"] if rid in response_map]
    group["outstanding_assumptions"]=["Collected normalized facts faithfully quote the recorded raw observations.","Observation completeness is bounded to the declared inventory and collection interval."]
    if number in generic:
        group["outstanding_assumptions"].append("The generic local obligations and implementation-to-model relation must be established for the actual applicable deployment; they are not assumed satisfied.")
    if group["open_issue_ids"]:
        group["outstanding_assumptions"].append("Authoritative source clarification is required for "+", ".join(group["open_issue_ids"])+".")
    if number in external:
        group["outstanding_assumptions"].append("Required organizational, policy, physical or historical evidence is unavailable as recorded in the evidence responses.")
    if number in {4,5}:
        group["status"]="demonstrated_violation"
        group["violation_scope"]="Recorded shared-host Linux emulation; based on fresh inventory/implementation observations and Evidence Agent response, not a claim about every possible deployment."
    if import_report and number in {8,17,19,20,22,23,29,30,35,38,39,40,54}:
        group["evidence_dependencies"]=[{"bundle":str(source_path("baseline")),"manifest_sha256":import_report["validation"]["source_manifest_sha256"],"snapshot_sha256":import_report["validation"]["source_snapshot_sha256"],"import_report":"outputs/baseline-import.json","validation":"outputs/baseline-round1-validation.json"}]
    if import_report and number in {29,30}:
        prefix="I_" if number==29 else "O_"
        group["lean_theorems"] += [c["theorem"] for c in import_report["forwarding_certificates"] if c.get("theorem") and c["chain_id"].startswith(prefix)]
        group["status"]="partial_results"
    if number==34:
        group["lean_theorems"]=["TDN.Imported.baseline_adjacency_ipv6_20261017T2112Z_topology.snapshot_public_internet_RG034"]
        group["status"]="conditional_results"
        group["establishment_scope"]="Candidate complete selected Public-Internet virtual-topology branch; ER-014 hashed applicability declaration pending."
    if number==22:
        group["lean_theorems"]=["TDN.Imported.baseline_20261017T2101Z.observed_vpn_modes_conform"]
        group["status"]="partial_results"
    for clause in group["clause_progress"]:
        clause["requirement_strength_review"]=clause.pop("force",clause.get("requirement_strength_review"))
        clause["status"]="unproved"
        clause["reason"]=specific[number]
        clause["formalization_work_remaining"]=group["proposed_formal_meaning"]
        clause["lean_theorems"]=[]
        if number==22:
            clause["status"]="snapshot_supported_selected_alternative" if any(x in clause["text"] for x in ["MSC-VG-9 ","MSC-VG-12 ","MSC-VG-18 "]) else "source_alternative_retained_not_witnessed_by_gcm_snapshot"
            clause["lean_theorems"]=group["lean_theorems"] if clause["status"].startswith("snapshot_supported") else []
        if number in {29,30}:
            threshold_ids=["MSC-IR-3 ","MSC-IR-5 "] if number==29 else ["MSC-OR-2 ","MSC-OR-5 "]
            if any(identity in clause["text"] for identity in threshold_ids):
                clause["status"]="partial_forwarding_policy_contribution"
                clause["lean_theorems"]=group["lean_theorems"]
            elif any(identity in clause["text"] for identity in ["MSC-IR-1 ","MSC-OR-1 "]):
                clause["status"]="snapshot_tunnel_mode_subclause_checked"
                clause["lean_theorems"]=["TDN.Imported.baseline_20261017T2101Z.observed_ipsec_tunnel_modes"]
            else:
                clause["status"]="unproved_no_clause_specific_theorem"
                clause["lean_theorems"]=[]
            clause["whole_clause_established"]=False
        if number==23 and "MSC-VG-14 " in clause["text"]:
            clause["status"]="observed_esp_state_lifetime_bound_checked"
            clause["lean_theorems"]=["TDN.Imported.baseline_20261017T2101Z.observed_esp_hard_lifetimes_within_bound"]
            clause["whole_clause_established"]=False

loaded=json.loads((output_path("loaded-baseline-import.json")).read_text())
topology=json.loads((output_path("topology-analysis.json")).read_text())
mechanisms=json.loads((output_path("mechanism-import.json")).read_text())
for group in data["groups"]:
    number=int(group["group_id"].split("-")[1])
    group["established_scopes"]=[]
    if number in {22,34}:
        theorem=loaded["loaded_mode_policy"]["configuration_target"] if number==22 else topology["outer_topology_target"]
        scope="Complete loaded IKEv2/encryption-mode policy for all inventoried VPN gateways of ipsec-baseline at baseline-loaded-20261017T2117Z; selected GCM objective alternatives" if number==22 else "Declared emulated Public-Internet ipsec-baseline with required Gray Firewalls at baseline-adjacency-ipv6-20261017T2112Z; both external placement and internal Gray role/path connection"
        assumptions=["Truth and completeness of observed inventory during the collection interval","Faithful importer translation of raw observations and declared component roles"]
        assumptions += ["Successful exact-file strongSwan loader and reconciled VICI inventory faithfully associate offered proposals with loaded connections; VICI 5.9 omits proposal suites"] if number==22 else ["Separately hashed representative transport declaration selects the Public-Internet branch","Conservative contraction of each observed device overapproximates internal connectivity; ordinary Gray switches may mediate role connections"]
        group["established_scopes"]=[{"scope":scope,"theorem":theorem,"validation":"outputs/loaded-mechanisms-round1-validation.json","assumptions":assumptions,"report":"outputs/loaded-baseline-import.json" if number==22 else "outputs/topology-analysis.json"}]
        group["status"]="established_within_listed_scopes"
        group["established"]=False
        group["establishment_scope"]=scope
        group["disposition_reason"]="The encompassing target is Lean-checked within the listed snapshot/profile scope. Other collected profiles and all-time behavior are not included."
        group["remaining_scopes"]=["Manual-SA mechanism experiments have no IKE configuration and are not RG-022 witnesses","Other configured/observed VPN profiles need their own complete loaded-policy inventory"] if number==22 else ["Other representative topologies and the non-Public-Internet conditional need separate applicability and adjacency instantiations","Physical-world correspondence and future topology remain outside the virtual snapshot theorem"]
        group["remaining_construction_work"]=group["remaining_scopes"]
        group["outstanding_assumptions"]=assumptions
        group["lean_theorems"]=[theorem]
        group["formalization_status"]="encompassing_proposition_checked_for_listed_scopes"
        for clause in group["clause_progress"]:
            clause["status"]="selected_profile_clause_or_conditional_checked"
            clause["reason"]=scope
            clause["lean_theorems"]=[theorem]
            clause["whole_clause_established"]=False
            clause["established_within_listed_scope"]=True
    if number==22:
        for clause in group["clause_progress"]:
            if "MSC-VG-10 " in clause["text"]:
                clause["status"]="threshold_alternative_replaced_by_selected_VG18_objective"
                clause["reason"]="The encompassing target preserves CBC as an alternative; these profiles select GCM under VG-18 and do not claim CBC is configured."
            elif "MSC-VG-11 " in clause["text"]:
                clause["status"]="threshold_alternative_replaced_by_selected_VG12_objective"
                clause["reason"]="The encompassing target preserves CBC with HMAC as an alternative; these profiles select GCM under VG-12."
            else:
                clause["reason"]="All inventoried loaded policies use version 2 and the selected GCM alternative; implementation correspondence is an explicit trust boundary."
    if number==34:
        group["remaining_scopes"].append("The non-Public-Internet branch permits mediated external connectivity, including an intervening firewall. A nonempty generic example validates consistency; a concrete representative instance is still separate.")
        for clause in group["clause_progress"]:
            if clause["text"] in {"1.","3)."}:
                clause["status"]="source_cross_reference_continuation_retained"
                clause["reason"]="Literal extraction continuation of the preceding Section reference; it introduces no independent semantic obligation."
                clause["lean_theorems"]=[]
                clause["established_within_listed_scope"]=False
            elif clause["text"].startswith("Otherwise"):
                clause["status"]="nonselected_conditional_retained_uninstantiated"
                clause["reason"]="The baseline declaration selects Public Internet. The otherwise branch remains in the encompassing target and requires a different applicability instance."
                clause["lean_theorems"]=[]
                clause["established_within_listed_scope"]=False
            elif "internal interface" in clause["text"] and "Gray" in clause["text"]:
                clause["reason"]="Gray Firewalls are required in this profile. Arbitrary Gray role connectivity permits intervening ordinary switches; the no-Gray-Firewall alternative remains unselected."
    if number in {7,15,16,25,28,41,54}:
        group["mechanism_evidence"]={"report":"outputs/mechanism-import.json","cases":[{"id":c["id"],"manifest_sha256":c["manifest_sha256"]} for c in mechanisms["cases"]],"scope":"Bounded data-channel mechanisms/settings and parsed probes; no complete authentication, encapsulation-order or universal-forwarding theorem"}
        group["lean_theorems"]+= ["TDN.Imported.Mechanisms.each_case_has_positive_traffic","TDN.Imported.Mechanisms.recorded_probe_expectations"]
        if not group["open_issue_ids"]:group["status"]="partial_results"
        if number==7:group["lean_theorems"].append("TDN.Imported.Mechanisms.all_four_declared_layer_pairings")
        if number==41:group["lean_theorems"].append("TDN.Imported.Mechanisms.all_eight_declared_family_choices")
        if number in {25,28}:group["lean_theorems"].append("TDN.Imported.Mechanisms.recorded_macsec_selected_flags")
        for clause in group["clause_progress"]:
            if number==25 and "MSC-MD-2 " in clause["text"]:
                clause["status"]="observed_macsec_cipher_subclause_checked"
                clause["lean_theorems"]=["TDN.Imported.Mechanisms.recorded_macsec_selected_flags"]
                clause["reason"]="All 20 imported MACsec interface observations report GCM-AES-256; AES Key Wrap distribution remains separate."
            if number==28 and any(x in clause["text"] for x in ["MSC-MD-9 ","MSC-MD-10 ","MSC-MD-16 "]):
                clause["status"]="observed_interface_flags_partial_contribution"
                clause["lean_theorems"]=["TDN.Imported.Mechanisms.recorded_macsec_selected_flags"]
                clause["reason"]="Observed replay window 0, protect/encrypt and strict validation; all external-port connectivity and MKA settings are not inferred."
    if number in {13,53}:
        group["topology_evolution"]={"before_report":"outputs/shared_before-gray.json","after_reports":["outputs/shared_after-gray.json","outputs/redundant_after-gray.json"],"before_result":"Six structural Gray firewall-free cross-level paths; all sampled Red probe expectations still matched","after_result":"The same conservative Gray graph semantics excludes every cross-level path avoiding Gray Firewalls","physical_claim":False}
        group["lean_theorems"] += ["TDN.Imported.shared_three_level_20261017T2117Z_gray.concrete_bypass","TDN.Imported.shared_inline_20261017T2128Z_gray.cross_level_waypointing","TDN.Imported.redundant_inline_20261017T2128Z_gray.cross_level_waypointing"]
        group["status"]="partial_results"
        if number==13:group["disposition_reason"]="Before-state structural bypass is checked and both repaired graphs have universal Gray separators. The full group still includes prohibited-flow semantics, management-service paths and Outer filtering."

headers=json.loads(output_path("header-import.json").read_text())
events=json.loads(output_path("events-import.json").read_text())
ike_headers=json.loads(output_path("ike-header-import.json").read_text())
for group in data["groups"]:
    number=int(group["group_id"].split("-")[1])
    if number==22:
        for name in ["shared_before","shared_after","redundant_after"]:
            report=json.loads(output_path(name+"-policies.json").read_text())
            group["established_scopes"].append({"scope":"Complete loaded gateway mode policy of "+report["snapshot_id"],"theorem":report["loaded_mode_policy"]["configuration_target"],"report":"outputs/"+name+"-policies.json","validation":"outputs/expanded-policy-events-round1-validation.json","assumptions":group["established_scopes"][0]["assumptions"],"manifest_sha256":report["validation"]["source_manifest_sha256"]})
            group["lean_theorems"].append(report["loaded_mode_policy"]["configuration_target"])
    if number==38:
        group["established_scopes"]=[{"scope":headers["scope"],"theorem":headers["theorem"],"validation":"outputs/headers-round3-validation.json","assumptions":headers["assumptions"],"report":"outputs/header-import.json","manifest_sha256":headers["validation"]["source_manifest_sha256"]}]
        group["status"]="established_within_listed_scopes"
        group["established"]=False
        group["formalization_status"]="encompassing_proposition_checked_for_listed_scopes"
        group["establishment_scope"]=headers["scope"]
        group["outstanding_assumptions"]=headers["assumptions"]
        group["lean_theorems"]=[headers["theorem"]]
        group["disposition_reason"]="Every modeled packet accepted by the baseline IPv4 filter hooks satisfies the source protocol restrictions, Outer objective header-length restriction and external multicast exclusion. IPv6 inactivity is checked in the same collection."
        group["remaining_scopes"]=["REQ-I10 requirement-strength question remains unresolved globally; the selected configuration satisfies the additional PF-10 objective explicitly", "Active IPv6 and MACsec profiles require separate header/traffic-model instantiations","Actual Linux packet-hook correspondence, no bypass and collector completeness remain explicit assumptions; no all-time behavior claim"]
        group["remaining_construction_work"]=group["remaining_scopes"]
        for clause in group["clause_progress"]:
            clause["status"]="checked_for_ipv4_baseline_or_inactive_ipv6_applicability"
            clause["reason"]=group["disposition_reason"]
            clause["lean_theorems"]=[headers["theorem"]]
            clause["established_within_listed_scope"]=True
            clause["whole_clause_established"]=False
            if "MSC-PF-12 " in clause["text"]:
                clause["status"]="inactive_ipv6_applicability_checked"
                clause["reason"]="Same-interval all/default/per-interface disablement and absent IPv6 addresses/routes justify IPv4-only scope; no active IPv6 filter theorem is claimed."
            elif "MSC-PF-10 " in clause["text"]:
                clause["reason"]="All accepted modeled Outer IPv4 packets have five-word headers. The additional objective is satisfied explicitly while REQ-I10 remains unresolved globally."
    if number in {17,19,20,23,24,25,27,28,33}:
        group["finite_event_evidence"]={"report":"outputs/events-import.json","ike_manifest_sha256":events["ike"]["manifest_sha256"],"mka_manifest_sha256":[e["manifest_sha256"] for e in events["mka"]],"scope":"Selected finite experiments; configured key matching is declared, successful MKA secured/kernel state and useful/negative probes are observed"}
        if number in {17,19,20,23}:
            group["lean_theorems"].append("TDN.Imported.Events.observed_objective_exchange_sequence")
        if number in {17,24,25,27,28}:
            group["lean_theorems"] += ["TDN.Imported.Events.matching_mka_outcome","TDN.Imported.Events.mismatched_mka_outcome"]
        if number in {19,33}:
            group["finite_header_evidence"]={"report":"outputs/ike-header-import.json","manifest_sha256":ike_headers["manifest_sha256"],"scope":ike_headers["scope"],"assumptions":ike_headers["assumptions"]}
            group["lean_theorems"].append("TDN.Imported.IKEHeaders.recorded_headers_fit_without_ip_fragmentation")
        if not group["open_issue_ids"]:group["status"]="partial_results"
        for clause in group["clause_progress"]:
            text=clause["text"]
            if number==19 and any(term in text for term in ["IKE_INTERMEDIATE","PMTU","fragmentation","ML-KEM-1024","ML-DSA-87"]):
                clause["status"]="finite_objective_exchange_partial_contribution"
                clause["lean_theorems"]=["TDN.Imported.Events.observed_objective_exchange_sequence","TDN.Imported.IKEHeaders.recorded_headers_fit_without_ip_fragmentation"]
                clause["reason"]="Ordered selected exchange algorithms and complete recorded fragment sets are checked; complete RFC/profile conformance and capture completeness remain separate."
            if number==25 and "MSC-MD-1 " in text:
                clause["reason"]="MKA negotiated secured state with AES-GCM-256 data SAs, but raw evidence does not directly identify the AES Key Wrap operation/key size."
            if number==28 and "MSC-MD-8 " in text:
                clause["status"]="observed_hello_timeout_partial_contribution"
                clause["reason"]="Both MKA peer statuses report Hello Time=2000 ms; lifetime timeout 6000 ms and data-delay protection remain unobserved."
    if number==19:group["disposition_reason"]="Finite classical-then-ML-KEM1024-then-ML-DSA87 objective exchange and its recorded unfragmented IP headers now have checked contributions. Full configured threshold/objective profiles and all referenced extension semantics remain unproved."
    if number==20:group["disposition_reason"]="Observed unique peer identities and ML-DSA chain authentication are partial evidence. The objective trace explicitly reports certificate status unavailable before successful authentication; revoked/expired rejection remains unproved and is not inferred."

data,requests=refresh(data,requests)

for request in requests["requests"]:
    if request["request_id"]=="ER-012":
        request["status"]="supported_for_disabled_ipv6_profile"
        request["response"]={"artifact":str(source_path("adjacency")),"report":"outputs/topology-analysis.json","finding":"All/default/per-interface IPv6 disablement, forwarding=0 and absent IPv6 addresses/routes checked for eight encryption devices; active IPv6 mechanism cases remain separate."}
    if request["request_id"]=="ER-014":
        request["status"]="supported_within_declared_scope"
        request["response"]={"artifact":str(source_path("scenario")),"sha256":topology["scenario_declaration_sha256"],"finding":"Hashed declaration binds ipsec-baseline to emulated Public Internet; no live Internet connection claim"}
    if request["request_id"]=="ER-015":
        request["status"]="supported_for_finite_recorded_exchange"
        request["response"]={"artifact":str(source_path("ikev2_headers")),"report":"outputs/ike-header-import.json","manifest_sha256":ike_headers["manifest_sha256"],"finding":"56 matching endpoint header records, 28 unique packets, 1500-byte direct-bridge MTU bound and maximum 1280 bytes; no recorded IP fragmentation. Capture completeness remains explicit."}
    if request["request_id"]=="ER-013":
        request["status"]="supported_with_loader_assumption"
        request["response"]={"artifact":str(source_path("loaded")),"report":"outputs/loaded-baseline-import.json","finding":"Complete public configuration, exact-file load and runtime connection/CHILD inventory match all eight gateways; runtime suites rely on explicit loader association"}
(output_path("evidence_requests.json")).write_text(json.dumps(requests,indent=2,ensure_ascii=False)+"\n")

data["updated_at"]=datetime.now(timezone.utc).isoformat()
data["summary"]={"whole_groups_established_across_all_profiles":0,"groups_established_within_listed_scopes":sum(bool(g["established_scopes"]) for g in data["groups"]),"target_count":len(data["groups"]),"formal_propositions_encoded":len(formal),"generic_results_do_not_discharge_whole_groups":True,"status_counts":{status:sum(g["status"]==status for g in data["groups"]) for status in sorted({g["status"] for g in data["groups"]})}}
def remap_output_references(value):
    if isinstance(value,str) and value.startswith("outputs/"):
        return str(output_path(value.removeprefix("outputs/")))
    if isinstance(value,list):return [remap_output_references(v) for v in value]
    if isinstance(value,dict):return {k:remap_output_references(v) for k,v in value.items()}
    return value
data=remap_output_references(data)
data=reconcile(data)
p.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n")
print(json.dumps(data["summary"],indent=2))
