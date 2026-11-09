import json
from source_paths import output_path,source_path


def refresh(register,requests):
    groups={int(g["group_id"].split("-")[1]):g for g in register["groups"]}
    for group in groups.values():
        group["partial_contributions"]=[]
        for scope in group.get("established_scopes",[]):
            scope["platform_scope"]="Historical Linux container/static-routing/bridge profile; not a native FRR/OVS profile"
    def partial(number,meaning,theorems,keywords=()):
        group=groups[number]
        group["lean_theorems"]+=theorems
        group["partial_contributions"].append({"meaning":meaning,"theorems":theorems,"whole_group_established":False})
        if group["status"] not in {"established_within_listed_scopes","unresolved_interpretation","demonstrated_violation"}:group["status"]="partial_results"
        for clause in group["clause_progress"]:
            if any(word.lower() in clause["text"].lower() for word in keywords):
                clause["status"]="partial_contribution_full_clause_unproved"
                clause["reason"]=meaning
                clause["lean_theorems"]=list(dict.fromkeys(clause["lean_theorems"]+theorems))
                clause["whole_clause_established"]=False
    keys=["coherent_baseline","coherent_same_level","coherent_shared","coherent_redundant","coherent_management","four_shared","four_redundant"]
    for key in keys:
        report=json.loads(output_path(key+"-import.json").read_text())
        theorem=report["loaded_mode_policy"]["configuration_target"]
        scope={"scope":"Complete loaded gateway IKEv2/encryption-mode policy of "+report["snapshot_id"],"theorem":theorem,"report":str(output_path(key+"-import.json")),"assumptions":groups[22]["established_scopes"][0]["assumptions"],"manifest_sha256":report["validation"]["source_manifest_sha256"],"platform_scope":"Historical Linux container/static-routing/bridge profile; not native FRR/OVS","validation_reference_kind":"see dependency reconciliation"}
        groups[22]["established_scopes"].append(scope)
        groups[22]["lean_theorems"].append(theorem)
        for number,prefix in [(29,"I_"),(30,"O_")]:
            theorems=[c["theorem"] for c in report["forwarding_certificates"] if c.get("theorem") and c["chain_id"].startswith(prefix)]
            partial(number,"Additional loaded Linux-profile forwarding-chain certificates for "+report["snapshot_id"]+". Each certificate constrains all accepted modeled packets to matching directional tunnel-policy metadata. Local/input/output paths, cryptographic execution and full refinement remain open.",theorems,["bypass","split tunneling"])
        graph=json.loads(output_path(key+"-gray.json").read_text())
        if graph["cross_level_cut_passed"] is True and graph["applicable_cross_level_pairs"]>0:
            theorem=graph["theorem_namespace"]+".cross_level_waypointing"
            partial(13,"Universal Gray firewall separators in the conservative observed graph of "+report["snapshot_id"]+". Inactive fallback interfaces meet explicit checked conditions. Firewall packet rules and management endpoints are separate obligations.",[theorem],["paths","traverse"])
    for namespace in ["SameLevelBinding","FourSharedBinding","FourRedundantBinding"]:
        theorems=["TDN.Deployments."+namespace+"."+n for n in ["observed_inner_peers_have_same_full_declared_level","recorded_logical_domain_outcomes","positive_and_negative_witnesses"]]
        partial(8,"Exact-spec v2 declarations bind full security labels and logical Red-network identity to observed peers and finite directed probe outcomes in "+namespace+". Same-level distinct networks remain distinct. Universal authentication/communication exclusion is still unproved.",theorems,["same security","same level","Red Network"])
        partial(54,"Positive probe witnesses cover the hash-bound recorded Inner peer relationships of "+namespace+"; complete product interoperability and all required technologies remain broader.",[theorems[-1]],["interoperab"])
    for namespace in ["FourSharedBinding","FourRedundantBinding"]:
        partial(8,"The captured full-level labels include Top Secret, Secret US-only and Secret Coalition; an additional Unclassified domain remains separate.",["TDN.Deployments."+namespace+".captured_source_figure_six_levels"])
    tls=["TDN.Deployments.Management.recorded_tls_outcomes","TDN.Deployments.Management.both_test_branches_present"]
    ca=["TDN.Deployments.Supplemental.observed_good_crl_authentication_exchanges"]
    for number in [10,44,46,47]:
        partial(number,"The historical independent-management Linux profile has 28 raw-bound TLS application attempts across 14 managed components. Credentialed tests succeed; missing-client-certificate tests explicitly receive certificate-required alerts. These events do not identify human administrators, prove every administrative action gated, or establish physical/network isolation.",tls,["secure","authenticate","management"])
    for number in [10,11,17,20,48]:
        partial(number,"Three separate local/enterprise/central CA experiments contain six successful ECDSA-SHA384 exchanges with good leaf/intermediate CRL status, reached roots and useful traffic. CA ownership, approved NPE issuance, provisioning history, and revoked/expired rejection remain unproved.",ca,["certificate","revocation","CA "])
    partial(11,"Finite TLS responses and explicit client-certificate refusals include the central-management endpoint experiment. The 12 supplemental dual-IPsec channel settings are parser-checked only and do not establish complete management path protection.",["TDN.Deployments.Supplemental.supplemental_tls_recorded_outcomes"],["management"])
    partial(46,"Central management, an alternative Red egress and a same-VLAN management case each have positive and explicit certificate-required negative TLS outcomes. No NSA approval or universal administrative protocol claim follows.",["TDN.Deployments.Supplemental.supplemental_tls_recorded_outcomes"],["TLS","management"])
    partial(31,"Four permitted routing endpoints across Black/Red OSPF experiments have Full neighbor states and selected installed OSPF routes. Complete absence of routing daemons on Outer components awaits ER-018; broad routing-function source wording remains separate.",["TDN.Deployments.Supplemental.recorded_ospf_neighbors_and_routes"],["routing"])
    partial(42,"Six NTP responses echo the request origin and have valid server-mode/stratum fields. The generated theorem explicitly records that clocks were not adjusted. Trusted time authority and actual independent-clock synchronization remain unproved.",["TDN.Deployments.Supplemental.observed_ntp_replies_without_clock_adjustment"],["time","synchron"])
    partial(50,"The software relay logs one accepted event, one rejected unauthorized payload, and one matching Red receiver event. The finite test does not establish approved CDS status, complete log collection, alerting or retention.",["TDN.Deployments.Supplemental.recorded_relay_both_branches"],["CDS","SIEM","log"])
    partial(54,"53 ICMP tests across the supplemental routing/utility experiments preserve their expected outcomes and include useful traffic. Six TLS tests are recorded separately, with no fabricated packet counts.",["TDN.Deployments.Supplemental.recorded_probe_expectations","TDN.Deployments.Supplemental.useful_and_negative_probe_witnesses"],["interoperab"])
    groups[8]["disposition_reason"]="Full-level and logical-network bindings now cover same-level, shared four-level and redundant four-level Linux profiles. Finite successful/refused probes and observed peer levels do not establish all communications or authentication exclusion."
    groups[20]["disposition_reason"]="The objective IKE trace still reports unavailable certificate status. Separate CA experiments now establish finite good-CRL authentication events. Revoked/expired rejection, complete trust-store/default-certificate alternatives, and all-time enforcement remain open."
    groups[31]["disposition_reason"]="Allowed routing infrastructure has finite OSPF neighbor/route evidence. ER-018 requests Outer process/default observations; native FRR/OVS profile fidelity is independently tracked by ER-019."
    groups[42]["disposition_reason"]="Layer-specific NTP response samples are checked, including the explicit absence of clock adjustment. Trusted authority and actual synchronization remain unproved."
    groups[43]["remaining_construction_work"]=["Import and verify ER-018 public DNS, bootstrap and access-default observations when supplied.","Separate present configuration from historical default changes and preserve the DNS server-specified alternative."]
    groups[37]["remaining_construction_work"]=["Use ER-018 process/socket/startup inventory to identify applicable third-party services.","Prove blocked-or-disabled behavior per identified feature; do not infer absence from empty optional fields."]
    groups[13]["remaining_construction_work"]=["Combine structural separators with source-specific Gray/Outer filtering semantics and management-service path obligations.","Instantiate the graph translation for native FRR/OVS profiles after ER-019 observations; retain historical Linux scope."]
    groups[22]["remaining_scopes"]=["Historical Linux and one native FRR/OVS configuration scope are listed separately. Other native profiles need separate inputs and instantiation.","Manual-SA mechanism experiments have no IKE configuration and are not witnesses for this target.","Successful-load/VICI correspondence remains explicit; no future operational guarantee is asserted."]
    groups[22]["remaining_construction_work"]=groups[22]["remaining_scopes"]
    groups[34]["disposition_reason"]="The public-Internet intent branch is checked for one historical Linux virtual topology. Mediated non-Internet connectivity has a consistent nonempty generic example. Other topology/platform instances remain separate."
    extensions=json.loads(output_path("extensions-import.json").read_text())
    for number in [20,40]:
        partial(number,"Finite HTTP CRL and OCSP experiments verify good and revoked status for the same test credential. The revoked CRL check fails specifically with certificate-revoked; OCSP verifies signed response status. These are OpenSSL endpoint checks, not VPN authentication enforcement. The OCSP response signature is explicitly SHA256, so no full CNSA profile result is inferred.",["TDN.Deployments.Extensions.observed_revocation_status_pairs"],["revocation","CRL","OCSP","HTTP"])
    partial(40,"Two parsed default-deny bridge chains admit IPv4 TCP only for a designated client/server HTTP request and response pair. The universal modeled exception bound is separate from observed negative HTTP timeouts, which do not establish causal denial.",["TDN.Deployments.Extensions.http_exception_0_bounded","TDN.Deployments.Extensions.http_exception_1_bounded"],["HTTP","packet","filter"])
    for number in [17,24,26]:
        partial(number,"Six separate reversed-role EAP trials record TLS1.2 mutual certificate verification and EAP success. Polls preserve transient MACsec interfaces; reverse-v4 data ping is a network-unreachable runtime error. No successful data delivery is recorded. Same-configuration dual-role duties and complete Table10/11 suites remain unproved.",["TDN.Deployments.Extensions.eap_authentication_without_successful_data_probe"],["EAP","certificate","supplicant","authenticator"])
    for number in [45,46,47]:
        partial(number,"Two observed client environments, a host reporting virtualization none and a KVM guest with its own kernel, each have successful credentialed TLS use and explicit missing-certificate refusal. Assembly time is distinct from raw event time. Dedicated use, facility protection, human identities, product approval and direct cable management are not established.",["TDN.Deployments.Extensions.recorded_host_and_guest_tls_use"],["AW","virtual","physical","manage","authenticate"])
    partial(74,"Seventeen recorded outcomes cover primary use, active sharing, a tagged primary forwarding DROP, manual standby route selection and restoration. A refused outage sample and useful standby samples are explicit. No automatic failover, physical fault or all-time availability claim is made.",["TDN.Deployments.Extensions.recorded_manual_redundancy_probe_outcomes","TDN.Deployments.Extensions.outage_and_restoration_witnesses"],["redundan","failover","throughput"])
    for key,namespace in [("native_baseline","NativeBaseline"),("native_same_level","NativeSameLevel"),("native_shared","NativeShared"),("native_redundant","NativeRedundant"),("native_management","NativeManagement")]:
        native=json.loads(output_path(key+"-import.json").read_text())
        native_graph=json.loads(output_path(key+"-gray.json").read_text())
        native_topology=json.loads(output_path(key+"-topology.json").read_text())
        native_header=json.loads(output_path(key+"-headers.json").read_text())
        native_theorem=native["loaded_mode_policy"]["configuration_target"]
        platform="Device FRR/OVS infrastructure with raw shared control/forwarding namespaces and OVS UUID/port/ifindex correspondence; Linux encryption endpoints"
        groups[22]["established_scopes"].append({"scope":"Complete loaded gateway IKEv2/encryption-mode policy of "+native["snapshot_id"],"theorem":native_theorem,"report":str(output_path(key+"-import.json")),"assumptions":groups[22]["established_scopes"][0]["assumptions"],"manifest_sha256":native["validation"]["source_manifest_sha256"],"platform_scope":platform})
        groups[22]["lean_theorems"].append(native_theorem)
        groups[34]["established_scopes"].append({"scope":"Declared emulated-Public-Internet branch in the conservative observed graph of "+native["snapshot_id"],"theorem":native_topology["outer_topology_target"],"report":str(output_path(key+"-topology.json")),"assumptions":native_topology["assumptions"],"manifest_sha256":native_topology["manifest_sha256"],"declaration_sha256":native_topology["scenario_declaration_sha256"],"platform_scope":platform})
        groups[34]["lean_theorems"].append(native_topology["outer_topology_target"])
        groups[38]["established_scopes"].append({"scope":native_header["scope"]+" in "+native["snapshot_id"],"theorem":native_header["theorem"],"report":str(output_path(key+"-headers.json")),"assumptions":native_header["assumptions"],"manifest_sha256":native_header["validation"]["source_manifest_sha256"],"platform_scope":platform})
        groups[38]["lean_theorems"].append(native_header["theorem"])
        if native_graph["applicable_cross_level_pairs"]>0:
            partial(13,"The native FRR/OVS profile "+native["snapshot_id"]+" has a conservative observed Gray separator after raw OVS UUID/ifindex/MAC and FRR namespace correspondence checks. All supported switch ports are contracted; OpenFlow packet semantics and future controller behavior remain separate.",[native_graph["theorem_namespace"]+".cross_level_waypointing"],["paths","traverse"])
        snapshot=json.loads((source_path(key)/"snapshot.json").read_text())
        roles={d["id"]:d["role"] for d in snapshot["devices"]}
        for number,role in [(29,"inner"),(30,"outer")]:
            theorems=[c["theorem"] for c in native["forwarding_certificates"] if c.get("theorem") and roles[c["chain_id"].split(":")[0]]==role]
            partial(number,"Encryption endpoints in "+native["snapshot_id"]+" have directional FORWARD policy metadata certificates. Device infrastructure identity checks leave full cryptographic execution and local-path refinement outstanding.",theorems,["bypass","split tunneling"])
        binding_theorems=["TDN.Deployments."+namespace+"Binding."+name for name in ["observed_inner_peers_have_same_full_declared_level","recorded_logical_domain_outcomes","positive_and_negative_witnesses"]]
        partial(8,"Device exact-manifest/spec declarations bind full security levels, separate logical network identities, observed Inner peers and finite ordered host probes for "+native["snapshot_id"]+". Classification authority and universal communication/authentication exclusion remain separate.",binding_theorems,["same security","same level","Red Network"])
        if key in {"native_shared","native_redundant"}:
            partial(8,"Device source-faithful four-level profiles include Top Secret, Secret US-only and Secret Coalition, plus a separate Unclassified domain.",["TDN.Deployments."+namespace+"Binding.captured_source_figure_six_levels"])
    for number in [10,44,46,47]:
        partial(number,"Device independent management records 28 TLS application attempts across 14 components: useful credentialed responses and explicit certificate-required refusals. Human identity, authorization, physical separation and all administrative traffic remain unproved.",["TDN.Deployments.NativeManagementTLS.recorded_tls_outcomes","TDN.Deployments.NativeManagementTLS.both_test_branches_present"],["secure","authenticate","management"])
    partial(31,"Host-wide process records bind all five native profiles, including FRR sidecars sharing network namespaces. None of the recorded Inner/Outer process names belongs to the explicit routing-daemon dictionary. Semantic absence of all routing implementations and the broader routing-function phrase remain unproved.",["TDN.Deployments.NativeInventory.no_recorded_encryptor_process_has_known_routing_name"],["routing"])
    partial(43,"All 145 native component resolver files specify a valid literal DNS server. Their root password fields are locked and nonempty. Docker-inherited lookup remains configured; historical changes to all vendor defaults and automatic remote-boot disablement remain unproved.",["TDN.Deployments.NativeInventory.every_recorded_component_has_specified_dns_server","TDN.Deployments.NativeInventory.recorded_root_passwords_locked"],["DNS","default","password"])
    partial(74,"The native redundant profile records 17 primary, active-sharing, outage, manual FRR standby selection and restoration outcomes. The tagged primary DROP remains installed while standby useful traffic succeeds; automatic HA and physical failure are outside scope.",["TDN.Deployments.NativeRedundancy.recorded_probe_outcomes","TDN.Deployments.NativeRedundancy.outage_and_restoration_witnesses"],["redundan","failover","throughput"])
    authentication=json.loads(output_path("authentication-import.json").read_text())
    auth_theorems=["TDN.Deployments.Authentication."+name for name in ["observed_credentials_and_configured_hash_constraints","selected_authentication_uses_sha384","observed_capabilities_distinguish_request_and_response","recorded_sha256_refusal_and_sha384_recovery"]]
    for number in [17,19,20]:
        partial(number,"ER-017 binds eight unchanged secp384r1 public credentials to explicit ecdsa-384-sha384 loaded constraints and four fresh SHA384 exchanges. One deliberately SHA256-signed Inner authentication is rejected for its signature scheme, followed by restored SHA384 success. Responder capability advertisements remain distinct from effective per-peer policy; minimum strength is not an exact curve restriction.",auth_theorems,["authentication","certificate","CNSA","Table 6"])
    for request in requests["requests"]:
        if request["request_id"]=="ER-017":
            request["status"]="supported_selected_credentials_and_hash_enforcement_trial"
            request["response"]={"report":str(output_path("authentication-import.json")),"after_manifest_sha256":authentication["after"]["manifest_sha256"],"negative_manifest_sha256":authentication["negative_trial"]["manifest_sha256"],"finding":"Public credential curve/signature, exact loaded hash constraints, selected exchanges and cause-specific negative/recovery checked. Full CNSA profile and exact curve-universe restriction remain unproved."}
    for group in groups.values():
        group["lean_theorems"]=list(dict.fromkeys(group["lean_theorems"]))
        group["platform_scope_note"]="Historical Linux static-routing/bridge profiles remain distinct from the separately imported native FRR/OVS baseline. Every establishment is bound to its own listed snapshot and platform scope. Additional native representative profiles remain pending ER-019."
    for request in requests["requests"]:
        if request["request_id"]=="ER-016":
            request["status"]="supported_with_declared_identity_scope"
            request["response"]={"artifact":str(source_path("domain_declaration")),"reports":[str(output_path(n)) for n in ["same-level-binding.json","four_shared-binding.json","four_redundant-binding.json"]],"finding":"All three current exact-spec declarations bind full levels/logical domains to observed device/iface/peer/probe data. Classification authority and physical identity remain external."}
    revised={
        7:"Generic layer invariants, all five encapsulation pairings and eight family combinations have checked contributions. Independence, cryptographic execution and complete concrete forwarding refinement remain unproved.",
        8:"Historical and five native profiles bind full security labels and logical Red domains to observed peers and finite positive/negative probes. Universal authentication and communication exclusion remain unproved.",
        10:"Independent native management, historical management and three CA configurations provide finite TLS/certificate contributions. Complete management separation and method-specific cross-site trust obligations remain unproved.",
        11:"Central Red management and CA experiments provide partial contributions. The Gray Enterprise Management Annex is unavailable; complete protected management paths and source qualifications remain unresolved.",
        12:"Distinct declared domain identities and observed certificate peers are checked. Full CA/CAK management separation and universal cross-domain authentication exclusion remain unproved.",
        15:"Five mechanism pairings include nested MACsec/IPsec and Ethernet encapsulation observations. Manual test SAs do not discharge authentication, independent standalone device duties or the source scope conflict.",
        17:"Certificate IPsec, selected SHA384 enforcement, PSK MKA and reversed-role EAP authentication have finite checked contributions. EAP-derived protected data delivery and simultaneous roles remain unsupported; NPE and approval duties remain external.",
        18:"Classical and objective post-quantum exchange observations provide partial algorithm evidence. Complete configured purpose-specific profiles, external CNSS policy and objective selection remain unproved.",
        20:"Separate CA exchanges establish finite good-CRL authentication events. HTTP endpoint experiments check good/revoked CRL and OCSP responses. VPN revocation enforcement, expiry, complete trust/default-certificate alternatives and temporal duties remain unproved.",
        22:"The encompassing loaded IKEv2/permitted-encryption-mode target is checked for eleven historical Linux scopes and five native FRR/OVS scopes. Every instance keeps its snapshot, loader assumption and manifest binding.",
        24:"PSK MKA and reversed-role EAP authentication are checked at event scope. EAP-derived MACsec delivery and simultaneous supplicant/authenticator roles remain unsupported; AS source scope still needs clarification.",
        26:"Six trials record mutually verified EAP TLS1.2 authentication. Complete Table 10/11 negotiated suites and protected EAP-derived delivery remain unproved.",
        28:"All six obligations are encoded. PSK traffic and kernel settings provide partial evidence. Pinned-source review reports a delay-protection limitation at the required 2000 ms hello interval; the source audit remains separately tracked until imported.",
        29:"Directional Inner FORWARD metadata certificates and installed XFRM associations are checked across historical and five native profiles. Full input/output/local paths, cryptographic execution and concrete semantic refinement remain unproved.",
        30:"Directional Outer FORWARD metadata certificates and installed XFRM associations are checked across historical and five native profiles. Complete control exceptions, already-encrypted Gray input, local traffic and concrete execution refinement remain unproved.",
        31:"Allowed routing endpoints have finite OSPF neighbor/route facts. Five native profiles bind 145 device inventories and 33 FRR sidecars; recorded encryptor process names exclude the explicit routing dictionary. Complete routing-function semantics and protocol absence remain unproved.",
        33:"The objective IKE capture has bounded recorded IP lengths, explicit encrypted fragmentation and no IP fragmentation in recorded headers. All-path PMTU, encapsulation overhead and broader avoidance/reduction duties remain unproved.",
        34:"The encompassing declared Public-Internet branch is checked for one historical Linux and five native FRR/OVS conservative virtual graphs. A mediated non-Internet generic witness is consistent; physical and all-time obligations remain outside these scopes.",
        37:"Complete finite native process/socket/startup inventories are supplied, with unavailable systemctl queries explicit. Identification of every third-party feature and its blocked-or-disabled behavior remains unresolved proof construction.",
        40:"Generic separators and two universal modeled HTTP exception bounds are checked. Full same-level allowance, control exceptions, physical management interfaces and the source address/exception conflict remain unresolved.",
        43:"All 145 native resolver files specify literal DNS servers and record locked root password flags. Complete vendor-default change history is unavailable; remote-boot disablement and optional DNS-lookup objective remain unproved.",
        44:"Device and historical independent management provide finite secure application trials. Adequate distinct AW roles, universal administrative gating and physical/cryptographic/ACL separation remain unproved.",
        45:"Host and KVM-guest AW experiments record useful TLS management and explicit missing-certificate refusals. Facility protection, dedicated use, hardening, patch history and shutdown duties remain external or temporal gaps.",
        46:"Device and supplemental management paths provide finite TLS outcomes, including same-LAN/VLAN alternatives. Complete approved transport/protocol/address policy and the local-management source qualification remain unresolved.",
        50:"A software relay logs accepted/refused payloads and matching Red receipt. Approved CDS status, complete SIEM sources/alerts, retention and recommended transport coverage remain unproved.",
        54:"Finite useful traffic is checked across native profiles, manual-SA pairings, address-family matrix, CA, management and routing experiments. Product-wide interoperability remains broader than those sessions.",
        74:"Historical and native event traces check tagged primary forwarding failure, active sharing, manual standby selection and restoration. Every added component still owes its applicable requirements; automatic availability is not established."}
    for number,reason in revised.items():groups[number]["disposition_reason"]=reason
    groups[22]["remaining_scopes"]=["Manual-SA mechanism cases do not instantiate IKE configuration requirements.","Loaded-file/VICI correspondence remains an explicit implementation assumption; future policy changes are outside recorded scopes."]
    groups[22]["remaining_construction_work"]=groups[22]["remaining_scopes"]
    groups[13]["remaining_construction_work"]=["Combine checked historical/native structural cuts with complete flow rules and management-service path obligations."]
    groups[31]["remaining_construction_work"]=["Define and justify the source routing-function interpretation and all-interface execution correspondence; finite process names are not an exhaustive implementation semantics."]
    groups[37]["remaining_construction_work"]=["Classify the supplied service/process/socket inventory against all applicable third-party feature duties and prove blocked-or-disabled behavior."]
    groups[43]["remaining_construction_work"]=["Obtain authenticated original-default/change history; the supplied current access flags cannot prove historical changes.","Construct remote-boot disablement semantics and establish optional DNS-lookup objective applicability."]
    partial(25,"Pinned source assigns KEK length from declared 256-bit test CAK and passes that length to aes_wrap. The arithmetic width fact is checked; source/build correspondence and primitive execution correctness remain explicit gaps.",["TDN.Deployments.MKASource.source_derived_test_kek_width"],["wrap","256"])
    partial(28,"Pinned source constants are 6000 ms lifetime and 2000 ms hello. The selected delay flag expression is hello <= 500, so required 2000 ms disables the modeled flag. A generic conditional theorem refutes full RG-028 for any listed component whose CP delay-protection field corresponds to that source flag.",["TDN.Deployments.MKASource.source_timer_constants","TDN.Deployments.MKASource.required_hello_disables_source_delay_flag","TDN.Deployments.MKASource.full_RG028_fails_under_source_flag_correspondence"],["delay","hello","lifetime"])
    groups[28]["disposition_reason"]="The full target remains unproved. Pinned source plus observed 2000 ms hello exposes a delay-flag limitation under explicit source/build/CP correspondence. Replay feasibility and all-data protection remain separate gaps; required hello is unchanged."
    groups[38]["disposition_reason"]="The encompassing IPv4 IPsec header/filter target is checked for one historical baseline and five native profiles, including the selected Outer options objective and modeled multicast exclusion. Inactive fallback interfaces retain explicit checked abstraction conditions; active IPv6/MACsec alternatives remain unproved."
    for group in groups.values():
        group["platform_scope_note"]="Historical Linux static-routing/bridge profiles and five native FRR/OVS profiles remain separately scoped. Supplemental mechanism experiments are independently scoped. Every establishment binds its own snapshot and assumptions."
    ledger=json.loads(source_path("evidence_responses").read_text())
    responses={r["request_id"]:r for r in ledger["requests"] if "request_id" in r}
    for request in requests["requests"]:
        response=responses.get(request["request_id"])
        if response is None:continue
        request["evidence_agent_final_response"]=response
        request["pending_evidence_items"]=response.get("pending",[])
        request["closure_scope"]="Evidence-request disposition only; all mathematical and external obligations remain recorded per group."
        if not response.get("pending"):
            request["status"]="closed_"+response["status"]
        if request["request_id"]=="ER-005":
            request["construction_source_audit_report"]=str(output_path("mka-source-import.json"))
    return register,requests
