"""Record the source-reviewed positive partial applications for the revised stopping goal."""
import hashlib
import json
import os
from pathlib import Path

RUN = Path(os.environ.get("TDN_OUTPUT_DIR", "data/construction/2026-10-24T014455Z"))
P = "TDN.Targets."
I = "TDN.Imported."
ROWS = [
(4,"ComponentAttributes","os_separation_from_role_family_sets","FreshPositiveClauseBridges","FreshOSDiversity.captured_OS_separation_from_family_partition","fresh-os-diversity-import.json","PS7 OS diversity: four actual ND Inner/Outer components have disjoint FreeBSD/Linux families.","Manufacturer, library and full applicable-pair diversity remain separately accounted."),
(10,"PeerInteroperability","peer_issuers_available_from_loaded_coverage","FreshPeerInteroperability","FreshRecordedOperations.actual_peer_signing_ca_is_available","fresh-recorded-operations.json","p14 peer CA provision: each declared logical enterprise A/B site loads the opposite site's layer-specific signing CA.","Independent human governance, revocation and complete trust policy remain open. NET023 supplies the selected logical-site interpretation."),
(15,"CarrierClauses","carrier_step_wraps_the_exact_input_body","FreshCarrierClauses","PairingInnerMacsecOuterIpsec.ForwardVLAN0.actual_carrier_precedes_outer_encryption","bridged-macsec-execution-v8/bridged-Inner-MACsec-Outer-IPsec.json","Selected Inner MACsec carrier clause: the actual path adds L2TP around the existing MACsec body before Outer ESP.","Standalone component approval, all carrier alternatives and complete Section11.1 remain separate."),
(17,"VPNObservedClauses","mutual_certificate_admission_requires_both_verifications","FreshVPNObservedClauses","FreshVPNObservedClauses.admitted_selected_peers_require_mutual_certificate_verification","fresh-vpn-observed-clauses.json","Mutual certificate authentication: eight actual shared Inner policies require the peer certificate on both sides.","Standard strongSwan verification-before-admission correspondence is explicit; full profiles, authority approval and future configuration changes remain separate."),
(20,"VPNObservedClauses","distinct_loaded_certificates_from_fingerprint_inventory","FreshVPNObservedClauses","FreshVPNObservedClauses.loaded_certificates_are_unique_per_device","fresh-vpn-observed-clauses.json","VG4 device-certificate uniqueness for eight loaded shared Inner endpoint certificates.","Endpoint DER identities are checked. Factory-certificate removal, CA anchors and complete lifecycle inventory remain separate."),
(23,"VPNObservedClauses","active_esp_age_below_required_maximum","FreshVPNObservedClauses","FreshVPNObservedClauses.every_selected_active_esp_age_is_below_eight_hours","fresh-vpn-observed-clauses.json","VG14 active ESP lifetime: all 20 selected installed states have positive 3600-second hard add lifetimes, below 8 hours.","Kernel lifetime enforcement is the implementation contract. IKE hard lifetime and reauthentication/rekey ordering remain separate."),
(26,"Cryptography","negotiated_suite_inherits_profile","FreshPositiveClauseBridges","FinalMACsecRuntime.observed_eap_choice_inherits_checked_profile","final-macsec-runtime.json","Selected EAP objective algorithm fields: actual TLS 1.3 negotiated CNSA 2 suite.","Full EAP-TLS RFC/profile conformance and approval remain separate."),
(31,"RoutingProcesses","outer_routing_protocols_from_process_inventory","FreshRoutingProcesses","FreshRoutingProcesses.captured_outers_have_no_routing_protocol_service","fresh-routing-processes.json","OR8 no routing protocols: complete selected six-Outer process inventory contains only ordinary sleep and charon.","Fixed interval; collector completeness/no relevant skipped reads and ordinary-program behavior are explicit contracts. Future processes remain outside the result."),
(35,"PeerOutput","accepted_nonloopback_output_has_peer_destination","FreshOuterPeerOutput","FreshOuterPeerOutput.every_external_local_output_targets_the_actual_peer","fresh-clause-role-bindings.json","OR10 local-output subset: both shared Outers allow nonloopback local output only to their actual peer.","Forwarded traffic and all interface/protocol clauses remain separately accounted."),
(36,"InterfaceDisablement","unused_interfaces_disabled_from_empty_active_subset","FreshUnusedInterfaces","FreshUnusedInterfaces.captured_unused_interfaces_are_disabled","fresh-unused-interfaces.json","PF2: 42 actual unused unconfigured GRE-family fallback interfaces are administratively disabled.","Other interface classes and PF1 range/port/protocol minimality remain separate."),
(37,"PeerOutput","nonpeer_local_output_is_blocked","FreshOuterPeerOutput","FreshOuterPeerOutput.locally_generated_third_party_contacts_are_blocked","fresh-clause-role-bindings.json","PF6 blocking alternative for locally generated Outer contacts to third-party destinations.","Both actual peers and complete OUTPUT chains are bound. Forwarded traffic and other clauses remain separate."),
(39,"GrayAddressClauses","accepted_named_peer_addresses_share_level","FreshGrayAddressClauses","FreshSharedAddressing.outer_accepted_addresses_share_full_level","shared-addressing-import.json","PF17 selected Outer FORWARD rules admit only named Inner address pairs with the same full security label under INT014.","Control/local-management exceptions and all remaining PF clauses remain separate."),
(40,"GrayAddressClauses","different_level_addresses_are_denied","FreshGrayAddressClauses","FreshSharedAddressing.gray_firewall_rejects_cross_level_addresses","fresh-clause-role-bindings.json","PF32 both shared Gray Firewalls reject packets between known Inner addresses belonging to different full security labels.","Actual same-level ESP forwarding is also checked. All other interface/filter duties remain separate."),
(41,"ServicePlacement","service_location_from_shared_bridge","FreshRedTimePlacement","FreshRedTimePlacement.actual_time_source_is_on_selected_red_network","fresh-red-time-placement.json","Inner control-service placement: actual selected time source is attached to the same Red bridge as the Inner's Red interface.","Raw bridge and guest-MAC bindings are checked; trust, other services and future attachment changes remain separate."),
(42,"ServicePlacement","service_location_from_shared_bridge","FreshRedTimePlacement","FreshRedTimePlacement.actual_time_source_is_on_selected_red_network","fresh-red-time-placement.json","SR3 Red time-source location subclause for the selected Inner clock correction.","Cross-accounted with RG041 location. Source trust, continuous synchronization and Gray Management placement remain open."),
(44,"RecordedOperations","administrative_assignments_do_not_share_layers","FreshRecordedOperations","FreshRecordedOperations.assigned_workstations_do_not_cross_layers","fresh-recorded-operations.json","DM17 configured AW assignments: ten actual component assignments do not share an AW across Inner/Outer layers.","Physical zone separation, all AW duties and future assignment changes remain separate."),
(45,"RecordedOperations","power_trace_keeps_unused_guest_off","FreshRecordedOperations","FreshRecordedOperations.final_guest_is_off","fresh-recorded-operations.json","DM27 actual four-state AW guest use/power history finishes unused and powered off.","Use windows are declared experiment intervals; named process termination is observed. Physical workstation and all future idle periods remain separate."),
(46,"RecordedOperations","recognized_tls_is_allowed","FreshRecordedOperations","FreshRecordedOperations.observed_management_uses_allowed_protocol","fresh-recorded-operations.json","p030:u007.s004–s005 permitted management transport: 14 recorded management sessions negotiate TLS 1.3.","Complete cipher/profile requirements, every management interface and human authorization remain separate."),
(48,"RecordedOperations","issued_credential_follows_request","FreshRecordedOperations","FreshRecordedOperations.loaded_credentials_follow_signed_requests","fresh-recorded-operations.json","Certificate request/sign/load sequence: four actual CSR/sign/mount/load chains include loaded signer/root objects.","Component-owned key and CSR generation is not established; the retained worker-generation finding remains. Physical authorization and human appointments remain open."),
(53,"PlacementClauses","independent_inner_branch_from_chain","FreshPlacementClauses","FreshSharedTopology.every_inner_has_an_independent_outer_branch","fresh-placement-clauses.json","SR16 parallel-placement structural subset: each of eight shared Inners has a Gray path to its Outer without traversing another Inner.","Shared Gray may admit other walks. Physical NIC separation and complete hardware placement remain open."),
(54,"PeerInteroperability","successful_ethernet_peer_restores_header","FreshPeerInteroperability","PairingInnerMacsecOuterIpsec.ForwardVLAN0.actual_peer_restores_original_ethernet","bridged-macsec-execution-v8/bridged-Inner-MACsec-Outer-IPsec.json","Peer interoperability: actual forward and reverse useful bridged MACsec/L2TP/ESP paths deliver restored opaque Ethernet headers.","Selected path and mechanism implementation contracts apply. All product/case interoperability remains separate."),
(56,"PlacementClauses","red_egress_crosses_inner_from_attachment_cut","FreshPlacementClauses","FreshSharedTopology.every_virtual_red_egress_crosses_inner","fresh-placement-clauses.json","SR14 structural egress protection: every observed virtual path from eight Red hosts to outside Red crosses an Inner.","Physical cable/NIC boundary and approved complete MSC protection remain separate."),
(58,"RecordedOperations","successful_readback_makes_settings_available","FreshRecordedOperations","FreshRecordedOperations.auditor_obtained_configuration","fresh-recorded-operations.json","GD26 selected configuration availability: an authenticated Auditor receives the saved diagnostic filter configuration fragment.","The fragment is not the whole maintained device baseline; organization, maintenance and all devices remain open."),
(68,"RecordedOperations","successful_readback_makes_settings_available","FreshRecordedOperations","FreshRecordedOperations.administrator_obtained_configuration","fresh-recorded-operations.json","Security Administrator monitoring: actual role-authorized diagnostic configuration readback.","Human appointment and comprehensive ongoing administrative duties remain open."),
(72,"RecordedOperations","retained_table_covers_selected_tests","FreshRecordedOperations","FreshRecordedOperations.selected_network_test_results_are_retained","fresh-recorded-operations.json","Selected test-result retention: all 12 declared native management network probe results have retained raw records.","Testing Annex equivalence, complete test planning and authority submission remain open."),
(74,"Paths","no_firewall_free_crossing","FreshPlacementClauses","FreshRedundantPlacement.redundant_outers_preserve_required_firewall_cut","fresh-placement-clauses.json","Redundant components retain applicable CP placement: four actual redundant Outers have mandatory firewall-separated paths to selected Black transport.","No automatic failover or whole-component compliance claim. The source permission alone is not counted.")
]


def main():
    path = RUN / "practical-provability-review.json"
    prior = path.read_bytes()
    (RUN / "assessment-revisions" / (hashlib.sha256(prior).hexdigest()+"-"+path.name)).write_bytes(prior)
    review = json.loads(prior)
    for number, module, general, evidence_module, application, report, clause, gaps in ROWS:
        gid = f"RG-{number:03}"
        prefix = "TDN.RecordedOperations." if module == "RecordedOperations" else "TDN.Paths." if module == "Paths" else P
        review[gid].update(classification="meaningful_positive_partial", review_complete=True,
            general=prefix+general, application=I+application,
            evidence=[str(RUN/report)], clause=clause, reason=clause+" "+gaps,
            stronger_scope_limitations=gaps,
            next_action="No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.")
    for row in review.values():
        if row["classification"] == "meaningful_positive_partial":
            if "being rechecked" in row["reason"]:
                row["reason"] = row["clause"] + " The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register."
            if "Verify exact" in row.get("next_action",""):
                row["next_action"] = "Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately."
    path.write_text(json.dumps(review,indent=2)+"\n")
    mappings = []
    for number, module, general, evidence_module, application, report, clause, gaps in ROWS:
        gid=f"RG-{number:03}"
        namespace, name = application.rsplit(".",1)
        mappings.append({"group_id":gid, "general":review[gid]["general"],
                         "module":evidence_module, "namespace":namespace, "name":name, "scope":clause+" "+gaps})
    (RUN/"practical-new-declaration-mappings.json").write_text(json.dumps(mappings,indent=2)+"\n")


if __name__ == "__main__":
    main()
