"""Refresh declaration locations and explicitly scoped current-run results without claiming convergence."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re

RUN = Path(os.environ["TDN_OUTPUT_DIR"])
GENERAL = {
    "RG-001": ["TDN.Targets.cp_local_resolution_preserves_precedence"],
    "RG-004": ["TDN.Targets.shared_os_refutes_diversity"],
    "RG-005": ["TDN.Targets.physical_separation_from_disjoint_role_hardware"],
    "RG-007": ["TDN.Targets.nested_layers_from_operational_invariant",
               "TDN.Targets.protected_red_stack_from_local_checks",
               "TDN.Targets.protected_black_execution_has_two_encryptions"],
    "RG-008": ["TDN.Targets.security_connectivity_from_delivery_and_peer_checks",
               "TDN.Targets.delivered_domain_from_local_checks"],
    "RG-012": ["TDN.Targets.separate_authentication_and_management_of_scoped_material"],
    "RG-013": ["TDN.Targets.gray_firewall_paths_from_local_separation"],
    "RG-014": ["TDN.Targets.gray_addressing_of_separated_ranges_and_named_rules"],
    "RG-015": ["TDN.Targets.encapsulation_preserves_macsec_body"],
    "RG-021": ["TDN.AccessControl.absent_path_is_denied"],
    "RG-023": ["TDN.Targets.rekey_discipline_from_admitted_events"],
    "RG-033": ["TDN.Targets.packet_sizes_fit_from_budget"],
    "RG-035": ["TDN.Targets.boundary_filtering_from_rule_checks"],
    "RG-039": ["TDN.Targets.outer_gray_policy_from_local_rules"],
    "RG-040": ["TDN.Targets.gray_firewall_policy_from_local_rules"],
    "RG-041": ["TDN.Targets.control_normalizer_disables_unapproved"],
    "RG-044": ["TDN.Targets.workstation_zone_check_excludes_cross_layer"],
    "RG-045": ["TDN.Targets.non_aw_workload_refutes_host_dedication"],
    "RG-046": ["TDN.Targets.endpoint_range_is_minimal"],
    "RG-047": ["TDN.Targets.administrator_authentication_from_admitted_operations"],
    "RG-048": ["TDN.Targets.installed_certificate_has_key_generation"],
    "RG-049": ["TDN.Targets.solution_clearance_covers_site"],
    "RG-050": ["TDN.Targets.generated_siem_rules_cover_required_events"],
    "RG-051": ["TDN.Targets.no_selected_cds_excludes_cds_obligations"],
    "RG-057": ["TDN.Targets.every_admitted_patch_was_tested"],
    "RG-058": ["TDN.Targets.generated_baselines_cover_components"],
    "RG-060": ["TDN.Targets.generated_audits_cover_annual_windows"],
    "RG-062": ["TDN.Targets.retention_from_enforced_deletion_guard"],
    "RG-064": ["TDN.Targets.incident_reporting_from_generated_reports"],
    "RG-068": ["TDN.Targets.generated_administration_matrix_covers"],
    "RG-069": ["TDN.Targets.generated_reviews_cover_actions_and_events",
               "TDN.AccessControl.role_permission_restricts_operations"],
    "RG-070": ["TDN.Targets.integrator_permissions_allow_listed_and_additional"],
    "RG-071": ["TDN.Targets.revocation_matrix_covers_all_components"],
    "RG-072": ["TDN.Targets.generated_test_plan_covers_obligations"]
}
APPLICATIONS = {
    "RG-004": [("FreshOSDiversity", "captured_OS_families_differ", "Observed OS-family clause for the four ND encryption components"),
               ("FreshOSDiversity", "observed_IKE_provider_names_differ", "Observed IKE provider names; manufacturer independence remains separate")],
    "RG-005": [("FreshPhysicalPartition", "captured_role_pairs_are_physically_distinct", "Captured four-worker security-role partition")],
    "RG-007": [(name, "snapshot_RG007_IPv4_ESP_packet_stack", "All modeled Red-to-Black payload executions for the fixed native IPv4/ESP case")
               for name in ["FreshSharedExecution", "FreshBaselineExecution"]],
    "RG-008": [(name, "snapshot_RG008_full_label_delivery", "All modeled plaintext delivery preserves the complete declared security label")
               for name in ["FreshSharedIsolation", "FreshBaselineIsolation"]],
    "RG-012": [(name, "snapshot_RG012_management_free", "Certificate material separation and peer exclusion with management unselected")
               for name in ["FreshSharedTrust", "FreshBaselineTrust"]],
    "RG-021": [("FreshServiceAuthorization", "all_private_key_paths_denied", "Private-key path denial for the recorded API only")],
    "RG-069": [("FreshServiceAuthorization", "every_accepted_auditor_request_is_within_scope", "Every authorized API request under an Auditor certificate binding")]
}


GENERAL["RG-007"] += ["TDN.Targets.protected_black_execution_applies_layers_in_order",
                       "TDN.Targets.every_black_fragment_has_both_layers"]
GENERAL["RG-028"] = ["TDN.Targets.macsec_protection_from_local_checks",
                     "TDN.LinkProtection.every_emitted_frame_is_encrypted",
                     "TDN.SequenceFreshness.accepted_transmission_is_recent"]
GENERAL["RG-029"] = ["TDN.Targets.inner_tunnel_requirements_from_local_checks",
                     "TDN.Execution.inbound_crossing_requires_local_decryption"]
GENERAL["RG-030"] = ["TDN.Targets.outer_tunnel_requirements_from_local_checks",
                     "TDN.Execution.inbound_crossing_requires_local_decryption"]
GENERAL["RG-034"] = ["TDN.Targets.outer_firewall_placement_from_local_checks"]
GENERAL["RG-043"] = ["TDN.Targets.dns_egress_disabled_of_deny_prefix",
    "TDN.StatefulFilter.empty_cache_preserved",
    "TDN.Targets.StatefulDNS.enabled_egress_denies_local_dns"]
APPLICATIONS["RG-028"] = [("FreshMACsecRuntime", "every_runtime_data_emission_is_encrypted",
    "Universal local controlled-port data protection; other MD clauses remain separate")]
APPLICATIONS["RG-038"] = [("FreshFamilyImmediateHeaders", "admitted_header_before_defragmentation_is_permitted",
    "Literal immediate IPv6 Next Header at 64 captured early hooks; kernel hook-order contract explicit")]
APPLICATIONS["RG-043"] = [("FreshDNSHardening", "every_new_conventional_dns_request_is_denied",
    "Seven selected Linux devices; conventional IPv4/IPv6 DNS transport; arbitrary later OUTPUT policy")]
APPLICATIONS["RG-043"] += [("FreshFreeBSDDNS", "guest" + str(i) + "_enabled_egress_dns_denial",
    "Actual FreeBSD guest: complete rule/state/scrub/translation/interface flags; every fixed-configuration history") for i in range(2)]
for family in ["444", "446", "464", "466", "644", "646", "664", "666"]:
    APPLICATIONS["RG-007"].append(("FreshFamily" + family, "snapshot_IPv4_IPv6_ESP_packet_stack",
        "Universal family-tagged packet-stack clause for supplemental family " + family, "Family" + family))
    for group, devices in [("RG-029", ["IA", "IB"]), ("RG-030", ["OA", "OB"])]:
        for device in devices:
            APPLICATIONS.setdefault(group, []).append(("FreshFamilyTunnelBoundaries",
                "boundary" + device + "_no_bypass",
                "Device-local traversal; arbitrary inbound envelopes, empty initial authentication; actual local layer decryption",
                "Family" + family))

GENERAL["RG-007"] += ["TDN.MultiProtocolExecution.all_executions_preserve_stack",
                     "TDN.Targets.mixed_nested_layers_from_local_checks"]
for pairing in ["IpsecIpsecIntegrated", "IpsecMacsecIntegrated", "MacsecIpsecIntegrated",
                "MacsecIpsecStandalone", "MacsecMacsecIntegrated", "MacsecMacsecStandalone"]:
    APPLICATIONS["RG-007"].append(("FreshPairingStackChecks",
        "every_red_origin_transmission_has_gray_or_black_protection",
        "All modeled data executions in repaired pairings v7; opaque Ethernet source supported, routed fixtures have no positive non-IP path; both useful directions now have checked model executions and actual positive controls",
        "Pairing" + pairing))
    if pairing != "IpsecIpsecIntegrated":
        APPLICATIONS["RG-028"].append(("FreshPairingConfigs",
            "every_configured_mac_port_emits_full_encryption",
            "Every configured controlled-port data emission; authentication and time/freshness clauses remain separate",
            "Pairing" + pairing))
    APPLICATIONS["RG-007"].append(("FreshPairingStackChecks",
        "actual_inner_encryption_precedes_outer",
        "Actual payload-specific Inner encryption precedes Outer encryption in every Black-reaching execution",
        "Pairing" + pairing))
    for direction in ["Forward", "Reverse"]:
        APPLICATIONS["RG-007"].append(("FreshPairing" + pairing + direction,
            "positive_mixed_delivery", "Checked useful execution with actual positive bridge-filter checks",
            "Pairing" + pairing + "." + direction))

GENERAL["RG-007"] += ["TDN.MultiProtocolExecution.nested_stack_requires_ordered_encryptions",
    "TDN.Targets.mixed_black_transmission_has_ordered_encryptions"]
GENERAL["RG-015"] += ["TDN.MultiProtocolExecution.all_executions_preserve_original_ethernet"]
GENERAL["RG-029"] += ["TDN.MultiProtocolExecution.boundary_removal_has_actual_decryption"]
GENERAL["RG-030"] += ["TDN.MultiProtocolExecution.boundary_removal_has_actual_decryption"]
GENERAL["RG-061"] = ["TDN.Targets.version_deadlines_of_earlier_limit"]
GENERAL["RG-062"] += ["TDN.Targets.audit_retention_spec_implies_current_presence"]
for declaration in ["every_red_origin_transmission_has_gray_or_black_protection",
                    "actual_inner_encryption_precedes_outer"]:
    APPLICATIONS["RG-007"].append(("FreshBridgedMACsecChecks", declaration,
        "Bridged opaque Ethernet with protected VLAN fields; fixed observed MACsec/L2TP/ESP configuration",
        "PairingInnerMacsecOuterIpsec"))
for direction in ["Forward", "Reverse"]:
    for count in range(3):
        label = direction + "VLAN" + str(count)
        APPLICATIONS["RG-007"].append(("FreshPairingInnerMacsecOuterIpsec" + label,
            "positive_mixed_delivery", "Actual opaque Ethernet path with " + str(count) + " protected VLAN tags",
            "PairingInnerMacsecOuterIpsec." + label))

GENERAL["RG-033"].append("TDN.Targets.packet_sizes_fit_from_monotone_encoding")
GENERAL["RG-036"] = ["TDN.Targets.minimal_exposure_from_necessary_permissions"]
APPLICATIONS["RG-014"] = [(name, "snapshot_RG014_outer_forwarding",
    "Complete selected Gray ranges and raw Outer forwarding-rule correspondence under the documented interpretation")
    for name in ["FreshSharedAddressing", "FreshBaselineAddressing"]]
APPLICATIONS["RG-033"] = [("FreshPMTU", "every_datagram_within_discovered_limit_fits",
    "Observed 1326-byte IPv6 socket limit and 1400-byte Black bottleneck; exact ESP padding contract")]


GENERAL["RG-007"] += ["TDN.Targets.native_packet_stack_with_kernel_response_guards",
    "TDN.SourceResponseGuards.finite_reply_checks_preserve_layers",
    "TDN.Execution.execution_preserves_authentication_selectors",
    "TDN.ReassemblyOrigins.every_reassembly_history_preserves_byte_safety"]
for ns in ["FreshSharedExecution", "FreshBaselineExecution"]:
    APPLICATIONS["RG-007"].append(("FreshNativeResponseGuards",
        "packet_stack_survives_gateway_echo_and_error_generation",
        "Native Inner/Outer OUTPUT confinement with kernel echo/error generation before or after local filter hooks", ns))
APPLICATIONS["RG-007"] += [
    ("FreshFamily444V13", "snapshot_IPv4_IPv6_ESP_packet_stack",
     "Retained v13 family444 ordinary packet execution with exact typed local ICMP guards", "Family444V13"),
    ("FreshFamily444V13Witness", "positive_delivery_execution",
     "Thirty-nine-step useful packet execution; every gateway ingress also passes its actual early source guard", "Family444V13"),
    ("FreshFamily444V13ResponseGuards", "source_output_reply_layers",
     "Local source/output response confinement from exact intervals, all interfaces and authenticated inbound selectors; full response execution composition remains active", "Family444V13")]


GENERAL["RG-022"] = ["TDN.Targets.vpn_mode_policies_from_complete_local_checks"]
APPLICATIONS["RG-022"] = [(namespace, "complete_loaded_mode_configuration",
    "Complete loaded IKEv2 and IKE/ESP GCM objective configuration for every inventoried gateway; fixed load/runtime interval")
    for namespace in ["FreshBaselineVPNModes", "FreshSharedVPNModes"]]
APPLICATIONS["RG-007"].append(("FreshFamily444V13ResponseExecution", "gateway_response_executions_keep_stack",
    "All guarded executions with pre-encryption gateway echo/error generation; copied-prefix and hook-order contracts explicit; post-encryption error connection remains active", "Family444V13"))


GENERAL["RG-025"] = ["TDN.Targets.macsec_algorithms_from_local_checks"]
APPLICATIONS["RG-025"] = [("FinalMACsecAlgorithms", "selected_runtime_algorithms",
    "All four final v18 software MACsec ports; reviewed source/binary binding and primitive implementation contract")]
APPLICATIONS["RG-026"] = [("FinalMACsecAlgorithms", "twelve_public_vectors_match",
    "Twelve public Annex G outputs only; complete EAP profile conformance remains separate")]
APPLICATIONS["RG-028"] += [("FinalMACsecRuntime", "every_runtime_data_emission_is_encrypted",
    "Final v18 four-port local transmit semantics with exact runtime settings")]

APPLICATIONS["RG-034"] = [(name, "snapshot_public_internet_RG034",
    "Complete current native topology under the explicitly selected untrusted Public Internet scenario")
    for name in ["FreshBaselineTopology", "FreshSharedTopology"]]


GENERAL["RG-075"] = ["TDN.Targets.additional_controls_from_black_screening_placement"]


for group, components in [("RG-029", ["IA", "IB"]), ("RG-030", ["OA", "OB"])]:
    GENERAL[group] += ["TDN.Targets.mixed_tunnel_boundary_from_local_checks",
                      "TDN.MultiProtocolExecution.inbound_crossing_has_actual_boundary_decryption"]
    for namespace in ["PairingIpsecIpsecIntegrated", "PairingIpsecMacsecIntegrated",
                      "PairingMacsecIpsecIntegrated", "PairingMacsecIpsecStandalone",
                      "PairingMacsecMacsecIntegrated", "PairingMacsecMacsecStandalone",
                      "PairingInnerMacsecOuterIpsec"]:
        for component in components:
            for suffix, scope in [
                ("no_bypass", "Arbitrary inbound body requires an actual receiving decryption at the component; outbound protection inherits the surrounding payload invariant"),
                ("positive_inbound", "Checked useful inward execution through the actual selected component"),
                ("nonempty_attachments", "Observed inside and outside attachment inventories are nonempty")]:
                APPLICATIONS.setdefault(group, []).append(("FreshMixedTunnelBoundaries",
                    "mixedBoundary" + component + "_" + suffix, scope, namespace))

APPLICATIONS["RG-047"] = [("FreshAdministratorSessions", "recorded_service_authentication",
    "Ten successful retained service requests, with source-derived TLS authentication and per-request session witnesses; human ownership, AW accounts, other paths and future executions remain unproved")]

APPLICATIONS["RG-075"] = [("FreshOptionalScreening", "selected_optional_control_placement",
    "Two actual existing Black screening routers; complete observed attachments, selected declared MSC component boundary; added bridge case remains distinct")]

GENERAL["RG-007"] += ["TDN.EncryptedResponseGuards.encrypted_error_cannot_leave_component",
                      "TDN.EncryptedResponseGuards.combined_executions_preserve_stack"]
APPLICATIONS["RG-007"] += [("FreshEncryptedResponseGuards",
    "gateway_pre_and_post_encryption_responses_keep_stack",
    "Retained family444-v13 pre-encryption processing and locally encrypted gateway error quotes; copied-byte, kernel hook and remaining host/transport scope explicit",
    "Family444V13"), ("FreshEncryptedResponseGuards",
    "useful_delivery_in_combined_response_system",
    "Existing 39-step guarded delivery remains admitted after adding the post-encryption response cases",
    "Family444V13")]

GENERAL["RG-007"] += ["TDN.UniformResponseRegions.all_component_response_executions_preserve_stack",
                      "TDN.HistoricalResponses.all_historical_responses_preserve_safety"]
APPLICATIONS["RG-007"] += [("FreshUniformResponses", name, scope, "Family444V13")
    for name, scope in [
        ("all_component_copied_responses_keep_stack", "All eight retained family444-v13 device owners are covered by checked gateway or uniform-region reply conditions"),
        ("all_retained_packet_responses_keep_stack", "Delayed replies may use any saved safe packet processing context under the fixed configuration"),
        ("useful_delivery_with_retained_packet_contexts", "The useful 39-step path remains admitted with historical response contexts"),
        ("response_component_inventory_complete", "Every observed port owner has a checked response treatment")]]

GENERAL["RG-032"] = ["TDN.Targets.transec_conditions_from_cover_installations",
                     "TDN.CoverTraffic.all_executions_have_bounded_queues_and_fixed_records",
                     "TDN.CoverTraffic.equal_schedule_gives_equal_size_observations"]
APPLICATIONS["RG-032"] = [("FreshTransecCover", name, scope) for name, scope in [
    ("selected_cover_enablement", "Two recorded Outer MACsec objective endpoints; selected bounded size-masking interpretation, Public Internet unselected"),
    ("all_sender_executions_obey_size_and_capacity", "Every finite sender execution preserves queue capacity and padded record size; supplied schedules and implementation contract explicit"),
    ("recorded_attemptsOA", "All retained OA attempts including send errors; only observed finite size, depth and lag bounds"),
    ("recorded_attemptsOB", "All retained OB attempts; only observed finite size, depth and lag bounds")]]


GENERAL["RG-042"] = ["TDN.Targets.trusted_time_from_component_assignments",
                     "TDN.Targets.all_checked_clock_corrections_improve_offset"]
APPLICATIONS["RG-042"] = [("FreshClockCorrections", "each_observed_correction_reduces_offset",
    "Four actual guest corrections in two separate experiments; measured offsets only, with source trust, Gray Management placement and continuing synchronization unfulfilled"),
    ("FreshClockCorrections", "complete_selected_clock_inventory",
    "Complete two-client inventory in each selected correction experiment; not the whole SR3/SR4 component inventory")]
APPLICATIONS["RG-028"] += [("FinalMACsecProtection", "selected_protection_configuration",
    "All four final v18 controlled ports: enabled delay algorithm/callback, normal and bounded timers, zero replay window, full local encryption and must-secure; physical timing and lower-interface bypass scope remains explicit"),
    ("FinalMACsecProtection", "runtime_inventory_nonempty", "Four actual final v18 ports across both EAP role arrangements")]
APPLICATIONS["RG-026"] += [("FinalMACsecRuntime", "negotiated_suite_cnsa2",
    "Actual final EAP negotiated ML-KEM1024, ML-DSA87, AES256-GCM and SHA384 algorithm fields; full TLS/EAP profile conformance remains separate")]
APPLICATIONS["RG-018"] = [("FinalMACsecRuntime", "observed_algorithms_satisfy_cnsa_choice",
    "The selected final EAP negotiated algorithm suite satisfies the CNSA2 algorithm predicate; no component approval claim")]


GENERAL["RG-008"] += ["TDN.Targets.same_domain_delivery_with_strict_gateway_responses",
    "TDN.Targets.received_domain_from_local_checks",
    "TDN.Targets.reassembled_delivery_domain_from_checked_reception"]
for namespace in ["FreshSharedIsolation", "FreshBaselineIsolation"]:
    APPLICATIONS["RG-008"] += [
        ("FreshNativeResponseIsolation", "gateway_response_delivery_preserves_full_label",
         "Native strict gateway OUTPUT checks preserve full-label isolation with arbitrary gateway echo/error generation; other generators retain separate scope", namespace),
        ("FreshReassembledDomains", "snapshot_received_domain",
         "Actual source-port domain checks exclude wrong-domain plaintext reception before endpoint reassembly", namespace),
        ("FreshReassembledDomains", "reassembled_bytes_have_recipient_full_label",
         "Arbitrary mixed-packet fragment buffer histories preserve byte domains under explicit received-piece path correspondence; backend connection remains separately reviewed", namespace)]
GENERAL["RG-027"] = ["TDN.Targets.checked_key_server_is_central",
    "TDN.Targets.macsec_key_requirements_from_separate_checks"]
APPLICATIONS["RG-027"] = [("FinalMACsecKeyServers", name, scope) for name, scope in [
    ("local_settings", "Reported minimum CKN lengths and configured 0/1 priorities for both final EAP role arrangements; CKN bytes redacted"),
    ("configured_server_matches_central_site", "Lower-priority configured choice matches the source-declared central site; no distributed election convergence claim"),
    ("both_arrangements_present", "Both distinct role arrangements have complete two-peer settings")]]


GENERAL["RG-007"] += ["TDN.Targets.assembled_packet_at_black_keeps_each_byte_protected"]
GENERAL["RG-008"] += ["TDN.Targets.assembled_packet_delivery_preserves_each_byte_domain",
    "TDN.ByteFlows.all_executions_preserve_byte_properties"]
for namespace in ["FreshSharedIsolation", "FreshBaselineIsolation"]:
    APPLICATIONS["RG-007"].append(("FreshByteDomains", "every_assembled_black_byte_has_both_layers",
        "Arbitrary simultaneous source-byte histories with repeated partitioning and intermediate plaintext assembly; encrypted assembly/backend correspondence explicit", namespace))
    APPLICATIONS["RG-008"].append(("FreshByteDomains", "every_assembled_delivered_byte_preserves_full_label",
        "Every delivered byte after mixed-packet plaintext assembly retains its actual Red source label; further forwarding is included", namespace))
GENERAL["RG-027"] += ["TDN.Targets.eap_key_sources_disable_pre_shared_fallback"]
APPLICATIONS["RG-027"] += [("FinalMACsecKeySources", "eap_ports_have_no_pre_shared_fallback",
    "All reachable participant origins in the four final fresh-process fixed EAP configurations; selected MD15 interpretation permits authenticated renewal")]


GENERAL["RG-062"] += ["TDN.Targets.complete_audit_copy_from_contiguous_batches",
    "TDN.Targets.observed_restart_preserves_audit_copy"]
APPLICATIONS["RG-062"] = [("FreshAuditOffload", name, scope) for name, scope in [
    ("all_recorded_source_positions_copied", "Every position in one frozen 136,535-byte source copy is covered by three contiguous committed journal ranges"),
    ("observed_service_restart_keeps_copy", "The same complete range coverage survives one observed collector process restart; frequency, retention period and power failures remain separate")]]


GENERAL["RG-007"] += ["TDN.Targets.bytes_with_plaintext_assembly_and_gateway_responses_keep_domains"]
GENERAL["RG-008"] += ["TDN.Targets.bytes_with_plaintext_assembly_and_gateway_responses_keep_domains"]
for namespace in ["FreshSharedIsolation", "FreshBaselineIsolation"]:
    APPLICATIONS["RG-007"].append(("FreshByteResponses", "assembled_gateway_response_black_bytes_keep_both_layers",
        "Combined simultaneous byte flows, repeated plaintext assembly and strict gateway response generation preserve both Black layers", namespace))
    APPLICATIONS["RG-008"].append(("FreshByteResponses", "assembled_gateway_response_delivery_keeps_full_labels",
        "Combined simultaneous byte flows, repeated plaintext assembly and strict gateway response generation preserve each delivered byte label", namespace))


GENERAL["RG-048"] += ["TDN.Targets.installed_certificate_has_component_key_generation",
    "TDN.Targets.worker_generation_cannot_supply_component_request"]
APPLICATIONS["RG-048"] = [("FreshProvisioningLocations", name, scope) for name, scope in [
    ("generation_request_signing_order", "Two retained worker commands have source-bound key/CSR/signing order and paths; no per-stage key fingerprint is invented"),
    ("recorded_worker_generation_does_not_admit_component_request", "The actual worker executor cannot discharge the required component-owned key/CSR generation premise")]]


GENERAL["RG-007"] += ["TDN.Targets.bytes_with_plaintext_assembly_and_component_responses_keep_domains"]
GENERAL["RG-008"] += ["TDN.Targets.bytes_with_plaintext_assembly_and_component_responses_keep_domains"]
for namespace in ["FreshSharedIsolation", "FreshBaselineIsolation"]:
    APPLICATIONS["RG-007"].append(("FreshComponentByteResponses", "assembled_component_response_black_bytes_keep_both_layers",
        "All retained component owners, saved copied-byte contexts and plaintext assembly; protection provenance is preserved for permitted host and transport responses", namespace))
    APPLICATIONS["RG-008"].append(("FreshComponentByteResponses", "assembled_component_response_delivery_keeps_full_labels",
        "Every delivered byte retains its full source label with all retained component response classes and plaintext assembly", namespace))


for group in ["RG-007", "RG-029", "RG-030"]:
    GENERAL[group] += ["TDN.Targets.every_black_byte_has_ordered_encryption_path"]
    for namespace in ["FreshSharedIsolation", "FreshBaselineIsolation"]:
        APPLICATIONS[group].append(("FreshByteLayerOrder", "every_assembled_black_byte_has_inner_before_outer",
            "Each source byte has an individual modeled path with actual Inner encryption before actual Outer encryption, including copying, plaintext assembly and all native component responses", namespace))


GENERAL.setdefault("RG-011", []).extend(["TDN.Targets.EnterpriseGray.source_filtering_from_rule_checks",
    "TDN.Targets.EnterpriseGray.management_ingress_from_rule_checks"])
APPLICATIONS.setdefault("RG-011", []).extend([("FreshEnterpriseGrayFilters", name, scope) for name, scope in [
    ("selected_forwarding_requires_an_explicit_allow", "Four raw-bound selected IPv4 FORWARD chains require explicit first-match permission; no whole-annex claim"),
    ("captured_local_input_accepts_every_packet", "Four selected IPv4 INPUT chains are empty ACCEPT; recorded enforcement gap, not a live whole-kernel counterexample")]])

for group in ["RG-007", "RG-008", "RG-029", "RG-030"]:
    GENERAL[group] += ["TDN.FragmentHeaders.allow_only_rules_cover_noninitial_fragments"]
    for namespace in ["FreshSharedIsolation", "FreshBaselineIsolation"]:
        for hook in ["input", "forward", "output"]:
            APPLICATIONS[group].append(("FreshFragmentHeaders",
                "noninitial_" + hook + "_accepted_by_header_completion",
                "All native explicit rules allow; accepted noninitial IPv4 fragment filtering is covered without reading absent transport fields", namespace))

GENERAL.setdefault("RG-073", []).extend(["TDN.Targets.software_signature_choice_from_artifact_checks"])
APPLICATIONS.setdefault("RG-073", []).extend([("FreshSoftwareSignatures", "recorded_executable_has_table2_signature_choice",
    "Recorded deployment utility uses Table 2 ML-DSA-87; outside a complete Solution Component software/firmware inventory")])


for group in ["RG-018", "RG-019"]:
    GENERAL.setdefault(group, []).extend([
        "TDN.Targets.classical_ike_choices_from_local_checks",
        "TDN.Targets.negotiated_classical_ike_from_checked_offers"])
    for namespace in ["FreshBaselineClassicalIKE", "FreshSharedClassicalIKE"]:
        APPLICATIONS.setdefault(group, []).append((namespace,
            "every_recorded_inner_ike_offer_uses_cnsa1",
            "Complete captured Inner IKE offers and P-384/SHA384 credentials; cross-capture identifier collision/replacement and unchanged association assumptions are explicit; Outer and whole-profile duties remain separate"))


for group in ["RG-007", "RG-029", "RG-030"]:
    GENERAL.setdefault(group, []).append("TDN.Targets.every_mixed_black_byte_has_ordered_encryptions")
    for namespace in ["PairingIpsecIpsecIntegrated", "PairingIpsecMacsecIntegrated",
                      "PairingMacsecIpsecIntegrated", "PairingMacsecIpsecStandalone",
                      "PairingMacsecMacsecIntegrated", "PairingMacsecMacsecStandalone",
                      "PairingInnerMacsecOuterIpsec"]:
        APPLICATIONS.setdefault(group, []).append(("FreshMixedByteProtection",
            "every_mixed_black_byte_has_actual_layer_order",
            "Each byte has actual ordered Inner/Outer encryption after concurrent flows, copying, splitting and plaintext assembly; seven accepted configurations, including opaque Ethernet; encrypted assembly and local responses remain separately scoped",
            namespace))

GENERAL.setdefault("RG-033", []).append("TDN.Targets.NestedSizing.all_sizes_fit_each_interface")
APPLICATIONS.setdefault("RG-033", []).append(("FreshNestedSizing",
    "every_bounded_red_datagram_fits_each_stage",
    "Selected fourteen-port two-ESP geometry with distinct Red/Gray/Black lengths; source-limit enforcement, path coverage and minimal padding remain explicit"))

GENERAL.setdefault("RG-016", []).append("TDN.Targets.macsec_options_of_supported_enablement")
APPLICATIONS.setdefault("RG-016", []).append(("FreshMACsecOptions",
    "selected_options_use_supported_features",
    "Six software MACsec ports with observed operational XPN and zero/one/two clear VLAN choices; standard implementation correspondence and other protection duties explicit"))

for group in ["RG-007", "RG-008"]:
    GENERAL.setdefault(group, []).extend([
        "TDN.Execution.recovered_content_follows_checked_transit",
        "TDN.AuthenticatedAssembly.accepted_messages_from_seeded_history"])
for group in ["RG-007", "RG-008", "RG-017"]:
    APPLICATIONS.setdefault(group, []).append(("FreshSharedIKEContexts",
        "recorded_directional_contexts_agree",
        "Ten shared gateway public IKE/CHILD records, reciprocal role/PFS/SPI and raw SAD/SPD bindings; real key derivation and complete producer/history contracts remain explicit"))


GENERAL.setdefault("RG-004", []).append("TDN.Targets.os_separation_from_role_family_sets")
APPLICATIONS.setdefault("RG-004", []).append(("FreshPositiveClauseBridges",
    "captured_OS_separation_from_family_partition",
    "Four actual ND components; disjoint observed OS-family sets, with complete role binding",
    "FreshOSDiversity"))
GENERAL.setdefault("RG-026", []).append("TDN.Targets.negotiated_suite_inherits_profile")
APPLICATIONS.setdefault("RG-026", []).append(("FreshPositiveClauseBridges",
    "observed_eap_choice_inherits_checked_profile",
    "The actual final negotiated EAP suite satisfies the selected CNSA2 algorithm fields; complete profile conformance remains separate",
    "FinalMACsecRuntime"))
GENERAL.setdefault("RG-013", []).append("TDN.Paths.no_firewall_free_crossing")
APPLICATIONS.setdefault("RG-013", []).append(("FreshSharedTopology",
    "cross_level_gray_paths_cross_firewall",
    "Fresh complete shared Gray topology; all different-level Inner-to-Inner paths cross a Gray Firewall"))
GENERAL.setdefault("RG-038", []).append("TDN.PacketPolicy.accepted_immediate_header")
GENERAL.setdefault("RG-039", []).append("TDN.Targets.accepted_named_peer_addresses_share_level")
APPLICATIONS.setdefault("RG-039", []).append(("FreshGrayAddressClauses",
    "outer_accepted_addresses_share_full_level",
    "PF17 actual Outer FORWARD chains and unique full-level Gray addresses; selected data-path scope",
    "FreshSharedAddressing"))
GENERAL.setdefault("RG-040", []).append("TDN.Targets.different_level_addresses_are_denied")
APPLICATIONS.setdefault("RG-040", []).append(("FreshGrayAddressClauses",
    "gray_firewall_rejects_cross_level_addresses",
    "PF32 both actual shared Gray Firewalls reject known Inner endpoint addresses from different full levels",
    "FreshSharedAddressing"))
GENERAL.setdefault("RG-031", []).append("TDN.Targets.outer_routing_protocols_from_process_inventory")
APPLICATIONS.setdefault("RG-031", []).append(("FreshRoutingProcesses",
    "captured_outers_have_no_routing_protocol_service",
    "Six actual Outer process inventories under explicit collector completeness and ordinary-program correspondence; fixed interval only"))

def main():
    register_path = RUN / "theorem_register.json"
    register = json.loads(register_path.read_text())
    declarations = {}
    for path in Path("TDN").rglob("*.lean"):
        content = path.read_text()
        namespaces = []
        for line, text in enumerate(content.splitlines(), 1):
            opened = re.match(r"^namespace\s+([A-Za-z0-9_.]+)", text)
            if opened:
                namespaces.append(opened[1])
            if re.match(r"^end(?:\s|$)", text) and namespaces:
                namespaces.pop()
            match = re.match(r"^(def|theorem|lemma|tdn_data)\s+([A-Za-z0-9_]+)", text)
            if match:
                declarations.setdefault(match[2], []).append({
                    "kind": "def" if match[1] == "tdn_data" else match[1], "path": str(path), "line": line,
                    "qualified_name": ".".join(namespaces + [match[2]]),
                    "source_sha256": hashlib.sha256(content.encode()).hexdigest()})
    practical_mappings = RUN / "practical-new-declaration-mappings.json"
    if practical_mappings.exists():
        for row in json.loads(practical_mappings.read_text()):
            generals = GENERAL.setdefault(row["group_id"], [])
            if row["general"] not in generals:
                generals.append(row["general"])
            application = (row["module"], row["name"], row["scope"], row["namespace"])
            applications = APPLICATIONS.setdefault(row["group_id"], [])
            if application not in applications:
                applications.append(application)
    practical_review = RUN / "practical-provability-review.json"
    if practical_review.exists():
        for gid, row in json.loads(practical_review.read_text()).items():
            if row.get("classification") != "meaningful_positive_partial":
                continue
            generals = GENERAL.setdefault(gid, [])
            if row["general"] not in generals:
                generals.append(row["general"])
            name = row["application"].rsplit(".", 1)[1]
            matches = [entry for entry in declarations.get(name, [])
                       if entry["qualified_name"] == row["application"]]
            if len(matches) != 1:
                raise ValueError("Missing practical application declaration: " + row["application"])
            namespace = row["application"].removeprefix("TDN.Imported.").rsplit(".", 1)[0]
            application = (Path(matches[0]["path"]).stem, name, row["clause"], namespace)
            applications = APPLICATIONS.setdefault(gid, [])
            if not any(item[0] == application[0] and item[1] == name and
                       (item[3] if len(item) > 3 else item[0]) == namespace for item in applications):
                applications.append(application)
    inventory = []
    for group in register["groups"]:
        target = group["top_level_target"]
        locations = declarations.get(target, [])
        if len(locations) != 1:
            raise ValueError("Missing or ambiguous target declaration: " + target)
        general = []
        for name in GENERAL.get(group["group_id"], []):
            candidates = declarations.get(name.rsplit(".", 1)[1], [])
            if not candidates:
                raise ValueError("Missing mapped proof: " + name)
            general.append({"name": name, "locations": candidates,
                            "scope": "General or supporting clause result; whole-group coverage requires separate reconciliation"})
        applications = []
        for application in APPLICATIONS.get(group["group_id"], []):
            namespace, name, scope = application[:3]
            actual_namespace = application[3] if len(application) > 3 else namespace
            full_name = "TDN.Imported." + actual_namespace + "." + name
            expected = "TDN/Evidence/" + namespace + ".lean"
            location = [row for row in declarations.get(name, []) if row["path"] == expected and row["qualified_name"] == full_name]
            if len(location) != 1:
                raise ValueError("Missing mapped application: " + namespace + "." + name)
            applications.append({"name": full_name,
                                 "location": location[0], "scope": scope,
                                 "whole_group_claim": bool(group.get("established") and group.get("completion_certificate", {}).get("application", {}).get("lean_proof") == full_name)})
        current = {
            "specification": {"name": "TDN.Targets." + target, "location": locations[0]},
            "general_and_supporting_results": general, "checked_applications": applications,
            "source_passages_accounted": len(group["source_passages"]),
            "whole_group_reconciliation": "established_in_explicit_selected_configuration" if group.get("established") else "in_progress",
            "active_work_queue": str(RUN / "WORK_QUEUE.md")
        }
        group["current_development"] = current
        group["formal_definition"] = "TDN.Targets." + target
        if general and not group.get("general_theorem"):
            group["general_theorem"] = general[0]["name"]
            group["general_theorem_scope"] = general[0]["scope"]
        group["checked_applications"] = applications
        group["formalization_status"] = ("specification_proved_in_explicit_selected_configuration" if group.get("established") else "specification_present_source_review_and_proof_coverage_in_progress")
        inventory.append({"group_id": group["group_id"], **current})
    register["updated_at"] = datetime.now(timezone.utc).isoformat()
    register["current_development_summary"] = {
        "specifications_present": len(inventory),
        "source_passages": sum(row["source_passages_accounted"] for row in inventory),
        "completion_claim": False,
        "note": "All 76 specifications are present. Source passages include context and recommendations. General theorem and application coverage remains under active clause-level reconciliation."
    }
    register_path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n")
    (RUN / "current_declaration_map.json").write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(register["current_development_summary"]))


if __name__ == "__main__":
    main()
