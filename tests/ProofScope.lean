import TDN

/- Every retained RG mapping resolves in the active theory. Multiple groups may share a result. -/

/- RG-007 -/
#check TDN.Targets.every_black_byte_has_ordered_encryption_path
#check TDN.Imported.FreshSharedIsolation.every_assembled_black_byte_has_inner_before_outer

/- RG-008 -/
#check TDN.Targets.delivered_domain_from_local_checks
#check TDN.Imported.FreshSharedIsolation.snapshot_RG008_full_label_delivery

/- RG-012 -/
#check TDN.Targets.separate_authentication_and_management_of_scoped_material
#check TDN.Imported.FreshSharedTrust.snapshot_RG012_management_free

/- RG-013 -/
#check TDN.Paths.no_firewall_free_crossing
#check TDN.Imported.FreshSharedTopology.cross_level_gray_paths_cross_firewall

/- RG-014 -/
#check TDN.Targets.gray_addressing_of_separated_ranges_and_named_rules
#check TDN.Imported.FreshSharedAddressing.snapshot_RG014_outer_forwarding

/- RG-015 -/
#check TDN.Targets.carrier_step_wraps_the_exact_input_body
#check TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0.actual_carrier_precedes_outer_encryption

/- RG-021 -/
#check TDN.AccessControl.absent_path_is_denied
#check TDN.Imported.FreshServiceAuthorization.all_private_key_paths_denied

/- RG-024 -/
#check TDN.KeySources.executions_have_only_authenticated_sources
#check TDN.Imported.FinalMACsecKeySources.eap_ports_have_no_pre_shared_fallback

/- RG-027 -/
#check TDN.Targets.eap_key_sources_disable_pre_shared_fallback
#check TDN.Imported.FinalMACsecKeySources.eap_ports_have_no_pre_shared_fallback

/- RG-028 -/
#check TDN.LinkProtection.every_emitted_frame_is_encrypted
#check TDN.Imported.FinalMACsecRuntime.every_runtime_data_emission_is_encrypted

/- RG-029 -/
#check TDN.Execution.inbound_crossing_requires_local_decryption
#check TDN.Imported.Family444.boundaryIA_no_bypass

/- RG-030 -/
#check TDN.Execution.inbound_crossing_requires_local_decryption
#check TDN.Imported.Family444.boundaryOA_no_bypass

/- RG-032 -/
#check TDN.CoverTraffic.all_executions_have_bounded_queues_and_fixed_records
#check TDN.Imported.FreshTransecCover.all_sender_executions_obey_size_and_capacity

/- RG-033 -/
#check TDN.Targets.NestedSizing.all_sizes_fit_each_interface
#check TDN.Imported.FreshNestedSizing.every_bounded_red_datagram_fits_each_stage

/- RG-034 -/
#check TDN.Targets.outer_firewall_placement_from_local_checks
#check TDN.Imported.FreshSharedTopology.snapshot_public_internet_RG034

/- RG-035 -/
#check TDN.Targets.accepted_nonloopback_output_has_peer_destination
#check TDN.Imported.FreshOuterPeerOutput.every_external_local_output_targets_the_actual_peer

/- RG-037 -/
#check TDN.Targets.nonpeer_local_output_is_blocked
#check TDN.Imported.FreshOuterPeerOutput.locally_generated_third_party_contacts_are_blocked

/- RG-038 -/
#check TDN.PacketPolicy.accepted_immediate_header
#check TDN.Imported.FreshFamilyImmediateHeaders.admitted_header_before_defragmentation_is_permitted

/- RG-039 -/
#check TDN.Targets.accepted_named_peer_addresses_share_level
#check TDN.Imported.FreshSharedAddressing.outer_accepted_addresses_share_full_level

/- RG-040 -/
#check TDN.Targets.different_level_addresses_are_denied
#check TDN.Imported.FreshSharedAddressing.gray_firewall_rejects_cross_level_addresses

/- RG-047 -/
#check TDN.Targets.administrator_authentication_from_admitted_operations
#check TDN.Imported.FreshAdministratorSessions.recorded_service_authentication

/- RG-054 -/
#check TDN.Targets.successful_ethernet_peer_restores_header
#check TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0.actual_peer_restores_original_ethernet

/- RG-056 -/
#check TDN.Targets.red_egress_crosses_inner_from_attachment_cut
#check TDN.Imported.FreshSharedTopology.every_virtual_red_egress_crosses_inner

/- RG-074 -/
#check TDN.Paths.no_firewall_free_crossing
#check TDN.Imported.FreshRedundantPlacement.redundant_outers_preserve_required_firewall_cut
