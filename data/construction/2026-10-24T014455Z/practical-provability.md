# Practical proof coverage under the revised stopping condition

Every RG practically provable with available evidence and current emulations has at least one meaningful positive partial proof, with a reusable general result and checked concrete evidence.

Actual requirement clauses only. Definitions, context, vacuous checks, negative diagnostics, and unfulfilled conditional results do not count.

A positive partial result does not establish the encompassing RG or all representative cases. Stronger unfinished work is retained separately.

Current classification: meaningful_positive_partial: 53, no_positive_clause_supported_currently: 23.

Stopping is permitted: true. Independent coordinator validation passed; see [final validation](validation/final-partial-coverage.md).

## RG-001: Applicable requirements and policy precedence

**meaningful_positive_partial.** Actual selected Inner endpoints satisfy the required CNSA1 algorithm-choice clause. That concrete technical subclause contributes to the aggregate applicable-guidance duty; aggregate CP/CNSS/local-policy compliance and policy-conflict handling remain unproved.

Clause and scope: p009:u002.s003 technical CNSS algorithm-policy contribution, cross-accounted with the selected CNSA1 Inner IKE configuration.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p008:u007.s005, CSFC-MSC-1.3.0-4e40e3d83708:p009:u002.s003
General proof: TDN.Targets.classical_ike_choices_from_local_checks
Checked application: TDN.Imported.FreshSharedClassicalIKE.every_recorded_inner_ike_offer_uses_cnsa1
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-shared-classical-ike-qualified.json
Next action: No stronger clause is required for the revised stopping threshold.

## RG-002: Validated configuration and component modification

**no_positive_clause_supported_currently.** PS16 and modification statements require an actual NIAP-evaluated configuration and any applicable NIAP maintenance statement. The custom stack has neither; observed local configurations cannot establish the evaluated-reference relation. Advisory consultation text is not a positive requirement proof.

Clause and scope: All selected source clauses reviewed; current authority/product evidence cannot support a positive requirement clause.
Next action: Reopen only if appropriate authoritative records or a source-faithful new evidence basis is supplied.

## RG-003: Product eligibility on the CSfC Components List

**no_positive_clause_supported_currently.** The dated official Components List and actual custom software/product inventory have been compared. No exact deployed eligible product identity is established. The optional unselected IPS implication is excluded from positive counting; product-list negative diagnostics do not count.

Clause and scope: All selected source clauses reviewed; current authority/product evidence cannot support a positive requirement clause.
Next action: Reopen only if appropriate authoritative records or a source-faithful new evidence basis is supplied.

## RG-004: Independent product, operating-system, and cryptographic implementations

**meaningful_positive_partial.** PS7 OS diversity: four actual ND Inner/Outer components have disjoint FreeBSD/Linux families. Manufacturer, library and full applicable-pair diversity remain separately accounted.

Clause and scope: PS7 OS diversity: four actual ND Inner/Outer components have disjoint FreeBSD/Linux families.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p033:u011
General proof: TDN.Targets.os_separation_from_role_family_sets
Checked application: TDN.Imported.FreshOSDiversity.captured_OS_separation_from_family_partition
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-os-diversity-import.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-005: Physical separation of security components

**meaningful_positive_partial.** Physical role-pair separation, PS separation clauses. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: Physical role-pair separation, PS separation clauses.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p034:u003, CSFC-MSC-1.3.0-4e40e3d83708:p034:u004
General proof: TDN.Targets.physical_separation_from_disjoint_role_hardware
Checked application: TDN.Imported.FreshPhysicalPartition.captured_role_pairs_are_physically_distinct
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-physical-partition-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-006: Product Supply Chain Threat Assessment

**no_positive_clause_supported_currently.** Both source duties require a Product Supply Chain Threat Assessment under an AO-approved process for the selected product/application. No authentic assessment, approval or mitigation decision is supplied. Software manifests and build records do not establish those decisions.

Clause and scope: All selected source clauses reviewed; current authority/product evidence cannot support a positive requirement clause.
Next action: Reopen only if appropriate authoritative records or a source-faithful new evidence basis is supplied.

## RG-007: Two independent encryption layers and allowed tunnel pairings

**meaningful_positive_partial.** Ordered Inner and Outer encryption for protected Red payload reaching Black in the selected native model. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: Ordered Inner and Outer encryption for protected Red payload reaching Black in the selected native model.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p010:u007.s001
General proof: TDN.Targets.every_black_byte_has_ordered_encryption_path
Checked application: TDN.Imported.FreshSharedIsolation.every_assembled_black_byte_has_inner_before_outer
Evidence: artifacts/construction/2026-10-24T014455Z/shared-execution-nft-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-008: Connectivity restricted to the same security level

**meaningful_positive_partial.** Plaintext delivery excludes different security-level Red endpoints in the selected native model. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: Plaintext delivery excludes different security-level Red endpoints in the selected native model.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p011:u005.s004
General proof: TDN.Targets.delivered_domain_from_local_checks
Checked application: TDN.Imported.FreshSharedIsolation.snapshot_RG008_full_label_delivery
Evidence: artifacts/construction/2026-10-24T014455Z/shared-execution-nft-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-009: Gray-network control and classification boundary

**no_positive_clause_supported_currently.** Selected passages require Solution Owner/trusted-party physical and logical control and a classification-authority determination. No authentic ownership/control/classification decision is supplied. Adjacent Red packet isolation facts are outside those selected authority clauses and do not count.

Clause and scope: All selected source clauses reviewed; current authority/product evidence cannot support a positive requirement clause.
Next action: Reopen only if appropriate authoritative records or a source-faithful new evidence basis is supplied.

## RG-010: Independently managed site administration and trust

**meaningful_positive_partial.** p14 peer CA provision: each declared logical enterprise A/B site loads the opposite site's layer-specific signing CA. Independent human governance, revocation and complete trust policy remain open. NET023 supplies the selected logical-site interpretation.

Clause and scope: p14 peer CA provision: each declared logical enterprise A/B site loads the opposite site's layer-specific signing CA.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p014:u007.s002
General proof: TDN.Targets.peer_issuers_available_from_loaded_coverage
Checked application: TDN.Imported.FreshRecordedOperations.actual_peer_signing_ca_is_available
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-recorded-operations.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-011: Central management, CA placement, and intersite protection

**meaningful_positive_partial.** Both actual Gray management firewall/encryptors have raw-bound DROP-default FORWARD chains. Existing first-match proof covers that actual traffic subset. INPUT acceptance remains a recorded broader failure.

Clause and scope: Enterprise Gray Table8 EG-FW4/12 forwarded-traffic default-denial portion.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p015:u004.s002
General proof: TDN.Filter.allowed_has_matching_allow
Checked application: TDN.Imported.FreshEnterpriseGrayFilters.selected_forwarding_requires_an_explicit_allow
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-enterprise-gray-filters.json
Next action: No stronger clause is required for the revised stopping threshold.

## RG-012: Separate authentication and management for security levels

**meaningful_positive_partial.** Different security levels have separated credential/authority material and cannot authenticate across levels. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: Different security levels have separated credential/authority material and cannot authenticate across levels.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p016:u002.s008, CSFC-MSC-1.3.0-4e40e3d83708:p016:u004.s002
General proof: TDN.Targets.separate_authentication_and_management_of_scoped_material
Checked application: TDN.Imported.FreshSharedTrust.snapshot_RG012_management_free
Evidence: artifacts/construction/2026-10-24T014455Z/trust-partition-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-013: Gray Firewalls on all paths needing level separation

**meaningful_positive_partial.** SR7: every modeled Gray path between actual different-level Inner gateways crosses a Gray Firewall. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: SR7: every modeled Gray path between actual different-level Inner gateways crosses a Gray Firewall.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p035:u009
General proof: TDN.Paths.no_firewall_free_crossing
Checked application: TDN.Imported.FreshSharedTopology.cross_level_gray_paths_cross_firewall
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-shared-topology.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-014: Gray addressing supports security-level filtering

**meaningful_positive_partial.** Gray address ranges and selected Outer filtering distinguish full security levels. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: Gray address ranges and selected Outer filtering distinguish full security levels.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p017:u006.s002, CSFC-MSC-1.3.0-4e40e3d83708:p023:u010.s002
General proof: TDN.Targets.gray_addressing_of_separated_ranges_and_named_rules
Checked application: TDN.Imported.FreshSharedAddressing.snapshot_RG014_outer_forwarding
Evidence: artifacts/construction/2026-10-24T014455Z/shared-addressing-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-015: MACsec encapsulation and standalone encapsulator obligations

**meaningful_positive_partial.** Selected Inner MACsec carrier clause: the actual path adds L2TP around the existing MACsec body before Outer ESP. Standalone component approval, all carrier alternatives and complete Section11.1 remain separate.

Clause and scope: Selected Inner MACsec carrier clause: the actual path adds L2TP around the existing MACsec body before Outer ESP.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p019:u008.s001, CSFC-MSC-1.3.0-4e40e3d83708:p020:u002.s001, CSFC-MSC-1.3.0-4e40e3d83708:p025:u007.s001
General proof: TDN.Targets.carrier_step_wraps_the_exact_input_body
Checked application: TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0.actual_carrier_precedes_outer_encryption
Evidence: artifacts/construction/2026-10-24T014455Z/bridged-macsec-execution-v8/bridged-Inner-MACsec-Outer-IPsec.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-016: Permitted MACsec clear VLAN tags and XPN

**meaningful_positive_partial.** p20u003.s007 and u004.s004: enabled clear VLAN and XPN features have recorded operational support on all six selected ports. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: p20u003.s007 and u004.s004: enabled clear VLAN and XPN features have recorded operational support on all six selected ports.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p020:u003.s007, CSFC-MSC-1.3.0-4e40e3d83708:p020:u004.s004
General proof: TDN.Targets.macsec_options_of_supported_enablement
Checked application: TDN.Imported.FreshMACsecOptions.selected_options_use_supported_features
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-macsec-options.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-017: Mutual authentication and Non-Person Entity certificates

**meaningful_positive_partial.** Mutual certificate authentication: eight actual shared Inner policies require the peer certificate on both sides. Standard strongSwan verification-before-admission correspondence is explicit; full profiles, authority approval and future configuration changes remain separate.

Clause and scope: Mutual certificate authentication: eight actual shared Inner policies require the peer certificate on both sides.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p020:u006.s001
General proof: TDN.Targets.mutual_certificate_admission_requires_both_verifications
Checked application: TDN.Imported.FreshVPNObservedClauses.admitted_selected_peers_require_mutual_certificate_verification
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-vpn-observed-clauses.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-018: CNSS algorithm-policy requirements and choices

**meaningful_positive_partial.** CNSA1 algorithm choices for every offered IKE suite on eight selected Inner gateways. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: CNSA1 algorithm choices for every offered IKE suite on eight selected Inner gateways.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p009:u003.s003
General proof: TDN.Targets.classical_ike_choices_from_local_checks
Checked application: TDN.Imported.FreshSharedClassicalIKE.every_recorded_inner_ike_offer_uses_cnsa1
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-shared-classical-ike-qualified.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-019: IPsec CNSA profile and post-quantum exchange sequence

**meaningful_positive_partial.** VG1 IKE-offer subclause: every selected Inner offer uses the CNSA1 suite and inspected credentials. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: VG1 IKE-offer subclause: every selected Inner offer uses the CNSA1 suite and inspected credentials.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p038:u006
General proof: TDN.Targets.classical_ike_choices_from_local_checks
Checked application: TDN.Imported.FreshSharedClassicalIKE.every_recorded_inner_ike_offer_uses_cnsa1
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-shared-classical-ike-qualified.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-020: VPN certificate loading and authentication checks

**meaningful_positive_partial.** VG4 device-certificate uniqueness for eight loaded shared Inner endpoint certificates. Endpoint DER identities are checked. Factory-certificate removal, CA anchors and complete lifecycle inventory remain separate.

Clause and scope: VG4 device-certificate uniqueness for eight loaded shared Inner endpoint certificates.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p038:u009
General proof: TDN.Targets.distinct_loaded_certificates_from_fingerprint_inventory
Checked application: TDN.Imported.FreshVPNObservedClauses.loaded_certificates_are_unique_per_device
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-vpn-observed-clauses.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-021: VPN private-key access confinement

**meaningful_positive_partial.** VG5 interface-access subclause: the actual selected administration API cannot return private-key paths. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: VG5 interface-access subclause: the actual selected administration API cannot return private-key paths.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p038:u010
General proof: TDN.AccessControl.absent_path_is_denied
Checked application: TDN.Imported.FreshServiceAuthorization.all_private_key_paths_denied
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-service-authorization-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-022: IKEv2 and IKE/ESP encryption-mode alternatives

**meaningful_positive_partial.** VG9/12/18: complete captured gateway configurations select IKEv2 and IKE/ESP GCM. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: VG9/12/18: complete captured gateway configurations select IKEv2 and IKE/ESP GCM.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p038:u014, CSFC-MSC-1.3.0-4e40e3d83708:p039:u004, CSFC-MSC-1.3.0-4e40e3d83708:p039:u010
General proof: TDN.Targets.vpn_mode_policies_from_complete_local_checks
Checked application: TDN.Imported.FreshSharedVPNModes.complete_loaded_mode_configuration
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-shared-vpn-modes.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-023: VPN SA lifetimes and reauthentication

**meaningful_positive_partial.** VG14 active ESP lifetime: all 20 selected installed states have positive 3600-second hard add lifetimes, below 8 hours. Kernel lifetime enforcement is the implementation contract. IKE hard lifetime and reauthentication/rekey ordering remain separate.

Clause and scope: VG14 active ESP lifetime: all 20 selected installed states have positive 3600-second hard add lifetimes, below 8 hours.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p039:u006
General proof: TDN.Targets.active_esp_age_below_required_maximum
Checked application: TDN.Imported.FreshVPNObservedClauses.every_selected_active_esp_age_is_below_eight_hours
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-vpn-observed-clauses.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-024: MACsec authentication alternatives and AS scope

**meaningful_positive_partial.** The final v18 source/runtime bindings and observed participant creation support the general KeySources invariant. No configured pre-shared entry point is enabled, so every reachable CAK participant originates through the authenticated EAP creation path. AS placement, both-role use and other authentication clauses remain separate.

Clause and scope: p020:u008.s003 authenticated-exchange origin of EAP-derived CAKs.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p020:u008.s003
General proof: TDN.KeySources.executions_have_only_authenticated_sources
Checked application: TDN.Imported.FinalMACsecKeySources.eap_ports_have_no_pre_shared_fallback
Evidence: artifacts/construction/2026-10-24T014455Z/final-macsec-key-sources.json
Next action: No stronger clause is required for the revised stopping threshold.

## RG-025: MACsec encryption and key wrapping algorithms

**meaningful_positive_partial.** MD1/2: AES256 key wrap and MACsec GCM256 on all four final EAP ports. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: MD1/2: AES256 key wrap and MACsec GCM256 on all four final EAP ports.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p041:u006, CSFC-MSC-1.3.0-4e40e3d83708:p041:u007
General proof: TDN.Targets.macsec_algorithms_from_local_checks
Checked application: TDN.Imported.FinalMACsecAlgorithms.selected_runtime_algorithms
Evidence: artifacts/construction/2026-10-24T014455Z/final-macsec-algorithms.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-026: MACsec EAP-TLS CNSA profile alternatives

**meaningful_positive_partial.** Selected EAP objective algorithm fields: actual TLS 1.3 negotiated CNSA 2 suite. Full EAP-TLS RFC/profile conformance and approval remain separate.

Clause and scope: Selected EAP objective algorithm fields: actual TLS 1.3 negotiated CNSA 2 suite.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p042:u013
General proof: TDN.Targets.negotiated_suite_inherits_profile
Checked application: TDN.Imported.FinalMACsecRuntime.observed_eap_choice_inherits_checked_profile
Evidence: artifacts/construction/2026-10-24T014455Z/final-macsec-runtime.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-027: MACsec key generation, key-server selection, and rollover

**meaningful_positive_partial.** MD15: no pre-shared fallback CAK under the selected fresh-process, fixed EAP configurations. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: MD15: no pre-shared fallback CAK under the selected fresh-process, fixed EAP configurations.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p042:u006
General proof: TDN.Targets.eap_key_sources_disable_pre_shared_fallback
Checked application: TDN.Imported.FinalMACsecKeySources.eap_ports_have_no_pre_shared_fallback
Evidence: artifacts/construction/2026-10-24T014455Z/final-macsec-key-sources.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-028: MACsec mandatory protection parameters

**meaningful_positive_partial.** MD10/12/16: controlled-port data emissions are encrypted with zero confidentiality offset. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: MD10/12/16: controlled-port data emissions are encrypted with zero confidentiality offset.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p041:u015, CSFC-MSC-1.3.0-4e40e3d83708:p042:u003, CSFC-MSC-1.3.0-4e40e3d83708:p042:u007
General proof: TDN.LinkProtection.every_emitted_frame_is_encrypted
Checked application: TDN.Imported.FinalMACsecRuntime.every_runtime_data_emission_is_encrypted
Evidence: artifacts/construction/2026-10-24T014455Z/final-macsec-runtime.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-029: Inner encryption and decryption cannot be bypassed

**meaningful_positive_partial.** IR5: arbitrary inbound component traversal requires actual local Inner decryption. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: IR5: arbitrary inbound component traversal requires actual local Inner decryption.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p043:u005
General proof: TDN.Execution.inbound_crossing_requires_local_decryption
Checked application: TDN.Imported.Family444.boundaryIA_no_bypass
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-family444-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-030: Outer encryption and decryption cannot be bypassed

**meaningful_positive_partial.** OR5: arbitrary inbound component traversal requires actual local Outer decryption. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: OR5: arbitrary inbound component traversal requires actual local Outer decryption.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p044:u004
General proof: TDN.Execution.inbound_crossing_requires_local_decryption
Checked application: TDN.Imported.Family444.boundaryOA_no_bypass
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-family444-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-031: Routing and switching limits on Encryption Components

**meaningful_positive_partial.** OR8 no routing protocols: complete selected six-Outer process inventory contains only ordinary sleep and charon. Fixed interval; collector completeness/no relevant skipped reads and ordinary-program behavior are explicit contracts. Future processes remain outside the result.

Clause and scope: OR8 no routing protocols: complete selected six-Outer process inventory contains only ordinary sleep and charon.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p044:u007
General proof: TDN.Targets.outer_routing_protocols_from_process_inventory
Checked application: TDN.Imported.FreshRoutingProcesses.captured_outers_have_no_routing_protocol_service
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-routing-processes.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-032: TRANSEC under the stated deployment conditions

**meaningful_positive_partial.** OR9 selected objective: installed size-cover mechanism preserves padded record sizes and bounded queues under the declared schedule contract. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: OR9 selected objective: installed size-cover mechanism preserves padded record sizes and bounded queues under the declared schedule contract.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p044:u008
General proof: TDN.CoverTraffic.all_executions_have_bounded_queues_and_fixed_records
Checked application: TDN.Imported.FreshTransecCover.all_sender_executions_obey_size_and_capacity
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-transec-cover.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-033: Packet sizing to control fragmentation

**meaningful_positive_partial.** SR23/IR2 sizing subclause: each bounded source datagram fits actual stage-specific interface MTUs. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: SR23/IR2 sizing subclause: each bounded source datagram fits actual stage-specific interface MTUs.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p036:u013, CSFC-MSC-1.3.0-4e40e3d83708:p042:u019
General proof: TDN.Targets.NestedSizing.all_sizes_fit_each_interface
Checked application: TDN.Imported.FreshNestedSizing.every_bounded_red_datagram_fits_each_stage
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-nested-sizing.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-034: Outer Firewall placement for untrusted Black transport

**meaningful_positive_partial.** SR12: actual Outer-to-untrusted-Black paths contain the required Outer Firewall. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: SR12: actual Outer-to-untrusted-Black paths contain the required Outer Firewall.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p036:u002
General proof: TDN.Targets.outer_firewall_placement_from_local_checks
Checked application: TDN.Imported.FreshSharedTopology.snapshot_public_internet_RG034
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-shared-topology.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-035: Permitted protocols and peers at encryption and firewall boundaries

**meaningful_positive_partial.** OR10 local-output subset: both shared Outers allow nonloopback local output only to their actual peer. Forwarded traffic and all interface/protocol clauses remain separately accounted.

Clause and scope: OR10 local-output subset: both shared Outers allow nonloopback local output only to their actual peer.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p044:u009
General proof: TDN.Targets.accepted_nonloopback_output_has_peer_destination
Checked application: TDN.Imported.FreshOuterPeerOutput.every_external_local_output_targets_the_actual_peer
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-clause-role-bindings.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-036: Minimal network-interface exposure

**meaningful_positive_partial.** PF2: 42 actual unused unconfigured GRE-family fallback interfaces are administratively disabled. Other interface classes and PF1 range/port/protocol minimality remain separate.

Clause and scope: PF2: 42 actual unused unconfigured GRE-family fallback interfaces are administratively disabled.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p044:u015
General proof: TDN.Targets.unused_interfaces_disabled_from_empty_active_subset
Checked application: TDN.Imported.FreshUnusedInterfaces.captured_unused_interfaces_are_disabled
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-unused-interfaces.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-037: Outer-component third-party contact restrictions

**meaningful_positive_partial.** PF6 blocking alternative for locally generated Outer contacts to third-party destinations. Both actual peers and complete OUTPUT chains are bound. Forwarded traffic and other clauses remain separate.

Clause and scope: PF6 blocking alternative for locally generated Outer contacts to third-party destinations.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p045:u004
General proof: TDN.Targets.nonpeer_local_output_is_blocked
Checked application: TDN.Imported.FreshOuterPeerOutput.locally_generated_third_party_contacts_are_blocked
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-clause-role-bindings.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-038: IP header and multicast filtering

**meaningful_positive_partial.** PF12: actual pre-defragmentation IPv6 immediate-header gates permit only the four required protocol numbers. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: PF12: actual pre-defragmentation IPv6 immediate-header gates permit only the four required protocol numbers.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p045:u010
General proof: TDN.PacketPolicy.accepted_immediate_header
Checked application: TDN.Imported.FreshFamilyImmediateHeaders.admitted_header_before_defragmentation_is_permitted
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-family666-import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-039: Outer Gray-interface allowlist and default denial

**meaningful_positive_partial.** PF17 selected Outer FORWARD rules admit only named Inner address pairs with the same full security label under INT014. Control/local-management exceptions and all remaining PF clauses remain separate.

Clause and scope: PF17 selected Outer FORWARD rules admit only named Inner address pairs with the same full security label under INT014.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p046:u004
General proof: TDN.Targets.accepted_named_peer_addresses_share_level
Checked application: TDN.Imported.FreshSharedAddressing.outer_accepted_addresses_share_full_level
Evidence: artifacts/construction/2026-10-24T014455Z/shared-addressing-import.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-040: Gray Firewall allowlist and cross-level denial

**meaningful_positive_partial.** PF32 both shared Gray Firewalls reject packets between known Inner addresses belonging to different full security labels. Actual same-level ESP forwarding is also checked. All other interface/filter duties remain separate.

Clause and scope: PF32 both shared Gray Firewalls reject packets between known Inner addresses belonging to different full security labels.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p047:u009
General proof: TDN.Targets.different_level_addresses_are_denied
Checked application: TDN.Imported.FreshSharedAddressing.gray_firewall_rejects_cross_level_addresses
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-clause-role-bindings.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-041: Control-plane approval, defaults, and service location

**meaningful_positive_partial.** Inner control-service placement: actual selected time source is attached to the same Red bridge as the Inner's Red interface. Raw bridge and guest-MAC bindings are checked; trust, other services and future attachment changes remain separate.

Clause and scope: Inner control-service placement: actual selected time source is attached to the same Red bridge as the Inner's Red interface.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p035:u003
General proof: TDN.Targets.service_location_from_shared_bridge
Checked application: TDN.Imported.FreshRedTimePlacement.actual_time_source_is_on_selected_red_network
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-red-time-placement.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-042: Layer-specific trusted time synchronization

**meaningful_positive_partial.** SR3 Red time-source location subclause for the selected Inner clock correction. Cross-accounted with RG041 location. Source trust, continuous synchronization and Gray Management placement remain open.

Clause and scope: SR3 Red time-source location subclause for the selected Inner clock correction.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p035:u005
General proof: TDN.Targets.service_location_from_shared_bridge
Checked application: TDN.Imported.FreshRedTimePlacement.actual_time_source_is_on_selected_red_network
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-red-time-placement.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-043: Default credentials, DNS, and remote bootstrap

**meaningful_positive_partial.** SR19 selected DNS-disablement objective: conventional DNS egress is denied under actual Linux and FreeBSD policies. The listed application discharges the local checks from the named retained evidence. The enclosing specification and additional cases remain in the stronger-work register.

Clause and scope: SR19 selected DNS-disablement objective: conventional DNS egress is denied under actual Linux and FreeBSD policies.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p036:u009
General proof: TDN.Targets.dns_egress_disabled_of_deny_prefix
Checked application: TDN.Imported.FreshDNSHardening.every_new_conventional_dns_request_is_denied
Evidence: artifacts/construction/2026-10-24T014455Z/dns_hardening_import.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-044: Layer-specific administration and management-plane separation

**meaningful_positive_partial.** DM17 configured AW assignments: ten actual component assignments do not share an AW across Inner/Outer layers. Physical zone separation, all AW duties and future assignment changes remain separate.

Clause and scope: DM17 configured AW assignments: ten actual component assignments do not share an AW across Inner/Outer layers.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p049:u005
General proof: TDN.RecordedOperations.administrative_assignments_do_not_share_layers
Checked application: TDN.Imported.FreshRecordedOperations.assigned_workstations_do_not_cross_layers
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-recorded-operations.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-045: Dedicated, protected, hardened Administrative Workstations

**meaningful_positive_partial.** DM27 actual four-state AW guest use/power history finishes unused and powered off. Use windows are declared experiment intervals; named process termination is observed. Physical workstation and all future idle periods remain separate.

Clause and scope: DM27 actual four-state AW guest use/power history finishes unused and powered off.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p049:u015
General proof: TDN.RecordedOperations.power_trace_keeps_unused_guest_off
Checked application: TDN.Imported.FreshRecordedOperations.final_guest_is_off
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-recorded-operations.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-046: Management transport protection and local exceptions

**meaningful_positive_partial.** p030:u007.s004–s005 permitted management transport: 14 recorded management sessions negotiate TLS 1.3. Complete cipher/profile requirements, every management interface and human authorization remain separate.

Clause and scope: p030:u007.s004–s005 permitted management transport: 14 recorded management sessions negotiate TLS 1.3.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s004, CSFC-MSC-1.3.0-4e40e3d83708:p030:u007.s005
General proof: TDN.RecordedOperations.recognized_tls_is_allowed
Checked application: TDN.Imported.FreshRecordedOperations.observed_management_uses_allowed_protocol
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-recorded-operations.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-047: Administrator authentication and individual credentials

**meaningful_positive_partial.** Existing admitted-operation certificate authentication general theorem and imported service session checks. Existing selected positive contribution meets the revised partial-proof threshold.

Clause and scope: DM9 service request authentication: each of ten successful retained operations has a source-bound authenticated session.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p048:u008
General proof: TDN.Targets.administrator_authentication_from_admitted_operations
Checked application: TDN.Imported.FreshAdministratorSessions.recorded_service_authentication
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-administrator-sessions.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-048: Authorized provisioning and initial certificate requests

**meaningful_positive_partial.** Certificate request/sign/load sequence: four actual CSR/sign/mount/load chains include loaded signer/root objects. Component-owned key and CSR generation is not established; the retained worker-generation finding remains. Physical authorization and human appointments remain open.

Clause and scope: Certificate request/sign/load sequence: four actual CSR/sign/mount/load chains include loaded signer/root objects.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s003, CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s004, CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s005, CSFC-MSC-1.3.0-4e40e3d83708:p029:u011.s007
General proof: TDN.RecordedOperations.issued_credential_follows_request
Checked application: TDN.Imported.FreshRecordedOperations.loaded_credentials_follow_signed_requests
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-recorded-operations.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-049: Personnel clearance and Outer administration

**no_positive_clause_supported_currently.** No authentic personnel clearance/approval records. A network observation cannot establish a person's clearance.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-050: SIEM placement, collection, alerting, and log transport

**no_positive_clause_supported_currently.** Retained supplemental SIEM code merely receives and prints synthetic Gray-producer messages. It lacks actual named Inner/Outer/Gray-Firewall event-to-SIEM binding and configured analysis/alerts. Audit offload is not automatically SIEM. Do not count incidental AW clauses as SIEM coverage.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-051: Cross Domain Solution approval conditions

**no_positive_clause_supported_currently.** Software CDS relay is unapproved. Required CDS approval/registration/authority records are absent; unselected branch would be vacuous.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-052: Physical protection, authorized access, and disposal

**no_positive_clause_supported_currently.** Physical classified-facility protection/access and secure disposal evidence absent. Host UUID/container isolation does not prove those properties.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-053: Parallel Inner components and distinct Outer internal interfaces

**meaningful_positive_partial.** SR16 parallel-placement structural subset: each of eight shared Inners has a Gray path to its Outer without traversing another Inner. Shared Gray may admit other walks. Physical NIC separation and complete hardware placement remain open.

Clause and scope: SR16 parallel-placement structural subset: each of eight shared Inners has a Gray path to its Outer without traversing another Inner.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p036:u006
General proof: TDN.Targets.independent_inner_branch_from_chain
Checked application: TDN.Imported.FreshSharedTopology.every_inner_has_an_independent_outer_branch
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-placement-clauses.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-054: Interoperable components across communicating sites

**meaningful_positive_partial.** Peer interoperability: actual forward and reverse useful bridged MACsec/L2TP/ESP paths deliver restored opaque Ethernet headers. Selected path and mechanism implementation contracts apply. All product/case interoperability remains separate.

Clause and scope: Peer interoperability: actual forward and reverse useful bridged MACsec/L2TP/ESP paths deliver restored opaque Ethernet headers.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p035:u004
General proof: TDN.Targets.successful_ethernet_peer_restores_header
Checked application: TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0.actual_peer_restores_original_ethernet
Evidence: artifacts/construction/2026-10-24T014455Z/bridged-macsec-execution-v8/bridged-Inner-MACsec-Outer-IPsec.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-055: Firewall requirements when combining capability packages

**no_positive_clause_supported_currently.** Combined-Gray demonstration does not identify an actual selected other CP and its applicable mandatory firewall clauses. Unselected implication would be vacuous.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-056: Approved physical paths out of Red Networks

**meaningful_positive_partial.** SR14 structural egress protection: every observed virtual path from eight Red hosts to outside Red crosses an Inner. Physical cable/NIC boundary and approved complete MSC protection remain separate.

Clause and scope: SR14 structural egress protection: every observed virtual path from eight Red hosts to outside Red crosses an Inner.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p036:u004
General proof: TDN.Targets.red_egress_crosses_inner_from_attachment_cut
Checked application: TDN.Imported.FreshSharedTopology.every_virtual_red_egress_crosses_inner
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-placement-clauses.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-057: Operational security updates and TEMPEST policy

**no_positive_clause_supported_currently.** No actual security-patch test/install lifecycle, authority-selected update schedule or TEMPEST policy. Version strings alone are insufficient.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-058: Hardware inventory and available baseline configuration

**meaningful_positive_partial.** GD26 selected configuration availability: an authenticated Auditor receives the saved diagnostic filter configuration fragment. The fragment is not the whole maintained device baseline; organization, maintenance and all devices remain open.

Clause and scope: GD26 selected configuration availability: an authenticated Auditor receives the saved diagnostic filter configuration fragment.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p052:u008
General proof: TDN.RecordedOperations.successful_readback_makes_settings_available
Checked application: TDN.Imported.FreshRecordedOperations.auditor_obtained_configuration
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-recorded-operations.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-059: Procurement documentation excludes classified-protection purpose

**no_positive_clause_supported_currently.** No actual procurement or contracting requirement records.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-060: Annual and NSA-authorized compliance audits

**no_positive_clause_supported_currently.** No actual annual audit or NSA access/notification records; lab tests are not an annual compliance audit.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-061: Registration, approval, annual renewal, and version updates

**no_positive_clause_supported_currently.** No actual NSA registration/AO approval or approved risk acceptance.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-062: Audit retention, storage monitoring, backup, and continuity

**meaningful_positive_partial.** Existing checked contiguous audit export and restart persistence. No annual retention or quarterly review claim. Existing selected positive contribution meets the revised partial-proof threshold.

Clause and scope: GD15 technical copy coverage: every byte of a frozen audit source is copied through contiguous committed batches.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p051:u010
General proof: TDN.Targets.complete_audit_copy_from_contiguous_batches
Checked application: TDN.Imported.FreshAuditOffload.all_recorded_source_positions_copied
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-audit-offload.json
Next action: Final combined proof-body dependency audit and coordinator source review; stronger obligations remain recorded separately.

## RG-063: Infrastructure authentication alternatives

**no_positive_clause_supported_currently.** Actual infrastructure-device authentication/password-generation entropy/domain-authentication records absent. Outer role-admin TLS service does not establish authentication for infrastructure routers/switches.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-064: Incident triggers, required report fields, and reporting deadline

**no_positive_clause_supported_currently.** No actual reportable incident/JIMS/NSA delivery records; synthetic incident formats do not establish reporting.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-065: Separation of administrative and auditing personnel

**no_positive_clause_supported_currently.** Certificate role map does not establish different actual people. Docker default AppArmor does not encode SecurityAdministrator/Auditor mandatory-access-control roles. No selected implemented RB11 policy evidence.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-066: Personnel training and physical tamper inspections

**no_positive_clause_supported_currently.** No actual training, appointment or physical inspection records.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-067: Revocation or CAK destruction before disposal

**no_positive_clause_supported_currently.** Revocation tests exist, but no actual device-disposal event and before-disposal credential-removal ordering. Do not relabel ordinary revocation as disposal.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-068: Security Administrator operational duties

**meaningful_positive_partial.** Security Administrator monitoring: actual role-authorized diagnostic configuration readback. Human appointment and comprehensive ongoing administrative duties remain open.

Clause and scope: Security Administrator monitoring: actual role-authorized diagnostic configuration readback.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p054:u007.s001
General proof: TDN.RecordedOperations.successful_readback_makes_settings_available
Checked application: TDN.Imported.FreshRecordedOperations.administrator_obtained_configuration
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-recorded-operations.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-069: Auditor review duties and access boundary

**meaningful_positive_partial.** The authenticated Auditor successfully rotates the actual ND_O_A1 service log. All eight earlier readback records are preserved as an exact prefix of the captured archives and active log. Complete canonical event objects, client responses, runtime role/source/listener identity and archive contents are checked. The reconstructed pre-rotation active file is explicitly distinguished from the earlier independent readback. Human review, incident reporting, full component access restrictions and all future audit duties remain open.

Clause and scope: p054:u014.s001: the actual Auditor log-management operation preserves all eight independently retrieved earlier audit entries through rotation and later append-only activity.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p054:u014.s001
General proof: TDN.Targets.observed_audit_prefix_survives_rotation
Checked application: TDN.Imported.FreshAuditorRotation.actual_auditor_rotation_preserves_observed_log
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-auditor-rotation.json, artifacts/construction/2026-10-24T014455Z/evidence/derived-auditor-rotation-v1/rotation.json
Next action: No additional construction is needed for the revised partial-proof threshold. Final combined validation and coordinator acceptance remain required.

## RG-070: Optional Integrator involvement and duty scope

**no_positive_clause_supported_currently.** No actual Integrator engagement/credential/contract records; unselected optional Integrator is vacuous.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-071: AO authorization evidence and lifecycle control

**no_positive_clause_supported_currently.** No actual approving-authority lifecycle/acceptance records.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-072: Whole-solution testing and preserved results

**meaningful_positive_partial.** Selected test-result retention: all 12 declared native management network probe results have retained raw records. Testing Annex equivalence, complete test planning and authority submission remain open.

Clause and scope: Selected test-result retention: all 12 declared native management network probe results have retained raw records.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p057:u010
General proof: TDN.RecordedOperations.retained_table_covers_selected_tests
Checked application: TDN.Imported.FreshRecordedOperations.selected_network_test_results_are_retained
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-recorded-operations.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-073: Objective software and firmware signing algorithms

**no_positive_clause_supported_currently.** ML-DSA87 demonstration signs a Twinet deployment utility outside Solution Component software inventory. No selected Firewall/VPN/AS executable/firmware is bound to that signed artifact. Existing theorem remains a diagnostic/example, not counted positive RG coverage.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

## RG-074: Redundant component and load-balancing permission

**meaningful_positive_partial.** Redundant components retain applicable CP placement: four actual redundant Outers have mandatory firewall-separated paths to selected Black transport. No automatic failover or whole-component compliance claim. The source permission alone is not counted.

Clause and scope: Redundant components retain applicable CP placement: four actual redundant Outers have mandatory firewall-separated paths to selected Black transport.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p021:u007.s004
General proof: TDN.Paths.no_firewall_free_crossing
Checked application: TDN.Imported.FreshRedundantPlacement.redundant_outers_preserve_required_firewall_cut
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-placement-clauses.json
Next action: No additional construction is needed for this partial result. Final combined validation and coordinator review are required before stopping.

## RG-075: Optional additional controls and screening-router scope

**no_positive_clause_supported_currently.** The selected p022:u007 text explicitly places no configuration or security requirements on the added components. The p026:u010 screening-router text permits placement and classifies the router as part of Black, outside MSC. The existing concrete placement theorem is useful architectural accounting, but it does not discharge a security requirement clause under the revised counting rule.

Clause and scope: p022:u007.s001–s002 and p026:u010.s001–s006 are optional design/context and boundary classification. No source-faithful positive security obligation has been identified for counting.
Selected original source passages: CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s002, CSFC-MSC-1.3.0-4e40e3d83708:p026:u010.s006
Evidence: artifacts/construction/2026-10-24T014455Z/fresh-optional-screening.json
Next action: Retain the architectural theorem; reopen eligibility only if an actual applicable requirement clause is identified with supporting evidence.

## RG-076: CP user legal undertaking and disclaimer

**no_positive_clause_supported_currently.** No actual party acceptance of legal terms; document text alone cannot establish acceptance.

Clause and scope: All selected source clauses reviewed; no positive clause supported by the current setup and retained evidence.
Next action: No new proof required by the revised stopping condition unless additional authoritative evidence or a relevant selected deployment changes the classification.

