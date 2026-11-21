import TDN.Deployments.SecurityLevelConnectivity_SharedFlows
import TDN.Deployments.RedConnectivityInventory

namespace TDN.Deployments.SecurityLevelConnectivity_Shared
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding
  OuterTunnelNoBypass_Shared MtuSizing_Records SecurityLevelConnectivity NestedProtection

set_option maxRecDepth 1000000

load_network_records capture : ConnectivityCapture from "../../data/evidence/securityLevelConnectivity/Shared.json" ["capture"]

lemma roster_and_assignments_cover_capture : capture.MatchesEndpoints devices redNetworks entries := by
  unfold ConnectivityCapture.MatchesEndpoints
  native_decide

lemma standalone_roster : capture.roster.referencedConformingSolutions = [] := by native_decide

lemma all_ike_and_child_bindings_checked : capture.MatchesPeerSessions authentication
    installedChildren authenticated installed (records.tunnels.map associatedIPTunnelView) := by
  unfold ConnectivityCapture.MatchesPeerSessions PublicAuthenticationBinding.Check CertificateAuthoritySetting.Check
  native_decide

lemma configured_network_demands : requiredPairs = capture.peers.map (fun p => (p.sourceNetwork, p.peerNetwork)) := by
  native_decide

lemma intended_pairs_and_observed_probe_matrix : capture.ProbeResultsAgree redNetworks requiredPairs := by
  unfold ConnectivityCapture.ProbeResultsAgree
  native_decide

lemma complete_host_placements : CompleteHostPlacements devices capture.placements := by
  unfold CompleteHostPlacements
  native_decide

def sourceNetwork (state : State records.inventory.ifaces) : String :=
  (contextFor state.deviceState.frame.originDomain).flow.sourceNetwork

lemma per_step_network_labels (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (first : State records.inventory.ifaces) (action : Action records.inventory.ifaces)
    (last : State records.inventory.ifaces) (safe : FlowInvariant primitive first)
    (run : (interpretedForwarding primitive).system.Tr first action last) :
    FlowInvariant primitive last ∧ sourceNetwork last = sourceNetwork first ∧
    ∀ event ∈ (interpretedForwarding primitive).events action,
      ConnectivityEvent redNetworks (sourceNetwork first) event := by
  have ids : ∀ s ∈ contexts, redNetwork s.originDomain = s.flow.sourceNetwork := by native_decide
  have owners : ∀ s ∈ contexts, ∀ i ∈ records.inventory.ifaces,
      (s.SourceSide (capturedConfiguration.ip.owner i) ∨ s.DestinationSide (capturedConfiguration.ip.owner i)) →
      ∀ domain ∈ (capturedConfiguration.ip.ifaceSecurityDomain i).toList,
      ∃ a ∈ redNetworks, ∃ b ∈ redNetworks, a.id = s.flow.sourceNetwork ∧
        b.id = redNetwork domain ∧ a.level = b.level := by
    unfold IpsecFlowEndpoints.SourceSide IpsecFlowEndpoints.DestinationSide
    native_decide
  let chosen := contextFor first.deviceState.frame.originDomain
  have included : chosen ∈ contexts := safe.1
  have name := ids chosen included
  have origin := (MultiProtocolForwarding.step_preserves_payload run.2.2.2.1).2
  refine ⟨shared_step_preserves_flow primitive safe run, ?_, ?_⟩
  · simp only [sourceNetwork, origin]
  · apply checked_ipsec_step_events (deviceBinding primitive) records.inventory.ifaces
      (interpretedDeployment primitive) redNetworks expectedEncapStack chosen run
    · change PayloadOrigin.red (redNetwork first.deviceState.frame.originDomain) = _
      rw [← safe.2.1]
      exact congrArg PayloadOrigin.red name
    · exact safe.2.2
    · intro domain recipient side
      apply owners chosen included first.deviceState.iface first.ifacePresent side domain
      change capturedConfiguration.ip.ifaceSecurityDomain first.deviceState.iface = some domain at recipient
      simp [recipient]

def context (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (base : ComplianceContext (State records.inventory.ifaces) (Action records.inventory.ifaces)) :=
  connectedContext base (labelDeployment primitive) (interpretedForwarding primitive) capture.roster.solution
    capture.roster.referencedConformingSolutions authenticated installed requiredPairs

lemma capture_matches_context (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (base : ComplianceContext (State records.inventory.ifaces) (Action records.inventory.ifaces))
    (placement : RecordsMatchPhysicalHosts base.records capture.placements)
    (technical : ∀ device ∈ devices, ∃ record ∈ base.records.components, record.component = device.id) :
    capture.MatchesContext (context primitive base) entries authentication installedChildren := by
  exact ⟨rfl, fun _ => Iff.rfl, roster_and_assignments_cover_capture, all_ike_and_child_bindings_checked,
    rfl, rfl, configured_network_demands, rfl, placement, technical⟩

theorem snapshot_rg008_shared_scoped_connectivity (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    scoped_security_level_connectivity (labelDeployment primitive) (interpretedForwarding primitive)
      authenticated installed requiredPairs (unclassifiedNetworkIds redNetworks) :=
  scoped_connectivity_from_forwarding _ _ _ _ _ _ sourceNetwork (FlowInvariant primitive)
    (labeled_forwarding_coverage primitive) checked_dedicated_networks.1 checked_dedicated_networks.2
    checked_peer_inventory.2.2.2 (initial_flow_invariant primitive) (per_step_network_labels primitive)
    (required_pairs_have_forwarding_traces primitive) rfl

theorem snapshot_rg008_shared_references_closed (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (base : ComplianceContext (State records.inventory.ifaces) (Action records.inventory.ifaces)) :
    ∃ contexts, context primitive base ∈ contexts ∧ ReferencesClosed contexts := by
  refine ⟨[context primitive base], by simp, ?_⟩
  intro included member id declared
  obtain rfl := List.mem_singleton.mp member
  change id ∈ capture.roster.referencedConformingSolutions at declared
  rw [standalone_roster] at declared
  cases declared

theorem snapshot_rg008_shared_physical_separation_failure (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (base : ComplianceContext (State records.inventory.ifaces) (Action records.inventory.ifaces))
    (physical : RecordsMatchPhysicalHosts base.records capture.placements) :
    ¬ security_level_connectivity (context primitive base) := by
  have placementPair : ∃ inner ∈ capture.placements, ∃ outer ∈ capture.placements,
      inner.device = "V31F_I_A4" ∧ outer.device = "V31F_O_A1" ∧ inner.host = outer.host ∧
      inner.virtualization = "container-shared-kernel" ∧ outer.virtualization = "container-shared-kernel" ∧
      inner.observations ≠ [] ∧ outer.observations ≠ [] := by native_decide
  obtain ⟨inner, innerRow, outer, outerRow, innerName, outerName, same, _⟩ := placementPair
  refine cohosted_encryptors_violate_unclassified_duty (context primitive base)
    "V31F_I_A4/red-network" inner.device outer.device ?_ ?_ ?_ ?_ ?_
  · change "V31F_I_A4/red-network" ∈ unclassifiedNetworkIds redNetworks
    native_decide
  · rw [innerName, outerName]
    decide
  · rw [innerName]
    change ∃ d ∈ devices, d.id = "V31F_I_A4" ∧ d.layer = some .inner
    native_decide
  · rw [outerName]
    change ∃ d ∈ devices, d.id = "V31F_O_A1" ∧ d.layer = some .outer
    native_decide
  · intro first firstMember firstId last lastMember lastId
    exact (physical inner innerRow first firstMember firstId.symm).symm.trans
      (same.trans (physical outer outerRow last lastMember lastId.symm))

theorem snapshot_rg008_shared_with_observed_hosts (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (base : ComplianceContext (State records.inventory.ifaces) (Action records.inventory.ifaces))
    (fields : String → ComponentDutyRecord) :
    let observed := {base with records := recordsWithObservedPlacement capture.placements base.records fields}
    RecordsMatchPhysicalHosts observed.records capture.placements ∧
    (∀ device ∈ devices, ∃ record ∈ observed.records.components, record.component = device.id) ∧
    ¬ security_level_connectivity (context primitive observed) :=
  ⟨(observed_placement_records_match devices capture.placements complete_host_placements base.records fields).1,
    (observed_placement_records_match devices capture.placements complete_host_placements base.records fields).2,
    snapshot_rg008_shared_physical_separation_failure primitive _
      (observed_placement_records_match devices capture.placements complete_host_placements base.records fields).1⟩

theorem snapshot_rg008_shared_has_evidence_matched_context (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    ∃ witness : ComplianceContext (State records.inventory.ifaces) (Action records.inventory.ifaces),
      witness.model = interpretedForwarding primitive ∧ witness.deployment = labelDeployment primitive ∧
      capture.MatchesContext witness entries authentication installedChildren ∧
      capture.ProbeResultsAgree witness.deployment.networks witness.requiredConnectivity ∧
      ¬ security_level_connectivity witness := by
  obtain ⟨base⟩ := residual_context_exists (labelDeployment primitive) (interpretedForwarding primitive)
    deliveryPath.datagram (contextFor 1).flow
  let fields : String → ComponentDutyRecord := fun _ => by constructor <;> exact default
  let observed := {base with records := recordsWithObservedPlacement capture.placements base.records fields}
  have results := snapshot_rg008_shared_with_observed_hosts primitive base fields
  exact ⟨context primitive observed, rfl, rfl, capture_matches_context primitive observed results.1 results.2.1,
    intended_pairs_and_observed_probe_matrix, results.2.2⟩

end TDN.Deployments.SecurityLevelConnectivity_Shared
