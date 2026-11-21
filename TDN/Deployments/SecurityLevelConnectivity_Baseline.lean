import TDN.Deployments.SecurityLevelConnectivity_BaselinePaths
import TDN.Deployments.NestedProtection_BaselineSources
import TDN.Deployments.RedConnectivityInventory

namespace TDN.Deployments.SecurityLevelConnectivity_Baseline
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding
  OuterTunnelNoBypass_Baseline MtuSizing_Records SecurityLevelConnectivity NestedProtection

set_option maxRecDepth 1000000

load_network_records capture : ConnectivityCapture from "../../data/evidence/securityLevelConnectivity/Baseline.json" ["capture"]

lemma roster_and_assignments_cover_capture : capture.MatchesEndpoints devices redNetworks entries := by
  unfold ConnectivityCapture.MatchesEndpoints
  native_decide

lemma standalone_roster : capture.roster.referencedConformingSolutions = [] := by native_decide

lemma all_ike_and_child_bindings_checked : capture.MatchesPeerSessions NestedProtection_Baseline.authenticationBindings
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
  (NestedProtection_Baseline.contextFor state.deviceState.frame.originDomain).flow.sourceNetwork

lemma per_step_network_labels (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (first : State records.inventory.ifaces) (action : Action records.inventory.ifaces)
    (last : State records.inventory.ifaces) (safe : NestedProtection_Baseline.ForwardingInvariant primitive first)
    (run : (interpretedForwarding primitive).system.Tr first action last) :
    NestedProtection_Baseline.ForwardingInvariant primitive last ∧ sourceNetwork last = sourceNetwork first ∧
    ∀ event ∈ (interpretedForwarding primitive).events action,
      ConnectivityEvent redNetworks (sourceNetwork first) event := by
  have ids : ∀ s ∈ NestedProtection_Baseline.contexts, redNetwork s.originDomain = s.flow.sourceNetwork := by native_decide
  have owners : ∀ s ∈ NestedProtection_Baseline.contexts, ∀ i ∈ records.inventory.ifaces,
      (s.SourceSide (capturedConfiguration.ip.owner i) ∨ s.DestinationSide (capturedConfiguration.ip.owner i)) →
      ∀ domain ∈ (capturedConfiguration.ip.ifaceSecurityDomain i).toList,
      ∃ a ∈ redNetworks, ∃ b ∈ redNetworks, a.id = s.flow.sourceNetwork ∧
        b.id = redNetwork domain ∧ a.level = b.level := by
    unfold IpsecFlowEndpoints.SourceSide IpsecFlowEndpoints.DestinationSide
    native_decide
  let chosen := NestedProtection_Baseline.contextFor first.deviceState.frame.originDomain
  have included : chosen ∈ NestedProtection_Baseline.contexts := safe.1
  have name := ids chosen included
  have origin := (MultiProtocolForwarding.step_preserves_payload run.2.2.2.1).2
  refine ⟨NestedProtection_Baseline.step_preserves_forwarding_invariant primitive safe run, ?_, ?_⟩
  · simp only [sourceNetwork, origin]
  · apply checked_ipsec_step_events (deviceBinding primitive) records.inventory.ifaces
      (interpretedDeployment primitive) redNetworks expectedEncapStack chosen run
    · change PayloadOrigin.red (redNetwork first.deviceState.frame.originDomain) = _
      rw [← safe.2.1]
      exact congrArg PayloadOrigin.red name
    · exact safe.2.2.1
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
    capture.MatchesContext (context primitive base) entries NestedProtection_Baseline.authenticationBindings installedChildren := by
  exact ⟨rfl, fun _ => Iff.rfl, roster_and_assignments_cover_capture, all_ike_and_child_bindings_checked,
    rfl, rfl, configured_network_demands, rfl, placement, technical⟩

theorem snapshot_rg008_baseline_security_level_connectivity (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (base : ComplianceContext (State records.inventory.ifaces) (Action records.inventory.ifaces)) :
    security_level_connectivity (context primitive base) := by
  let current := context primitive base
  apply security_level_connectivity_from_forwarding current sourceNetwork
    (NestedProtection_Baseline.ForwardingInvariant primitive)
    (labeled_forwarding_coverage primitive) checked_dedicated_networks.1 checked_dedicated_networks.2
    checked_peer_inventory.2.2.2 (NestedProtection_Baseline.initial_selected_flow primitive)
    (per_step_network_labels primitive) (required_pairs_have_forwarding_traces primitive) rfl
    [current] (by simp) []
  · intro solution listed name
    obtain rfl := List.mem_singleton.mp listed
    change name ∈ capture.roster.referencedConformingSolutions ↔ _ ∈ []
    simp [standalone_roster]
  · intro edge absent
    cases absent
  · intro id member
    change id ∈ unclassifiedNetworkIds redNetworks at member
    have classified : unclassifiedNetworkIds redNetworks = [] := by native_decide
    rw [classified] at member
    cases member

theorem snapshot_rg008_baseline_has_evidence_matched_context (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial) :
    ∃ witness : ComplianceContext (State records.inventory.ifaces) (Action records.inventory.ifaces),
      witness.model = interpretedForwarding primitive ∧ witness.deployment = labelDeployment primitive ∧
      capture.MatchesContext witness entries NestedProtection_Baseline.authenticationBindings installedChildren ∧
      capture.ProbeResultsAgree witness.deployment.networks witness.requiredConnectivity ∧
      security_level_connectivity witness := by
  obtain ⟨base⟩ := residual_context_exists (labelDeployment primitive) (interpretedForwarding primitive)
    deliveryPath.datagram (NestedProtection_Baseline.contextFor 1).flow
  let fields : String → ComponentDutyRecord := fun _ => by constructor <;> exact default
  let observed := {base with records := recordsWithObservedPlacement capture.placements base.records fields}
  have matched := observed_placement_records_match devices capture.placements complete_host_placements base.records fields
  exact ⟨context primitive observed, rfl, rfl, capture_matches_context primitive observed matched.1 matched.2,
    intended_pairs_and_observed_probe_matrix, snapshot_rg008_baseline_security_level_connectivity primitive observed⟩

end TDN.Deployments.SecurityLevelConnectivity_Baseline
