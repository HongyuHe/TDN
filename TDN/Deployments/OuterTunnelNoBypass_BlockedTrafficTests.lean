import TDN.Deployments.OuterTunnelNoBypass_Baseline
import TDN.Deployments.OuterTunnelNoBypass_Shared

namespace TDN.Deployments.OuterTunnelNoBypass_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 8000000

def noOuterPolicyHeader : PacketPolicy.Packet :=
  { source := 0, destination := 0, protocol := "esp", ipv4HeaderWords := 5, ingress := "", egress := "",
    sourcePort := 0, destinationPort := 0, matchedInboundPolicyIds := [],
    matchedOutboundPolicyIds := [], connectionState := "new" }

def unauthenticatedBlackInput : MultiProtocolForwarding.State :=
  { iface := 106, enteredIface := 104, datapathStage := .routed,
    frame := { originDomain := 1, payload := 1, body := .datagram noOuterPolicyHeader },
    authenticated := [], tracking := "new" }

def noOuterPolicyOutput : MultiProtocolForwarding.State :=
  { unauthenticatedBlackInput with iface := 104, enteredIface := 106 }

lemma no_outer_policy_match :
    DataPlaneForwarding.lookupSpdPolicies (capturedConfiguration.ip.egressPolicies 104) noOuterPolicyHeader = [] := by decide

theorem snapshot_RG030_baseline_unauthenticated_black_input_blocked (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ after, (interpretedForwarding primitive).native.AcceptedStep
      unauthenticatedBlackInput .forwardFilter after := by
  rintro ⟨after, accepted⟩
  cases accepted.1 with
  | forwardFilter stage visible permitted =>
    have same := Option.some.inj visible
    change noOuterPolicyHeader = _ at same
    subst same
    exact unauthenticated_external_ingress_across_cannot_forward (configuration primitive)
      unauthenticatedBlackInput noOuterPolicyHeader "black"
      (outer_forward_chain primitive _ (by change OuterOwner (capturedConfiguration.ip.owner 106); decide)) rfl rfl permitted

theorem snapshot_RG030_baseline_missing_outer_policy_blocked (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ after, (interpretedForwarding primitive).native.AcceptedStep
      noOuterPolicyOutput .forwardFilter after := by
  rintro ⟨after, accepted⟩
  cases accepted.1 with
  | forwardFilter stage visible permitted =>
    have same := Option.some.inj visible
    change noOuterPolicyHeader = _ at same
    subst same
    exact (accepted_external_output_across_requires_policy (configuration primitive)
      noOuterPolicyOutput noOuterPolicyHeader "black"
      (outer_forward_chain primitive _ (by change OuterOwner (capturedConfiguration.ip.owner 104); decide)) rfl permitted) no_outer_policy_match

lemma component_without_outbound_policy :
    ∃ component ∈ components, component.outboundMACPolicy = false := by decide

lemma component_without_inbound_policy :
    ∃ component ∈ components, component.inboundMACPolicy = false := by decide

theorem snapshot_RG030_baseline_outbound_objective_rejects_missing_policy (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_outer_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive) components true false := by
  intro accepted
  obtain ⟨component, member, disabled⟩ := component_without_outbound_policy
  have enabled := (accepted.2.2.1 component member (Or.inl rfl)).2.1 rfl
  rw [disabled] at enabled
  cases enabled

theorem snapshot_RG030_baseline_inbound_objective_rejects_missing_policy (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_outer_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive) components false true := by
  intro accepted
  obtain ⟨component, member, disabled⟩ := component_without_inbound_policy
  have enabled := (accepted.2.2.1 component member (Or.inl rfl)).2.2 rfl
  rw [disabled] at enabled
  cases enabled

theorem snapshot_RG030_baseline_unprotected_gray_receive_unreachable (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ start actions finish, (interpretedForwarding primitive).initial start ∧
      (interpretedForwarding primitive).system.MTr start actions finish ∧
      .receive ⟨1,1⟩ (records.ifaceName 106) [] .protectedData ∈
        (interpretedForwarding primitive).history.Events ++ actions.flatMap (interpretedForwarding primitive).events := by
  rintro ⟨start, actions, finish, initial, run, received⟩
  have data : ¬ (interpretedForwarding primitive).GenuineControl ⟨1,1⟩ := by
    rintro ⟨component, protocol, impossible⟩
    cases impossible
  obtain ⟨tunnel, stored, inner, singleton⟩ :=
    (snapshot_RG030_baseline_outer_tunnel_no_bypass primitive).2.2.2 start actions finish initial run
      ⟨1,1⟩ (records.ifaceName 106) [] .protectedData received data records.interfaces[106]
      (by change records.interfaces[106] ∈ records.interfaces; decide) (Or.inl rfl)
      (by decide) (by decide) (by change OuterDevice records.interfaces[106].device; decide)
  cases singleton

end TDN.Deployments.OuterTunnelNoBypass_Baseline

namespace TDN.Deployments.OuterTunnelNoBypass_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 8000000

def noOuterPolicyHeader : PacketPolicy.Packet :=
  { source := 0, destination := 0, protocol := "esp", ipv4HeaderWords := 5, ingress := "", egress := "",
    sourcePort := 0, destinationPort := 0, matchedInboundPolicyIds := [],
    matchedOutboundPolicyIds := [], connectionState := "new" }

def unauthenticatedBlackInput : MultiProtocolForwarding.State :=
  { iface := 156, enteredIface := 154, datapathStage := .routed,
    frame := { originDomain := 1, payload := 1, body := .datagram noOuterPolicyHeader },
    authenticated := [], tracking := "new" }

def noOuterPolicyOutput : MultiProtocolForwarding.State :=
  { unauthenticatedBlackInput with iface := 154, enteredIface := 156 }

lemma no_outer_policy_match :
    DataPlaneForwarding.lookupSpdPolicies (capturedConfiguration.ip.egressPolicies 154) noOuterPolicyHeader = [] := by decide

theorem snapshot_RG030_shared_unauthenticated_black_input_blocked (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ after, (interpretedForwarding primitive).native.AcceptedStep
      unauthenticatedBlackInput .forwardFilter after := by
  rintro ⟨after, accepted⟩
  cases accepted.1 with
  | forwardFilter stage visible permitted =>
    have same := Option.some.inj visible
    change noOuterPolicyHeader = _ at same
    subst same
    exact unauthenticated_external_ingress_across_cannot_forward (configuration primitive)
      unauthenticatedBlackInput noOuterPolicyHeader "black"
      (outer_forward_chain primitive _ (by change OuterOwner (capturedConfiguration.ip.owner 156); decide)) rfl rfl permitted

theorem snapshot_RG030_shared_missing_outer_policy_blocked (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ after, (interpretedForwarding primitive).native.AcceptedStep
      noOuterPolicyOutput .forwardFilter after := by
  rintro ⟨after, accepted⟩
  cases accepted.1 with
  | forwardFilter stage visible permitted =>
    have same := Option.some.inj visible
    change noOuterPolicyHeader = _ at same
    subst same
    exact (accepted_external_output_across_requires_policy (configuration primitive)
      noOuterPolicyOutput noOuterPolicyHeader "black"
      (outer_forward_chain primitive _ (by change OuterOwner (capturedConfiguration.ip.owner 154); decide)) rfl permitted) no_outer_policy_match

lemma component_without_outbound_policy :
    ∃ component ∈ components, component.outboundMACPolicy = false := by decide

lemma component_without_inbound_policy :
    ∃ component ∈ components, component.inboundMACPolicy = false := by decide

theorem snapshot_RG030_shared_outbound_objective_rejects_missing_policy (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_outer_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive) components true false := by
  intro accepted
  obtain ⟨component, member, disabled⟩ := component_without_outbound_policy
  have enabled := (accepted.2.2.1 component member (Or.inl rfl)).2.1 rfl
  rw [disabled] at enabled
  cases enabled

theorem snapshot_RG030_shared_inbound_objective_rejects_missing_policy (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_outer_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive) components false true := by
  intro accepted
  obtain ⟨component, member, disabled⟩ := component_without_inbound_policy
  have enabled := (accepted.2.2.1 component member (Or.inl rfl)).2.2 rfl
  rw [disabled] at enabled
  cases enabled

theorem snapshot_RG030_shared_unprotected_gray_receive_unreachable (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ start actions finish, (interpretedForwarding primitive).initial start ∧
      (interpretedForwarding primitive).system.MTr start actions finish ∧
      .receive ⟨1,1⟩ (records.ifaceName 156) [] .protectedData ∈
        (interpretedForwarding primitive).history.Events ++ actions.flatMap (interpretedForwarding primitive).events := by
  rintro ⟨start, actions, finish, initial, run, received⟩
  have data : ¬ (interpretedForwarding primitive).GenuineControl ⟨1,1⟩ := by
    rintro ⟨component, protocol, impossible⟩
    cases impossible
  obtain ⟨tunnel, stored, inner, singleton⟩ :=
    (snapshot_RG030_shared_outer_tunnel_no_bypass primitive).2.2.2 start actions finish initial run
      ⟨1,1⟩ (records.ifaceName 156) [] .protectedData received data records.interfaces[156]
      (by change records.interfaces[156] ∈ records.interfaces; decide) (Or.inl rfl)
      (by decide) (by decide) (by change OuterDevice records.interfaces[156].device; decide)
  cases singleton

lemma invalid_observed_binding_disables_component (record : TunnelModeBinding) (invalid : ¬ record.Check) :
    record.component.espTunnelMode = false := by
  simp [TunnelModeBinding.component, invalid]

def mismatchedOuterModeBinding : TunnelModeBinding :=
  { outerModeBindings[0] with mode := "transport" }

def mismatchedOuterEndpointBinding : TunnelModeBinding :=
  { outerModeBindings[0] with
    association := { outerModeBindings[0].association with sender := outerModeBindings[0].association.sender + 1 } }

def componentsWithObservedBinding (record : TunnelModeBinding) : List EncryptionComponentConfiguration :=
  components.map (fun component => if component.id = record.component.id then record.component else component)

lemma mismatched_outer_mode_binding_is_rejected : ¬ mismatchedOuterModeBinding.Check := by decide

lemma mismatched_outer_endpoint_binding_is_rejected : ¬ mismatchedOuterEndpointBinding.Check := by decide

theorem snapshot_RG030_shared_mode_mismatch_blocks_application (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_outer_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive)
      (componentsWithObservedBinding mismatchedOuterModeBinding) false false := by
  intro accepted
  have member : mismatchedOuterModeBinding.component ∈ componentsWithObservedBinding mismatchedOuterModeBinding := by
    change mismatchedOuterModeBinding.component ∈ mismatchedOuterModeBinding.component :: _
    exact List.mem_cons_self
  have enabled := (accepted.2.2.1 mismatchedOuterModeBinding.component member (Or.inl rfl)).1 rfl
  have disabled := invalid_observed_binding_disables_component _ mismatched_outer_mode_binding_is_rejected
  rw [disabled] at enabled
  cases enabled

theorem snapshot_RG030_shared_endpoint_mismatch_blocks_application (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ msc_outer_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive)
      (componentsWithObservedBinding mismatchedOuterEndpointBinding) false false := by
  intro accepted
  have member : mismatchedOuterEndpointBinding.component ∈ componentsWithObservedBinding mismatchedOuterEndpointBinding := by
    change mismatchedOuterEndpointBinding.component ∈ mismatchedOuterEndpointBinding.component :: _
    exact List.mem_cons_self
  have enabled := (accepted.2.2.1 mismatchedOuterEndpointBinding.component member (Or.inl rfl)).1 rfl
  have disabled := invalid_observed_binding_disables_component _ mismatched_outer_endpoint_binding_is_rejected
  rw [disabled] at enabled
  cases enabled

lemma gray_receive_test_tunnels_are_inner :
    records.tunnels[0].layer = .inner ∧ records.tunnels[2].layer = .inner ∧
    records.tunnels[0].id ≠ records.tunnels[2].id := by decide

theorem snapshot_RG030_shared_multiple_inner_layers_receive_unreachable (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ¬ ∃ start actions finish, (interpretedForwarding primitive).initial start ∧
      (interpretedForwarding primitive).system.MTr start actions finish ∧
      .receive ⟨1,1⟩ (records.ifaceName 156) [records.tunnels[0].id, records.tunnels[2].id] .protectedData ∈
        (interpretedForwarding primitive).history.Events ++ actions.flatMap (interpretedForwarding primitive).events := by
  rintro ⟨start, actions, finish, initial, run, received⟩
  have data : ¬ (interpretedForwarding primitive).GenuineControl ⟨1,1⟩ := by
    rintro ⟨component, protocol, impossible⟩
    cases impossible
  obtain ⟨tunnel, stored, inner, singleton⟩ :=
    (snapshot_RG030_shared_outer_tunnel_no_bypass primitive).2.2.2 start actions finish initial run
      ⟨1,1⟩ (records.ifaceName 156) [records.tunnels[0].id, records.tunnels[2].id] .protectedData received data records.interfaces[156]
      (by change records.interfaces[156] ∈ records.interfaces; decide) (Or.inl rfl)
      (by decide) (by decide) (by change OuterDevice records.interfaces[156].device; decide)
  have lengths := congrArg List.length singleton
  simp at lengths

end TDN.Deployments.OuterTunnelNoBypass_Shared
