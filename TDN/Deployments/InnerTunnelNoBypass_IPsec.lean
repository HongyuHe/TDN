import TDN.Deployments.InnerTunnelNoBypass_IPsecTunnelBindings

namespace TDN.Deployments.InnerTunnelNoBypass_IPsec
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

lemma ingress_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    IPsecIngressGateChecks (interpretedForwarding primitive).native (interpretedDeployment primitive) .inner receiveTarget := by
  refine ⟨rfl, rfl, ?_, source_receive_components, route_owners, ?_, ?_, ?_⟩
  · intro payload iface component selected
    exact (receive_target_index payload iface component selected).2
  · intro payload first last connected
    exact bridge_receive_components (first,last) connected
  · intro state header component owned selected unauthenticated
    obtain ⟨member, enteredOwner⟩ := receive_target_index _ state.enteredIface component selected
    have entered := gray_iface_owner state.enteredIface member
    have ownerSame := inner_owner_name_forces_index (capturedConfiguration.ip.owner state.enteredIface)
      entered.1 (capturedConfiguration.ip.owner state.iface) (owned.trans enteredOwner.symm)
    have inner : innerOwner ((configuration primitive).ip.owner state.iface) := by
      change innerOwner (capturedConfiguration.ip.owner state.iface)
      rw [ownerSame]
      exact entered.1
    exact unauthenticated_external_ingress_cannot_forward (configuration primitive) state header "red" "gray"
      (by native_decide) (inner_forward_chain primitive state.iface inner) entered.2 unauthenticated
  · intro payload iface component policy association selected configured installed bound
    obtain ⟨member, owner⟩ := receive_target_index payload iface component selected
    obtain ⟨tunnel, present, identity, selectedLayer, receiver⟩ :=
      inbound_tunnel_bindings iface member policy configured association installed bound
    exact ⟨tunnel, present, identity, selectedLayer, receiver.trans owner⟩

lemma outbound_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    IPsecLayerBoundaryChecks (interpretedForwarding primitive).native (interpretedDeployment primitive)
      expectedStack innerOwner ⟨fun _ => 64, fun _ => 64⟩ := by
  refine ⟨headered_stack_conditions (codec primitive), rfl, ?_, ?_, ?_, source_layouts, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro iface
    exact ⟨by change 64 ≤ 255; native_decide, by change 64 ≤ 255; native_decide⟩
  · refine ⟨rfl, rfl, route_owners, ?_⟩
    intro first last connected
    exact bridge_outputs_outside_inner (first,last) connected
  · intro domain
    exact ⟨redNetwork domain, rfl⟩
  · intro iface interface member name layer
    exact interface_owner_alignment iface (interface_is_listed interface member iface name) interface member name layer
  · intro first last linked
    exact inner_physical_input_stacks (first,last) linked
  · intro first last linked
    exact inner_physical_output_stacks (first,last) linked
  · intro iface next linked interface member name layer external
    obtain ⟨gray, inner⟩ := inner_external_outputs (iface,next) linked interface member name layer external
    exact ⟨gray, inner_forward_chain primitive iface inner⟩
  · intro first last same
    change capturedConfiguration.ip.owner first = capturedConfiguration.ip.owner last at same
    change (DataPlaneForwarding.deviceAt records.nativeDevices (capturedConfiguration.ip.owner first)).egressPolicies =
        (DataPlaneForwarding.deviceAt records.nativeDevices (capturedConfiguration.ip.owner last)).egressPolicies ∧
      directionalStates installations (capturedConfiguration.ip.owner first) .outbound =
        directionalStates installations (capturedConfiguration.ip.owner last) .outbound
    rw [same]
    exact ⟨rfl, rfl⟩
  · intro iface policy association route configured installed bound member egress low high interface stored name layer
    subst iface
    exact outbound_tunnel_bindings route member policy configured association installed bound low high interface stored name layer

lemma target_binding (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    InboundGateReceiversBound (interpretedDeployment primitive) (interpretedForwarding primitive).GenuineControl .inner receiveTarget := by
  intro payload data interface member layer external
  exact external_receive_components interface member layer external

def components : List EncryptionComponentConfiguration :=
  innerModeBindings.map TunnelModeBinding.component

lemma component_coverage (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ComponentConfigurationCoverage (interpretedDeployment primitive) .inner components := by
  have checked : ∀ device ∈ records.components, device.layer = some .inner →
      ∃ component ∈ components, component.id = device.id ∧
        ((device.kind = .vpn ∧ component.mechanism = .ipsec) ∨
          (device.kind = .macsec ∧ component.mechanism = .macsec)) := by native_decide
  intro device member relevant layer
  exact checked device member layer

lemma component_parameters (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ∀ component ∈ components, (interpretedDeployment primitive).Relevant component.id →
      (component.mechanism = .ipsec → component.espTunnelMode = true ∧ component.associatedIPTunnel = true) ∧
      (false = true → component.outboundMACPolicy = true) ∧
      (false = true → component.inboundMACPolicy = true) := by
  intro component member relevant
  obtain ⟨record, selected, same⟩ := List.mem_map.mp member
  subst component
  have stored : record ∈ tunnelModeBindings := (List.mem_filter.mp selected).1
  have parameters := checked_mode_binding_has_component_parameters record (tunnel_mode_bindings_checked record stored)
  exact ⟨fun _ => parameters, fun impossible => Bool.noConfusion impossible,
    fun impossible => Bool.noConfusion impossible⟩

theorem snapshot_RG029_ipsec_inner_tunnel_no_bypass (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    msc_inner_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive) components false false := by
  have covered := interpreted_deployment_covered primitive
  exact inner_tunnel_no_bypass_from_outbound_and_inbound_checks (interpretedDeployment primitive)
    (interpretedForwarding primitive) components false false receiveTarget covered
    (ipsecLayerOutboundChecks (interpretedForwarding primitive) (interpretedDeployment primitive) expectedStack innerOwner
      ⟨fun _ => 64, fun _ => 64⟩ covered (outbound_checks primitive))
    (ipsecIngressDeviceGate (interpretedForwarding primitive).native (interpretedDeployment primitive) .inner receiveTarget
      (ingress_checks primitive)) (target_binding primitive) (component_coverage primitive) (component_parameters primitive)

end TDN.Deployments.InnerTunnelNoBypass_IPsec
