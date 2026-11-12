import TDN.Deployments.OuterTunnelNoBypass_SharedModeChecks

namespace TDN.Deployments.OuterTunnelNoBypass_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 4000000

lemma ingress_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    IPsecIngressGateChecks (interpretedForwarding primitive).native (interpretedDeployment primitive) .outer receiveComponent := by
  refine ⟨rfl, rfl, ?_, source_receive_components, route_owners, ?_, ?_, ?_⟩
  · intro payload iface component selected
    exact (receive_component_iface payload iface component selected).2
  · intro payload first last connected
    exact bridge_receive_components (first,last) connected
  · intro state header component owned selected unauthenticated
    obtain ⟨member, enteredOwner⟩ := receive_component_iface _ state.enteredIface component selected
    have entered := external_iface_owner state.enteredIface member
    have ownerSame := outer_owner_name_forces_index (capturedConfiguration.ip.owner state.enteredIface)
      entered.1 (capturedConfiguration.ip.owner state.iface) (owned.trans enteredOwner.symm)
    have ownedOuter : OuterOwner ((configuration primitive).ip.owner state.iface) := by
      change OuterOwner (capturedConfiguration.ip.owner state.iface)
      rw [ownerSame]
      exact entered.1
    exact unauthenticated_external_ingress_across_cannot_forward (configuration primitive) state header "black" (outer_forward_chain primitive state.iface ownedOuter) entered.2 unauthenticated
  · intro payload iface component policy association selected configured installed bound
    obtain ⟨member, owner⟩ := receive_component_iface payload iface component selected
    obtain ⟨tunnel, present, identity, selectedLayer, receiver⟩ :=
      inbound_tunnel_bindings iface member policy configured association installed bound
    exact ⟨tunnel, present, identity, selectedLayer, receiver.trans owner⟩

lemma encap_layer_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    IPsecEncapLayerChecks (interpretedForwarding primitive).native (interpretedDeployment primitive) := by
  refine ⟨rfl, rfl, ?_, tunnel_layer_names_unique⟩
  intro iface policy association configured installed bound
  obtain ⟨device, deviceMember, policyMember⟩ := raw_device_member records.nativeDevices
    ((DataPlaneForwarding.ifaceAt records.nativeIfaces iface).owner) policy true configured
  obtain ⟨record, stored, owner, direction, same⟩ :=
    (directional_state_member installations _ .outbound association).mp installed
  change ∃ tunnel ∈ declaredTunnels, tunnel.id = ipsecTunnel records (policy.seal association) ∧
    protectionLayerTag tunnel.layer = policy.tag
  have recordBound := bound
  rw [← same] at recordBound
  rw [← same]
  exact configured_layer_bindings device deviceMember policy policyMember record stored direction recordBound

lemma outbound_checks (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    IPsecOuterBoundaryChecks (interpretedForwarding primitive).native (interpretedDeployment primitive)
      expectedEncapStack OuterOwner ⟨fun _ => 64, fun _ => 64⟩ := by
  refine ⟨encap_layer_checks primitive, source_not_outer_gray, headered_stack_conditions (codec primitive), rfl, ?_, ?_, ?_, source_encap_stacks, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro iface
    exact ⟨by change 64 ≤ 255; native_decide, by change 64 ≤ 255; native_decide⟩
  · refine ⟨rfl, rfl, route_owners, ?_⟩
    intro first last connected
    exact bridge_outputs_outside_outer (first,last) connected
  · intro domain
    exact ⟨redNetwork domain, rfl⟩
  · intro iface interface member name layer
    exact interface_owner_alignment iface (interface_is_listed interface member iface name) interface member name layer
  · intro first last linked
    exact outer_physical_input_stacks (first,last) linked
  · intro first last linked
    exact outer_physical_output_stacks (first,last) linked
  · intro iface next linked interface member name layer external
    obtain ⟨black, ownedOuter⟩ := outer_external_outputs (iface,next) linked interface member name layer external
    exact ⟨black, outer_forward_chain primitive iface ownedOuter⟩
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

lemma receive_component_binding (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    InboundGateReceiversBound (interpretedDeployment primitive) (interpretedForwarding primitive).GenuineControl .outer receiveComponent := by
  intro payload data interface member layer external
  exact external_receive_components interface member layer external

def components : List EncryptionComponentConfiguration :=
  outerModeBindings.map (fun record => record.component)

lemma component_coverage (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ComponentConfigurationCoverage (interpretedDeployment primitive) .outer components := by
  have checked : ∀ device ∈ records.components, device.layer = some .outer →
      ∃ component ∈ components, component.id = device.id ∧
        ((device.kind = .vpn ∧ component.mechanism = .ipsec) ∨
          (device.kind = .macsec ∧ component.mechanism = .macsec)) := by native_decide
  intro device member relevant layer
  exact checked device member layer

lemma component_parameters (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ∀ component ∈ components, (interpretedDeployment primitive).Relevant component.id →
      (component.mechanism = .ipsec → component.espTunnelMode = true) ∧
      (false = true → component.outboundMACPolicy = true) ∧
      (false = true → component.inboundMACPolicy = true) := by
  intro component member relevant
  obtain ⟨record, selected, same⟩ := List.mem_map.mp member
  subst component
  have stored : record ∈ tunnelModeBindings := (List.mem_filter.mp selected).1
  have parameters := checked_mode_binding_has_component_parameters record (tunnel_mode_bindings_checked record stored)
  exact ⟨fun _ => parameters.1, fun impossible => Bool.noConfusion impossible,
    fun impossible => Bool.noConfusion impossible⟩

theorem snapshot_RG030_shared_outer_tunnel_no_bypass (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    msc_outer_tunnel_no_bypass (interpretedDeployment primitive) (interpretedForwarding primitive) components false false := by
  have covered := interpreted_deployment_covered primitive
  exact outer_tunnel_no_bypass_from_local_checks (interpretedDeployment primitive)
    (interpretedForwarding primitive) components false false receiveComponent covered
    (ipsecOuterOutboundChecks (interpretedForwarding primitive) (interpretedDeployment primitive) expectedEncapStack OuterOwner
      ⟨fun _ => 64, fun _ => 64⟩ covered (outbound_checks primitive))
    (ipsecIngressDeviceGate (interpretedForwarding primitive).native (interpretedDeployment primitive) .outer receiveComponent
      (ingress_checks primitive)) (receive_component_binding primitive) (component_coverage primitive) (component_parameters primitive)
    (ipsecOuterGrayReceiveChecks (interpretedForwarding primitive) (interpretedDeployment primitive) expectedEncapStack OuterOwner
      ⟨fun _ => 64, fun _ => 64⟩ covered (outbound_checks primitive))

end TDN.Deployments.OuterTunnelNoBypass_Shared
