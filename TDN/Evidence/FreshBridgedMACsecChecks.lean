import TDN.Evidence.FreshBridgedMACsecConfig
import TDN.Semantics.MultiProtocolProvenance

namespace TDN.Imported.PairingInnerMacsecOuterIpsec
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma ip_peer_tag_checks : Execution.FinitePeerTagAgreement devices := by
  unfold Execution.FinitePeerTagAgreement Execution.StateBindsPolicy Execution.SameWireAssociation devices
  decide

lemma ip_peer_wire_tag_agreement : Execution.PeerTagAgreement config.ip :=
  Execution.finite_peer_tag_agreement_sound devices ports routes links [] ip_peer_tag_checks

theorem reachable_IPsec_seals_have_actual_transmit_provenance
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish) :
    ProducedIPBodies config finish.frame.body := by
  apply all_executions_preserve_ip_provenance config run
  rcases source.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [ProducedIPBodies, plain]

lemma route_owner_checks : ∀ route ∈ routes,
    (Execution.portAt ports route.egress).owner = (Execution.portAt ports route.ingress).owner := by
  unfold routes ports; decide

lemma link_stack_checks : ∀ edge ∈ links,
    (Execution.portAt ports edge.1).stack = (Execution.portAt ports edge.2).stack := by
  unfold links ports; decide

lemma bridge_stack_checks : ∀ edge ∈ bridges,
    (Execution.portAt ports edge.1).stack = (Execution.portAt ports edge.2).stack := by
  unfold bridges ports; decide

lemma forward_checks : Execution.FiniteRoutedForwardChecks devices ports routes := by
  unfold Execution.FiniteRoutedForwardChecks devices ports routes; decide

lemma output_checks : Execution.FiniteOutputChecks devices ports := by
  unfold Execution.FiniteOutputChecks devices ports; decide

lemma outer_route_checks : Execution.FiniteOuterRoutes devices ports routes := by
  unfold Execution.FiniteOuterRoutes devices ports routes; decide

lemma ip_local_conditions : Execution.LocalStackConditions config.ip layout := by
  exact Execution.local_stack_conditions_of_routed_finite_checks devices ports routes links []
    route_owner_checks link_stack_checks (by simp)
    (by unfold devices; decide) forward_checks output_checks outer_route_checks

lemma mac_transmit_checks : ∀ port ∈ macPorts, MACTransmitCheck ports port := by
  unfold macPorts ports; decide

lemma mac_receive_checks : ∀ port ∈ macPorts, ∀ association ∈ port.receiveAssociations,
    association.tag :: (Execution.portAt ports port.logicalPort).stack =
      (Execution.portAt ports port.physicalPort).stack := by
  unfold macPorts ports; decide

lemma mac_role_checks : ∀ sender ∈ macPorts, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ macPorts,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag := by
  simp [macPorts, SameMACWireIdentity]

lemma mac_secure_checks : ∀ port ∈ macPorts,
    port.settings.protectFrames = true ∧ port.settings.encryptFrames = true ∧
    port.settings.confidentialityOffset = 0 ∧ port.validateStrict = true := by
  unfold macPorts; decide

lemma carrier_output_checks : ∀ carrier ∈ carriers,
    (Execution.portAt ports carrier.virtualPort).stack =
      (Execution.portAt ports carrier.routingPort).stack := by
  unfold carriers ports; decide

lemma carrier_route_checks : CarrierRouteChecks devices ports routes carriers := by
  unfold CarrierRouteChecks devices ports routes carriers; decide

lemma carrier_peer_checks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
    CarrierPeers sender receiver →
      (Execution.portAt ports sender.virtualPort).stack =
        (Execution.portAt ports receiver.virtualPort).stack := by
  unfold carriers ports CarrierPeers; decide

lemma mixed_local_conditions : LocalConditions config layout :=
  local_conditions_from_finite_checks devices ports routes links bridges macPorts carriers
    ip_local_conditions link_stack_checks bridge_stack_checks mac_transmit_checks mac_receive_checks
    mac_role_checks mac_secure_checks carrier_output_checks carrier_route_checks carrier_peer_checks

lemma red_sources_checked : ∀ port ∈ redSources, layout port = [] ∧ config.ip.payloadOrigin port := by
  unfold redSources layout config MultiProtocolExecution.finiteConfig Execution.finiteConfig
    Execution.finiteLayout ports; decide

lemma gray_ports_checked : ∀ port ∈ grayPorts, layout port = [1] := by
  unfold grayPorts layout Execution.finiteLayout ports; decide

lemma black_ports_checked : ∀ port ∈ blackPorts, layout port = [2, 1] := by
  unfold blackPorts layout Execution.finiteLayout ports; decide

theorem every_red_origin_transmission_has_gray_or_black_protection
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) :
    (finish.port ∈ grayPorts → finish.frame.body.protectionLayers = [1]) ∧
    (finish.port ∈ blackPorts → finish.frame.body.protectionLayers = [2, 1]) := by
  have initial := Targets.mixed_red_initial_invariant config layout redSources red_sources_checked source
  have preserved := all_executions_preserve_stack config layout mixed_local_conditions run initial
  have layers : finish.frame.body.protectionLayers = layout finish.port := by
    simpa only [ready] using preserved.2
  exact ⟨fun member => layers.trans (gray_ports_checked finish.port member),
    fun member => layers.trans (black_ports_checked finish.port member)⟩

lemma outer_port_shapes : ∀ port ∈ ({} : Execution.PortData) :: ports,
    port.stack.head? = some 2 → port.stack = [2, 1] := by
  unfold ports; decide

theorem actual_inner_encryption_precedes_outer {start finish : MultiProtocolExecution.State}
    {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    MultiProtocolExecution.OrderedEncryptions config 1 2 start actions finish :=
  Targets.mixed_black_transmission_has_ordered_encryptions config layout redSources blackPorts
    mixed_local_conditions red_sources_checked black_ports_checked
    (fun port => outer_port_shapes _ (Execution.port_at_member_or_default ports port))
    source run ready black

theorem every_mixed_execution_keeps_actual_layers {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish)
    (initial : StackInvariant config layout start) :
    StackInvariant config layout finish :=
  all_executions_preserve_stack config layout mixed_local_conditions run initial

end TDN.Imported.PairingInnerMacsecOuterIpsec
