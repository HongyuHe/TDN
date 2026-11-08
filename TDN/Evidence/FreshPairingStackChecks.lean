import TDN.Evidence.FreshPairingConfigs
import TDN.Semantics.MultiProtocolProvenance

namespace TDN.Imported.PairingIpsecIpsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma ip_peer_tag_checks : Execution.FinitePeerTagAgreement devices := by
  unfold Execution.FinitePeerTagAgreement Execution.StateBindsPolicy Execution.SameWireAssociation devices
  decide

lemma ip_peer_wire_tag_agreement : Execution.PeerTagAgreement config.ip :=
  Execution.finite_peer_tag_agreement_sound devices ifaces routes links [] ip_peer_tag_checks

theorem reachable_IPsec_seals_have_actual_transmit_provenance
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish) :
    ProducedIPBodies config finish.frame.body := by
  apply all_executions_preserve_ip_provenance config run
  rcases source.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [ProducedIPBodies, plain]

lemma route_owner_checks : ∀ route ∈ routes,
    (Execution.ifaceAt ifaces route.egress).owner = (Execution.ifaceAt ifaces route.ingress).owner := by
  unfold routes ifaces; decide

lemma link_stack_checks : ∀ edge ∈ links,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold links ifaces; decide

lemma bridge_stack_checks : ∀ edge ∈ bridges,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold bridges ifaces; decide

lemma forward_checks : Execution.FiniteRoutedForwardChecks devices ifaces routes := by
  unfold Execution.FiniteRoutedForwardChecks devices ifaces routes; decide

lemma output_checks : Execution.FiniteOutputChecks devices ifaces := by
  unfold Execution.FiniteOutputChecks devices ifaces; decide

lemma outer_route_checks : Execution.FiniteOuterRoutes devices ifaces routes := by
  unfold Execution.FiniteOuterRoutes devices ifaces routes; decide

lemma ip_local_conditions : Execution.LocalStackConditions config.ip expectedEncapStack := by
  exact Execution.local_stack_conditions_of_routed_finite_checks devices ifaces routes links []
    route_owner_checks link_stack_checks (by simp)
    (by unfold devices; decide) forward_checks output_checks outer_route_checks

lemma mac_transmit_checks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface := by
  unfold macIfaces ifaces; decide

lemma mac_receive_checks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    association.tag :: (Execution.ifaceAt ifaces iface.logicalIface).stack =
      (Execution.ifaceAt ifaces iface.physicalIface).stack := by
  unfold macIfaces ifaces; decide

lemma mac_role_checks : ∀ sender ∈ macIfaces, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ macIfaces,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag := by
  simp [macIfaces, SameMACWireIdentity]

lemma mac_secure_checks : ∀ iface ∈ macIfaces,
    iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
    iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true := by
  unfold macIfaces; decide

lemma carrier_output_checks : ∀ carrier ∈ carriers,
    (Execution.ifaceAt ifaces carrier.virtualIface).stack =
      (Execution.ifaceAt ifaces carrier.routingIface).stack := by
  unfold carriers ifaces; decide

lemma carrier_route_checks : CarrierRouteChecks devices ifaces routes carriers := by
  unfold CarrierRouteChecks devices ifaces routes carriers; decide

lemma carrier_peer_checks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
    CarrierPeers sender receiver →
      (Execution.ifaceAt ifaces sender.virtualIface).stack =
        (Execution.ifaceAt ifaces receiver.virtualIface).stack := by
  unfold carriers ifaces CarrierPeers; decide

lemma mixed_local_conditions : LocalConditions config expectedEncapStack :=
  local_conditions_from_finite_checks devices ifaces routes links bridges macIfaces carriers
    ip_local_conditions link_stack_checks bridge_stack_checks mac_transmit_checks mac_receive_checks
    mac_role_checks mac_secure_checks carrier_output_checks carrier_route_checks carrier_peer_checks

lemma red_sources_checked : ∀ iface ∈ redSources, expectedEncapStack iface = [] ∧ config.ip.payloadOrigin iface := by
  unfold redSources expectedEncapStack config MultiProtocolExecution.dataPlaneConfigFromRecords Execution.dataPlaneConfigFromRecords
    Execution.expectedEncapStackFromRecords ifaces; decide

lemma gray_ifaces_checked : ∀ iface ∈ grayIfaces, expectedEncapStack iface = [1] := by
  unfold grayIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

lemma black_ifaces_checked : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1] := by
  unfold blackIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

theorem every_red_origin_transmission_has_gray_or_black_protection
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) :
    (finish.iface ∈ grayIfaces → finish.frame.body.protectionLayers = [1]) ∧
    (finish.iface ∈ blackIfaces → finish.frame.body.protectionLayers = [2, 1]) := by
  have initial := Targets.mixed_red_initial_invariant config expectedEncapStack redSources red_sources_checked source
  have preserved := all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  exact ⟨fun member => layers.trans (gray_ifaces_checked finish.iface member),
    fun member => layers.trans (black_ifaces_checked finish.iface member)⟩

lemma outer_iface_shapes : ∀ iface ∈ ({} : Execution.IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces; decide

theorem actual_inner_encryption_precedes_outer {start finish : MultiProtocolExecution.State}
    {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolExecution.OrderedEncryptions config 1 2 start actions finish :=
  Targets.mixed_black_transmission_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (Execution.iface_at_member_or_default ifaces iface))
    source run ready black

theorem every_mixed_execution_keeps_actual_layers {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish)
    (initial : StackInvariant config expectedEncapStack start) :
    StackInvariant config expectedEncapStack finish :=
  all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial

end TDN.Imported.PairingIpsecIpsecIntegrated

namespace TDN.Imported.PairingIpsecMacsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma ip_peer_tag_checks : Execution.FinitePeerTagAgreement devices := by
  unfold Execution.FinitePeerTagAgreement Execution.StateBindsPolicy Execution.SameWireAssociation devices
  decide

lemma ip_peer_wire_tag_agreement : Execution.PeerTagAgreement config.ip :=
  Execution.finite_peer_tag_agreement_sound devices ifaces routes links [] ip_peer_tag_checks

theorem reachable_IPsec_seals_have_actual_transmit_provenance
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish) :
    ProducedIPBodies config finish.frame.body := by
  apply all_executions_preserve_ip_provenance config run
  rcases source.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [ProducedIPBodies, plain]

lemma route_owner_checks : ∀ route ∈ routes,
    (Execution.ifaceAt ifaces route.egress).owner = (Execution.ifaceAt ifaces route.ingress).owner := by
  unfold routes ifaces; decide

lemma link_stack_checks : ∀ edge ∈ links,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold links ifaces; decide

lemma bridge_stack_checks : ∀ edge ∈ bridges,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold bridges ifaces; decide

lemma forward_checks : Execution.FiniteRoutedForwardChecks devices ifaces routes := by
  unfold Execution.FiniteRoutedForwardChecks devices ifaces routes; decide

lemma output_checks : Execution.FiniteOutputChecks devices ifaces := by
  unfold Execution.FiniteOutputChecks devices ifaces; decide

lemma outer_route_checks : Execution.FiniteOuterRoutes devices ifaces routes := by
  unfold Execution.FiniteOuterRoutes devices ifaces routes; decide

lemma ip_local_conditions : Execution.LocalStackConditions config.ip expectedEncapStack := by
  exact Execution.local_stack_conditions_of_routed_finite_checks devices ifaces routes links []
    route_owner_checks link_stack_checks (by simp)
    (by unfold devices; decide) forward_checks output_checks outer_route_checks

lemma mac_transmit_checks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface := by
  unfold macIfaces ifaces; decide

lemma mac_receive_checks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    association.tag :: (Execution.ifaceAt ifaces iface.logicalIface).stack =
      (Execution.ifaceAt ifaces iface.physicalIface).stack := by
  unfold macIfaces ifaces; decide

lemma mac_role_checks : ∀ sender ∈ macIfaces, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ macIfaces,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag := by
  simp [macIfaces, SameMACWireIdentity]

lemma mac_secure_checks : ∀ iface ∈ macIfaces,
    iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
    iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true := by
  unfold macIfaces; decide

lemma carrier_output_checks : ∀ carrier ∈ carriers,
    (Execution.ifaceAt ifaces carrier.virtualIface).stack =
      (Execution.ifaceAt ifaces carrier.routingIface).stack := by
  unfold carriers ifaces; decide

lemma carrier_route_checks : CarrierRouteChecks devices ifaces routes carriers := by
  unfold CarrierRouteChecks devices ifaces routes carriers; decide

lemma carrier_peer_checks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
    CarrierPeers sender receiver →
      (Execution.ifaceAt ifaces sender.virtualIface).stack =
        (Execution.ifaceAt ifaces receiver.virtualIface).stack := by
  unfold carriers ifaces CarrierPeers; decide

lemma mixed_local_conditions : LocalConditions config expectedEncapStack :=
  local_conditions_from_finite_checks devices ifaces routes links bridges macIfaces carriers
    ip_local_conditions link_stack_checks bridge_stack_checks mac_transmit_checks mac_receive_checks
    mac_role_checks mac_secure_checks carrier_output_checks carrier_route_checks carrier_peer_checks

lemma red_sources_checked : ∀ iface ∈ redSources, expectedEncapStack iface = [] ∧ config.ip.payloadOrigin iface := by
  unfold redSources expectedEncapStack config MultiProtocolExecution.dataPlaneConfigFromRecords Execution.dataPlaneConfigFromRecords
    Execution.expectedEncapStackFromRecords ifaces; decide

lemma gray_ifaces_checked : ∀ iface ∈ grayIfaces, expectedEncapStack iface = [1] := by
  unfold grayIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

lemma black_ifaces_checked : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1] := by
  unfold blackIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

theorem every_red_origin_transmission_has_gray_or_black_protection
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) :
    (finish.iface ∈ grayIfaces → finish.frame.body.protectionLayers = [1]) ∧
    (finish.iface ∈ blackIfaces → finish.frame.body.protectionLayers = [2, 1]) := by
  have initial := Targets.mixed_red_initial_invariant config expectedEncapStack redSources red_sources_checked source
  have preserved := all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  exact ⟨fun member => layers.trans (gray_ifaces_checked finish.iface member),
    fun member => layers.trans (black_ifaces_checked finish.iface member)⟩

lemma outer_iface_shapes : ∀ iface ∈ ({} : Execution.IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces; decide

theorem actual_inner_encryption_precedes_outer {start finish : MultiProtocolExecution.State}
    {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolExecution.OrderedEncryptions config 1 2 start actions finish :=
  Targets.mixed_black_transmission_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (Execution.iface_at_member_or_default ifaces iface))
    source run ready black

theorem every_mixed_execution_keeps_actual_layers {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish)
    (initial : StackInvariant config expectedEncapStack start) :
    StackInvariant config expectedEncapStack finish :=
  all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial

end TDN.Imported.PairingIpsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma ip_peer_tag_checks : Execution.FinitePeerTagAgreement devices := by
  unfold Execution.FinitePeerTagAgreement Execution.StateBindsPolicy Execution.SameWireAssociation devices
  decide

lemma ip_peer_wire_tag_agreement : Execution.PeerTagAgreement config.ip :=
  Execution.finite_peer_tag_agreement_sound devices ifaces routes links [] ip_peer_tag_checks

theorem reachable_IPsec_seals_have_actual_transmit_provenance
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish) :
    ProducedIPBodies config finish.frame.body := by
  apply all_executions_preserve_ip_provenance config run
  rcases source.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [ProducedIPBodies, plain]

lemma route_owner_checks : ∀ route ∈ routes,
    (Execution.ifaceAt ifaces route.egress).owner = (Execution.ifaceAt ifaces route.ingress).owner := by
  unfold routes ifaces; decide

lemma link_stack_checks : ∀ edge ∈ links,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold links ifaces; decide

lemma bridge_stack_checks : ∀ edge ∈ bridges,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold bridges ifaces; decide

lemma forward_checks : Execution.FiniteRoutedForwardChecks devices ifaces routes := by
  unfold Execution.FiniteRoutedForwardChecks devices ifaces routes; decide

lemma output_checks : Execution.FiniteOutputChecks devices ifaces := by
  unfold Execution.FiniteOutputChecks devices ifaces; decide

lemma outer_route_checks : Execution.FiniteOuterRoutes devices ifaces routes := by
  unfold Execution.FiniteOuterRoutes devices ifaces routes; decide

lemma ip_local_conditions : Execution.LocalStackConditions config.ip expectedEncapStack := by
  exact Execution.local_stack_conditions_of_routed_finite_checks devices ifaces routes links []
    route_owner_checks link_stack_checks (by simp)
    (by unfold devices; decide) forward_checks output_checks outer_route_checks

lemma mac_transmit_checks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface := by
  unfold macIfaces ifaces; decide

lemma mac_receive_checks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    association.tag :: (Execution.ifaceAt ifaces iface.logicalIface).stack =
      (Execution.ifaceAt ifaces iface.physicalIface).stack := by
  unfold macIfaces ifaces; decide

lemma mac_role_checks : ∀ sender ∈ macIfaces, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ macIfaces,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag := by
  simp [macIfaces, SameMACWireIdentity]

lemma mac_secure_checks : ∀ iface ∈ macIfaces,
    iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
    iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true := by
  unfold macIfaces; decide

lemma carrier_output_checks : ∀ carrier ∈ carriers,
    (Execution.ifaceAt ifaces carrier.virtualIface).stack =
      (Execution.ifaceAt ifaces carrier.routingIface).stack := by
  unfold carriers ifaces; decide

lemma carrier_route_checks : CarrierRouteChecks devices ifaces routes carriers := by
  unfold CarrierRouteChecks devices ifaces routes carriers; decide

lemma carrier_peer_checks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
    CarrierPeers sender receiver →
      (Execution.ifaceAt ifaces sender.virtualIface).stack =
        (Execution.ifaceAt ifaces receiver.virtualIface).stack := by
  unfold carriers ifaces CarrierPeers; decide

lemma mixed_local_conditions : LocalConditions config expectedEncapStack :=
  local_conditions_from_finite_checks devices ifaces routes links bridges macIfaces carriers
    ip_local_conditions link_stack_checks bridge_stack_checks mac_transmit_checks mac_receive_checks
    mac_role_checks mac_secure_checks carrier_output_checks carrier_route_checks carrier_peer_checks

lemma red_sources_checked : ∀ iface ∈ redSources, expectedEncapStack iface = [] ∧ config.ip.payloadOrigin iface := by
  unfold redSources expectedEncapStack config MultiProtocolExecution.dataPlaneConfigFromRecords Execution.dataPlaneConfigFromRecords
    Execution.expectedEncapStackFromRecords ifaces; decide

lemma gray_ifaces_checked : ∀ iface ∈ grayIfaces, expectedEncapStack iface = [1] := by
  unfold grayIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

lemma black_ifaces_checked : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1] := by
  unfold blackIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

theorem every_red_origin_transmission_has_gray_or_black_protection
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) :
    (finish.iface ∈ grayIfaces → finish.frame.body.protectionLayers = [1]) ∧
    (finish.iface ∈ blackIfaces → finish.frame.body.protectionLayers = [2, 1]) := by
  have initial := Targets.mixed_red_initial_invariant config expectedEncapStack redSources red_sources_checked source
  have preserved := all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  exact ⟨fun member => layers.trans (gray_ifaces_checked finish.iface member),
    fun member => layers.trans (black_ifaces_checked finish.iface member)⟩

lemma outer_iface_shapes : ∀ iface ∈ ({} : Execution.IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces; decide

theorem actual_inner_encryption_precedes_outer {start finish : MultiProtocolExecution.State}
    {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolExecution.OrderedEncryptions config 1 2 start actions finish :=
  Targets.mixed_black_transmission_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (Execution.iface_at_member_or_default ifaces iface))
    source run ready black

theorem every_mixed_execution_keeps_actual_layers {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish)
    (initial : StackInvariant config expectedEncapStack start) :
    StackInvariant config expectedEncapStack finish :=
  all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial

end TDN.Imported.PairingMacsecIpsecIntegrated

namespace TDN.Imported.PairingMacsecIpsecStandalone
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma ip_peer_tag_checks : Execution.FinitePeerTagAgreement devices := by
  unfold Execution.FinitePeerTagAgreement Execution.StateBindsPolicy Execution.SameWireAssociation devices
  decide

lemma ip_peer_wire_tag_agreement : Execution.PeerTagAgreement config.ip :=
  Execution.finite_peer_tag_agreement_sound devices ifaces routes links [] ip_peer_tag_checks

theorem reachable_IPsec_seals_have_actual_transmit_provenance
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish) :
    ProducedIPBodies config finish.frame.body := by
  apply all_executions_preserve_ip_provenance config run
  rcases source.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [ProducedIPBodies, plain]

lemma route_owner_checks : ∀ route ∈ routes,
    (Execution.ifaceAt ifaces route.egress).owner = (Execution.ifaceAt ifaces route.ingress).owner := by
  unfold routes ifaces; decide

lemma link_stack_checks : ∀ edge ∈ links,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold links ifaces; decide

lemma bridge_stack_checks : ∀ edge ∈ bridges,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold bridges ifaces; decide

lemma forward_checks : Execution.FiniteRoutedForwardChecks devices ifaces routes := by
  unfold Execution.FiniteRoutedForwardChecks devices ifaces routes; decide

lemma output_checks : Execution.FiniteOutputChecks devices ifaces := by
  unfold Execution.FiniteOutputChecks devices ifaces; decide

lemma outer_route_checks : Execution.FiniteOuterRoutes devices ifaces routes := by
  unfold Execution.FiniteOuterRoutes devices ifaces routes; decide

lemma ip_local_conditions : Execution.LocalStackConditions config.ip expectedEncapStack := by
  exact Execution.local_stack_conditions_of_routed_finite_checks devices ifaces routes links []
    route_owner_checks link_stack_checks (by simp)
    (by unfold devices; decide) forward_checks output_checks outer_route_checks

lemma mac_transmit_checks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface := by
  unfold macIfaces ifaces; decide

lemma mac_receive_checks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    association.tag :: (Execution.ifaceAt ifaces iface.logicalIface).stack =
      (Execution.ifaceAt ifaces iface.physicalIface).stack := by
  unfold macIfaces ifaces; decide

lemma mac_role_checks : ∀ sender ∈ macIfaces, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ macIfaces,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag := by
  simp [macIfaces, SameMACWireIdentity]

lemma mac_secure_checks : ∀ iface ∈ macIfaces,
    iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
    iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true := by
  unfold macIfaces; decide

lemma carrier_output_checks : ∀ carrier ∈ carriers,
    (Execution.ifaceAt ifaces carrier.virtualIface).stack =
      (Execution.ifaceAt ifaces carrier.routingIface).stack := by
  unfold carriers ifaces; decide

lemma carrier_route_checks : CarrierRouteChecks devices ifaces routes carriers := by
  unfold CarrierRouteChecks devices ifaces routes carriers; decide

lemma carrier_peer_checks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
    CarrierPeers sender receiver →
      (Execution.ifaceAt ifaces sender.virtualIface).stack =
        (Execution.ifaceAt ifaces receiver.virtualIface).stack := by
  unfold carriers ifaces CarrierPeers; decide

lemma mixed_local_conditions : LocalConditions config expectedEncapStack :=
  local_conditions_from_finite_checks devices ifaces routes links bridges macIfaces carriers
    ip_local_conditions link_stack_checks bridge_stack_checks mac_transmit_checks mac_receive_checks
    mac_role_checks mac_secure_checks carrier_output_checks carrier_route_checks carrier_peer_checks

lemma red_sources_checked : ∀ iface ∈ redSources, expectedEncapStack iface = [] ∧ config.ip.payloadOrigin iface := by
  unfold redSources expectedEncapStack config MultiProtocolExecution.dataPlaneConfigFromRecords Execution.dataPlaneConfigFromRecords
    Execution.expectedEncapStackFromRecords ifaces; decide

lemma gray_ifaces_checked : ∀ iface ∈ grayIfaces, expectedEncapStack iface = [1] := by
  unfold grayIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

lemma black_ifaces_checked : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1] := by
  unfold blackIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

theorem every_red_origin_transmission_has_gray_or_black_protection
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) :
    (finish.iface ∈ grayIfaces → finish.frame.body.protectionLayers = [1]) ∧
    (finish.iface ∈ blackIfaces → finish.frame.body.protectionLayers = [2, 1]) := by
  have initial := Targets.mixed_red_initial_invariant config expectedEncapStack redSources red_sources_checked source
  have preserved := all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  exact ⟨fun member => layers.trans (gray_ifaces_checked finish.iface member),
    fun member => layers.trans (black_ifaces_checked finish.iface member)⟩

lemma outer_iface_shapes : ∀ iface ∈ ({} : Execution.IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces; decide

theorem actual_inner_encryption_precedes_outer {start finish : MultiProtocolExecution.State}
    {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolExecution.OrderedEncryptions config 1 2 start actions finish :=
  Targets.mixed_black_transmission_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (Execution.iface_at_member_or_default ifaces iface))
    source run ready black

theorem every_mixed_execution_keeps_actual_layers {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish)
    (initial : StackInvariant config expectedEncapStack start) :
    StackInvariant config expectedEncapStack finish :=
  all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial

end TDN.Imported.PairingMacsecIpsecStandalone

namespace TDN.Imported.PairingMacsecMacsecIntegrated
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma ip_peer_tag_checks : Execution.FinitePeerTagAgreement devices := by
  unfold Execution.FinitePeerTagAgreement Execution.StateBindsPolicy Execution.SameWireAssociation devices
  decide

lemma ip_peer_wire_tag_agreement : Execution.PeerTagAgreement config.ip :=
  Execution.finite_peer_tag_agreement_sound devices ifaces routes links [] ip_peer_tag_checks

theorem reachable_IPsec_seals_have_actual_transmit_provenance
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish) :
    ProducedIPBodies config finish.frame.body := by
  apply all_executions_preserve_ip_provenance config run
  rcases source.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [ProducedIPBodies, plain]

lemma route_owner_checks : ∀ route ∈ routes,
    (Execution.ifaceAt ifaces route.egress).owner = (Execution.ifaceAt ifaces route.ingress).owner := by
  unfold routes ifaces; decide

lemma link_stack_checks : ∀ edge ∈ links,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold links ifaces; decide

lemma bridge_stack_checks : ∀ edge ∈ bridges,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold bridges ifaces; decide

lemma forward_checks : Execution.FiniteRoutedForwardChecks devices ifaces routes := by
  unfold Execution.FiniteRoutedForwardChecks devices ifaces routes; decide

lemma output_checks : Execution.FiniteOutputChecks devices ifaces := by
  unfold Execution.FiniteOutputChecks devices ifaces; decide

lemma outer_route_checks : Execution.FiniteOuterRoutes devices ifaces routes := by
  unfold Execution.FiniteOuterRoutes devices ifaces routes; decide

lemma ip_local_conditions : Execution.LocalStackConditions config.ip expectedEncapStack := by
  exact Execution.local_stack_conditions_of_routed_finite_checks devices ifaces routes links []
    route_owner_checks link_stack_checks (by simp)
    (by unfold devices; decide) forward_checks output_checks outer_route_checks

lemma mac_transmit_checks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface := by
  unfold macIfaces ifaces; decide

lemma mac_receive_checks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    association.tag :: (Execution.ifaceAt ifaces iface.logicalIface).stack =
      (Execution.ifaceAt ifaces iface.physicalIface).stack := by
  unfold macIfaces ifaces; decide

lemma mac_role_checks : ∀ sender ∈ macIfaces, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ macIfaces,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag := by
  simp [macIfaces, SameMACWireIdentity]

lemma mac_secure_checks : ∀ iface ∈ macIfaces,
    iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
    iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true := by
  unfold macIfaces; decide

lemma carrier_output_checks : ∀ carrier ∈ carriers,
    (Execution.ifaceAt ifaces carrier.virtualIface).stack =
      (Execution.ifaceAt ifaces carrier.routingIface).stack := by
  unfold carriers ifaces; decide

lemma carrier_route_checks : CarrierRouteChecks devices ifaces routes carriers := by
  unfold CarrierRouteChecks devices ifaces routes carriers; decide

lemma carrier_peer_checks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
    CarrierPeers sender receiver →
      (Execution.ifaceAt ifaces sender.virtualIface).stack =
        (Execution.ifaceAt ifaces receiver.virtualIface).stack := by
  unfold carriers ifaces CarrierPeers; decide

lemma mixed_local_conditions : LocalConditions config expectedEncapStack :=
  local_conditions_from_finite_checks devices ifaces routes links bridges macIfaces carriers
    ip_local_conditions link_stack_checks bridge_stack_checks mac_transmit_checks mac_receive_checks
    mac_role_checks mac_secure_checks carrier_output_checks carrier_route_checks carrier_peer_checks

lemma red_sources_checked : ∀ iface ∈ redSources, expectedEncapStack iface = [] ∧ config.ip.payloadOrigin iface := by
  unfold redSources expectedEncapStack config MultiProtocolExecution.dataPlaneConfigFromRecords Execution.dataPlaneConfigFromRecords
    Execution.expectedEncapStackFromRecords ifaces; decide

lemma gray_ifaces_checked : ∀ iface ∈ grayIfaces, expectedEncapStack iface = [1] := by
  unfold grayIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

lemma black_ifaces_checked : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1] := by
  unfold blackIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

theorem every_red_origin_transmission_has_gray_or_black_protection
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) :
    (finish.iface ∈ grayIfaces → finish.frame.body.protectionLayers = [1]) ∧
    (finish.iface ∈ blackIfaces → finish.frame.body.protectionLayers = [2, 1]) := by
  have initial := Targets.mixed_red_initial_invariant config expectedEncapStack redSources red_sources_checked source
  have preserved := all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  exact ⟨fun member => layers.trans (gray_ifaces_checked finish.iface member),
    fun member => layers.trans (black_ifaces_checked finish.iface member)⟩

lemma outer_iface_shapes : ∀ iface ∈ ({} : Execution.IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces; decide

theorem actual_inner_encryption_precedes_outer {start finish : MultiProtocolExecution.State}
    {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolExecution.OrderedEncryptions config 1 2 start actions finish :=
  Targets.mixed_black_transmission_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (Execution.iface_at_member_or_default ifaces iface))
    source run ready black

theorem every_mixed_execution_keeps_actual_layers {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish)
    (initial : StackInvariant config expectedEncapStack start) :
    StackInvariant config expectedEncapStack finish :=
  all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial

end TDN.Imported.PairingMacsecMacsecIntegrated

namespace TDN.Imported.PairingMacsecMacsecStandalone
open MultiProtocolExecution LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma ip_peer_tag_checks : Execution.FinitePeerTagAgreement devices := by
  unfold Execution.FinitePeerTagAgreement Execution.StateBindsPolicy Execution.SameWireAssociation devices
  decide

lemma ip_peer_wire_tag_agreement : Execution.PeerTagAgreement config.ip :=
  Execution.finite_peer_tag_agreement_sound devices ifaces routes links [] ip_peer_tag_checks

theorem reachable_IPsec_seals_have_actual_transmit_provenance
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish) :
    ProducedIPBodies config finish.frame.body := by
  apply all_executions_preserve_ip_provenance config run
  rcases source.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [ProducedIPBodies, plain]

lemma route_owner_checks : ∀ route ∈ routes,
    (Execution.ifaceAt ifaces route.egress).owner = (Execution.ifaceAt ifaces route.ingress).owner := by
  unfold routes ifaces; decide

lemma link_stack_checks : ∀ edge ∈ links,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold links ifaces; decide

lemma bridge_stack_checks : ∀ edge ∈ bridges,
    (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack := by
  unfold bridges ifaces; decide

lemma forward_checks : Execution.FiniteRoutedForwardChecks devices ifaces routes := by
  unfold Execution.FiniteRoutedForwardChecks devices ifaces routes; decide

lemma output_checks : Execution.FiniteOutputChecks devices ifaces := by
  unfold Execution.FiniteOutputChecks devices ifaces; decide

lemma outer_route_checks : Execution.FiniteOuterRoutes devices ifaces routes := by
  unfold Execution.FiniteOuterRoutes devices ifaces routes; decide

lemma ip_local_conditions : Execution.LocalStackConditions config.ip expectedEncapStack := by
  exact Execution.local_stack_conditions_of_routed_finite_checks devices ifaces routes links []
    route_owner_checks link_stack_checks (by simp)
    (by unfold devices; decide) forward_checks output_checks outer_route_checks

lemma mac_transmit_checks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface := by
  unfold macIfaces ifaces; decide

lemma mac_receive_checks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    association.tag :: (Execution.ifaceAt ifaces iface.logicalIface).stack =
      (Execution.ifaceAt ifaces iface.physicalIface).stack := by
  unfold macIfaces ifaces; decide

lemma mac_role_checks : ∀ sender ∈ macIfaces, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ macIfaces,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag := by
  simp [macIfaces, SameMACWireIdentity]

lemma mac_secure_checks : ∀ iface ∈ macIfaces,
    iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
    iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true := by
  unfold macIfaces; decide

lemma carrier_output_checks : ∀ carrier ∈ carriers,
    (Execution.ifaceAt ifaces carrier.virtualIface).stack =
      (Execution.ifaceAt ifaces carrier.routingIface).stack := by
  unfold carriers ifaces; decide

lemma carrier_route_checks : CarrierRouteChecks devices ifaces routes carriers := by
  unfold CarrierRouteChecks devices ifaces routes carriers; decide

lemma carrier_peer_checks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
    CarrierPeers sender receiver →
      (Execution.ifaceAt ifaces sender.virtualIface).stack =
        (Execution.ifaceAt ifaces receiver.virtualIface).stack := by
  unfold carriers ifaces CarrierPeers; decide

lemma mixed_local_conditions : LocalConditions config expectedEncapStack :=
  local_conditions_from_finite_checks devices ifaces routes links bridges macIfaces carriers
    ip_local_conditions link_stack_checks bridge_stack_checks mac_transmit_checks mac_receive_checks
    mac_role_checks mac_secure_checks carrier_output_checks carrier_route_checks carrier_peer_checks

lemma red_sources_checked : ∀ iface ∈ redSources, expectedEncapStack iface = [] ∧ config.ip.payloadOrigin iface := by
  unfold redSources expectedEncapStack config MultiProtocolExecution.dataPlaneConfigFromRecords Execution.dataPlaneConfigFromRecords
    Execution.expectedEncapStackFromRecords ifaces; decide

lemma gray_ifaces_checked : ∀ iface ∈ grayIfaces, expectedEncapStack iface = [1] := by
  unfold grayIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

lemma black_ifaces_checked : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1] := by
  unfold blackIfaces expectedEncapStack Execution.expectedEncapStackFromRecords ifaces; decide

theorem every_red_origin_transmission_has_gray_or_black_protection
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) :
    (finish.iface ∈ grayIfaces → finish.frame.body.protectionLayers = [1]) ∧
    (finish.iface ∈ blackIfaces → finish.frame.body.protectionLayers = [2, 1]) := by
  have initial := Targets.mixed_red_initial_invariant config expectedEncapStack redSources red_sources_checked source
  have preserved := all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  exact ⟨fun member => layers.trans (gray_ifaces_checked finish.iface member),
    fun member => layers.trans (black_ifaces_checked finish.iface member)⟩

lemma outer_iface_shapes : ∀ iface ∈ ({} : Execution.IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces; decide

theorem actual_inner_encryption_precedes_outer {start finish : MultiProtocolExecution.State}
    {actions : List MultiProtocolExecution.Action}
    (source : Targets.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolExecution.OrderedEncryptions config 1 2 start actions finish :=
  Targets.mixed_black_transmission_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (Execution.iface_at_member_or_default ifaces iface))
    source run ready black

theorem every_mixed_execution_keeps_actual_layers {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (run : (lts config).MTr start actions finish)
    (initial : StackInvariant config expectedEncapStack start) :
    StackInvariant config expectedEncapStack finish :=
  all_executions_preserve_stack config expectedEncapStack mixed_local_conditions run initial

end TDN.Imported.PairingMacsecMacsecStandalone
