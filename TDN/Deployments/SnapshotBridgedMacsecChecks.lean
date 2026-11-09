import TDN.Deployments.SnapshotBridgedMacsecConfig
import TDN.Models.MultiProtocolSaOriginAttribution

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec
open MultiProtocolForwarding LayeredFrame
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma ip_peer_tag_checks : DataPlaneForwarding.TableDrivenPeerTagAgreement devices := by
  unfold DataPlaneForwarding.TableDrivenPeerTagAgreement DataPlaneForwarding.saMatchesPolicy DataPlaneForwarding.SameWireAssociation devices
  decide

lemma ip_peer_wire_tag_agreement : DataPlaneForwarding.PeerTagAgreement config.ip :=
  DataPlaneForwarding.table_driven_peer_tag_agreement_sound devices ifaces routes links [] ip_peer_tag_checks

theorem reachable_IPsec_seals_have_actual_transmit_provenance
    {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (source : Requirements.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish) :
    ProducedIPBodies config finish.frame.body := by
  apply all_traces_preserve_ip_provenance config run
  rcases source.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [ProducedIPBodies, plain]

lemma route_owner_checks : ∀ route ∈ routes,
    (DataPlaneForwarding.ifaceAt ifaces route.egress).owner = (DataPlaneForwarding.ifaceAt ifaces route.ingress).owner := by
  unfold routes ifaces; decide

lemma link_stack_checks : ∀ edge ∈ links,
    (DataPlaneForwarding.ifaceAt ifaces edge.1).stack = (DataPlaneForwarding.ifaceAt ifaces edge.2).stack := by
  unfold links ifaces; decide

lemma bridge_stack_checks : ∀ edge ∈ bridges,
    (DataPlaneForwarding.ifaceAt ifaces edge.1).stack = (DataPlaneForwarding.ifaceAt ifaces edge.2).stack := by
  unfold bridges ifaces; decide

lemma forward_checks : DataPlaneForwarding.TableDrivenRoutedForwardChecks devices ifaces routes := by
  unfold DataPlaneForwarding.TableDrivenRoutedForwardChecks devices ifaces routes; decide

lemma output_checks : DataPlaneForwarding.TableDrivenOutputChecks devices ifaces := by
  unfold DataPlaneForwarding.TableDrivenOutputChecks devices ifaces; decide

lemma outer_route_checks : DataPlaneForwarding.TableDrivenOuterRoutes devices ifaces routes := by
  unfold DataPlaneForwarding.TableDrivenOuterRoutes devices ifaces routes; decide

lemma ip_local_conditions : DataPlaneForwarding.PerHopEncapConditions config.ip expectedEncapStack := by
  exact DataPlaneForwarding.local_stack_conditions_of_routed_finite_checks devices ifaces routes links []
    route_owner_checks link_stack_checks (by simp)
    (by unfold devices; decide) forward_checks output_checks outer_route_checks

lemma mac_transmit_checks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface := by
  unfold macIfaces ifaces; decide

lemma mac_receive_checks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
    association.tag :: (DataPlaneForwarding.ifaceAt ifaces iface.logicalIface).stack =
      (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).stack := by
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
    (DataPlaneForwarding.ifaceAt ifaces carrier.virtualIface).stack =
      (DataPlaneForwarding.ifaceAt ifaces carrier.routingIface).stack := by
  unfold carriers ifaces; decide

lemma carrier_route_checks : CarrierRouteChecks devices ifaces routes carriers := by
  unfold CarrierRouteChecks devices ifaces routes carriers; decide

lemma carrier_peer_checks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
    CarrierPeers sender receiver →
      (DataPlaneForwarding.ifaceAt ifaces sender.virtualIface).stack =
        (DataPlaneForwarding.ifaceAt ifaces receiver.virtualIface).stack := by
  unfold carriers ifaces CarrierPeers; decide

lemma mixed_local_conditions : LocalConditions config expectedEncapStack :=
  local_conditions_from_finite_checks devices ifaces routes links bridges macIfaces carriers
    ip_local_conditions link_stack_checks bridge_stack_checks mac_transmit_checks mac_receive_checks
    mac_role_checks mac_secure_checks carrier_output_checks carrier_route_checks carrier_peer_checks

lemma red_sources_checked : ∀ iface ∈ redSources, expectedEncapStack iface = [] ∧ config.ip.canOriginateTraffic iface := by
  unfold redSources expectedEncapStack config MultiProtocolForwarding.dataPlaneModelFromRecords DataPlaneForwarding.dataPlaneModelFromRecords
    DataPlaneForwarding.expectedEncapStackFromRecords ifaces; decide

lemma gray_ifaces_checked : ∀ iface ∈ grayIfaces, expectedEncapStack iface = [1] := by
  unfold grayIfaces expectedEncapStack DataPlaneForwarding.expectedEncapStackFromRecords ifaces; decide

lemma black_ifaces_checked : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1] := by
  unfold blackIfaces expectedEncapStack DataPlaneForwarding.expectedEncapStackFromRecords ifaces; decide

theorem every_red_origin_transmission_has_gray_or_black_protection
    {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (source : Requirements.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) :
    (finish.iface ∈ grayIfaces → finish.frame.body.protectionLayers = [1]) ∧
    (finish.iface ∈ blackIfaces → finish.frame.body.protectionLayers = [2, 1]) := by
  have initial := Requirements.mixed_red_initial_invariant config expectedEncapStack redSources red_sources_checked source
  have preserved := all_traces_preserve_stack config expectedEncapStack mixed_local_conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  exact ⟨fun member => layers.trans (gray_ifaces_checked finish.iface member),
    fun member => layers.trans (black_ifaces_checked finish.iface member)⟩

lemma outer_iface_shapes : ∀ iface ∈ ({} : DataPlaneForwarding.IfaceData) :: ifaces,
    iface.stack.head? = some 2 → iface.stack = [2, 1] := by
  unfold ifaces; decide

theorem actual_inner_encryption_precedes_outer {start finish : MultiProtocolForwarding.State}
    {actions : List MultiProtocolForwarding.Action}
    (source : Requirements.MixedRedOrigin redSources start) (run : (lts config).MTr start actions finish)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolForwarding.OrderedEncryptions config 1 2 start actions finish :=
  Requirements.mixed_black_transmission_has_ordered_encryptions config expectedEncapStack redSources blackIfaces
    mixed_local_conditions red_sources_checked black_ifaces_checked
    (fun iface => outer_iface_shapes _ (DataPlaneForwarding.iface_at_member_or_default ifaces iface))
    source run ready black

theorem every_mixed_forwarding_keeps_actual_layers {start finish : MultiProtocolForwarding.State} {actions : List MultiProtocolForwarding.Action}
    (run : (lts config).MTr start actions finish)
    (initial : EncapStackConsistent config expectedEncapStack start) :
    EncapStackConsistent config expectedEncapStack finish :=
  all_traces_preserve_stack config expectedEncapStack mixed_local_conditions run initial

end TDN.Deployments.PairingInnerMacsecOuterIpsec
