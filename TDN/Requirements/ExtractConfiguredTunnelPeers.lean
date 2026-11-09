import TDN.Requirements.ExtractAllowedIpProtocols

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

structure BoundaryPeer where
  source : String
  destination : String
  sourceAddress : Nat
  destinationAddress : Nat
  deriving DecidableEq

def BoundaryPeer.Bound (record : BoundaryPeer) (d : Deployment) : Prop :=
  (∃ interface ∈ d.interfaces, interface.device = record.source ∧
    interface.address = some record.sourceAddress) ∧
  (∃ interface ∈ d.interfaces, interface.device = record.destination ∧
    interface.address = some record.destinationAddress) ∧
  d.intendedPeer record.source record.destination

instance boundaryPeerBoundDecidable (record : BoundaryPeer) (d : Deployment) [DecidableRel d.intendedPeer] :
    Decidable (record.Bound d) := by
  unfold BoundaryPeer.Bound
  infer_instance

lemma bound_IP_peer_has_intended_destination (d : Deployment)
    (coherent : d.AddressInventoryCoherent) (record : BoundaryPeer) (bound : record.Bound d)
    (traffic : Traffic) (supported : d.Supported traffic)
    (protocol : traffic.packet.protocol ≠ "ethernet")
    (destination : traffic.packet.destination = record.destinationAddress) :
    d.IntendedPacketPeer record.source traffic := by
  obtain ⟨_, ⟨interface, member, owner, assigned⟩, intended⟩ := bound
  have packetAddress : interface.PacketAddress traffic.packet = some traffic.packet.destination := by
    simp [Interface.PacketAddress, protocol, destination, assigned]
  have metadata := packet_owner_of_interface d traffic.packet interface member _ packetAddress
    (DeriveEndpointInputOutputRules.address_inventory_owner_uniqueness d coherent traffic.packet _)
  exact Or.inl ⟨record.destination,
    (congrArg Traffic.destinationDevice supported.1).trans (metadata.trans (congrArg some owner)),
    intended⟩


theorem outbound_boundary_peer_from_raw_destination_or_required_transform
    (d : Deployment) (coherent : d.AddressInventoryCoherent)
    (configuration : Config) (context : PacketProcessing.Context)
    (device : String) (peers : List BoundaryPeer)
    (bound : ∀ record ∈ peers, record.Bound d)
    (policies : ∀ policy ∈ configuration.ip.egressPolicies context.state.iface,
      ∃ record ∈ peers, record.source = device ∧ policy.receiver = record.destinationAddress)
    (iface : Nat) (packet : PacketPolicy.Packet) (traffic : Traffic)
    (supported : d.Supported traffic) (samePacket : traffic.packet = packet)
    (visible : configuration.visibleHeader context.state.frame = some context.header)
    (view : DeviceBoundaryView configuration context .outbound iface packet)
    (permitted : iface = context.state.iface →
      (∃ record ∈ peers, record.source = device ∧
        context.header.destination = record.destinationAddress ∧ context.header.protocol ≠ "ethernet") ∨
      ∃ requestId, requestId ∈ (context.Packet configuration).matchedOutboundPolicyIds) :
    d.IntendedPacketPeer device traffic := by
  cases view with
  | outbound filtered ready afterWire filter run wire header boundaryVisible =>
    have preserved := boundary_filter_preserves_frame_and_iface configuration context filtered filter
    have filteredVisible : configuration.visibleHeader filtered.frame = some context.header := by
      simpa only [preserved.1] using visible
    have generatedPeer : ∀ encrypted,
        MultiProtocolForwarding.Step configuration filtered .encryptIPsec encrypted →
        MultiProtocolForwarding.Step configuration encrypted .route ready →
        d.IntendedPacketPeer device traffic := by
      intro encrypted protect route
      obtain ⟨policy, member, association, installed, selected, actual, actualVisible,
        source, destination, protocol⟩ :=
        IPsec_suffix_boundary_packet_uses_installed_policy configuration protect route
      have actualSame : actual = header := Option.some.inj (actualVisible.symm.trans boundaryVisible)
      subst actual
      have policyMember : policy ∈ configuration.ip.egressPolicies context.state.iface := by
        simpa only [preserved.2.1] using member
      obtain ⟨record, recordMember, owner, peer⟩ := policies policy policyMember
      have finalProtocol : traffic.packet.protocol ≠ "ethernet" := by
        rw [samePacket]
        change header.protocol ≠ "ethernet"
        have esp : header.protocol = "esp" := protocol
        simp [esp]
      have finalDestination : traffic.packet.destination = record.destinationAddress := by
        rw [samePacket]
        exact destination.trans peer
      simpa only [owner] using bound_IP_peer_has_intended_destination d coherent record
        (bound record recordMember) traffic supported finalProtocol finalDestination
    have suffix := first_ready_run_from_filtered_is_native_suffix configuration preserved.2.2 run
    cases suffix with
    | IPsec protect route => exact generatedPeer _ protect route
    | forwardWithoutEncap step datapathStage =>
      have sameIface : ready.iface = context.state.iface := by
        have ifaceSame : ready.iface = filtered.iface := by cases step <;> simp_all
        exact ifaceSame.trans preserved.2.1
      rcases permitted sameIface with ⟨record, recordMember, owner, peer, protocol⟩ | ⟨requestId, required⟩
      · have frameSame : ready.frame = filtered.frame := by
          cases step <;> simp_all
        have actualVisible : configuration.visibleHeader ready.frame = some context.header :=
          (congrArg configuration.visibleHeader frameSame).trans filteredVisible
        have headerSame : header = context.header :=
          Option.some.inj (boundaryVisible.symm.trans actualVisible)
        have finalProtocol : traffic.packet.protocol ≠ "ethernet" := by
          rw [samePacket]
          change header.protocol ≠ "ethernet"
          exact headerSame ▸ protocol
        have finalDestination : traffic.packet.destination = record.destinationAddress := by
          rw [samePacket]
          change header.destination = record.destinationAddress
          exact headerSame ▸ peer
        simpa only [owner] using bound_IP_peer_has_intended_destination d coherent record
          (bound record recordMember) traffic supported finalProtocol finalDestination
      · have annotation := boundary_filter_preserves_outbound_annotation configuration context filtered
          filter requestId required
        have impossible : False := by
          cases step <;> simp_all [policyHeader]
        exact impossible.elim

end TDN.Requirements.Msc
