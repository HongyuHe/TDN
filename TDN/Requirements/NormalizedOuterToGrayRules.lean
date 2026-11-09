import TDN.Requirements.OuterToGrayInterfaceAllowlist
import TDN.Models.MultiProtocolHeaderCoherence
import TDN.Models.RawIkeAndUdpEspByteOffsets

namespace TDN.Requirements.Msc
open Compliance DeriveEndpointInputOutputRules

lemma IPsecPacket.not_ethernet (packet : PacketPolicy.Packet) (ipsec : IPsecPacket packet) :
    packet.protocol ≠ "ethernet" := by
  rcases ipsec with esp | ike | udpESP
  · simp [esp]
  · simp [ike.1]
  · simp [udpESP.1]

lemma IPsecPacket.InnerPair_is_IP (d : Deployment) (traffic : Traffic)
    (source destination : String) (ipsec : IPsecPacket traffic.packet)
    (noCarriers : d.carrierBindings = []) (pair : d.InnerPair traffic source destination) :
    traffic.sourceDevice = some source ∧ traffic.destinationDevice = some destination ∧
      (∃ interface ∈ d.interfaces, interface.device = source ∧ interface.zone = .gray ∧
        interface.address = some traffic.packet.source) ∧
      ∃ interface ∈ d.interfaces, interface.device = destination ∧ interface.zone = .gray ∧
        interface.address = some traffic.packet.destination := by
  have nonEthernet := IPsecPacket.not_ethernet traffic.packet ipsec
  rcases pair with ordinary | link | mka | carrier
  · simpa only [Interface.PacketAddress, nonEthernet, false_and, ↓reduceIte] using ordinary
  · obtain ⟨association, bytes, _, _, alternatives⟩ := link
    rcases alternatives with ⟨macsec, _⟩ | ⟨mka, _⟩
    · exact False.elim (nonEthernet macsec.1.1)
    · exact False.elim (nonEthernet mka.1.1)
  · obtain ⟨_, _, _, _, mka, _⟩ := mka
    exact False.elim (nonEthernet mka.1.1)
  · obtain ⟨binding, member, _⟩ := carrier
    simp [noCarriers] at member

def InnerIPsecAddressCoverage (d : Deployment) (pairs : List InnerIPsecPair) : Prop :=
  ∀ tunnel ∈ d.tunnels, tunnel.layer = .inner →
    ∀ source ∈ d.interfaces, source.device = tunnel.sender → source.zone = .gray →
      ∀ destination ∈ d.interfaces, destination.device = tunnel.receiver → destination.zone = .gray →
        ∃ record ∈ pairs, source.address = some record.endpoints.sourceAddress ∧
          destination.address = some record.endpoints.destinationAddress

instance (d : Deployment) (pairs : List InnerIPsecPair) :
    Decidable (InnerIPsecAddressCoverage d pairs) := by
  unfold InnerIPsecAddressCoverage
  infer_instance

lemma appropriate_inner_IPsec_has_record (d : Deployment) (pairs : List InnerIPsecPair)
    (udp : d.udpBindings = []) (carrier : d.carrierBindings = [])
    (mechanisms : ∀ tunnel ∈ d.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec)
    (coverage : InnerIPsecAddressCoverage d pairs) (traffic : Traffic)
    (appropriate : d.AppropriateInnerTunnel traffic) :
    IPsecPacket traffic.packet ∧ ∃ record ∈ pairs,
      traffic.packet.source = record.endpoints.sourceAddress ∧
      traffic.packet.destination = record.endpoints.destinationAddress := by
  obtain ⟨tunnel, member, layer, pair, protocol⟩ := appropriate
  have mechanism := mechanisms tunnel member layer
  have ipsec : IPsecPacket traffic.packet := by
    rcases protocol with ⟨_, protocol⟩ | ⟨macsec, _⟩
    · rcases protocol with native | configured
      · exact native
      · simp [Deployment.ConfiguredUDPProtocol, Deployment.UDPModePacket, udp] at configured
    · simp [mechanism] at macsec
  obtain ⟨_, _, source, destination⟩ :=
    IPsecPacket.InnerPair_is_IP d traffic tunnel.sender tunnel.receiver ipsec carrier pair
  obtain ⟨sourceInterface, sourceMember, sourceOwner, sourceGray, sourceAddress⟩ := source
  obtain ⟨destinationInterface, destinationMember, destinationOwner, destinationGray,
    destinationAddress⟩ := destination
  obtain ⟨record, recordMember, first, second⟩ := coverage tunnel member layer sourceInterface
    sourceMember sourceOwner sourceGray destinationInterface destinationMember destinationOwner destinationGray
  exact ⟨ipsec, record, recordMember, Option.some.inj (sourceAddress.symm.trans first),
    Option.some.inj (destinationAddress.symm.trans second)⟩

lemma Outer_IPsec_allowance_has_record (d : Deployment) (pairs : List InnerIPsecPair)
    (udp : d.udpBindings = []) (carrier : d.carrierBindings = [])
    (mechanisms : ∀ tunnel ∈ d.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec)
    (coverage : InnerIPsecAddressCoverage d pairs)
    (noApproved : ∀ component traffic, ¬ d.policyApproved component traffic)
    (noManagement : ∀ component traffic, ¬ d.grayManagementService component traffic)
    (component : String) (traffic : Traffic)
    (allowance : OuterPolicyAllowance d component false traffic) :
    IPsecPacket traffic.packet ∧ ∃ record ∈ pairs,
      traffic.packet.source = record.endpoints.sourceAddress ∧
      traffic.packet.destination = record.endpoints.destinationAddress := by
  rcases allowance with ⟨_, sameLevel | management⟩ | ⟨cdp, _⟩ | ⟨_, approved⟩
  · exact appropriate_inner_IPsec_has_record d pairs udp carrier mechanisms coverage traffic sameLevel.2
  · exact False.elim (noManagement component traffic management.1)
  · cases cdp
  · exact False.elim (noApproved component traffic approved)

end TDN.Requirements.Msc
