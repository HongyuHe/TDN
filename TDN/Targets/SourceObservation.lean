import TDN.Targets.CanonicalSourceCoverage
import TDN.Semantics.SourceProcessingCodec

namespace TDN.Compliance
open PacketSource

lemma source_header_packet_owner (d : Deployment) (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (address : Nat) :
    d.PacketOwner (sourceHeader request packet payload) address = d.PacketOwner packet address := by
  rfl

lemma source_header_registered_service (d : Deployment) (request : Request)
    (packet : PacketPolicy.Packet) (payload : List UInt8) :
    d.RegisteredService (sourceHeader request packet payload) = d.RegisteredService packet := by
  rfl

lemma source_header_class (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (same : packet.payloadBytes = some payload ∨ packet.protocol = "tcp") :
    PacketClass (sourceHeader request packet payload) = PacketClass packet := by
  have ike : PacketIKE (sourceHeader request packet payload) ↔ PacketIKE packet := by
    rcases same with bytes | tcp
    · simp only [PacketIKE, sourceHeader, bytes]
    · simp [PacketIKE, sourceHeader, tcp]
  have esp : PacketUDPESP (sourceHeader request packet payload) ↔ PacketUDPESP packet := by
    rcases same with bytes | tcp
    · simp only [PacketUDPESP, sourceHeader, bytes]
    · simp [PacketUDPESP, sourceHeader, tcp]
  have mka : PacketMKA (sourceHeader request packet payload) ↔ PacketMKA packet := by
    rcases same with bytes | tcp
    · simp only [PacketMKA, PacketIsEthernet, sourceHeader, bytes]
    · simp [PacketMKA, PacketIsEthernet, sourceHeader, tcp]
  simp only [PacketClass, PacketService, ike, esp, mka]
  rfl

lemma source_header_observed_class (d : Deployment) (request : Request)
    (packet : PacketPolicy.Packet) (payload : List UInt8) (noUDPBindings : d.udpBindings = [])
    (same : packet.payloadBytes = some payload ∨ packet.protocol = "tcp") :
    (d.Observe (sourceHeader request packet payload)).trafficClass = (d.Observe packet).trafficClass := by
  have ike : PacketIKE (sourceHeader request packet payload) ↔ PacketIKE packet := by
    rcases same with bytes | tcp
    · simp only [PacketIKE, sourceHeader, bytes]
    · simp [PacketIKE, sourceHeader, tcp]
  have esp : PacketUDPESP (sourceHeader request packet payload) ↔ PacketUDPESP packet := by
    rcases same with bytes | tcp
    · simp only [PacketUDPESP, sourceHeader, bytes]
    · simp [PacketUDPESP, sourceHeader, tcp]
  simp only [Deployment.Observe, Deployment.ObservedClass, noUDPBindings, List.any_nil, Bool.false_eq_true,
    ↓reduceIte, ike, esp, source_header_registered_service, source_header_class request packet payload same]
  rfl

lemma source_header_local_source (d : Deployment) (component : String) (request : Request)
    (packet : PacketPolicy.Packet) (payload : List UInt8) :
    d.LocalSourceAddress component (sourceHeader request packet payload) ↔ d.LocalSourceAddress component packet := by
  rfl

lemma source_header_local_body_source (d : Deployment) (component iface : String) (request : Request)
    (packet : PacketPolicy.Packet) (payload : List UInt8) :
    d.LocalBodySource component iface (.datagram (sourceHeader request packet payload)) ↔
      d.LocalBodySource component iface (.datagram packet) := by
  simp only [Deployment.LocalBodySource, source_header_local_source]

lemma source_header_management (d : Deployment) (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (noUDPBindings : d.udpBindings = [])
    (same : packet.payloadBytes = some payload ∨ packet.protocol = "tcp") :
    BodyManagement d (.datagram (sourceHeader request packet payload)) ↔
      BodyManagement d (.datagram packet) := by
  constructor
  · rintro ⟨header, shape, classified⟩
    have equal := LayeredFrame.Body.datagram.inj shape
    subst header
    exact ⟨packet, rfl, by rw [← source_header_observed_class d request packet payload noUDPBindings same]; exact classified⟩
  · rintro ⟨header, shape, classified⟩
    have equal := LayeredFrame.Body.datagram.inj shape
    subst header
    exact ⟨sourceHeader request packet payload, rfl,
      by rw [source_header_observed_class d request packet payload noUDPBindings same]; exact classified⟩

lemma source_header_control (d : Deployment) (request : Request) (packet : PacketPolicy.Packet)
    (payload : List UInt8) (protocol : String) (noUDPBindings : d.udpBindings = [])
    (same : packet.payloadBytes = some payload ∨ packet.protocol = "tcp") :
    BodyControlProtocol d (.datagram (sourceHeader request packet payload)) protocol ↔
      BodyControlProtocol d (.datagram packet) protocol := by
  simp [BodyControlProtocol, source_header_observed_class d request packet payload noUDPBindings same]
  exact fun _ => Iff.rfl

end TDN.Compliance
