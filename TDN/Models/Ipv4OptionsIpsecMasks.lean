import TDN.Models.IkeAndEspPacketFormats

namespace TDN.PacketPolicy

def IPsecForm.maskWithOptions (form : IPsecForm) (source destination : Nat)
    (ingress egress : String) (authenticated selected : List Nat) (mtu : Nat) : AclFlowSelector :=
  { form.mask source destination ingress egress authenticated selected mtu with
    ipv4HeaderWords := none }

lemma IPsecForm.maskWithOptions_matches (form : IPsecForm) (source destination : Nat)
    (ingress egress : String) (authenticated selected : List Nat) (mtu : Nat)
    (packet : Packet) (fields : form.Matches packet)
    (sourceEq : packet.source = source) (destinationEq : packet.destination = destination)
    (ingressEq : packet.ingress = ingress) (egressEq : packet.egress = egress)
    (inbound : authenticated = packet.matchedInboundPolicyIds)
    (outbound : selected = packet.matchedOutboundPolicyIds)
    (size : ∃ bytes, packet.networkBytes = some bytes ∧ bytes ≤ mtu) :
    (form.maskWithOptions source destination ingress egress authenticated selected mtu).Matches packet := by
  obtain ⟨bytes, total, bound⟩ := size
  refine ⟨sourceEq, destinationEq, fields.1, ingressEq, egressEq, fields.2.1,
    fields.2.2.1, ?_, ?_, ?_, ⟨bytes, total, Nat.zero_le _, bound⟩,
    fields.2.2.2.1, fields.2.2.2.2⟩
  · intro value impossible
    cases impossible
  · intro id member
    rw [← inbound]
    exact member
  · intro id member
    rw [← outbound]
    exact member

end TDN.PacketPolicy
