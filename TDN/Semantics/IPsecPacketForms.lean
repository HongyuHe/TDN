import TDN.Semantics.PolicyMasks
import TDN.Semantics.RawIPsecFraming

namespace TDN.PacketPolicy

inductive IPsecForm where
  | esp | request500 | request4500 | reply500 | reply4500
  deriving DecidableEq

def IPsecForm.all : List IPsecForm := [.esp, .request500, .request4500, .reply500, .reply4500]

def IPsecForm.protocol : IPsecForm → String
  | .esp => "esp"
  | _ => "udp"

def IPsecForm.sourcePort : IPsecForm → Option Nat
  | .reply500 => some 500
  | .reply4500 => some 4500
  | _ => none

def IPsecForm.destinationPort : IPsecForm → Option Nat
  | .request500 => some 500
  | .request4500 => some 4500
  | _ => none

def IPsecForm.requestFraming : IPsecForm → Bool
  | .request500 | .request4500 => true
  | _ => false

def IPsecForm.replyFraming : IPsecForm → Bool
  | .reply500 | .reply4500 => true
  | _ => false

def IPsecForm.Matches (form : IPsecForm) (packet : Packet) : Prop :=
  packet.protocol = form.protocol ∧
  (∀ port, form.sourcePort = some port → packet.sourcePort = port) ∧
  (∀ port, form.destinationPort = some port → packet.destinationPort = port) ∧
  (form.requestFraming = true → packet.IPsecUDPFramingWithOptions) ∧
  (form.replyFraming = true → packet.IPsecUDPReplyFramingWithOptions)

lemma request_framing_has_form (packet : Packet)
    (framing : packet.IPsecUDPFramingWithOptions) :
    ∃ form ∈ IPsecForm.all, form.Matches packet := by
  have udp : packet.protocol = "udp" := framing.2.2.2.2.2.1
  have ports : packet.destinationPort = 500 ∨ packet.destinationPort = 4500 := by
    obtain ⟨_, _, _, _, _, _, _, _, _, alternatives⟩ := framing
    rcases alternatives with ⟨port, _⟩ | ⟨port, _⟩
    · exact Or.inl port
    · exact Or.inr port
  rcases ports with port | port
  · refine ⟨.request500, by decide, ?_⟩
    simp [IPsecForm.Matches, IPsecForm.protocol, IPsecForm.sourcePort,
      IPsecForm.destinationPort, IPsecForm.requestFraming, IPsecForm.replyFraming, udp, port, framing]
  · refine ⟨.request4500, by decide, ?_⟩
    simp [IPsecForm.Matches, IPsecForm.protocol, IPsecForm.sourcePort,
      IPsecForm.destinationPort, IPsecForm.requestFraming, IPsecForm.replyFraming, udp, port, framing]

lemma reply_framing_has_form (packet : Packet)
    (framing : packet.IPsecUDPReplyFramingWithOptions) :
    ∃ form ∈ IPsecForm.all, form.Matches packet := by
  have udp : packet.protocol = "udp" := framing.2.2.2.2.2.1
  have ports : packet.sourcePort = 500 ∨ packet.sourcePort = 4500 := by
    obtain ⟨_, _, _, _, _, _, _, _, _, alternatives⟩ := framing
    rcases alternatives with ⟨port, _⟩ | ⟨port, _⟩
    · exact Or.inl port
    · exact Or.inr port
  rcases ports with port | port
  · refine ⟨.reply500, by decide, ?_⟩
    simp [IPsecForm.Matches, IPsecForm.protocol, IPsecForm.sourcePort,
      IPsecForm.destinationPort, IPsecForm.requestFraming, IPsecForm.replyFraming, udp, port, framing]
  · refine ⟨.reply4500, by decide, ?_⟩
    simp [IPsecForm.Matches, IPsecForm.protocol, IPsecForm.sourcePort,
      IPsecForm.destinationPort, IPsecForm.requestFraming, IPsecForm.replyFraming, udp, port, framing]

lemma decoded_IPsec_has_form (raw : PacketProcessing.RawPacket) (packet : Packet)
    (complete : raw.Complete packet) (ipv4 : packet.source < 2^32)
    (ipsec : packet.protocol = "esp" ∨
      (packet.protocol = "udp" ∧
        (((packet.sourcePort = 500 ∨ packet.destinationPort = 500) ∧ IKEHeader (packet.payloadBytes.getD [])) ∨
          ((packet.sourcePort = 4500 ∨ packet.destinationPort = 4500) ∧
            (packet.payloadBytes.getD []).take 4 = [0, 0, 0, 0] ∧ IKEHeader ((packet.payloadBytes.getD []).drop 4)))) ∨
      (packet.protocol = "udp" ∧ (packet.sourcePort = 4500 ∨ packet.destinationPort = 4500) ∧
        8 ≤ (packet.payloadBytes.getD []).length ∧ (packet.payloadBytes.getD []).take 4 ≠ [0, 0, 0, 0])) :
    ∃ form ∈ IPsecForm.all, form.Matches packet := by
  rcases ipsec with esp | ike | udpESP
  · refine ⟨.esp, by decide, ?_⟩
    simp [IPsecForm.Matches, IPsecForm.protocol, IPsecForm.sourcePort,
      IPsecForm.destinationPort, IPsecForm.requestFraming, IPsecForm.replyFraming, esp]
  · rcases PacketProcessing.eligible_IKE_has_framing raw packet complete ipv4 ike with request | reply
    · exact request_framing_has_form packet request
    · exact reply_framing_has_form packet reply
  · rcases PacketProcessing.eligible_UDPESP_has_framing raw packet complete ipv4 udpESP with request | reply
    · exact request_framing_has_form packet request
    · exact reply_framing_has_form packet reply

def IPsecForm.mask (form : IPsecForm) (source destination : Nat) (ingress egress : String)
    (authenticated selected : List Nat) (mtu : Nat) : Mask :=
  { source := source, destination := destination, protocol := form.protocol
    ingress := ingress, egress := egress
    sourcePort := form.sourcePort, destinationPort := form.destinationPort
    ipv4HeaderWords := some 5, inboundPolicies := authenticated, outboundPolicies := selected
    minimumBytes := 0, maximumBytes := mtu
    requestFraming := form.requestFraming, replyFraming := form.replyFraming }

lemma IPsecForm.mask_matches (form : IPsecForm) (source destination : Nat)
    (ingress egress : String) (authenticated selected : List Nat) (mtu : Nat)
    (packet : Packet) (fields : form.Matches packet)
    (sourceEq : packet.source = source) (destinationEq : packet.destination = destination)
    (ingressEq : packet.ingress = ingress) (egressEq : packet.egress = egress)
    (words : packet.ipv4HeaderWords = 5) (inbound : authenticated = packet.inboundPolicies)
    (outbound : selected = packet.outboundPolicies)
    (size : ∃ bytes, packet.networkBytes = some bytes ∧ bytes ≤ mtu) :
    (form.mask source destination ingress egress authenticated selected mtu).Matches packet := by
  obtain ⟨bytes, total, bound⟩ := size
  refine ⟨sourceEq, destinationEq, fields.1, ingressEq, egressEq, fields.2.1,
    fields.2.2.1, ?_, ?_, ?_, ⟨bytes, total, Nat.zero_le _, bound⟩,
    fields.2.2.2.1, fields.2.2.2.2⟩
  · intro value selectedWords
    have same : value = 5 := Option.some.inj selectedWords.symm
    simpa only [same] using words
  · intro id member
    rw [← inbound]
    exact member
  · intro id member
    rw [← outbound]
    exact member

end TDN.PacketPolicy
