import TDN.Semantics.Execution
import TDN.Semantics.LinkProtection

namespace TDN.LayeredFrame

structure MACsecAssociation where
  tag : Nat
  sci : Nat
  associationNumber : Nat

  keyGeneration : Nat
  deriving DecidableEq, Repr

def SameMACWireIdentity (first second : MACsecAssociation) : Prop :=
  first.sci = second.sci ∧ first.associationNumber = second.associationNumber

instance (first second : MACsecAssociation) : Decidable (SameMACWireIdentity first second) := by
  unfold SameMACWireIdentity
  infer_instance

structure Carrier where
  source : Nat
  destination : Nat
  sourcePort : Nat
  destinationPort : Nat
  peerSession : Nat
  deriving DecidableEq, Repr

structure EthernetHeader where
  source : Nat
  destination : Nat
  etherType : Nat
  vlanTags : List Nat
  deriving DecidableEq, Repr

inductive Body where
  | datagram (header : PacketPolicy.Packet)
  | ethernet (header : EthernetHeader)
  | ipsec (authentication : Execution.Seal) (body : Body)
  | macsec (association : MACsecAssociation) (body : Body)
  | carrier (endpoint : Carrier) (body : Body)

structure Frame where
  payload : Nat
  originDomain : Nat
  body : Body

def outerHeader (source destination : Nat) (protocol : String)
    (sourcePort destinationPort : Nat) : PacketPolicy.Packet :=
  { source := source, destination := destination, protocol := protocol
    ingress := "", egress := "", sourcePort := sourcePort, destinationPort := destinationPort
    ipv4HeaderWords := InternetAddresses.headerWords source,
    ipv6NextHeader := if source < 2^32 then 0 else if protocol = "esp" then 50 else 17, inboundPolicies := [], outboundPolicies := [], connectionState := "" }

def Body.visibleHeader : Body → Option PacketPolicy.Packet
  | .datagram header => some header
  | .ethernet _ => none
  | .ipsec authentication _ => some (outerHeader authentication.sender authentication.receiver "esp" 0 0)
  | .macsec _ _ => none
  | .carrier endpoint _ => some (outerHeader endpoint.source endpoint.destination "udp"
      endpoint.sourcePort endpoint.destinationPort)

def Body.protectionLayers : Body → List Nat
  | .datagram _ | .ethernet _ => []
  | .ipsec authentication body => authentication.tag :: body.protectionLayers
  | .macsec association body => association.tag :: body.protectionLayers
  | .carrier _ body => body.protectionLayers

def Body.originalHeader : Body → Option PacketPolicy.Packet
  | .datagram header => some header
  | .ethernet _ => none
  | .ipsec _ body | .macsec _ body | .carrier _ body => body.originalHeader

def Body.originalEthernet : Body → Option EthernetHeader
  | .datagram _ => none
  | .ethernet header => some header
  | .ipsec _ body | .macsec _ body | .carrier _ body => body.originalEthernet

def Body.isEthernetCiphertext : Body → Bool
  | .macsec _ _ => true
  | _ => false

lemma macsec_has_no_routable_inner_header (association : MACsecAssociation) (body : Body) :
    (Body.macsec association body).visibleHeader = none := rfl

lemma carrier_preserves_protection_layers (endpoint : Carrier) (body : Body) :
    (Body.carrier endpoint body).protectionLayers = body.protectionLayers := rfl

lemma nested_outer_inner_order (outer inner : MACsecAssociation) (header : PacketPolicy.Packet) :
    (Body.macsec outer (.macsec inner (.datagram header))).protectionLayers =
      [outer.tag, inner.tag] := rfl

def unwrapCarrier (localAddress remote sourcePort destinationPort localSession : Nat) :
    Body → Option Body
  | .carrier endpoint body =>
      if endpoint.destination = localAddress ∧ endpoint.source = remote ∧
        endpoint.sourcePort = sourcePort ∧ endpoint.destinationPort = destinationPort ∧
        endpoint.peerSession = localSession then some body else none
  | _ => none

theorem successful_carrier_unwrap_preserves_layers
    (localAddress remote sourcePort destinationPort localSession : Nat) (before after : Body)
    (unwrapped : unwrapCarrier localAddress remote sourcePort destinationPort localSession before = some after) :
    after.protectionLayers = before.protectionLayers := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched => cases unwrapped; rfl
    next missed => cases unwrapped

end TDN.LayeredFrame
