import TDN.Semantics.Execution
import TDN.Semantics.LinkProtection

namespace TDN.LayeredFrame

/-- IPsec and MACsec have different visible headers. The protection tag annotates
the configured security role; it is not an additional authenticated wire field. -/
structure MACsecAssociation where
  tag : Nat
  sci : Nat
  associationNumber : Nat
  /-- Local bookkeeping used for the transmit-SA operation, never a receive-side wire guard. -/
  keyGeneration : Nat
  deriving DecidableEq, Repr

def SameMACWireIdentity (first second : MACsecAssociation) : Prop :=
  first.sci = second.sci ∧ first.associationNumber = second.associationNumber

instance (first second : MACsecAssociation) : Decidable (SameMACWireIdentity first second) := by
  unfold SameMACWireIdentity
  infer_instance

/-- A carrier is an unencrypted Ethernet pseudowire over UDP. The local and peer
session identifiers are distinct. Only the peer session appears on transmitted data. -/
structure Carrier where
  source : Nat
  destination : Nat
  sourcePort : Nat
  destinationPort : Nat
  peerSession : Nat
  deriving DecidableEq, Repr

/-- Original Ethernet data retains its source, destination, EtherType and full
inner VLAN stack. Clear VLAN tags outside a MACsec envelope require a separate
wire-layout contract; the current mixed captures use an untagged MACsec carrier. -/
structure EthernetHeader where
  source : Nat
  destination : Nat
  etherType : Nat
  vlanTags : List Nat
  deriving DecidableEq, Repr

/-- Nested contents are semantic values. Cryptographic constructors hide their
contents under the same authenticated-encryption contract used by IPsec.
An L2TP carrier preserves its Ethernet body without adding confidentiality. -/
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

/-- Routing and IP filters can inspect only the currently visible IP header.
A physical MACsec frame has no visible IP header, even when its hidden body is IP. -/
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

/-- The outer wire protocol distinguishes encrypted Ethernet from routable IP. -/
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

/-- Unwrapping is tied to the receiving endpoint and its local session identifier.
The body is returned exactly, including any MACsec protection it already contains. -/
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
