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
  protocol : String := "l2tpv3"
  networkProtocol : String := "udp"
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
  activeHeader : Option PacketPolicy.Packet := none
  hiddenHeaders : List (Option PacketPolicy.Packet) := []

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
  | .carrier endpoint _ => some (outerHeader endpoint.source endpoint.destination endpoint.networkProtocol
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

def unwrapCarrier (localAddress remote sourcePort destinationPort localSession : Nat)
    (envelope : Body) (protocol : String := "l2tpv3") (networkProtocol : String := "udp") :
    Option Body :=
  match envelope with
  | .carrier endpoint body =>
      if endpoint.destination = localAddress ∧ endpoint.source = remote ∧
        endpoint.sourcePort = sourcePort ∧ endpoint.destinationPort = destinationPort ∧
        endpoint.peerSession = localSession ∧ endpoint.protocol = protocol ∧
        endpoint.networkProtocol = networkProtocol then some body else none
  | _ => none

theorem successful_carrier_unwrap_preserves_layers
    (localAddress remote sourcePort destinationPort localSession : Nat) {protocol networkProtocol : String} (before after : Body)
    (unwrapped : unwrapCarrier localAddress remote sourcePort destinationPort localSession before protocol networkProtocol = some after) :
    after.protectionLayers = before.protectionLayers := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched => cases unwrapped; rfl
    next missed => cases unwrapped

end TDN.LayeredFrame

namespace TDN.LayeredFrame

def Frame.visibleHeader (frame : Frame) : Option PacketPolicy.Packet :=
  match frame.body.visibleHeader with
  | none => none
  | some header => some (frame.activeHeader.getD header)

def Frame.pushHeader (frame : Frame) (body : Body) (header : Option PacketPolicy.Packet) : Frame :=
  { frame with
    body := body, activeHeader := header,
    hiddenHeaders := frame.activeHeader :: frame.hiddenHeaders }

def Frame.popHeader (frame : Frame) (body : Body) : Frame :=
  { frame with
    body := body, activeHeader := frame.hiddenHeaders.head?.getD none,
    hiddenHeaders := frame.hiddenHeaders.drop 1 }

def Frame.forwarded (frame : Frame) : Frame :=
  match frame.visibleHeader with
  | none => frame
  | some header => { frame with activeHeader := some { header with hopLimit := header.hopLimit - 1 } }

end TDN.LayeredFrame

namespace TDN.LayeredFrame

@[simp] lemma Frame.forwarded_payload (frame : Frame) : frame.forwarded.payload = frame.payload := by
  unfold Frame.forwarded
  cases frame.visibleHeader <;> rfl

@[simp] lemma Frame.forwarded_origin (frame : Frame) :
    frame.forwarded.originDomain = frame.originDomain := by
  unfold Frame.forwarded
  cases frame.visibleHeader <;> rfl

end TDN.LayeredFrame

namespace TDN.LayeredFrame

def HeaderIdentity (actual nominal : PacketPolicy.Packet) : Prop :=
  { actual with hopLimit := nominal.hopLimit } = nominal ∧ actual.hopLimit ≤ 255

def Body.HeadersCoherent : Body → Option PacketPolicy.Packet →
    List (Option PacketPolicy.Packet) → Prop
  | .datagram nominal, active, hidden =>
      HeaderIdentity (active.getD nominal) nominal ∧ hidden = []
  | .ethernet _, active, hidden => active = none ∧ hidden = []
  | .ipsec association body, active, hidden =>
      HeaderIdentity (active.getD (outerHeader association.sender association.receiver "esp" 0 0))
        (outerHeader association.sender association.receiver "esp" 0 0) ∧
      ∃ inner rest, hidden = inner :: rest ∧ body.HeadersCoherent inner rest
  | .carrier endpoint body, active, hidden =>
      HeaderIdentity (active.getD (outerHeader endpoint.source endpoint.destination
        endpoint.networkProtocol endpoint.sourcePort endpoint.destinationPort))
        (outerHeader endpoint.source endpoint.destination endpoint.networkProtocol
          endpoint.sourcePort endpoint.destinationPort) ∧
      ∃ inner rest, hidden = inner :: rest ∧ body.HeadersCoherent inner rest
  | .macsec _ body, active, hidden =>
      active = none ∧
      ∃ inner rest, hidden = inner :: rest ∧ body.HeadersCoherent inner rest

def Frame.HeadersCoherent (frame : Frame) : Prop :=
  frame.body.HeadersCoherent frame.activeHeader frame.hiddenHeaders

end TDN.LayeredFrame

namespace TDN.LayeredFrame

@[simp] lemma Frame.forwarded_body (frame : Frame) : frame.forwarded.body = frame.body := by
  unfold Frame.forwarded
  cases frame.visibleHeader <;> rfl

end TDN.LayeredFrame
