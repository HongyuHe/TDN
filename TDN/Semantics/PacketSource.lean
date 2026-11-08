import TDN.Semantics.LayeredFrame
import TDN.Semantics.Fragmentation

namespace TDN.PacketSource

def unsigned (bytes : List UInt8) : Nat :=
  bytes.foldl (fun value byte => value * 256 + byte.toNat) 0

def field (bytes : List UInt8) (offset count : Nat) : Nat :=
  unsigned ((bytes.drop offset).take count)

def protocolNumber (protocol : String) : Option Nat :=
  if protocol = "icmp" then some 1 else
  if protocol = "tcp" then some 6 else
  if protocol = "udp" then some 17 else
  if protocol = "esp" then some 50 else
  if protocol = "icmpv6" then some 58 else none

inductive Mode where
  | datagram (dontFragment : Bool)
  | stream
  deriving DecidableEq

structure Request where
  iface : Nat
  originDomain : Nat
  body : LayeredFrame.Body
  application : List UInt8
  networkHeaderBytes : Nat
  transportHeaderBytes : Nat
  mode : Mode
  requestId : Nat := 0

def Request.Overhead (request : Request) : Nat :=
  request.networkHeaderBytes + request.transportHeaderBytes

def HeaderRepresentable (packet : PacketPolicy.Packet) : Prop :=
  packet.hopLimit ≤ 255 ∧
  (2^32 ≤ packet.source → protocolNumber packet.protocol = some packet.ipv6NextHeader) ∧
  (packet.protocol ∈ ["icmp", "icmpv6"] →
    packet.sourcePort = 0 ∧ packet.destinationPort = 0 ∧
    packet.icmpType ≤ 255 ∧ packet.icmpCode ≤ 255)

def Request.HeadersRepresentable (request : Request) : Prop :=
  match request.body with
  | .datagram packet => HeaderRepresentable packet
  | _ => True

def Request.TemplateValid (request : Request) : Prop :=
  match request.body with
  | .datagram header =>
      ((header.source < 2^32 ∧ header.destination < 2^32 ∧
        5 ≤ header.ipv4HeaderWords ∧ header.ipv4HeaderWords ≤ 15 ∧
        request.networkHeaderBytes = 4 * header.ipv4HeaderWords) ∨
       (2^128 ≤ header.source ∧ header.source < 2^129 ∧
        2^128 ≤ header.destination ∧ header.destination < 2^129 ∧
        header.ipv4HeaderWords = 0 ∧ request.networkHeaderBytes = 40)) ∧
      ((header.protocol = "udp" ∧ request.transportHeaderBytes = 8) ∨
       (header.protocol = "tcp" ∧ 20 ≤ request.transportHeaderBytes ∧
        request.transportHeaderBytes ≤ 60 ∧ request.transportHeaderBytes % 4 = 0) ∨
       (header.protocol ∈ ["icmp", "icmpv6"] ∧ request.transportHeaderBytes = 8)) ∧
      header.sourcePort < 65536 ∧ header.destinationPort < 65536 ∧
      (request.mode = .stream → header.protocol = "tcp") ∧ HeaderRepresentable header
  | .ethernet header =>
      header.source < 2^48 ∧ header.destination < 2^48 ∧ header.etherType < 65536 ∧
      (∀ tag ∈ header.vlanTags, tag < 65536) ∧
      request.networkHeaderBytes = 14 + 4 * header.vlanTags.length ∧
      request.transportHeaderBytes = 0 ∧
      (∃ dontFragment, request.mode = .datagram dontFragment)
  | _ => False

def Request.PayloadMatches (request : Request) : Prop :=
  match request.body with
  | .datagram header => header.payloadBytes = some request.application
  | .ethernet _ => True
  | _ => False

def Request.ProtocolLimit (request : Request) : Nat :=
  match request.body with
  | .datagram header => if header.source < 2^32 then 65535 else 65575
  | .ethernet _ => request.Overhead + request.application.length
  | _ => 0

def Request.PacketSize (request : Request) : Nat :=
  request.Overhead + request.application.length

def Request.MtuOverhead (request : Request) : Nat :=
  match request.body with
  | .ethernet _ => request.transportHeaderBytes
  | _ => request.Overhead

def Request.MtuBytes (request : Request) : Nat :=
  request.MtuOverhead + request.application.length

def NetworkHeaderMatches (packet : PacketPolicy.Packet) (header : List UInt8)
    (dataBytes : Nat) : Prop :=
  (packet.source < 2^32 ∧ packet.destination < 2^32 ∧
    20 ≤ header.length ∧ header.length ≤ 60 ∧
    field header 0 1 / 16 = 4 ∧ field header 0 1 % 16 = packet.ipv4HeaderWords ∧
    header.length = 4 * packet.ipv4HeaderWords ∧
    field header 2 2 = header.length + dataBytes ∧
    field header 12 4 = packet.source ∧ field header 16 4 = packet.destination ∧
    field header 8 1 = packet.hopLimit ∧
    protocolNumber packet.protocol = some (field header 9 1)) ∨
  (2^128 ≤ packet.source ∧ packet.source < 2^129 ∧
    2^128 ≤ packet.destination ∧ packet.destination < 2^129 ∧
    field header 0 1 / 16 = 6 ∧ header.length = 40 ∧ packet.ipv4HeaderWords = 0 ∧
    field header 4 2 = dataBytes ∧
    2^128 + field header 8 16 = packet.source ∧
    2^128 + field header 24 16 = packet.destination ∧
    protocolNumber packet.protocol = some (field header 6 1) ∧
    packet.ipv6NextHeader = field header 6 1 ∧ packet.hopLimit = field header 7 1)

def TransportHeaderMatches (packet : PacketPolicy.Packet)
    (header application : List UInt8) : Prop :=
  (packet.protocol = "udp" ∧ header.length = 8 ∧
    field header 0 2 = packet.sourcePort ∧ field header 2 2 = packet.destinationPort ∧
    field header 4 2 = header.length + application.length) ∨
  (packet.protocol = "tcp" ∧ 20 ≤ header.length ∧ header.length ≤ 60 ∧
    field header 0 2 = packet.sourcePort ∧ field header 2 2 = packet.destinationPort ∧
    4 * (field header 12 1 / 16) = header.length) ∨
  (packet.protocol ∈ ["icmp", "icmpv6"] ∧ header.length = 8 ∧
    packet.sourcePort = 0 ∧ packet.destinationPort = 0 ∧
    field header 0 1 = packet.icmpType ∧ field header 1 1 = packet.icmpCode)

def EthernetHeaderMatches (packet : LayeredFrame.EthernetHeader)
    (header : List UInt8) : Prop :=
  header.length = 14 + 4 * packet.vlanTags.length ∧
  field header 0 6 = packet.destination ∧ field header 6 6 = packet.source ∧
  (∀ index, index < packet.vlanTags.length →
    field header (12 + index * 4) 2 = 33024 ∧
      packet.vlanTags[index]? = some (field header (14 + index * 4) 2)) ∧
  field header (12 + 4 * packet.vlanTags.length) 2 = packet.etherType

structure Fragment where
  networkHeader : List UInt8
  data : List UInt8
  offset : Nat
  more : Bool

def Fragment.Raw (fragment : Fragment) : List UInt8 :=
  fragment.networkHeader ++ fragment.data

def Fragment.MtuBytes (fragment : Fragment) (body : LayeredFrame.Body) : Nat :=
  match body with
  | .ethernet _ => fragment.data.length
  | _ => fragment.Raw.length

def Fragment.AsPiece (fragment : Fragment) : Fragmentation.Fragment Unit UInt8 :=
  ⟨(), fragment.offset, fragment.data⟩

def Fragment.IPv4Fields (packet : PacketPolicy.Packet) (identity : Nat)
    (fragment : Fragment) : Prop :=
  NetworkHeaderMatches packet fragment.networkHeader fragment.data.length ∧
  field fragment.networkHeader 4 2 = identity ∧
  field fragment.networkHeader 6 2 % 8192 * 8 = fragment.offset ∧
  (field fragment.networkHeader 6 2 / 8192 % 2 = 1 ↔ fragment.more = true) ∧
  (fragment.more = true → fragment.data.length % 8 = 0) ∧ fragment.offset % 8 = 0

def Fragment.IPv6Fields (packet : PacketPolicy.Packet) (identity : Nat)
    (fragment : Fragment) : Prop :=
  fragment.networkHeader.length = 48 ∧
  field fragment.networkHeader 0 1 / 16 = 6 ∧
  field fragment.networkHeader 4 2 = 8 + fragment.data.length ∧
  field fragment.networkHeader 6 1 = 44 ∧
  2^128 + field fragment.networkHeader 8 16 = packet.source ∧
  2^128 + field fragment.networkHeader 24 16 = packet.destination ∧
  protocolNumber packet.protocol = some (field fragment.networkHeader 40 1) ∧
  field fragment.networkHeader 42 2 / 8 * 8 = fragment.offset ∧
  (field fragment.networkHeader 42 2 % 2 = 1 ↔ fragment.more = true) ∧
  field fragment.networkHeader 44 4 = identity ∧
  (fragment.more = true → fragment.data.length % 8 = 0) ∧ fragment.offset % 8 = 0

structure Datagram where
  body : LayeredFrame.Body
  application : List UInt8
  networkHeader : List UInt8
  transportHeader : List UInt8
  fragments : List Fragment

def Datagram.Data (datagram : Datagram) : List UInt8 :=
  datagram.transportHeader ++ datagram.application

def Datagram.Raw (datagram : Datagram) : List UInt8 :=
  datagram.networkHeader ++ datagram.Data

def Datagram.MtuBytes (datagram : Datagram) : Nat :=
  match datagram.body with
  | .ethernet _ => datagram.Data.length
  | _ => datagram.Raw.length

def Datagram.Decoded (datagram : Datagram) : Prop :=
  match datagram.body with
  | .datagram packet =>
      packet.payloadBytes = some datagram.application ∧
      packet.networkBytes = some datagram.Raw.length ∧
      NetworkHeaderMatches packet datagram.networkHeader datagram.Data.length ∧
      TransportHeaderMatches packet datagram.transportHeader datagram.application ∧
      (packet.source < 2^32 → packet.IPv4FragmentOffsetDecoded datagram.networkHeader ∧
        field datagram.networkHeader 6 2 % 8192 = 0 ∧
        field datagram.networkHeader 6 2 / 8192 % 2 = 0)
  | .ethernet packet =>
      datagram.transportHeader = [] ∧ EthernetHeaderMatches packet datagram.networkHeader
  | _ => False

def Datagram.HeaderFrom (datagram : Datagram) (request : Request) : Prop :=
  match datagram.body, request.body with
  | .datagram actual, .datagram template =>
      actual = { template with
        payloadBytes := some datagram.application
        networkBytes := some datagram.Raw.length
        ipv4FragmentOffset := if template.source < 2^32 then some 0 else none } ∧
      datagram.networkHeader.length = request.networkHeaderBytes ∧
      datagram.transportHeader.length = request.transportHeaderBytes
  | .ethernet actual, .ethernet template => actual = template ∧
      datagram.networkHeader.length = request.networkHeaderBytes ∧ datagram.transportHeader = []
  | _, _ => False

def Datagram.Reassembles (datagram : Datagram) (mtu : Nat) : Prop :=
  Fragmentation.ValidPieces ⟨(), datagram.Data⟩
    (datagram.fragments.map Fragment.AsPiece) ∧
  (∀ fragment ∈ datagram.fragments,
    fragment.more = decide (fragment.offset + fragment.data.length < datagram.Data.length) ∧
    fragment.MtuBytes datagram.body ≤ mtu) ∧
  match datagram.body with
  | .datagram packet =>
      if datagram.fragments.length = 1 then
        ∀ fragment ∈ datagram.fragments, fragment.networkHeader = datagram.networkHeader ∧
          fragment.offset = 0 ∧ fragment.more = false ∧
          (packet.source < 2^32 → field fragment.networkHeader 6 2 % 8192 = 0 ∧
            field fragment.networkHeader 6 2 / 8192 % 2 = 0)
      else
        ∃ identity, ∀ fragment ∈ datagram.fragments,
          if packet.source < 2^32 then fragment.IPv4Fields packet identity ∧
            field fragment.networkHeader 6 2 / 16384 % 2 = 0
          else fragment.IPv6Fields packet identity
  | .ethernet _ => datagram.fragments.length = 1 ∧
      ∀ fragment ∈ datagram.fragments, fragment.networkHeader = datagram.networkHeader
  | _ => False

def Datagram.ValidFor (datagram : Datagram) (request : Request) (mtu : Nat) : Prop :=
  datagram.Decoded ∧ datagram.HeaderFrom request ∧ datagram.Reassembles mtu ∧
  datagram.Raw.length ≤ request.ProtocolLimit ∧
  (request.mode = .stream → datagram.Raw.length ≤ mtu) ∧
  (∀ dontFragment, request.mode = .datagram dontFragment →
    (dontFragment = true → datagram.MtuBytes ≤ mtu) ∧
    match datagram.body with
    | .datagram packet => packet.source < 2^32 →
        (field datagram.networkHeader 6 2 / 16384 % 2 = 1 ↔ dontFragment = true)
    | _ => True)

inductive Error where
  | unsupportedTemplate | protocolLength | mtuExceeded | invalidMtu
  deriving DecidableEq

inductive Outcome where
  | emitted (datagrams : List Datagram)
  | error (reason : Error)

def Outcome.Valid (outcome : Outcome) (request : Request) (mtu : Nat) : Prop :=
  match outcome with
  | .emitted datagrams =>
      request.TemplateValid ∧ request.MtuOverhead < mtu ∧ datagrams ≠ [] ∧
      (datagrams.map Datagram.application).flatten = request.application ∧
      (∀ datagram ∈ datagrams, datagram.ValidFor request mtu) ∧
      (∀ dontFragment, request.mode = .datagram dontFragment → datagrams.length = 1)
  | .error .unsupportedTemplate => ¬ request.TemplateValid
  | .error .invalidMtu => request.TemplateValid ∧ mtu ≤ request.MtuOverhead
  | .error .protocolLength => request.TemplateValid ∧
      (∃ dontFragment, request.mode = .datagram dontFragment) ∧
      request.ProtocolLimit < request.PacketSize
  | .error .mtuExceeded => request.TemplateValid ∧
      ((request.mode = .datagram true) ∨
        (∃ header, request.body = .ethernet header)) ∧ mtu < request.MtuBytes ∧
      request.PacketSize ≤ request.ProtocolLimit

structure Processing where
  sourceMtu : Nat → Nat
  process : Request → Outcome

end TDN.PacketSource
