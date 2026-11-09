import TDN.Models.EndpointTransmitSpec
import TDN.Models.MultiProtocolForwarding

namespace TDN.PacketProcessing

inductive Hook where
  | input | forward | output | link
  deriving DecidableEq, Repr

inductive RawPacket where
  | ip (network transport payload : List UInt8)
  | ethernet (header : LayeredFrame.EthernetHeader) (rawHeader payload : List UInt8)
  deriving DecidableEq, Repr

def RawPacket.Bytes : RawPacket → List UInt8
  | .ip network transport payload => network ++ transport ++ payload
  | .ethernet _ header payload => header ++ payload

def RawPacket.Decoded (raw : RawPacket) (packet : PacketPolicy.Packet) : Prop :=
  match raw with
  | .ip network transport payload =>
      (packet.payloadBytes = some payload ∨ packet.protocol = "esp" ∧ packet.payloadBytes = none) ∧
      packet.networkBytes = some (network.length + transport.length + payload.length) ∧
      PacketSource.NetworkHeaderMatches packet network (transport.length + payload.length) ∧
      (packet.source < 2^32 → packet.IPv4FragmentOffsetDecoded network ∨
        packet.protocol = "esp" ∧ packet.ipv4FragmentOffset = none) ∧
      (PacketSource.TransportHeaderMatches packet transport payload ∨
        (packet.protocol = "esp" ∧ transport = [] ∧ 8 ≤ payload.length))
  | .ethernet header rawHeader payload =>
      packet.protocol = "ethernet" ∧ packet.source = header.source ∧
      packet.destination = header.destination ∧ packet.etherType = some header.etherType ∧
      packet.payloadBytes = some payload ∧
      packet.networkBytes = some (rawHeader.length + payload.length) ∧
      PacketSource.EthernetHeaderMatches header rawHeader

def RawPacket.Complete (raw : RawPacket) (packet : PacketPolicy.Packet) : Prop :=
  raw.Decoded packet ∧
  match raw with
  | .ip network _ _ =>
      packet.source < 2^32 →
        PacketSource.field network 6 2 % 8192 = 0 ∧
        PacketSource.field network 6 2 / 8192 % 2 = 0
  | .ethernet .. => True

def RawPacket.Fragment (raw : RawPacket) (packet : PacketPolicy.Packet) : Prop :=
  match raw with
  | .ip network [] payload =>
      packet.source < 2^32 ∧
      packet.networkBytes = some (network.length + payload.length) ∧
      PacketSource.NetworkHeaderMatches packet network payload.length ∧
      packet.IPv4FragmentOffsetDecoded network ∧
      (PacketSource.field network 6 2 % 8192 ≠ 0 ∨
        PacketSource.field network 6 2 / 8192 % 2 = 1)
  | _ => False

inductive DecodeOutcome where
  | complete | fragment | malformed
  deriving DecidableEq

def DecodeOutcome.Valid (outcome : DecodeOutcome) (raw : RawPacket)
    (packet : PacketPolicy.Packet) : Prop :=
  match outcome with
  | .complete => raw.Complete packet
  | .fragment => raw.Fragment packet
  | .malformed => ¬ raw.Complete packet ∧ ¬ raw.Fragment packet

def Ingress (configuration : MultiProtocolForwarding.Config)
    (before after : MultiProtocolForwarding.State) : Prop :=
  MultiProtocolForwarding.Step configuration before .receive after ∨
  MultiProtocolForwarding.Step configuration before .decryptIPsec after

def inputPacket (configuration : MultiProtocolForwarding.Config)
    (state : MultiProtocolForwarding.State) (header : PacketPolicy.Packet) : PacketPolicy.Packet :=
  { MultiProtocolForwarding.policyHeader configuration state header with
    ingress := configuration.ip.interfaceName state.iface, egress := "", matchedOutboundPolicyIds := [] }

def InputAdmitted (configuration : MultiProtocolForwarding.Config)
    (state : MultiProtocolForwarding.State) : Prop :=
  ∃ header, state.frame.visibleHeader = some header ∧
    DataPlaneForwarding.accepts (configuration.ip.inputRules state.iface)
      (configuration.ip.inputFallback state.iface) (inputPacket configuration state header)

structure Context where
  entry : MultiProtocolForwarding.State
  state : MultiProtocolForwarding.State
  header : PacketPolicy.Packet
  raw : RawPacket
  hook : Hook

def Context.Packet (context : Context) (configuration : MultiProtocolForwarding.Config) :
    PacketPolicy.Packet :=
  let header := MultiProtocolForwarding.policyHeader configuration context.state context.header
  match context.hook with
  | .input => { header with egress := "", matchedOutboundPolicyIds := [] }
  | .output => { header with ingress := "", matchedInboundPolicyIds := [] }
  | _ => header

def Context.AtHook (context : Context) (configuration : MultiProtocolForwarding.Config) : Prop :=
  context.state.frame.visibleHeader = some context.header ∧
  match context.hook with
  | .input =>
      Ingress configuration context.entry context.state ∧
      configuration.ip.localAddress context.state.iface context.header.destination
  | .forward =>
      ∃ entered route, Ingress configuration context.entry entered ∧
        (∀ incoming, configuration.visibleHeader entered.frame = some incoming →
          configuration.ForwardableHeader incoming) ∧
        MultiProtocolForwarding.Step configuration entered .route context.state ∧
        entered.datapathStage = .ingress ∧ context.state.datapathStage = .routed ∧
        DataPlaneForwarding.SelectedFibRoute configuration.ip.routes route context.header ∧
        route.ingress = entered.iface ∧ route.egress = context.state.iface
  | .output =>
      context.entry.datapathStage = .localOutput ∧
      MultiProtocolForwarding.Step configuration context.entry .route context.state ∧
      context.state.datapathStage = .outputRouted
  | .link => False

structure LinkContext where
  iface : Nat
  peerIface : Nat
  packet : PacketPolicy.Packet
  raw : RawPacket

structure CarrierEncoding where
  protocol : String
  networkProtocol : String
  headers : List (Nat × List UInt8)
  deriving DecidableEq

def CarrierEncoding.header (codec : CarrierEncoding) (session : Nat) : List UInt8 :=
  ((codec.headers.find? (fun entry => entry.1 == session)).map Prod.snd).getD []

def CarrierEncoding.session (codec : CarrierEncoding) (bytes : List UInt8) : Option Nat :=
  (codec.headers.find? (fun entry => bytes.take entry.2.length == entry.2)).map Prod.fst

def carrierNetworkOrder (width value : Nat) : List UInt8 :=
  (List.range width).map (fun index => UInt8.ofNat (value / 256^(width - 1 - index) % 256))

def CarrierEncoding.Valid (codec : CarrierEncoding) : Prop :=
  codec.headers ≠ [] ∧
  ∀ entry ∈ codec.headers, entry.2 ≠ [] ∧ entry.1 < 2^32 ∧
    (∀ other ∈ codec.headers, entry.2.length = other.2.length ∧
      (entry.1 = other.1 ↔ entry.2 = other.2)) ∧
    (codec.protocol = "l2tpv3" → codec.networkProtocol = "udp" ∧
      entry.2 = [0, 3, 0, 0] ++ carrierNetworkOrder 4 entry.1 ++ [0, 0, 0, 0])

instance (codec : CarrierEncoding) : Decidable codec.Valid := by
  unfold CarrierEncoding.Valid
  infer_instance

structure CarrierBinding where
  endpoint : LayeredFrame.Carrier
  encoding : CarrierEncoding
  sourceEncapsulator : String
  destinationEncapsulator : String
  association : LayeredFrame.MACsecAssociation


structure MKAEndpoint where
  sourceIface : Nat
  destinationIface : Nat
  actorSCI : Nat
  tunnel : String
  deriving DecidableEq

structure IPsecSizeBinding where
  iface : Nat
  policy : DataPlaneForwarding.IpsecPolicy
  outerHeaderBytes : Nat := 20
  deriving DecidableEq

def IPsecSizeBinding.EncodedSize (binding : IPsecSizeBinding) (bytes : Nat) : Nat :=
  (binding.outerHeaderBytes + 32) + 4 * ((bytes + 2 + 3) / 4)

def IPsecSizeBinding.Valid (binding : IPsecSizeBinding) : Prop :=
  (binding.policy.sender < 2^32 ∧ binding.policy.receiver < 2^32 ∧ binding.outerHeaderBytes = 20) ∨
  (2^128 ≤ binding.policy.sender ∧ binding.policy.sender < 2^129 ∧
    2^128 ≤ binding.policy.receiver ∧ binding.policy.receiver < 2^129 ∧
    binding.outerHeaderBytes = 40)

instance (binding : IPsecSizeBinding) : Decidable binding.Valid := by
  unfold IPsecSizeBinding.Valid
  infer_instance

structure Inventory where
  ifaces : List Nat
  configuration : MultiProtocolForwarding.Config
  ifaceName : Nat → String
  componentName : Nat → String
  mkaPeers : List MKAEndpoint
  ipsecSizes : List IPsecSizeBinding := []
  macsecTunnel : LayeredFrame.MACsecAssociation → String

inductive UDPMode where
  | ike | ikeNATT | espNATT | keepalive
  deriving DecidableEq

structure UDPBinding where
  id : String
  sourceComponent : String
  destinationComponent : String
  sourceAddress : Nat
  destinationAddress : Nat
  sourcePort : Nat
  destinationPort : Nat
  sourceOriginalAddress : Nat
  destinationOriginalAddress : Nat
  sourceOriginalPort : Nat
  destinationOriginalPort : Nat
  translated : Bool
  mode : UDPMode
  sourceReference : String
  deriving DecidableEq

def UDPBinding.Tuple (binding : UDPBinding) (packet : PacketPolicy.Packet) : Prop :=
  packet.protocol = "udp" ∧ packet.source = binding.sourceAddress ∧
  packet.destination = binding.destinationAddress ∧
  packet.sourcePort = binding.sourcePort ∧ packet.destinationPort = binding.destinationPort

def UDPBinding.Framing (binding : UDPBinding) (packet : PacketPolicy.Packet) : Prop :=
  binding.Tuple packet ∧
  ∃ bytes, packet.payloadBytes = some bytes ∧
    match binding.mode with
    | .ike => PacketPolicy.IKEHeader bytes
    | .ikeNATT => bytes.take 4 = [0, 0, 0, 0] ∧ PacketPolicy.IKEHeader (bytes.drop 4)
    | .espNATT => 8 ≤ bytes.length ∧ bytes.take 4 ≠ [0, 0, 0, 0]
    | .keepalive => bytes = [255]

def UDPBinding.WellFormed (binding : UDPBinding) : Prop :=
  binding.id ≠ "" ∧ binding.sourceReference ≠ "" ∧
  binding.sourcePort < 65536 ∧ binding.destinationPort < 65536 ∧
  binding.sourceOriginalPort < 65536 ∧ binding.destinationOriginalPort < 65536 ∧
  (binding.mode = .ike →
    binding.sourceOriginalPort = 500 ∧ binding.destinationOriginalPort = 500) ∧
  (binding.mode ≠ .ike →
    binding.sourceOriginalPort = 4500 ∧ binding.destinationOriginalPort = 4500) ∧
  (binding.translated = false →
    binding.sourceAddress = binding.sourceOriginalAddress ∧
    binding.destinationAddress = binding.destinationOriginalAddress ∧
    binding.sourcePort = binding.sourceOriginalPort ∧
    binding.destinationPort = binding.destinationOriginalPort)

instance (binding : UDPBinding) (packet : PacketPolicy.Packet) :
    Decidable (binding.Tuple packet) := by
  unfold UDPBinding.Tuple
  infer_instance

instance (binding : UDPBinding) (packet : PacketPolicy.Packet) :
    Decidable (binding.Framing packet) := by
  unfold UDPBinding.Framing
  cases binding.mode <;> infer_instance

instance (binding : UDPBinding) : Decidable binding.WellFormed := by
  unfold UDPBinding.WellFormed
  infer_instance


def words16 : List UInt8 → Nat
  | [] => 0
  | [first] => first.toNat * 256
  | first :: second :: rest => first.toNat * 256 + second.toNat + words16 rest

def ChecksumValid (bytes : List UInt8) : Prop :=
  0 < words16 bytes ∧ words16 bytes % 65535 = 0

def networkOrder (width value : Nat) : List UInt8 :=
  (List.range width).map (fun index => UInt8.ofNat (value / 256^(width - 1 - index) % 256))

def pseudoHeader (packet : PacketPolicy.Packet) (length : Nat) : List UInt8 :=
  if packet.source < 2^32 then
    networkOrder 4 packet.source ++ networkOrder 4 packet.destination ++
      [0, UInt8.ofNat ((PacketSource.protocolNumber packet.protocol).getD 0)] ++ networkOrder 2 length
  else
    networkOrder 16 (packet.source - 2^128) ++ networkOrder 16 (packet.destination - 2^128) ++
      networkOrder 4 length ++ [0, 0, 0, UInt8.ofNat packet.ipv6NextHeader]

def optionsValid : Nat → List UInt8 → Bool
  | 0, bytes => bytes.isEmpty
  | _ + 1, [] => true
  | _ + 1, 0 :: rest => rest.all (fun byte => byte == 0)
  | fuel + 1, 1 :: rest => optionsValid fuel rest
  | _ + 1, [_] => false
  | fuel + 1, _ :: length :: rest =>
      decide (2 ≤ length.toNat ∧ length.toNat - 2 ≤ rest.length) &&
        optionsValid fuel (rest.drop (length.toNat - 2))

def IPv4OptionsValid (bytes : List UInt8) : Prop :=
  optionsValid bytes.length bytes = true

def RawPacket.PreHookValid (raw : RawPacket) (packet : PacketPolicy.Packet) (hook : Hook) : Prop :=
  raw.Complete packet ∧
  match raw with
  | .ip network transport payload =>
      (packet.source < 2^32 →
        ChecksumValid network ∧ PacketSource.field network 6 2 / 32768 = 0 ∧
        IPv4OptionsValid (network.drop 20)) ∧
      (hook = .forward → 0 < packet.hopLimit) ∧
      (packet.protocol = "udp" →
        (packet.source < 2^32 ∧ PacketSource.field transport 6 2 = 0) ∨
          ChecksumValid (pseudoHeader packet (transport.length + payload.length) ++ transport ++ payload)) ∧
      (packet.protocol = "tcp" →
        ChecksumValid (pseudoHeader packet (transport.length + payload.length) ++ transport ++ payload)) ∧
      (packet.protocol = "icmp" → ChecksumValid (transport ++ payload)) ∧
      (packet.protocol = "icmpv6" →
        ChecksumValid (pseudoHeader packet (transport.length + payload.length) ++ transport ++ payload))
  | .ethernet header _ _ =>
      header.etherType ∉ [2048, 34525]


instance (raw : RawPacket) (packet : PacketPolicy.Packet) : Decidable (raw.Decoded packet) := by
  cases raw <;> unfold RawPacket.Decoded PacketSource.NetworkHeaderMatches
    PacketSource.TransportHeaderMatches PacketSource.EthernetHeaderMatches
    PacketPolicy.Packet.IPv4FragmentOffsetDecoded <;> infer_instance

instance (raw : RawPacket) (packet : PacketPolicy.Packet) : Decidable (raw.Complete packet) := by
  cases raw <;> unfold RawPacket.Complete <;> infer_instance

instance (bytes : List UInt8) : Decidable (ChecksumValid bytes) := by
  unfold ChecksumValid
  infer_instance

instance (bytes : List UInt8) : Decidable (IPv4OptionsValid bytes) := by
  unfold IPv4OptionsValid
  infer_instance

instance (raw : RawPacket) (packet : PacketPolicy.Packet) (hook : Hook) :
    Decidable (raw.PreHookValid packet hook) := by
  cases raw <;> unfold RawPacket.PreHookValid <;> infer_instance


end TDN.PacketProcessing
