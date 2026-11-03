import TDN.Semantics.PacketSource

namespace TDN.LinkAdmission

structure Program where
  rules : List PacketPolicy.Rule
  fallback : Filter.Verdict
  deriving DecidableEq, Repr

structure PortPolicy where
  inbound : Program
  outbound : Program
  deriving DecidableEq, Repr

def Program.Accepts (program : Program) (packet : PacketPolicy.Packet) : Prop :=
  Filter.evaluate (program.rules.map PacketPolicy.Rule.toFilter) program.fallback packet = .allow

structure Frame where
  header : LayeredFrame.EthernetHeader
  headerBytes : List UInt8
  payload : List UInt8
  deriving DecidableEq

def Frame.Packet (frame : Frame) (ingress egress : String) : PacketPolicy.Packet :=
  { source := frame.header.source, destination := frame.header.destination,
    protocol := "ethernet", ingress := ingress, egress := egress,
    sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 0,
    inboundPolicies := [], outboundPolicies := [], connectionState := "",
    etherType := some frame.header.etherType, payloadBytes := some frame.payload,
    networkBytes := some (frame.headerBytes.length + frame.payload.length) }

def Frame.Decoded (frame : Frame) : Prop :=
  PacketSource.EthernetHeaderMatches frame.header frame.headerBytes

def MACsecFraming (association : LayeredFrame.MACsecAssociation) (bytes : List UInt8) : Prop :=
  22 ≤ bytes.length ∧ PacketSource.field bytes 0 1 % 4 = association.associationNumber ∧
  (if PacketSource.field bytes 0 1 / 32 % 2 = 1 then
    30 ≤ bytes.length ∧ PacketSource.field bytes 6 8 = association.sci
   else True)

instance (frame : Frame) : Decidable frame.Decoded := by
  unfold Frame.Decoded PacketSource.EthernetHeaderMatches
  infer_instance

def Frame.DescribesBody (frame : Frame) (body : LayeredFrame.Body) : Prop :=
  frame.Decoded ∧
  match body with
  | .ethernet header => frame.header = header
  | .macsec association _ =>
      frame.header.etherType = 35045 ∧ MACsecFraming association frame.payload ∧
      (PacketSource.field frame.payload 0 1 / 32 % 2 = 0 →
        frame.header.source = association.sci / 65536)
  | _ => False

def lookup (policies : List (Nat × PortPolicy)) (port : Nat) : Option PortPolicy :=
  (policies.find? (fun entry => entry.1 == port)).map Prod.snd

def Admitted (policies : List (Nat × PortPolicy)) (port : Nat) (outbound : Bool)
    (packet : PacketPolicy.Packet) : Prop :=
  ∃ policy, lookup policies port = some policy ∧
    (if outbound then policy.outbound else policy.inbound).Accepts packet

instance (program : Program) (packet : PacketPolicy.Packet) :
    Decidable (program.Accepts packet) := by
  unfold Program.Accepts
  infer_instance

instance (policies : List (Nat × PortPolicy)) (port : Nat) (outbound : Bool)
    (packet : PacketPolicy.Packet) : Decidable (Admitted policies port outbound packet) := by
  unfold Admitted
  infer_instance

def payloadCode (bytes : List UInt8) : Nat :=
  bytes.foldl (fun accumulator byte => accumulator * 256 + byte.toNat) 1

def Frame.Describes (frame : Frame) (native : LayeredFrame.Frame) : Prop :=
  match native.visibleHeader with
  | none => frame.DescribesBody native.body ∧
      (∀ header, native.body = .ethernet header → native.payload = payloadCode frame.payload)
  | some packet =>
      frame.Decoded ∧
      (if packet.source < 2^32 then frame.header.etherType = 2048
        else frame.header.etherType = 34525) ∧
      ∃ network transport payload,
        frame.payload = network ++ transport ++ payload ∧
        PacketSource.NetworkHeaderMatches packet network (transport.length + payload.length) ∧
        (∀ header, native.body = .datagram header →
          packet.payloadBytes = some payload ∧ native.payload = payloadCode payload) ∧
        (PacketSource.TransportHeaderMatches packet transport payload ∨
          packet.protocol = "esp" ∧ transport = [] ∧ 8 ≤ payload.length)

end TDN.LinkAdmission
