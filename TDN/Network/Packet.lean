import TDN.Network.Operational
import TDN.Network.Encapsulation

/-!
Packet contents are an arbitrary type. A clear packet carries either a protected
application message or control traffic. A cipher constructor records one ideal
authenticated encryption operation and retains the protected packet inside it.
The symbolic body is readable to Lean; the constructor models provenance and
processing order, not computational secrecy. An implementation interpretation
assumes that the trusted IPsec operation realizes the constructor.
-/
namespace TDN.Network

structure IPv4Header where
  source : UInt32
  destination : UInt32
  protocol : Nat
  destinationPort : Nat := 0
  headerWords : Nat := 5
  bytes : Nat := 20
  deriving DecidableEq, BEq, Repr

/-- ESP lookup uses wire-visible endpoint and SPI fields. The supported
protocol is explicit so the key does not identify an unrelated IPsec protocol.
UDP encapsulation carries the same ESP association inside its UDP wrapper. -/
structure ESPWireIdentity where
  source : UInt32
  destination : UInt32
  spi : Nat
  protocol : String
  deriving DecidableEq, BEq, Repr

/-- A symbolic cipher retains wire identity and the sealing endpoint's local
policy identifier separately. `reqid` supplies sender provenance for the
layer-label proof. It is proof-only metadata and is never compared against the
receiver's independently chosen local request ID. No key material is stored. -/
structure CipherIdentity where
  wire : ESPWireIdentity
  reqid : Nat
  deriving DecidableEq, BEq, Repr

inductive WirePacket (Message : Type) where
  | clear (header : IPv4Header) (message : Option Message)
  | cipher (header : IPv4Header) (identity : CipherIdentity) (body : WirePacket Message)
  deriving DecidableEq, BEq, Repr

variable {Message : Type}

def WirePacket.header : WirePacket Message → IPv4Header
  | .clear header _ => header
  | .cipher header _ _ => header

def WirePacket.message : WirePacket Message → Option Message
  | .clear _ message => message
  | .cipher _ _ body => body.message

def WirePacket.depth : WirePacket Message → Nat
  | .clear _ _ => 0
  | .cipher _ _ body => body.depth + 1

/-- The original application's header remains below every cipher wrapper.
The execution model includes no NAT operation that would rewrite that header. -/
def WirePacket.originalHeader : WirePacket Message → IPv4Header
  | .clear header _ => header
  | .cipher _ _ body => body.originalHeader

theorem zero_depth_header_is_original (packet : WirePacket Message) (clear : packet.depth = 0) :
    packet.header = packet.originalHeader := by
  cases packet with
  | clear => rfl
  | cipher => simp [WirePacket.depth] at clear

def ESPWireIdentity.ofState (state : XfrmState) : ESPWireIdentity :=
  ⟨state.source, state.destination, state.spi, state.protocol⟩

def CipherIdentity.ofState (state : XfrmState) : CipherIdentity :=
  ⟨ESPWireIdentity.ofState state, state.reqid⟩

def WirePacket.seal (state : XfrmState) (body : WirePacket Message) : WirePacket Message :=
  .cipher
    { source := state.source, destination := state.destination,
      protocol := if state.udpEncapsulation then 17 else 50,
      destinationPort := state.udpDestinationPort.getD 0,
      bytes := Encapsulation.espIPv4Size body.header.bytes state.udpEncapsulation }
    (CipherIdentity.ofState state) body

theorem seal_preserves_message (state : XfrmState) (packet : WirePacket Message) :
    (packet.seal state).message = packet.message := rfl

theorem seal_adds_one_layer (state : XfrmState) (packet : WirePacket Message) :
    (packet.seal state).depth = packet.depth + 1 := rfl

theorem seal_preserves_original_header (state : XfrmState) (packet : WirePacket Message) :
    (packet.seal state).originalHeader = packet.originalHeader := rfl

end TDN.Network
