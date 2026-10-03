import TDN.Network.Execution
import TDN.Network.SourcePolicy

/-!
A separate three-site fixture uses one gateway with two peer tunnels. It
imports no MSC declaration. The same policy-selection, sealing, and accounting
definitions handle both destinations without a fixed host or security-level
enumeration. The fixture targets the reusable XFRM operation; NetworkReuse
separately exercises a multi-host topology and routing-policy selection.
-/
namespace ExecutionReuse
open TDN.Network TDN.Network.Execution

def peerPolicy (subnet endpoint : UInt32) (request : Nat) : XfrmPolicy :=
  { source := ⟨0x0a010000, 24⟩, destination := ⟨subnet, 24⟩, direction := "out", priority := 10,
    tunnelSource := 0xc0000201, tunnelDestination := endpoint, reqid := request,
    mode := "tunnel", protocol := "esp" }

def peerState (endpoint : UInt32) (request spi : Nat) : XfrmState :=
  { source := 0xc0000201, destination := endpoint, spi := spi, reqid := request,
    mode := "tunnel", protocol := "esp", algorithm := "rfc4106(gcm(aes))", integrityBits := 128,
    replayWindow := 0, hardLifetimeSeconds := 3600, udpEncapsulation := false,
    udpSourcePort := none, udpDestinationPort := none, tfcPadding := 0 }

def observation : OperationalSnapshot :=
  { device := "three-site-fixture", observedAt := "fixture", interfaces := none,
    routes := none, routingRules := none, forwarding := none,
    policies := some [peerPolicy 0x0a020000 0xc6336401 71, peerPolicy 0x0a030000 0xcb007101 72],
    states := some [peerState 0xc6336401 71 871, peerState 0xcb007101 72 872],
    switching := none, clockEpoch := none, resolverServers := none, processes := none, startup := none }

def fixture : Model Nat :=
  { observed := fun node => if node == 1 then some observation else none,
    retainedPorts := fun _ => [], inputFilter := fun _ _ _ => false,
    outputFilter := fun _ _ _ => false, forwardFilter := fun _ _ _ _ _ _ => false,
    linked := fun _ _ => False, bridge := fun _ _ => False, protectionFloor := fun _ => 0 }

def messageTo (destination : UInt32) : WirePacket String :=
  .clear { source := 0x0a01000a, destination := destination, protocol := 1, bytes := 100 } (some "arbitrary data")

example : (fixture.send 1 (messageTo 0x0a02000a)).map Prod.snd = some (some 71) := by decide
example : (fixture.send 1 (messageTo 0x0a03000b)).map Prod.snd = some (some 72) := by decide

example (packet sent : WirePacket String) (tag : Option Nat)
    (accepted : fixture.send 1 packet = some (sent, tag)) : sent.message = packet.message :=
  (send_layer_accounting fixture 1 packet sent tag accepted).1

example : (fixture.send 1 (messageTo 0x0a02000a)).all
    (fun result => result.1.depth == 1 && result.1.message == some "arbitrary data") = true := by decide

/-- The address-partition argument supports any label type and cardinality. -/
def domains : List (LabeledPrefix Nat) :=
  [⟨10, ⟨0x0a010000, 24⟩⟩, ⟨20, ⟨0x0a020000, 24⟩⟩, ⟨30, ⟨0x0a030000, 24⟩⟩]

theorem domain_certificate : ∀ a ∈ domains, ∀ b ∈ domains,
    a.label ≠ b.label → a.network.sameWidthApart b.network = true := by decide

example (a b : LabeledPrefix Nat) (memberA : a ∈ domains) (memberB : b ∈ domains)
    (address : UInt32) (inA : a.network.contains address = true)
    (inB : b.network.contains address = true) : a.label = b.label :=
  labeled_prefix_members_share_label domains domain_certificate a b memberA memberB address inA inB

end ExecutionReuse
