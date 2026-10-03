import TDN.Network.Protection

/-!
Three encryption stages with numeric node and layer labels reuse the same
provenance and stack induction. The fixture executes actual policy selection,
routing, XFRM sealing, filtering, port/MTU checks, and two wire transfers. It
imports no MSC module and does not assume a two-layer architecture.
-/
namespace ProtectionReuse
open TDN.Network TDN.Network.Execution TDN.Network.Protection

abbrev Node := Fin 3

def sourceAddress (node : Node) : UInt32 :=
  if node == 0 then 0xc0000201 else if node == 1 then 0xc6336401 else 0xcb007101

def destinationAddress (node : Node) : UInt32 := sourceAddress node + 1

def previousSource (node : Node) : UInt32 :=
  if node == 0 then 0x0a010001 else if node == 1 then sourceAddress 0 else sourceAddress 1

def previousDestination (node : Node) : UInt32 := previousSource node + 1

def policy (node : Node) : XfrmPolicy :=
  { source := ⟨previousSource node, 32⟩, destination := ⟨previousDestination node, 32⟩,
    direction := "out", priority := 10, tunnelSource := sourceAddress node,
    tunnelDestination := destinationAddress node, reqid := 10 + node.val, mode := "tunnel", protocol := "esp" }

def association (node : Node) : XfrmState :=
  { source := sourceAddress node, destination := destinationAddress node, spi := 100 + node.val,
    reqid := 10 + node.val, mode := "tunnel", protocol := "esp", algorithm := "rfc4106(gcm(aes))",
    integrityBits := 128, replayWindow := 0, hardLifetimeSeconds := 3600, udpEncapsulation := false,
    udpSourcePort := none, udpDestinationPort := none, tfcPadding := 0 }

def route : FibRoute :=
  { destination := ⟨0, 0⟩, gateway := none, output := "out", table := 254,
    kind := "unicast", protocol := "static", metric := 0, preferredSource := none }

def interface (name : String) (index : Nat) : ObservedInterface :=
  { name := name, index := index, peerIndex := none, mtu := 3000, up := true, carrier := true,
    mac := "fixture", master := "", addresses := [] }

def observation (node : Node) : OperationalSnapshot :=
  { device := "fixture", observedAt := "fixture", interfaces := some [interface "in" 1, interface "out" 2],
    routes := some [route], routingRules := some [⟨32766, ⟨0, 0⟩, 254⟩], forwarding := some true,
    policies := some [policy node], states := some [association node], switching := none,
    clockEpoch := none, resolverServers := none, processes := none, startup := none }

def wires : List (Endpoint Node × Endpoint Node) :=
  [(⟨0, "out"⟩, ⟨1, "in"⟩), (⟨1, "out"⟩, ⟨2, "in"⟩)]

def permits (node : Node) (input output : String) (_ : IPv4Header) (inputTag outputTag : Option Nat) : Bool :=
  input == "in" && output == "out" && inputTag == none && outputTag == some (10 + node.val)

def network : Model Node :=
  { observed := fun node => some (observation node), retainedPorts := fun _ => ["in", "out"],
    inputFilter := fun _ _ _ => false, outputFilter := fun _ _ _ => false,
    forwardFilter := permits, linked := fun a b => (a, b) ∈ wires, bridge := fun _ _ => False,
    protectionFloor := fun _ => 0 }

def entering (node : Node) : List Nat :=
  if node == 0 then [] else if node == 1 then [10] else [11, 10]

def expected (endpoint : Endpoint Node) : List Nat :=
  if endpoint.port == "out" then (10 + endpoint.node.val) :: entering endpoint.node else entering endpoint.node

theorem wire_certificate : ∀ edge ∈ wires, expected edge.1 = expected edge.2 := by decide

theorem local_certificate : ProcessingStack network id expected := by
  intro node input output header inputTag outputTag _ _ _ _ _ _ filtered
  change permits node input output header inputTag outputTag = true at filtered
  simp only [permits, Bool.and_eq_true, beq_iff_eq] at filtered
  obtain ⟨⟨⟨rfl, rfl⟩, rfl⟩, rfl⟩ := filtered
  rfl

def original : WirePacket String :=
  .clear { source := 0x0a010001, destination := 0x0a010002, protocol := 1, bytes := 100 } (some "data")

def firstPacket := original.seal (association 0)
def secondPacket := firstPacket.seal (association 1)
def thirdPacket := secondPacket.seal (association 2)

def first : ForwardResult String := ⟨original, firstPacket, route, none, some 10⟩
def second : ForwardResult String := ⟨firstPacket, secondPacket, route, none, some 11⟩
def third : ForwardResult String := ⟨secondPacket, thirdPacket, route, none, some 12⟩

def initial : State Node String := ⟨⟨0, "in"⟩, .input, original⟩
def finalState : State Node String := ⟨⟨2, "out"⟩, .output, thirdPacket⟩

theorem three_stage_execution : Reach (Step network) initial finalState :=
  .step (.forward 0 "in" original first (by decide))
    (.step (.wire ⟨0, "out"⟩ ⟨1, "in"⟩ firstPacket
      (by change (⟨0, "out"⟩, ⟨1, "in"⟩) ∈ wires; decide) (by decide) (by decide))
      (.step (.forward 1 "in" firstPacket second (by decide))
        (.step (.wire ⟨1, "out"⟩ ⟨2, "in"⟩ secondPacket
          (by change (⟨1, "out"⟩, ⟨2, "in"⟩) ∈ wires; decide) (by decide) (by decide))
          (.step (.forward 2 "in" secondPacket third (by decide)) (.refl _)))))

example : GeneratedLayers network finalState.packet :=
  executions_preserve_layer_provenance network three_stage_execution (.clear _ _)

example : layerLabels id finalState.packet = [12, 11, 10] := by
  have initialSafe : StackInvariant id expected initial := by intro _; rfl
  have safe := executions_preserve_stack network id expected local_certificate
    (fun a b member => wire_certificate (a,b) member)
    (fun _ _ impossible => False.elim impossible) three_stage_execution initialSafe
  exact safe (by rfl)

end ProtectionReuse
