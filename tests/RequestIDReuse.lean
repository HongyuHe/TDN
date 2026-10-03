import TDN.Network.Execution
namespace IndependentRequestIDs
open TDN.Network TDN.Network.Execution

def association (request : Nat) : XfrmState :=
  { source := 0xc0000201, destination := 0xc6336401, spi := 871, reqid := request,
    mode := "tunnel", protocol := "esp", algorithm := "rfc4106(gcm(aes))", integrityBits := 128,
    replayWindow := 32, hardLifetimeSeconds := 3600, udpEncapsulation := false,
    udpSourcePort := none, udpDestinationPort := none, tfcPadding := 0 }

def policy (direction : String) : XfrmPolicy :=
  { source := ⟨0x0a010000,24⟩, destination := ⟨0x0a020000,24⟩, direction := direction,
    priority := 10, tunnelSource := 0xc0000201, tunnelDestination := 0xc6336401,
    reqid := 82, mode := "tunnel", protocol := "esp" }

def observation : OperationalSnapshot :=
  { device := "receiver", observedAt := "fixture", interfaces := none,
    routes := some [{ destination := ⟨0xc6336401,32⟩, gateway := none, output := "wan", table := 255, kind := "local", protocol := "kernel", metric := 0, preferredSource := none, scope := "host" }],
    routingRules := some [⟨0,⟨0,0⟩,255⟩], forwarding := none,
    policies := some [policy "in",policy "fwd"], states := some [association 82],
    switching := none, clockEpoch := none, resolverServers := none, processes := none, startup := none }

def receiver : Model Unit :=
  { observed := fun _ => some observation, retainedPorts := fun _ => ["wan"],
    inputFilter := fun _ _ _ => true, forwardFilter := fun _ _ _ _ _ _ => true,
    outputFilter := fun _ _ _ => true, linked := fun _ _ => False,
    bridge := fun _ _ => False, protectionFloor := fun _ => 0 }

def payload : WirePacket Unit :=
  .clear { source := 0x0a01000a, destination := 0x0a02000a, protocol := 1, bytes := 100 } (some ())

example : stateMatches (policy "in") (association 82) = true := by decide
example : receiver.receive () "wan" (payload.seal (association 82)) = some (payload,some 82) := by decide
example : receiver.receive () "wan" (payload.seal (association 71)) = some (payload,some 82) := by decide
example : receiver.receive () "wan" (payload.seal { association 71 with spi := 872 }) = none := by decide
example : receiver.receive () "wan" (payload.seal { association 71 with source := 0xc0000202 }) = none := by decide
example : receiver.receive () "wan" (payload.seal { association 71 with protocol := "ah" }) = none := by decide

/-- Sender metadata can vary independently while receiver policy stays fixed. -/
example : (CipherIdentity.ofState (association 71)).reqid = 71 := rfl
example : ESPWireIdentity.ofState (association 71) = ESPWireIdentity.ofState (association 82) := rfl
end IndependentRequestIDs
