import TDN

/-!
# Run the model without contacting the emulator

An `IO Unit` function performs console output and returns no useful value.
Every call to `transmit`, `deliver`, or `forwardDecision` below evaluates pure
Lean code. The printed snapshot identity lets a reader locate the source facts;
the runtime examples use explicit assumptions instead of claiming fresh state.
-/

open TDN.MSC

/-- Pattern matching distinguishes a blocked operation from a nested result.
Reading the payload is intentional in this symbolic model, not decryption. -/
def describe (result : Option BlackPacket) : String :=
  match result with
  | none => "blocked"
  | some packet =>
    s!"outer(inner({packet.protectedInner.protectedPayload.payload}))"

def main : IO Unit := do
  IO.println s!"Required MSC projection: {retainedDevices.length} devices, {retainedLinks.length} links"
  IO.println s!"Snapshot spec SHA-256: {Deployment.specHash}"
  IO.println "The following examples assume fixed healthy state; they are not live network probes."
  IO.println s!"Same level, healthy: {describe (transmit healthy sameLevelPacket)}"
  IO.println s!"Cross level, healthy: {describe (transmit healthy crossLevelPacket)}"
  IO.println s!"Inner SA down: {describe (transmit { healthy with innerSA := false } sameLevelPacket)}"
  IO.println s!"Outer SA down: {describe (transmit { healthy with outerSA := false } sameLevelPacket)}"
  IO.println s!"Untrusted inner peer: {describe (transmit { healthy with innerPeerAuthenticated := false } sameLevelPacket)}"
  IO.println s!"Untrusted outer peer: {describe (transmit { healthy with outerPeerAuthenticated := false } sameLevelPacket)}"
  IO.println s!"Inner policy removed: {describe (transmit { healthy with innerPolicy := false } sameLevelPacket)}"
  IO.println s!"Outer policy removed: {describe (transmit { healthy with outerPolicy := false } sameLevelPacket)}"
  IO.println s!"Black route unavailable: {describe (transmit { healthy with transportReady := false } sameLevelPacket)}"
  IO.println s!"OF_A1 permits declared ESP: {repr (forwardDecision "OF_A1" outerFirewallExample)}"
  IO.println s!"OF_A1 blocks ICMP: {repr (forwardDecision "OF_A1" { outerFirewallExample with protocol := 1 })}"
  IO.println s!"Delivered with both receiver layers ready: {repr (deliver healthy healthy sameLevelPacket)}"
  IO.println s!"Receiver inner SA absent: {repr (deliver healthy { healthy with innerSA := false } sameLevelPacket)}"
