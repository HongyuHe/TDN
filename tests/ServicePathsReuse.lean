import TDN.Network.Services

/-!
Three independently named endpoints use an addressless switch. The fixture
imports no MSC declaration. Successful control traces, route-coherent delivery,
and a changed next-hop counterexample exercise the reusable path machinery.
-/
namespace ServicePathsReuse
open TDN.Network TDN.Network.Execution TDN.Network.ExecutionTrace TDN.Network.Services

def endpoint (node : Nat) : Endpoint Nat := ⟨node, "uplink"⟩
def bridgePort (port : String) : Endpoint Nat := ⟨0, port⟩
def address (node : Nat) : UInt32 := UInt32.ofNat (167772160 + node)

def links : List (Endpoint Nat × Endpoint Nat) :=
  [(endpoint 1, bridgePort "west"), (bridgePort "west", endpoint 1),
   (endpoint 2, bridgePort "east"), (bridgePort "east", endpoint 2),
   (endpoint 3, bridgePort "north"), (bridgePort "north", endpoint 3)]

def ports (node : Nat) : List String := if node == 0 then ["west", "east", "north"] else ["uplink"]

def interface (node : Nat) (port : String) : ObservedInterface :=
  { name := port, index := node + 1, peerIndex := none, mtu := 1500, up := true, carrier := true,
    mac := "fixture", master := "", addresses := if node == 0 then [] else [⟨address node, 24⟩] }

def observed (node : Nat) : OperationalSnapshot :=
  { device := "generic-service-fixture", observedAt := "fixture",
    interfaces := some ((ports node).map (interface node)),
    routes := some
      [{ destination := ⟨address node, 32⟩, gateway := none, output := "uplink", table := 255,
         kind := "local", protocol := "kernel", metric := 0, preferredSource := none, scope := "host" },
       { destination := ⟨0x0a000000, 24⟩, gateway := none, output := "uplink", table := 254,
         kind := "unicast", protocol := "kernel", metric := 0, preferredSource := none, scope := "link" }],
    routingRules := some [⟨0, ⟨0, 0⟩, 255⟩, ⟨32766, ⟨0, 0⟩, 254⟩],
    forwarding := some false, policies := some [], states := some [], switching := none,
    clockEpoch := none, resolverServers := none, processes := none, startup := none }

def network : Model Nat :=
  { observed := fun node => some (observed node), retainedPorts := ports,
    inputFilter := fun _ _ _ => true, outputFilter := fun _ _ _ => true,
    forwardFilter := fun _ _ _ _ _ _ => false,
    linked := fun a b => (a, b) ∈ links,
    bridge := fun a b => a.node = 0 ∧ b.node = 0 ∧ a.port ∈ ports 0 ∧ b.port ∈ ports 0 ∧ a.port ≠ b.port,
    protectionFloor := fun _ => 0 }

instance : DecidableRel network.linked := fun a b =>
  inferInstanceAs (Decidable ((a, b) ∈ links))
instance : DecidableRel network.bridge := fun a b =>
  inferInstanceAs (Decidable (a.node = 0 ∧ b.node = 0 ∧ a.port ∈ ports 0 ∧ b.port ∈ ports 0 ∧ a.port ≠ b.port))

def start (target : Nat) : State Nat Unit :=
  let header : IPv4Header :=
    { source := address 1, destination := address target,
      protocol := 17, destinationPort := 123, bytes := 100 }
  ⟨endpoint 1, .output, .clear header none⟩

def commands (target : Nat) : List (Command Nat) :=
  [.wire (bridgePort "west"), .switch (if target == 2 then "east" else "north"), .wire (endpoint target)]

example : ∀ target ∈ [2, 3],
    (trace network (start target) (commands target)).isSome = true ∧
    ∀ result ∈ (trace network (start target) (commands target)).toList,
      result.last.location = endpoint target ∧
      (network.deliver target "uplink" result.last.packet).isSome = true ∧
      respectsNextHops network (start target :: result.visited) = true := by decide

def redirectedObservation (node : Nat) : OperationalSnapshot :=
  { observed node with
    routes := (observed node).routes.map fun routes => routes.map fun route =>
      if node == 1 && route.kind == "unicast" then { route with gateway := some (address 3) } else route }

def redirected : Model Nat :=
  { network with observed := fun node => some (redirectedObservation node) }

example : ∀ result ∈ (trace network (start 2) (commands 2)).toList,
    respectsNextHops redirected (start 2 :: result.visited) = false := by decide

example (target : Nat) (result : Result Nat Unit)
    (checked : trace network (start target) (commands target) = some result) :
    Route (Step network) (start target) result.last result.visited :=
  trace_is_route network (start target) (commands target) result checked

end ServicePathsReuse
