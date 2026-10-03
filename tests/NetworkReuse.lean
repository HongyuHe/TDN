import TDN.Network.Graph
import TDN.Network.Filter
import TDN.Network.Routing

/-!
An independent client of the reusable library imports no MSC deployment.
Vertices 2/3, 4/5, and 6/7 are pairs of hosts in three separate site/label
groups. Vertex 0 is a shared inspection gateway. Local interfaces use names
chosen by this client. The generic proofs are reused without modification.
-/
namespace NetworkReuse
open TDN.Network

def group (node : Nat) : Nat := node / 2

abbrev edge (a b : Nat) : Prop := group a = group b ∨ a = 0 ∨ b = 0

theorem every_cross_group_route_visits_gateway {a b : Nat} {nodes : List Nat}
    (different : group a ≠ group b) (path : Route edge a b nodes) :
    ∃ node ∈ a :: nodes, node = 0 := by
  apply path.must_visit_of_labels (fun node => node = 0) group _ different
  intro x y step
  rcases step.1 with same | hx | hy
  · exact same
  · exact False.elim (step.2.1 hx)
  · exact False.elim (step.2.2 hy)

example : Route edge 2 3 [3] := .cons (by decide) (.nil _)
example : Route edge 4 5 [5] := .cons (by decide) (.nil _)
example : Route edge 6 7 [7] := .cons (by decide) (.nil _)
example : Route edge 2 6 [0, 6] := .cons (by decide) (.cons (by decide) (.nil _))

structure Packet where
  ingress : String
  sourceGroup : Nat
  isProtected : Bool

def rules : List (Nat × String) := [(1, "red-east"), (2, "red-west"), (3, "red-north")]

def matchRule (rule : Nat × String) (packet : Packet) : Bool :=
  (rule.1 == packet.sourceGroup && rule.2 == packet.ingress) && packet.isProtected

theorem accepted_packets_are_protected (packet : Packet)
    (accepted : Filter.accepts matchRule rules false packet = true) :
    packet.isProtected = true := by
  apply Filter.accepted_satisfies matchRule rules (fun p => p.isProtected = true) _ packet accepted
  intro rule _ packet matched
  simp only [matchRule, Bool.and_eq_true] at matched
  exact matched.2

example : Filter.accepts matchRule rules false ⟨"red-north", 3, true⟩ = true := by decide
example : Filter.accepts matchRule rules false ⟨"red-north", 3, false⟩ = false := by decide
example : Filter.accepts matchRule rules false ⟨"red-east", 3, true⟩ = false := by decide

def route (network : UInt32) (length metric table : Nat) (output : String) : FibRoute :=
  { destination := ⟨network, length⟩, gateway := none, output := output,
    table := table, kind := "unicast", protocol := "static", metric := metric,
    preferredSource := none }

/-- Two hosts share one routed subnet, while a host-specific route takes
precedence. A third site's source rule selects a distinct policy table. -/
def routeRows : List FibRoute :=
  [route 0 0 5 254 "wan", route 0x0a020000 24 20 254 "site-two-slow",
   route 0x0a020000 24 5 254 "site-two-fast", route 0x0a02000a 32 100 254 "host-ten",
   route 0 0 1 100 "third-site-policy"]

def routeRules : List RoutingRule :=
  [⟨32766, ⟨0, 0⟩, 254⟩, ⟨100, ⟨0x0a030000, 16⟩, 100⟩, ⟨0, ⟨0, 0⟩, 255⟩]

example : (Routing.lookup routeRows routeRules 0x0a01000a 0x0a020014).map FibRoute.output =
    some "site-two-fast" := by decide
example : (Routing.lookup routeRows routeRules 0x0a01000b 0x0a02000a).map FibRoute.output =
    some "host-ten" := by decide
example : (Routing.lookup routeRows routeRules 0x0a030001 0x0a02000a).map FibRoute.output =
    some "third-site-policy" := by decide
example : Routing.lookup [] routeRules 0x0a01000a 0x0a02000a = none := by decide

/-- Reverse source reachability respects the longest prefix, route metric,
and source-specific routing table. The arrival interface is independently
specified, so an address reachable through a different port is rejected. -/
example : Routing.sourceReachableVia routeRows routeRules 0x0a01000a 0x0a020014
    "site-two-fast" = true := by decide
example : Routing.sourceReachableVia routeRows routeRules 0x0a01000a 0x0a020014
    "site-two-slow" = false := by decide
example : Routing.sourceReachableVia routeRows routeRules 0x0a01000a 0x0a02000a
    "site-two-fast" = false := by decide
example : Routing.sourceReachableVia routeRows routeRules 0x0a01000a 0x0a02000a
    "host-ten" = true := by decide
example : Routing.sourceReachableVia routeRows routeRules 0x0a030001 0x0a02000a
    "third-site-policy" = true := by decide
example : Routing.sourceReachableVia [] routeRules 0x0a01000a 0x0a02000a
    "host-ten" = false := by decide

example (source returnSource : UInt32) (interface : String)
    (known : Routing.sourceReachableVia routeRows routeRules returnSource source interface = true) :
    ∃ selected ∈ routeRows, Routing.lookup routeRows routeRules returnSource source = some selected ∧
      selected.kind = "unicast" ∧ selected.output = interface ∧
      selected.destination.contains source = true ∧
      ∃ rule ∈ routeRules, rule.source.contains returnSource = true ∧ rule.table = selected.table :=
  Routing.source_reachability_has_route routeRows routeRules returnSource source interface known

end NetworkReuse
