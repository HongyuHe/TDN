import TDN.Network.Operational

/-!
Route lookup separates table selection from longest-prefix selection. Rules
are visited in priority order. A matching rule selects its table only when
that table supplies a destination match; otherwise lookup continues.

Within a table, a longer destination prefix wins, followed by a lower metric.
Equal-cost ties choose the last retained row. A client that observes ECMP or
unsupported route actions must provide a corresponding extended model. The
MSC importer currently rejects multipath attributes and unsupported rule syntax.
This module keeps the observed route kind in the result, so a caller must
distinguish local delivery, broadcast, and unicast forwarding explicitly.
-/
namespace TDN.Network.Routing

/-- Select one element by a supplied preference. Selection never manufactures
a record, which is the evidence-membership fact needed by route lookup. -/
def select {α : Type} (prefer : α → α → Bool) : List α → Option α
  | [] => none
  | head :: tail =>
    match select prefer tail with
    | none => some head
    | some other => if prefer head other then some head else some other

theorem selected_is_member {α : Type} (prefer : α → α → Bool) (rows : List α)
    (result : α) (selected : select prefer rows = some result) : result ∈ rows := by
  induction rows with
  | nil => simp [select] at selected
  | cons head tail ih =>
    simp only [select] at selected
    cases rest : select prefer tail with
    | none => simp [rest] at selected; simp [← selected]
    | some other =>
      by_cases better : prefer head other = true
      · have equal : head = result := by simpa [rest, better] using selected
        simp [← equal]
      · have equal : other = result := by simpa [rest, better] using selected
        exact List.mem_cons_of_mem head (ih (rest.trans (congrArg some equal)))

def preferred (a b : FibRoute) : Bool :=
  b.destination.length < a.destination.length ||
    (a.destination.length == b.destination.length && a.metric < b.metric)

def inTable (routes : List FibRoute) (table : Nat) (destination : UInt32) : Option FibRoute :=
  select preferred (routes.filter fun route => route.table == table && route.destination.contains destination)

theorem table_result_is_observed_match (routes : List FibRoute) (table : Nat)
    (destination : UInt32) (result : FibRoute)
    (found : inTable routes table destination = some result) :
    result ∈ routes ∧ result.table = table ∧ result.destination.contains destination = true := by
  have member := selected_is_member preferred _ result found
  simpa only [List.mem_filter, Bool.and_eq_true, beq_iff_eq, and_assoc] using member

def lookupOrdered (routes : List FibRoute) (source destination : UInt32) :
    List RoutingRule → Option FibRoute
  | [] => none
  | rule :: tail =>
    if rule.source.contains source then
      match inTable routes rule.table destination with
      | some route => some route
      | none => lookupOrdered routes source destination tail
    else lookupOrdered routes source destination tail

def insertRule (rule : RoutingRule) : List RoutingRule → List RoutingRule
  | [] => [rule]
  | head :: tail =>
    if rule.priority ≤ head.priority then rule :: head :: tail
    else head :: insertRule rule tail

/-- Structural insertion sorting keeps finite checks reducible by the kernel
without relying on a native-code decision tactic. Rule inventories are small. -/
def prioritize : List RoutingRule → List RoutingRule
  | [] => []
  | head :: tail => insertRule head (prioritize tail)

theorem mem_insert_rule (rule item : RoutingRule) (rules : List RoutingRule) :
    item ∈ insertRule rule rules ↔ item = rule ∨ item ∈ rules := by
  induction rules with
  | nil => simp [insertRule]
  | cons head tail ih =>
    simp only [insertRule]
    split <;> simp_all [or_left_comm]

theorem mem_prioritize (item : RoutingRule) (rules : List RoutingRule) :
    item ∈ prioritize rules ↔ item ∈ rules := by
  induction rules with
  | nil => rfl
  | cons head tail ih => simp [prioritize, mem_insert_rule, ih]

def lookup (routes : List FibRoute) (rules : List RoutingRule)
    (source destination : UInt32) : Option FibRoute :=
  lookupOrdered routes source destination (prioritize rules)

/-- Any successful lookup is backed by one observed route and a source-matching
policy rule. Later forwarding proofs can use the route's output interface and
next hop without inventing reachability from tunnel intent. -/
theorem ordered_lookup_has_evidence (routes : List FibRoute) (rules : List RoutingRule)
    (source destination : UInt32) (result : FibRoute)
    (found : lookupOrdered routes source destination rules = some result) :
    result ∈ routes ∧ result.destination.contains destination = true ∧
      ∃ rule ∈ rules, rule.source.contains source = true ∧ rule.table = result.table := by
  induction rules with
  | nil => simp [lookupOrdered] at found
  | cons rule tail ih =>
    simp only [lookupOrdered] at found
    split at found
    next sourceMatch =>
      cases route : inTable routes rule.table destination with
      | none =>
        rw [route] at found
        obtain ⟨observed, target, used, member, matched, table⟩ := ih found
        exact ⟨observed, target, used, List.mem_cons_of_mem _ member, matched, table⟩
      | some value =>
        rw [route] at found
        have equal := Option.some.inj found
        subst result
        obtain ⟨observed, table, target⟩ := table_result_is_observed_match routes rule.table destination value route
        exact ⟨observed, target, rule, by simp, sourceMatch, table.symm⟩
    next sourceMismatch =>
      obtain ⟨observed, target, used, member, matched, table⟩ := ih found
      exact ⟨observed, target, used, List.mem_cons_of_mem _ member, matched, table⟩

theorem lookup_has_evidence (routes : List FibRoute) (rules : List RoutingRule)
    (source destination : UInt32) (result : FibRoute)
    (found : lookup routes rules source destination = some result) :
    result ∈ routes ∧ result.destination.contains destination = true ∧
      ∃ rule ∈ rules, rule.source.contains source = true ∧ rule.table = result.table := by
  obtain ⟨observed, target, rule, member, matched, table⟩ :=
    ordered_lookup_has_evidence routes (prioritize rules) source destination result found
  exact ⟨observed, target, rule, (mem_prioritize rule rules).mp member, matched, table⟩

/-- A source is known to be reachable through an arrival interface when a
reverse lookup selects a unicast route through that interface. The return
source is explicit because policy routing can depend on it. The predicate
checks sampled routing knowledge; it does not authenticate a packet's sender. -/
def sourceReachableVia (routes : List FibRoute) (rules : List RoutingRule)
    (returnSource source : UInt32) (interface : String) : Bool :=
  (lookup routes rules returnSource source).any fun route =>
    route.kind == "unicast" && route.output == interface

theorem source_reachability_has_route (routes : List FibRoute) (rules : List RoutingRule)
    (returnSource source : UInt32) (interface : String)
    (known : sourceReachableVia routes rules returnSource source interface = true) :
    ∃ route ∈ routes, lookup routes rules returnSource source = some route ∧
      route.kind = "unicast" ∧ route.output = interface ∧
      route.destination.contains source = true ∧
      ∃ rule ∈ rules, rule.source.contains returnSource = true ∧ rule.table = route.table := by
  cases found : lookup routes rules returnSource source with
  | none => simp [sourceReachableVia, found] at known
  | some route =>
    have fields : route.kind = "unicast" ∧ route.output = interface := by
      simpa [sourceReachableVia, found] using known
    obtain ⟨member, destination, rule, ruleMember, sourceMatch, table⟩ :=
      lookup_has_evidence routes rules returnSource source route found
    exact ⟨route, member, rfl, fields.1, fields.2, destination,
      rule, ruleMember, sourceMatch, table⟩

end TDN.Network.Routing
