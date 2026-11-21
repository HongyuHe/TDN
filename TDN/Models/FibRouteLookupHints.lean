import TDN.Models.IndexedLookupTree
import TDN.Models.DataPlaneForwarding

/-! A route lookup hint identifies the winning routes. Lean checks its entries against the captured forwarding table. -/
namespace TDN.DataPlaneForwarding
open LookupHints

def routePriorityAllows (route other : FibRoute) : Prop :=
  route.tablePriority ≤ other.tablePriority ∧
    (other.tablePriority = route.tablePriority → other.prefixLength ≤ route.prefixLength ∧
      (other.prefixLength = route.prefixLength → route.metric ≤ other.metric))

instance (route other : FibRoute) : Decidable (routePriorityAllows route other) := by
  unfold routePriorityAllows
  infer_instance

lemma route_priority_transitive (first second third : FibRoute)
    (a : routePriorityAllows first second) (b : routePriorityAllows second third) :
    routePriorityAllows first third := by
  unfold routePriorityAllows at *
  obtain ⟨aTable, ap⟩ := a
  obtain ⟨bt, bp⟩ := b
  refine ⟨by omega, ?_⟩
  intro table
  have t1 : second.tablePriority = first.tablePriority := by omega
  have t2 : third.tablePriority = second.tablePriority := by omega
  obtain ⟨al, am⟩ := ap t1
  obtain ⟨bl, bm⟩ := bp t2
  exact ⟨by omega, fun length => by
    have p1 : second.prefixLength = first.prefixLength := by omega
    have p2 : third.prefixLength = second.prefixLength := by omega
    have := am p1
    have := bm p2
    omega⟩

structure FibRouteLookupHint where
  destination : Nat
  winners : NatIndex (List Bool)
  retained : LookupTree FibRoute
  coverage : LookupTree (List Bool)
  origins : LookupTree (List Bool)
  deriving Repr, DecidableEq

def FibRouteLookupHint.best (hint : FibRouteLookupHint) (routes : LookupTree FibRoute)
    (ingress : Nat) : Option FibRoute :=
  (hint.winners.lookup ingress).bind routes.lookup

def FibRouteLookupHint.Covers (hint : FibRouteLookupHint) (routes : LookupTree FibRoute)
    (route : FibRoute) (index : List Bool) : Prop :=
  route.destPrefixLow ≤ hint.destination ∧ hint.destination ≤ route.destPrefixHigh →
    ∃ best, hint.best routes route.ingress = some best ∧
      best.ingress = route.ingress ∧
      best.destPrefixLow ≤ hint.destination ∧ hint.destination ≤ best.destPrefixHigh ∧
      routePriorityAllows best route ∧
      (routePriorityAllows route best → hint.retained.lookup index = some route)

instance (hint : FibRouteLookupHint) (routes : LookupTree FibRoute)
    (route : FibRoute) (index : List Bool) : Decidable (hint.Covers routes route index) := by
  unfold FibRouteLookupHint.Covers
  infer_instance

def FibRouteLookupHint.Retains (hint : FibRouteLookupHint) (routes : LookupTree FibRoute)
    (route : FibRoute) (index : List Bool) : Prop :=
  routes.lookup index = some route ∧
    route.destPrefixLow ≤ hint.destination ∧ hint.destination ≤ route.destPrefixHigh ∧
    ∃ best, hint.best routes route.ingress = some best ∧ routePriorityAllows route best

instance (hint : FibRouteLookupHint) (routes : LookupTree FibRoute)
    (route : FibRoute) (index : List Bool) : Decidable (hint.Retains routes route index) := by
  unfold FibRouteLookupHint.Retains
  infer_instance

def FibRouteLookupHint.check (routes : LookupTree FibRoute) (hint : FibRouteLookupHint) : Bool :=
  routes.checkWith (fun route index => decide (hint.Covers routes route index)) hint.coverage &&
    hint.retained.checkWith (fun route index => decide (hint.Retains routes route index)) hint.origins

lemma route_hint_covers (routes : LookupTree FibRoute) (hint : FibRouteLookupHint)
    (checked : hint.check routes = true) :
    ∀ route ∈ routes.values,
      route.destPrefixLow ≤ hint.destination ∧ hint.destination ≤ route.destPrefixHigh →
      ∃ best, hint.best routes route.ingress = some best ∧ best.ingress = route.ingress ∧
        best.destPrefixLow ≤ hint.destination ∧ hint.destination ≤ best.destPrefixHigh ∧
        routePriorityAllows best route ∧
        (routePriorityAllows route best → route ∈ hint.retained.values) := by
  have checks := (Bool.and_eq_true_iff.mp checked).1
  intro target member
  refine LookupTree.check_with_sound _ (fun route =>
    route.destPrefixLow ≤ hint.destination ∧ hint.destination ≤ route.destPrefixHigh →
      ∃ best, hint.best routes route.ingress = some best ∧ best.ingress = route.ingress ∧
        best.destPrefixLow ≤ hint.destination ∧ hint.destination ≤ best.destPrefixHigh ∧
        routePriorityAllows best route ∧
        (routePriorityAllows route best → route ∈ hint.retained.values))
    ?_ routes hint.coverage checks target member
  intro route index check matched
  obtain ⟨best, found, ingress, lower, upper, priority, retained⟩ := (of_decide_eq_true check) matched
  exact ⟨best, found, ingress, lower, upper, priority, fun rank => hint.retained.lookup_mem index route (retained rank)⟩

theorem checked_route_hint_selects_exact_routes (routes : LookupTree FibRoute)
    (hint : FibRouteLookupHint) (checked : hint.check routes = true)
    (route : FibRoute) (packet : PacketPolicy.Packet)
    (destination : packet.destination = hint.destination) :
    SelectedFibRoute routes.values route packet ↔ route ∈ hint.retained.values := by
  have coverage := route_hint_covers routes hint checked
  have retained : ∀ candidate ∈ hint.retained.values,
      SelectedFibRoute routes.values candidate packet := by
    intro target member
    refine LookupTree.check_with_sound _ (fun candidate => SelectedFibRoute routes.values candidate packet) ?_ hint.retained hint.origins
      (Bool.and_eq_true_iff.mp checked).2 target member
    intro candidate index check
    obtain ⟨original, lower, upper, best, found, rank⟩ := of_decide_eq_true check
    refine ⟨routes.lookup_mem index candidate original, ?_, ?_⟩
    · change candidate.destPrefixLow ≤ packet.destination ∧ packet.destination ≤ candidate.destPrefixHigh
      simpa only [destination] using And.intro lower upper
    · intro other member ingress matchOther
      obtain ⟨otherBest, otherFound, _, _, _, otherRank, _⟩ := coverage other member (destination ▸ matchOther)
      rw [ingress, found] at otherFound
      cases Option.some.inj otherFound
      exact route_priority_transitive candidate best other rank otherRank
  constructor
  · intro selected
    obtain ⟨best, found, ingress, lower, upper, _, includes⟩ := coverage route selected.1 (destination ▸ selected.2.1)
    have bestMember : best ∈ routes.values := by
      unfold FibRouteLookupHint.best at found
      cases h : hint.winners.lookup route.ingress with
      | none => simp [h] at found
      | some path => exact routes.lookup_mem path best (by simpa [h] using found)
    apply includes
    exact selected.2.2 best bestMember ingress (by
      change best.destPrefixLow ≤ packet.destination ∧ packet.destination ≤ best.destPrefixHigh
      simpa only [destination] using And.intro lower upper)
  · exact retained route

end TDN.DataPlaneForwarding
