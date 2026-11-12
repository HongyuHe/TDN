import TDN.Models.IndexedWitnessTree
import TDN.Models.DataPlaneForwarding

/-! Indexed certificates establish the exact selected routes without comparing every route pair. -/
namespace TDN.DataPlaneForwarding
open Certificates

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

structure RouteCertificate where
  destination : Nat
  winners : NatIndex (List Bool)
  retained : WitnessTree FibRoute
  coverage : WitnessTree (List Bool)
  origins : WitnessTree (List Bool)
  deriving Repr, DecidableEq

def RouteCertificate.best (certificate : RouteCertificate) (routes : WitnessTree FibRoute)
    (ingress : Nat) : Option FibRoute :=
  (certificate.winners.lookup ingress).bind routes.lookup

def RouteCertificate.Covers (certificate : RouteCertificate) (routes : WitnessTree FibRoute)
    (route : FibRoute) (index : List Bool) : Prop :=
  route.destPrefixLow ≤ certificate.destination ∧ certificate.destination ≤ route.destPrefixHigh →
    ∃ best, certificate.best routes route.ingress = some best ∧
      best.ingress = route.ingress ∧
      best.destPrefixLow ≤ certificate.destination ∧ certificate.destination ≤ best.destPrefixHigh ∧
      routePriorityAllows best route ∧
      (routePriorityAllows route best → certificate.retained.lookup index = some route)

instance (certificate : RouteCertificate) (routes : WitnessTree FibRoute)
    (route : FibRoute) (index : List Bool) : Decidable (certificate.Covers routes route index) := by
  unfold RouteCertificate.Covers
  infer_instance

def RouteCertificate.Retains (certificate : RouteCertificate) (routes : WitnessTree FibRoute)
    (route : FibRoute) (index : List Bool) : Prop :=
  routes.lookup index = some route ∧
    route.destPrefixLow ≤ certificate.destination ∧ certificate.destination ≤ route.destPrefixHigh ∧
    ∃ best, certificate.best routes route.ingress = some best ∧ routePriorityAllows route best

instance (certificate : RouteCertificate) (routes : WitnessTree FibRoute)
    (route : FibRoute) (index : List Bool) : Decidable (certificate.Retains routes route index) := by
  unfold RouteCertificate.Retains
  infer_instance

def RouteCertificate.check (routes : WitnessTree FibRoute) (certificate : RouteCertificate) : Bool :=
  routes.checkWith (fun route index => decide (certificate.Covers routes route index)) certificate.coverage &&
    certificate.retained.checkWith (fun route index => decide (certificate.Retains routes route index)) certificate.origins

lemma route_certificate_covers (routes : WitnessTree FibRoute) (certificate : RouteCertificate)
    (checked : certificate.check routes = true) :
    ∀ route ∈ routes.values,
      route.destPrefixLow ≤ certificate.destination ∧ certificate.destination ≤ route.destPrefixHigh →
      ∃ best, certificate.best routes route.ingress = some best ∧ best.ingress = route.ingress ∧
        best.destPrefixLow ≤ certificate.destination ∧ certificate.destination ≤ best.destPrefixHigh ∧
        routePriorityAllows best route ∧
        (routePriorityAllows route best → route ∈ certificate.retained.values) := by
  have checks := (Bool.and_eq_true_iff.mp checked).1
  intro target member
  refine WitnessTree.checkWith_sound _ (fun route =>
    route.destPrefixLow ≤ certificate.destination ∧ certificate.destination ≤ route.destPrefixHigh →
      ∃ best, certificate.best routes route.ingress = some best ∧ best.ingress = route.ingress ∧
        best.destPrefixLow ≤ certificate.destination ∧ certificate.destination ≤ best.destPrefixHigh ∧
        routePriorityAllows best route ∧
        (routePriorityAllows route best → route ∈ certificate.retained.values))
    ?_ routes certificate.coverage checks target member
  intro route index check matched
  obtain ⟨best, found, ingress, lower, upper, priority, retained⟩ := (of_decide_eq_true check) matched
  exact ⟨best, found, ingress, lower, upper, priority, fun rank => certificate.retained.lookup_mem index route (retained rank)⟩

theorem table_driven_route_certificate_sound (routes : WitnessTree FibRoute)
    (certificate : RouteCertificate) (checked : certificate.check routes = true)
    (route : FibRoute) (packet : PacketPolicy.Packet)
    (destination : packet.destination = certificate.destination) :
    SelectedFibRoute routes.values route packet ↔ route ∈ certificate.retained.values := by
  have coverage := route_certificate_covers routes certificate checked
  have retained : ∀ candidate ∈ certificate.retained.values,
      SelectedFibRoute routes.values candidate packet := by
    intro target member
    refine WitnessTree.checkWith_sound _ (fun candidate => SelectedFibRoute routes.values candidate packet) ?_ certificate.retained certificate.origins
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
      unfold RouteCertificate.best at found
      cases h : certificate.winners.lookup route.ingress with
      | none => simp [h] at found
      | some path => exact routes.lookup_mem path best (by simpa [h] using found)
    apply includes
    exact selected.2.2 best bestMember ingress (by
      change best.destPrefixLow ≤ packet.destination ∧ packet.destination ≤ best.destPrefixHigh
      simpa only [destination] using And.intro lower upper)
  · exact retained route

end TDN.DataPlaneForwarding
