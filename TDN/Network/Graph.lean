import Std

/-!
Reusable reachability, abstraction, and required-waypoint reasoning.
Vertices and labels have arbitrary types. A directed edge relation can describe
links, permitted forwarding, or another explicitly justified transition model.
`Reach` records existence of a finite walk. `Route` retains the visited vertices
so a waypoint conclusion can identify a device on the actual route.
-/
namespace TDN.Network
universe u v

inductive Reach {V : Type u} (edge : V → V → Prop) : V → V → Prop where
  | refl (a : V) : Reach edge a a
  | step {a b c : V} : edge a b → Reach edge b c → Reach edge a c

theorem Reach.preserves {V : Type u} {L : Type v} {edge : V → V → Prop}
    (label : V → L) (edgeInvariant : ∀ a b, edge a b → label a = label b)
    {a b : V} (path : Reach edge a b) : label a = label b := by
  induction path with
  | refl => rfl
  | step h _ ih => exact (edgeInvariant _ _ h).trans ih

/-- Refining a transition relation preserves every previously proved safety
property phrased as absence of reachability. The simulation premise names the
required connection between the more detailed and more abstract relations. -/
theorem Reach.map {V : Type u} {W : Type v} {edge : V → V → Prop}
    {abstractEdge : W → W → Prop} (abstract : V → W)
    (simulation : ∀ a b, edge a b → abstractEdge (abstract a) (abstract b))
    {a b : V} (path : Reach edge a b) : Reach abstractEdge (abstract a) (abstract b) := by
  induction path with
  | refl => exact .refl _
  | step h _ ih => exact .step (simulation _ _ h) ih

def Without {V : Type u} (edge : V → V → Prop) (cut : V → Prop) (a b : V) : Prop :=
  edge a b ∧ ¬ cut a ∧ ¬ cut b

theorem separated_by_cut {V : Type u} {L : Type v} {edge : V → V → Prop}
    (cut : V → Prop) (label : V → L)
    (edgeInvariant : ∀ a b, Without edge cut a b → label a = label b)
    {a b : V} (different : label a ≠ label b) : ¬ Reach (Without edge cut) a b := by
  intro path
  exact different (path.preserves label edgeInvariant)

/-- The node list omits the initial vertex and includes every subsequent
vertex. `nil` is the zero-hop route. Repeated vertices and loops are allowed. -/
inductive Route {V : Type u} (edge : V → V → Prop) : V → V → List V → Prop where
  | nil (a : V) : Route edge a a []
  | cons {a b c : V} {nodes : List V} :
      edge a b → Route edge b c nodes → Route edge a c (b :: nodes)

theorem Route.reachable {V : Type u} {edge : V → V → Prop}
    {a b : V} {nodes : List V} (path : Route edge a b nodes) : Reach edge a b := by
  induction path with
  | nil => exact .refl _
  | cons h _ ih => exact .step h ih

theorem Route.avoiding {V : Type u} {edge : V → V → Prop} (cut : V → Prop)
    {a b : V} {nodes : List V} (path : Route edge a b nodes)
    (absent : ∀ node ∈ a :: nodes, ¬ cut node) : Reach (Without edge cut) a b := by
  induction path with
  | nil => exact .refl _
  | @cons a next b nodes h tail ih =>
      apply Reach.step (b := next)
      · exact ⟨h, absent a (by simp), absent next (by simp)⟩
      · apply ih
        intro node member
        exact absent node (List.mem_cons_of_mem a member)

/-- An actual route crossing the proved separation contains a cut vertex.
The conclusion identifies a member of that route, so a user can instantiate
the cut predicate with a required firewall, inspection point, or trust boundary. -/
theorem Route.must_visit {V : Type u} {edge : V → V → Prop} (cut : V → Prop)
    {a b : V} {nodes : List V} (path : Route edge a b nodes)
    (separated : ¬ Reach (Without edge cut) a b) :
    ∃ node ∈ a :: nodes, cut node := by
  classical
  apply Classical.byContradiction
  intro none
  apply separated
  apply path.avoiding cut
  intro node member hit
  exact none ⟨node, member, hit⟩

theorem Route.must_visit_of_labels {V : Type u} {L : Type v}
    {edge : V → V → Prop} (cut : V → Prop) (label : V → L)
    (edgeInvariant : ∀ a b, Without edge cut a b → label a = label b)
    {a b : V} {nodes : List V} (different : label a ≠ label b)
    (path : Route edge a b nodes) : ∃ node ∈ a :: nodes, cut node :=
  path.must_visit cut (separated_by_cut cut label edgeInvariant different)

end TDN.Network
