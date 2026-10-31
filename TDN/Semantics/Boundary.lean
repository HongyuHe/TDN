import TDN.Semantics.Network

namespace TDN.Boundary

/-- Unlike Step, an edge may perform an unsafe plaintext forwarding operation. -/
inductive Operation where
  | forward | pushInner | pushOuter | popInner | popOuter
  deriving DecidableEq, Repr

structure Edge where
  sourceZone : Zone
  destinationZone : Zone
  operation : Operation
  deriving DecidableEq

/-- Local syntactic obligation, to be checked against every translated forwarding edge. -/
def Safe (e : Edge) : Prop :=
  match e.operation with
  | .forward => e.sourceZone = e.destinationZone
  | .pushInner => e.sourceZone = .red ∧ e.destinationZone = .gray
  | .pushOuter => e.sourceZone = .gray ∧ e.destinationZone = .black
  | .popInner => e.sourceZone = .gray ∧ e.destinationZone = .red
  | .popOuter => e.sourceZone = .black ∧ e.destinationZone = .gray

inductive StackEffect : Operation → List Seal → List Seal → Prop
  | forward (seals : List Seal) : StackEffect .forward seals seals
  | pushInner (seals : List Seal) (i : Seal) (layer : i.layer = .inner) :
      StackEffect .pushInner seals (i :: seals)
  | pushOuter (seals : List Seal) (o : Seal) (layer : o.layer = .outer) :
      StackEffect .pushOuter seals (o :: seals)
  | popInner (seals : List Seal) (i : Seal) (layer : i.layer = .inner) :
      StackEffect .popInner (i :: seals) seals
  | popOuter (seals : List Seal) (o : Seal) (layer : o.layer = .outer) :
      StackEffect .popOuter (o :: seals) seals

/-- Operational forwarding allows all supplied edges, including unsafe ones. -/
def Executes (e : Edge) (a b : State) : Prop :=
  a.zone = e.sourceZone ∧ b.zone = e.destinationZone ∧
  b.level = a.level ∧ StackEffect e.operation a.seals b.seals

def Shape (zone : Zone) (seals : List Seal) : Prop :=
  match zone with
  | .red => seals = []
  | .gray => ∃ i, seals = [i] ∧ i.layer = .inner
  | .black => ∃ o i, seals = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner

theorem effect_preserves_shape {source destination : Zone} {op : Operation}
    {input output : List Seal} (safe : Safe ⟨source, destination, op⟩)
    (effect : StackEffect op input output) (initial : Shape source input) :
    Shape destination output := by
  cases effect <;> cases source <;> cases destination <;> simp_all [Safe, Shape]

theorem checked_edge_preserves_layers (e : Edge) (safe : Safe e)
    {a b : State} (step : Executes e a b) (initial : WellLayered a) : WellLayered b := by
  rcases step with ⟨ha, hb, _, effect⟩
  have input : Shape a.zone a.seals := by
    cases hz : a.zone <;> simpa [Shape, WellLayered, hz] using initial
  rw [ha] at input
  have result := effect_preserves_shape safe effect input
  rw [← hb] at result
  cases hz : b.zone <;> simpa [Shape, WellLayered, hz] using result

def MachineStep (edges : List Edge) (a b : State) : Prop :=
  ∃ e ∈ edges, Executes e a b

/-- A finite per-edge certificate lifts to every finite modeled forwarding execution. -/
theorem checked_machine_preserves_layers (edges : List Edge)
    (checked : ∀ e ∈ edges, Safe e) {a b : State}
    (execution : Relation.ReflTransGen (MachineStep edges) a b)
    (initial : WellLayered a) : WellLayered b := by
  induction execution with
  | refl => exact initial
  | tail _ step ih =>
      obtain ⟨e, he, hs⟩ := step
      exact checked_edge_preserves_layers e (checked e he) hs ih

/-- Mutation witness: adding a Red-to-Gray plain forward edge fails its local obligation. -/
theorem plaintext_bypass_is_unsafe : ¬ Safe ⟨.red, .gray, .forward⟩ := by
  unfold Safe
  decide

/-- A missing Outer encryption operation also fails, even with a working Inner layer. -/
theorem outer_bypass_is_unsafe : ¬ Safe ⟨.gray, .black, .forward⟩ := by
  unfold Safe
  decide

end TDN.Boundary
