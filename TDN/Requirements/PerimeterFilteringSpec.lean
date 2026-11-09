import TDN.Requirements.TwoLayerOverlayArchitecture

namespace TDN.Boundary

inductive Operation where
  | forward | pushInner | pushOuter | popInner | popOuter
  deriving DecidableEq, Repr

structure Edge where
  sourceZone : Zone
  destinationZone : Zone
  operation : Operation
  deriving DecidableEq

def Safe (e : Edge) : Prop :=
  match e.operation with
  | .forward => e.sourceZone = e.destinationZone
  | .pushInner => e.sourceZone = .red ∧ e.destinationZone = .gray
  | .pushOuter => e.sourceZone = .gray ∧ e.destinationZone = .black
  | .popInner => e.sourceZone = .gray ∧ e.destinationZone = .red
  | .popOuter => e.sourceZone = .black ∧ e.destinationZone = .gray

inductive StackEffect : Operation → List TunnelHeader → List TunnelHeader → Prop
  | forward (tunnelStack : List TunnelHeader) : StackEffect .forward tunnelStack tunnelStack
  | pushInner (tunnelStack : List TunnelHeader) (i : TunnelHeader) (layer : i.layer = .inner) :
      StackEffect .pushInner tunnelStack (i :: tunnelStack)
  | pushOuter (tunnelStack : List TunnelHeader) (o : TunnelHeader) (layer : o.layer = .outer) :
      StackEffect .pushOuter tunnelStack (o :: tunnelStack)
  | popInner (tunnelStack : List TunnelHeader) (i : TunnelHeader) (layer : i.layer = .inner) :
      StackEffect .popInner (i :: tunnelStack) tunnelStack
  | popOuter (tunnelStack : List TunnelHeader) (o : TunnelHeader) (layer : o.layer = .outer) :
      StackEffect .popOuter (o :: tunnelStack) tunnelStack

def Executes (e : Edge) (a b : State) : Prop :=
  a.zone = e.sourceZone ∧ b.zone = e.destinationZone ∧
  b.level = a.level ∧ StackEffect e.operation a.tunnelStack b.tunnelStack

def Shape (zone : Zone) (tunnelStack : List TunnelHeader) : Prop :=
  match zone with
  | .local => False
  | .red => tunnelStack = []
  | .gray => ∃ i, tunnelStack = [i] ∧ i.layer = .inner
  | .black => ∃ o i, tunnelStack = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner

lemma effect_preserves_shape {source destination : Zone} {op : Operation}
    {input output : List TunnelHeader} (safe : Safe ⟨source, destination, op⟩)
    (effect : StackEffect op input output) (initial : Shape source input) :
    Shape destination output := by
  cases effect <;> cases source <;> cases destination <;> simp_all [Safe, Shape]

lemma checked_edge_preserves_layers (e : Edge) (safe : Safe e)
    {a b : State} (step : Executes e a b) (initial : MatchesZoneEncryptionPolicy a) : MatchesZoneEncryptionPolicy b := by
  rcases step with ⟨ha, hb, _, effect⟩
  have input : Shape a.zone a.tunnelStack := by
    cases hz : a.zone <;> simpa [Shape, MatchesZoneEncryptionPolicy, hz] using initial
  rw [ha] at input
  have result := effect_preserves_shape safe effect input
  rw [← hb] at result
  cases hz : b.zone <;> simpa [Shape, MatchesZoneEncryptionPolicy, hz] using result

def MachineStep (edges : List Edge) (a b : State) : Prop :=
  ∃ e ∈ edges, Executes e a b

theorem checked_machine_preserves_layers (edges : List Edge)
    (checked : ∀ e ∈ edges, Safe e) {a b : State}
    (execution : Relation.ReflTransGen (MachineStep edges) a b)
    (initial : MatchesZoneEncryptionPolicy a) : MatchesZoneEncryptionPolicy b := by
  induction execution with
  | refl => exact initial
  | tail _ step ih =>
      obtain ⟨e, he, hs⟩ := step
      exact checked_edge_preserves_layers e (checked e he) hs ih

theorem plaintext_bypass_is_unsafe : ¬ Safe ⟨.red, .gray, .forward⟩ := by
  unfold Safe
  decide

theorem outer_bypass_is_unsafe : ¬ Safe ⟨.gray, .black, .forward⟩ := by
  unfold Safe
  decide

end TDN.Boundary
