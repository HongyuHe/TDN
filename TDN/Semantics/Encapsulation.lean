import Cslib.Foundations.Semantics.LTS.Basic

namespace TDN.Encapsulation

inductive Frame (Payload : Type) where
  | wrapped (destination : Nat) (body : Payload)
  | exposed (body : Payload)

def Frame.body {Payload : Type} : Frame Payload → Payload
  | .wrapped _ body => body
  | .exposed body => body

structure State (Payload : Type) where
  node : Nat
  frame : Frame Payload

inductive Action where
  | forward | unwrap
  deriving DecidableEq

/-- Forwarding changes only the carrier's location. Unwrapping is allowed only at the
configured carrier endpoint and exposes exactly the retained body. -/
inductive Step {Payload : Type} (edge : Nat → Nat → Prop) :
    State Payload → Action → State Payload → Prop
  | forward (source next destination : Nat) (body : Payload) (linked : edge source next) :
      Step edge ⟨source, .wrapped destination body⟩ .forward ⟨next, .wrapped destination body⟩
  | unwrap (destination : Nat) (body : Payload) :
      Step edge ⟨destination, .wrapped destination body⟩ .unwrap ⟨destination, .exposed body⟩

def lts {Payload : Type} (edge : Nat → Nat → Prop) : Cslib.LTS (State Payload) Action :=
  ⟨Step edge⟩

def PreservedUntilEndpoint {Payload : Type} (destination : Nat) (body : Payload)
    (state : State Payload) : Prop :=
  state.frame = .wrapped destination body ∨
    (state.node = destination ∧ state.frame = .exposed body)

lemma step_preserves_carried_body {Payload : Type} (edge : Nat → Nat → Prop)
    {destination : Nat} {body : Payload} {before after : State Payload} {action : Action}
    (step : Step edge before action after) (valid : PreservedUntilEndpoint destination body before) :
    PreservedUntilEndpoint destination body after := by
  cases step with
  | forward source next endpoint payload linked =>
    rcases valid with wrapped | exposed
    · cases wrapped
      exact Or.inl rfl
    · cases exposed.2
  | unwrap endpoint payload =>
    rcases valid with wrapped | exposed
    · cases wrapped
      exact Or.inr ⟨rfl, rfl⟩
    · cases exposed.2

/-- An arbitrary number of routed hops cannot expose or alter the protected body
before the carrier endpoint. The implementation connection must preserve these operations. -/
theorem carried_body_preserved_to_endpoint {Payload : Type} (edge : Nat → Nat → Prop)
    (source destination : Nat) (body : Payload) {finish : State Payload} {actions : List Action}
    (run : (lts edge).MTr ⟨source, .wrapped destination body⟩ actions finish) :
    PreservedUntilEndpoint destination body finish := by
  have preserved : (lts edge).TrInv (PreservedUntilEndpoint destination body) :=
    fun _ _ _ step valid => step_preserves_carried_body edge step valid
  exact Cslib.LTS.mtrInv_of_trInv preserved _ _ _ run (Or.inl rfl)

end TDN.Encapsulation
