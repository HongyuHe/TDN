import TDN.Network.Execution

/-!
A source policy can apply at selected input or output interfaces. Its local
forwarding obligation constrains the original source header whenever the packet
is clear. Wire and bridge certificates propagate the obligation to a receiver.
The same induction then applies to paths with arbitrary length and loops.
-/
namespace TDN.Network.SourcePolicy
open Execution
variable {Node Message : Type}

abbrev Policy (Node : Type) := Endpoint Node → Phase → Option Prefix

def Compatible (a b : Option Prefix) : Prop := b = none ∨ a = b

instance (a b : Option Prefix) : Decidable (Compatible a b) :=
  inferInstanceAs (Decidable (b = none ∨ a = b))

def Checked (policy : Policy Node) (state : State Node Message) : Prop :=
  ∀ network, policy state.location state.phase = some network → state.packet.depth = 0 →
    network.contains state.packet.originalHeader.source = true

theorem compatible_transfer (policy : Policy Node) (a b : Endpoint Node) (phaseA phaseB : Phase)
    (packet : WirePacket Message) (compatible : Compatible (policy a phaseA) (policy b phaseB))
    (checked : Checked policy ⟨a, phaseA, packet⟩) : Checked policy ⟨b, phaseB, packet⟩ := by
  intro network required clear
  cases compatible with
  | inl absent => simp_all
  | inr same => exact checked network (same.trans required) clear

theorem step_preserves_source_policy (model : Model Node) (policy : Policy Node)
    (wire : ∀ a b, model.linked a b → Compatible (policy a .output) (policy b .input))
    (bridge : ∀ a b, model.bridge a b → Compatible (policy a .input) (policy b .output))
    (forward : ∀ node input packet result,
      model.forward node input packet = some result →
      Checked policy (⟨⟨node, result.route.output⟩, .output, result.packet⟩ : State Node Message))
    {before after : State Node Message} (step : Step model before after)
    (initial : Checked policy before) : Checked policy after := by
  cases step with
  | wire a b packet linked _ _ => exact compatible_transfer policy a b _ _ packet (wire a b linked) initial
  | switch a b packet connected _ _ => exact compatible_transfer policy a b _ _ packet (bridge a b connected) initial
  | forward node input packet result accepted => exact forward node input packet result accepted

theorem executions_preserve_source_policy (model : Model Node) (policy : Policy Node)
    (wire : ∀ a b, model.linked a b → Compatible (policy a .output) (policy b .input))
    (bridge : ∀ a b, model.bridge a b → Compatible (policy a .input) (policy b .output))
    (forward : ∀ node input packet result,
      model.forward node input packet = some result →
      Checked policy (⟨⟨node, result.route.output⟩, .output, result.packet⟩ : State Node Message))
    {before after : State Node Message} (path : Reach (Step model) before after) :
    Checked policy before → Checked policy after := by
  induction path with
  | refl => exact id
  | step edge _ ih =>
    intro initial
    exact ih (step_preserves_source_policy model policy wire bridge forward edge initial)

end TDN.Network.SourcePolicy
