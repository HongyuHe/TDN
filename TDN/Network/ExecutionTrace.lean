import TDN.Network.Execution

/-!
Executable path witnesses use the same generic transition relation as safety
proofs. A command can transfer a frame, select a switch output, or forward an
IP packet. Every successful command has a checked transition proof. The trace
runner retains all visited states so a service proof can inspect its footprint.
No deployment names, roles, address plan, or fixed path are imported.
-/
namespace TDN.Network.ExecutionTrace
open Execution
variable {Node Message : Type}

inductive Command (Node : Type) where
  | wire (target : Endpoint Node)
  | switch (output : String)
  | forward
  deriving DecidableEq, BEq, Repr

variable (model : Model Node) [DecidableRel model.linked] [DecidableRel model.bridge]

def advance (state : State Node Message) (command : Command Node) : Option (State Node Message) :=
  match state.phase, command with
  | .output, .wire target =>
    if model.linked state.location target ∧
        model.livePort state.location.node state.location.port state.packet.header.bytes = true ∧
        model.livePort target.node target.port state.packet.header.bytes = true then
      some ⟨target, .input, state.packet⟩
    else none
  | .input, .switch output =>
    let target := Endpoint.mk state.location.node output
    if model.bridge state.location target ∧
        model.livePort state.location.node state.location.port state.packet.header.bytes = true ∧
        model.livePort target.node target.port state.packet.header.bytes = true then
      some ⟨target, .output, state.packet⟩
    else none
  | .input, .forward => do
    let result ← model.forward state.location.node state.location.port state.packet
    some ⟨⟨state.location.node, result.route.output⟩, .output, result.packet⟩
  | _, _ => none

theorem advance_is_step (before after : State Node Message) (command : Command Node)
    (accepted : advance model before command = some after) : Step model before after := by
  cases before with
  | mk location phase packet =>
    cases command with
    | wire target =>
      cases phase with
      | input => simp [advance] at accepted
      | output =>
        simp only [advance] at accepted
        split at accepted
        next guards =>
          simp only [Option.some.injEq] at accepted
          subst after
          exact .wire location target packet guards.1 guards.2.1 guards.2.2
        next => simp at accepted
    | switch output =>
      cases phase with
      | output => simp [advance] at accepted
      | input =>
        simp only [advance] at accepted
        split at accepted
        next guards =>
          simp only [Option.some.injEq] at accepted
          subst after
          exact .switch location ⟨location.node, output⟩ packet guards.1 guards.2.1 guards.2.2
        next => simp at accepted
    | forward =>
      cases phase with
      | output => simp [advance] at accepted
      | input =>
        simp only [advance, bind, Option.bind_eq_some_iff, Option.some.injEq] at accepted
        obtain ⟨result, forwarded, equal⟩ := accepted
        subst after
        exact .forward location.node location.port packet result forwarded

def run (state : State Node Message) : List (Command Node) → Option (State Node Message)
  | [] => some state
  | command :: tail => (advance model state command).bind fun next => run next tail

theorem run_is_execution (before after : State Node Message) (commands : List (Command Node))
    (accepted : run model before commands = some after) : Reach (Step model) before after := by
  induction commands generalizing before with
  | nil => simp [run] at accepted; subst after; exact .refl _
  | cons command tail ih =>
    simp only [run, Option.bind_eq_some_iff] at accepted
    obtain ⟨next, step, tailRun⟩ := accepted
    exact .step (advance_is_step model before next command step) (ih next tailRun)

structure Result (Node Message : Type) where
  last : State Node Message
  visited : List (State Node Message)
  deriving DecidableEq, BEq, Repr

/-- `visited` omits the starting state and includes every subsequent state. -/
def trace (state : State Node Message) : List (Command Node) → Option (Result Node Message)
  | [] => some ⟨state, []⟩
  | command :: tail => do
    let next ← advance model state command
    let result ← trace next tail
    some ⟨result.last, next :: result.visited⟩

theorem trace_is_route (before : State Node Message) (commands : List (Command Node))
    (result : Result Node Message) (accepted : trace model before commands = some result) :
    Route (Step model) before result.last result.visited := by
  induction commands generalizing before result with
  | nil =>
    simp only [trace, Option.some.injEq] at accepted
    subst result
    exact .nil _
  | cons command tail ih =>
    simp only [trace, bind, Option.bind_eq_some_iff, Option.some.injEq] at accepted
    obtain ⟨next, first, later, rest, equal⟩ := accepted
    subst result
    exact .cons (advance_is_step model before next command first) (ih next later rest)

/-- An explicit footprint certificate proves that a service has an admitted
route avoiding a chosen device class. The route includes actual intermediate
packet states, so the claim cannot be inferred from a list of names alone. -/
theorem checked_trace_avoids (cut : State Node Message → Prop)
    (before : State Node Message) (commands : List (Command Node)) (result : Result Node Message)
    (accepted : trace model before commands = some result)
    (absent : ∀ state ∈ before :: result.visited, ¬ cut state) :
    Reach (Without (Step model) cut) before result.last :=
  (trace_is_route model before commands result accepted).avoiding cut absent

end TDN.Network.ExecutionTrace
