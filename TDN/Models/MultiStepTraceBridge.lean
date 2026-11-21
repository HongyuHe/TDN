import TDN.Models.FindStepInForwardingTrace

namespace TDN.MultiStepTraceBridge

theorem optional_actions {S A T B : Type} (source : Cslib.LTS S A) (target : Cslib.LTS T B)
    (state : S → T) (action : A → Option B)
    (stepProjection : ∀ before label after, source.Tr before label after →
      match action label with
      | none => state before = state after
      | some projected => target.Tr (state before) projected (state after))
    {before after : S} {actions : List A} (run : source.MTr before actions after) :
    target.MTr (state before) (actions.filterMap action) (state after) := by
  induction run with
  | refl => exact .refl
  | @stepL before label next actions after step rest ih =>
    have projected := stepProjection before label next step
    cases selected : action label with
    | none =>
      have same : state before = state next := by simpa [selected] using projected
      simpa [selected, same] using ih
    | some native =>
      have taken : target.Tr (state before) native (state next) := by
        simpa [selected] using projected
      simpa [selected] using Cslib.LTS.MTr.stepL taken ih

end TDN.MultiStepTraceBridge

namespace TDN.TraceEvents

theorem action_member_has_actual_step {S A : Type} (system : Cslib.LTS S A)
    {before after : S} {actions : List A} (run : system.MTr before actions after)
    {chosen : A} (member : chosen ∈ actions) :
    Contains system before actions after (fun _ action _ => action = chosen) := by
  obtain ⟨earlier, later, sequence⟩ := List.mem_iff_append.mp member
  rw [sequence] at run
  obtain ⟨left, first, remainder⟩ := Cslib.LTS.MTr.split run
  obtain ⟨right, step, last⟩ := Cslib.LTS.MTr.cons_iff.mp remainder
  exact ⟨earlier, later, left, chosen, right, sequence, first, step, last, rfl⟩

end TDN.TraceEvents

namespace TDN.MultiStepTraceBridge

theorem project_forwarding {S A T B : Type} (source : Cslib.LTS S A) (target : Cslib.LTS T B)
    (state : S → T) (action : A → B)
    (stepProjection : ∀ before label after, source.Tr before label after →
      target.Tr (state before) (action label) (state after))
    {before after : S} {actions : List A} (run : source.MTr before actions after) :
    target.MTr (state before) (actions.map action) (state after) := by
  have projected := optional_actions source target state (fun label => some (action label))
    stepProjection run
  have equal : actions.filterMap (fun label => some (action label)) = actions.map action :=
    List.filterMap_eq_map_iff_forall_eq_some.mpr (by intro _ _; rfl)
  rw [equal] at projected
  exact projected

end TDN.MultiStepTraceBridge

namespace TDN.CheckedPath

variable {Move View State Action Value : Type}

def finish (next : Move → View → View) (before : View) : List Move → View
  | [] => before
  | move :: rest => finish next (next move before) rest

def Checks (next : Move → View → View) (allowed : Move → View → Prop) (before : View) : List Move → Prop
  | [] => True
  | move :: rest => allowed move before ∧ Checks next allowed (next move before) rest

instance decidableChecks (next : Move → View → View) (allowed : Move → View → Prop)
    [∀ m v, Decidable (allowed m v)] (before : View) (moves : List Move) :
    Decidable (Checks next allowed before moves) := by
  induction moves generalizing before with
  | nil => exact isTrue trivial
  | cons m rest ih => exact @instDecidableAnd _ _ (inferInstanceAs (Decidable (allowed m before))) (ih _)

theorem reaches (system : Cslib.LTS State Action) (view : State → View) (value : View → Value)
    (next : Move → View → View) (allowed : Move → View → Prop) (start first : State)
    (moves : List Move) (actions : List Action) (run : system.MTr start actions first)
    (checked : Checks next allowed (view first) moves)
    (realize : ∀ state earlier move, system.MTr start earlier state → allowed move (view state) →
      ∃ action after, system.Tr state action after ∧ view after = next move (view state) ∧
        value (view after) = value (view state)) :
    ∃ steps last, system.MTr start steps last ∧ view last = finish next (view first) moves ∧
      value (view last) = value (view first) := by
  induction moves generalizing first actions with
  | nil => exact ⟨actions, first, run, rfl, rfl⟩
  | cons move rest ih =>
    obtain ⟨action, after, step, same, kept⟩ := realize first actions move run checked.1
    obtain ⟨steps, last, reachesLast, final, preserved⟩ := ih after (actions ++ [action])
      ((Cslib.LTS.MTr.append_iff system).mpr ⟨first, run, .stepL step .refl⟩)
      (same.symm ▸ checked.2)
    exact ⟨steps, last, reachesLast, by simpa only [finish, same] using final, preserved.trans kept⟩

end TDN.CheckedPath
