import TDN.Semantics.TraceEvents

namespace TDN.TraceProjection

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

end TDN.TraceProjection

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

namespace TDN.TraceProjection

theorem project_execution {S A T B : Type} (source : Cslib.LTS S A) (target : Cslib.LTS T B)
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

end TDN.TraceProjection
