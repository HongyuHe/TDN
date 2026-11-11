import TDN.Requirements.NetworkEventTraceOrder

namespace TDN.Requirements.Msc
open Compliance

lemma event_split_append_exact {α : Type} (first second earlier later : List α) (event : α)
    (split : first ++ second = earlier ++ [event] ++ later) :
    (∃ leading suffix, first = leading ++ [event] ++ suffix ∧
      earlier = leading ∧ later = suffix ++ second) ∨
    (∃ leading suffix, second = leading ++ [event] ++ suffix ∧
      earlier = first ++ leading ∧ later = suffix) := by
  induction first generalizing earlier with
  | nil => exact Or.inr ⟨earlier, later, split, rfl, rfl⟩
  | cons head tail ih =>
    cases earlier with
    | nil =>
      have same : head = event := (List.cons.inj split).1
      subst head
      exact Or.inl ⟨[], tail, rfl, rfl, (List.cons.inj split).2.symm⟩
    | cons previous rest =>
      have same : head = previous := (List.cons.inj split).1
      subst previous
      have smaller : tail ++ second = rest ++ [event] ++ later := (List.cons.inj split).2
      rcases ih rest smaller with ⟨leading, suffix, found, equal, remaining⟩ |
        ⟨leading, suffix, found, equal, remaining⟩
      · exact Or.inl ⟨head :: leading, suffix, congrArg (head :: ·) found,
          congrArg (head :: ·) equal, remaining⟩
      · exact Or.inr ⟨leading, suffix, found, congrArg (head :: ·) equal, remaining⟩

theorem forwarding_event_has_step {S A : Type} (model : ForwardingModel S A)
    {start finish : S} {actions : List A} (run : model.system.MTr start actions finish)
    {earlier later : List NetworkEvent} {event : NetworkEvent}
    (split : actions.flatMap model.events = earlier ++ [event] ++ later) :
    ∃ before after action leading trailing localBefore localAfter,
      actions = leading ++ [action] ++ trailing ∧
      model.system.MTr start leading before ∧ model.system.Tr before action after ∧
      model.system.MTr after trailing finish ∧
      model.events action = localBefore ++ [event] ++ localAfter ∧
      earlier = leading.flatMap model.events ++ localBefore ∧
      later = localAfter ++ trailing.flatMap model.events := by
  induction run generalizing earlier later with
  | refl => simp at split
  | @stepL first action next rest last step tail ih =>
    simp only [List.flatMap_cons] at split
    rcases event_split_append_exact _ _ _ _ _ split with
      ⟨leading, trailing, actionSplit, equal, remaining⟩ |
      ⟨leading, trailing, restSplit, equal, remaining⟩
    · exact ⟨first, next, action, [], rest, leading, trailing, rfl, .refl, step,
        tail, actionSplit, equal, remaining⟩
    · obtain ⟨before, after, chosen, prefixActions, suffixActions, localBefore, localAfter,
        actionsEqual, prefixRun, chosenStep, suffixRun, eventSplit, prior, following⟩ := ih restSplit
      refine ⟨before, after, chosen, action :: prefixActions, suffixActions, localBefore, localAfter,
        congrArg (action :: ·) actionsEqual, .stepL step prefixRun, chosenStep, suffixRun,
        eventSplit, ?_, ?_⟩
      · simpa only [List.flatMap_cons, List.append_assoc, prior] using equal
      · exact remaining.trans following

end TDN.Requirements.Msc
