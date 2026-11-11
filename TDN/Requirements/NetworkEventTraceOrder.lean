import TDN.Requirements.MscComplianceSchema

namespace TDN.Requirements.Msc
open Compliance

lemma event_split_append {α : Type} (first second earlier later : List α) (event : α)
    (split : first ++ second = earlier ++ [event] ++ later) :
    (∃ leading suffix, first = leading ++ [event] ++ suffix ∧ earlier = leading) ∨
      (∃ leading suffix, second = leading ++ [event] ++ suffix ∧ earlier = first ++ leading) := by
  induction first generalizing earlier with
  | nil => exact Or.inr ⟨earlier, later, split, rfl⟩
  | cons head tail ih =>
    cases earlier with
    | nil =>
      have same : head = event := (List.cons.inj split).1
      subst head
      exact Or.inl ⟨[], tail, rfl, rfl⟩
    | cons previous rest =>
      have same : head = previous := (List.cons.inj split).1
      subst previous
      have smaller : tail ++ second = rest ++ [event] ++ later := (List.cons.inj split).2
      rcases ih rest smaller with ⟨leading, suffix, found, equal⟩ | ⟨leading, suffix, found, equal⟩
      · exact Or.inl ⟨head :: leading, suffix, congrArg (head :: ·) found, congrArg (head :: ·) equal⟩
      · exact Or.inr ⟨leading, suffix, found, congrArg (head :: ·) equal⟩

lemma event_before_in_append {α : Type} {first second : List α} {event : α}
    (member : event ∈ first) : event ∈ first ++ second := List.mem_append_left _ member

lemma history_has_no_encrypt (history : ObservedHistory) (valid : history.Valid)
    (payload : PayloadId) (tunnel : String) : .encrypt payload tunnel ∉ history.Events := by
  intro member
  obtain ⟨record, present, same⟩ := List.mem_map.mp member
  have setup := (valid.2.1 record present).2.2.2.2
  simp [HistoricalEvent.SetupOnly, same] at setup

lemma history_precedes_encrypt {history : ObservedHistory} {current earlier later : List NetworkEvent}
    {payload : PayloadId} {tunnel : String} (valid : history.Valid)
    (split : history.Events ++ current = earlier ++ [.encrypt payload tunnel] ++ later) :
    ∃ leading suffix, current = leading ++ [.encrypt payload tunnel] ++ suffix ∧ earlier = history.Events ++ leading := by
  rcases event_split_append history.Events current earlier later (.encrypt payload tunnel) split with
    ⟨leading, suffix, found, same⟩ | found
  · have member : .encrypt payload tunnel ∈ history.Events := by rw [found]; simp
    exact False.elim (history_has_no_encrypt history valid payload tunnel member)
  · exact found

lemma event_index_is_bounded {α : Type} {events : List α} {position : Nat} {event : α}
    (found : events[position]? = some event) : position < events.length := by
  by_contra outside
  have missing : events[position]? = none := List.getElem?_eq_none (by omega)
  rw [missing] at found
  cases found

lemma event_index_in_left_append {α : Type} {first second : List α} {position : Nat} {event : α}
    (found : first[position]? = some event) : (first ++ second)[position]? = some event := by
  have bound := event_index_is_bounded found
  simpa [List.getElem?_append, bound] using found

lemma event_index_in_right_append {α : Type} {first second : List α} {position : Nat} {event : α}
    (found : second[position]? = some event) : (first ++ second)[first.length + position]? = some event := by
  simp [List.getElem?_append, found]

end TDN.Requirements.Msc
