import TDN.Semantics.CoverTraffic

open TDN.CoverTraffic

def small : Config := ⟨28, 24, 1, 20⟩

/-- A full queue preserves its existing payload; new arrivals are discarded. -/
example : enqueue small [[1, 2]] [3] = [[1, 2]] := by decide

/-- A payload exceeding the available four bytes cannot enter the queue. -/
example : enqueue small [] [1, 2, 3, 4, 5] = [] := by decide

/-- An empty queue still produces the same padded size as a nonempty queue. -/
example : paddedBytes small (payload []) = paddedBytes small [1, 2, 3] := by decide

/-- The sender consumes a queued payload even when its socket send fails. -/
example : Step small ⟨[[1, 2]], [], 100, 0⟩ (.tick 100 101 false)
    ⟨[], [⟨100, 28, false⟩], 120, 1⟩ := by
  exact Step.tick _ _ _ _ (by decide) (by decide) (by decide)

/-- A tick cannot fire before its deadline. -/
example (after : State) : ¬ Step small (initial 100) (.tick 99 99 true) after := by
  intro step
  cases step <;> simp_all [initial]

/-- A late sender schedules from completion rather than replaying missed slots. -/
example : nextDeadline small 100 160 = 180 := by decide

/-- Without the header-size condition, fixed-size padding would be false. -/
example : paddedBytes ⟨20, 24, 1, 20⟩ [] ≠ 20 := by decide
