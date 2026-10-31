import TDN.Targets.RecordedOperations

open TDN.RecordedOperations

/-- An unused guest that remains powered on cannot pass the observation check. -/
example : ¬ UnusedIsOff ⟨false, true⟩ := by simp [UnusedIsOff]

/-- Such a state also cannot be reached through the admitted use protocol. -/
example : ¬ Relation.ReflTransGen PowerStep ⟨true, true⟩ ⟨false, true⟩ := by
  intro trace
  have result := power_trace_keeps_unused_guest_off (by simp [UnusedIsOff]) trace
  exact Bool.noConfusion (result rfl)

/-- Older TLS and an unrecognized protocol must never become an allowed transport. -/
example : tlsProtection "TLSv1.1" = none ∧ tlsProtection "plaintext" = none := by decide

/-- A retained lookup cannot establish a result that has no saved entry. -/
example : ¬ ResultsRetained ["missing-test"] [] := by simp [ResultsRetained]

/-- A successful response from another role does not establish Auditor access. -/
example : ¬ AvailableThrough ⟨"SecurityAdministrator", 200, ["rule"]⟩ "Auditor" ["rule"] := by
  simp [AvailableThrough]
