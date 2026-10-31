import TDN.Targets.AuditOffload

open TDN.OffloadJournal TDN.Targets

def exampleBatches : List Batch := [⟨0, 3, 3, "first"⟩, ⟨3, 5, 2, "second"⟩]

example : RecordedAuditCopy 5 exampleBatches :=
  complete_audit_copy_from_contiguous_batches 5 exampleBatches (by decide) (by decide)

example : ¬ Contiguous 0 [⟨0, 3, 3, "first"⟩, ⟨4, 6, 2, "gap"⟩] := by decide

example : ¬ Contiguous 0 [⟨0, 3, 3, "first"⟩, ⟨2, 5, 3, "overlap"⟩] := by decide

example : ¬ Contiguous 0 [⟨0, 0, 0, "empty"⟩] := by decide

example : Acknowledges exampleBatches 3 5 := by
  exact ⟨⟨3, 5, 2, "second"⟩, by decide, rfl, rfl⟩
