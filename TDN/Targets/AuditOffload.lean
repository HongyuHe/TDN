import TDN.Semantics.OffloadJournal

namespace TDN.Targets
open OffloadJournal

/-- A particular frozen source file has complete range coverage in the collector's
retained journal. Actual byte identity relies on the hash/source observation contract. -/
def RecordedAuditCopy (sourceBytes : Nat) (journal : List Batch) : Prop :=
  ∀ position < sourceBytes,
    ∃ batch ∈ journal, batch.offset ≤ position ∧ position < batch.next

theorem complete_audit_copy_from_contiguous_batches (sourceBytes : Nat) (journal : List Batch)
    (contiguous : Contiguous 0 journal) (complete : finish 0 journal = sourceBytes) :
    RecordedAuditCopy sourceBytes journal := by
  intro position within
  exact contiguous_batches_cover_every_position contiguous position (Nat.zero_le _)
    (by simpa [complete] using within)

/-- Before/after journal identity transfers the coverage result across one observed
service restart. Power-loss behavior and future retention need further premises. -/
theorem observed_restart_preserves_audit_copy (sourceBytes : Nat)
    (before after : List Batch) (copied : RecordedAuditCopy sourceBytes before)
    (unchanged : after = before) : RecordedAuditCopy sourceBytes after := by
  rw [unchanged]
  exact copied

end TDN.Targets
