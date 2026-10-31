import TDN.Targets.AuditOffload

namespace TDN.Imported.FreshAuditOffload
open OffloadJournal Targets

def sourceBytes : Nat := 136535
def beforeRestart : List Batch := [⟨0, 65536, 65536, "a3aeaeba59c0210f8322c6e22908ff6d5bca1e70b0e84810cda16d7ce7a9d80b"⟩, ⟨65536, 131072, 65536, "5785bd26a669ca533d04d4ca1b78be7ee384d6ff308e2fe6a96f04270a30a208"⟩, ⟨131072, 136535, 5463, "408a2eaba7985e4501f6eb0763d9c8071dd95899d3332078faef61fd1a903465"⟩]
def afterRestart : List Batch := [⟨0, 65536, 65536, "a3aeaeba59c0210f8322c6e22908ff6d5bca1e70b0e84810cda16d7ce7a9d80b"⟩, ⟨65536, 131072, 65536, "5785bd26a669ca533d04d4ca1b78be7ee384d6ff308e2fe6a96f04270a30a208"⟩, ⟨131072, 136535, 5463, "408a2eaba7985e4501f6eb0763d9c8071dd95899d3332078faef61fd1a903465"⟩]

lemma local_range_checks : Contiguous 0 beforeRestart := by decide
lemma local_complete_cursor : finish 0 beforeRestart = sourceBytes := by decide
lemma local_restart_identity : afterRestart = beforeRestart := by decide

/-- Three local range checks cover every byte position in the frozen source copy. -/
theorem all_recorded_source_positions_copied : RecordedAuditCopy sourceBytes beforeRestart :=
  complete_audit_copy_from_contiguous_batches sourceBytes beforeRestart
    local_range_checks local_complete_cursor

theorem observed_service_restart_keeps_copy : RecordedAuditCopy sourceBytes afterRestart :=
  observed_restart_preserves_audit_copy sourceBytes beforeRestart afterRestart
    all_recorded_source_positions_copied local_restart_identity

end TDN.Imported.FreshAuditOffload
