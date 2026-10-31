import TDN.Import.Command
import TDN.Targets.AuditOffload

namespace TDN.Imported.FreshAuditOffload
open OffloadJournal Targets

tdn_data sourceBytes : Nat from "../../evidence/lean/FreshAuditOffload.json" ["TDN.Imported.FreshAuditOffload.sourceBytes"]

tdn_data beforeRestart : List Batch from "../../evidence/lean/FreshAuditOffload.json" ["TDN.Imported.FreshAuditOffload.beforeRestart"]

tdn_data afterRestart : List Batch from "../../evidence/lean/FreshAuditOffload.json" ["TDN.Imported.FreshAuditOffload.afterRestart"]

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
