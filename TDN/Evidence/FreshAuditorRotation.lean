import TDN.Import.Command
import TDN.Targets.AuditorLogManagement

namespace TDN.Imported.FreshAuditorRotation
open AuditRotation
set_option maxRecDepth 10000
set_option maxHeartbeats 0

/-- Canonical complete event objects, not only selected fields or hash identities. -/
tdn_data observedBefore : List String from "../../evidence/lean/FreshAuditorRotation.json" ["TDN.Imported.FreshAuditorRotation.observedBefore"]

/-- The source-ordered pre-rotation state is reconstructed from retained files.
Only observedBefore was independently retrieved before the rotation. -/
tdn_data before : Store String from "../../evidence/lean/FreshAuditorRotation.json" ["TDN.Imported.FreshAuditorRotation.before"]

tdn_data later : List String from "../../evidence/lean/FreshAuditorRotation.json" ["TDN.Imported.FreshAuditorRotation.later"]

tdn_data capturedAfter : Store String from "../../evidence/lean/FreshAuditorRotation.json" ["TDN.Imported.FreshAuditorRotation.capturedAfter"]

lemma actual_observation_nonempty : observedBefore.length = 8 ∧
    (entries before).length = 10 ∧ later.length = 14 := by decide

lemma observed_before_prefix : observedBefore <+: entries before := by decide

lemma source_ordered_rotation_check :
    capturedAfter = appendEntries (rotate before) later := by decide

/-- The actual Auditor-managed rotation preserves every independently retrieved
earlier record, in order and with multiplicity, in the later captured log files.
Human review and all other audit-management duties remain separate. -/
theorem actual_auditor_rotation_preserves_observed_log :
    observedBefore <+: entries capturedAfter :=
  Targets.observed_audit_prefix_survives_rotation before capturedAfter observedBefore later
    observed_before_prefix source_ordered_rotation_check

end TDN.Imported.FreshAuditorRotation
