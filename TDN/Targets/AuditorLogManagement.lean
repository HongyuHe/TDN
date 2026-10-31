import TDN.Semantics.AuditRotation

namespace TDN.Targets

/-- RG069 p054:u014.s001's selected log-management operation. Actual role
authorization, storage paths and complete file contents are separately imported.
The operation preserves every existing record; human review is not inferred. -/
theorem auditor_rotation_preserves_records {Entry : Type}
    (before after : AuditRotation.Store Entry) (operationRecord : Entry)
    (operation : after = AuditRotation.append (AuditRotation.rotate before) operationRecord) :
    AuditRotation.entries after = AuditRotation.entries before ++ [operationRecord] := by
  rw [operation]
  exact AuditRotation.rotation_and_record_preserves_prefix before operationRecord

/-- An independently retrieved pre-rotation prefix remains intact in the retained
files after the actual rotation and later append-only activity. The premise does
not pretend that the complete pre-rotation file was captured. -/
theorem observed_audit_prefix_survives_rotation {Entry : Type}
    (before after : AuditRotation.Store Entry) (observed later : List Entry)
    (hasPrefix : observed <+: AuditRotation.entries before)
    (operation : after = AuditRotation.appendEntries (AuditRotation.rotate before) later) :
    observed <+: AuditRotation.entries after := by
  rw [operation, AuditRotation.rotation_and_later_records_preserves_prefix]
  exact hasPrefix.trans (List.prefix_append _ _)

end TDN.Targets
