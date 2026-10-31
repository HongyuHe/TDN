import Mathlib.Data.List.Basic

namespace TDN.AuditRotation

/-- Completed archive files precede the current active log. The implementation
connection requires a fresh archive destination and no concurrent mutation. -/
structure Store (Entry : Type) where
  archives : List (List Entry)
  active : List Entry
  deriving DecidableEq

def entries {Entry : Type} (store : Store Entry) : List Entry :=
  store.archives.flatten ++ store.active

def rotate {Entry : Type} (store : Store Entry) : Store Entry :=
  ⟨store.archives ++ [store.active], []⟩

def append {Entry : Type} (store : Store Entry) (entry : Entry) : Store Entry :=
  ⟨store.archives, store.active ++ [entry]⟩

def appendEntries {Entry : Type} (store : Store Entry) (records : List Entry) : Store Entry :=
  ⟨store.archives, store.active ++ records⟩

/-- Moving the complete active log to a fresh archive preserves every entry,
including order and multiplicity. Empty active logs are allowed. -/
theorem rotation_preserves_all_entries {Entry : Type} (store : Store Entry) :
    entries (rotate store) = entries store := by
  simp [entries, rotate]

/-- Recording the successful rotation afterward preserves the full prior log
as an exact prefix and adds only the new operation record. -/
theorem rotation_and_record_preserves_prefix {Entry : Type}
    (store : Store Entry) (record : Entry) :
    entries (append (rotate store) record) = entries store ++ [record] := by
  simp [entries, append, rotate, List.append_assoc]

/-- Later append-only log activity cannot change any entry preserved by rotation. -/
theorem rotation_and_later_records_preserves_prefix {Entry : Type}
    (store : Store Entry) (records : List Entry) :
    entries (appendEntries (rotate store) records) = entries store ++ records := by
  simp [entries, appendEntries, rotate, List.append_assoc]

end TDN.AuditRotation
