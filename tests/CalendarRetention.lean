import TDN.Targets.Auditing
import TDN.Targets.Lifecycle

open TDN TDN.Targets

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

-- The leap-day anniversary follows the documented end-of-month clipping rule.
example : CalendarTime.oneYearAfter 1709164800 = 1740700800 := by decide +kernel
example : CalendarTime.oneYearAfter 0 = 31536000 := by decide +kernel

-- August 31 plus six months clips to February's final day.
example : CalendarTime.sixMonthsAfter 1725062400 = 1740700800 := by decide +kernel

-- Inspection after the anniversary cannot hide permanent data loss on day one.
example : ¬ msc_audit_log_retention_and_continuity 40000000
    [⟨1, 0, 31536000, some 86400⟩] [] [] [] [] (fun _ => True)
    RequiredAuditProcedures := by
  intro h
  have deleted := (h.1 ⟨1, 0, 31536000, some 86400⟩ (by simp)).2.2 86400 rfl
  have impossible : 31536000 ≤ 86400 := deleted.1
  omega

-- An arbitrary remote expiry cannot pass the computed annual-expiry condition.
example : ¬ msc_registration_and_version_updates
    [⟨1, "solution", "1.3.0", 0, 1, 1000000000, 1000000000,
      true, true, true, true⟩] [] := by
  intro h
  have bad := (h.1 ⟨1, "solution", "1.3.0", 0, 1, 1000000000, 1000000000, true, true, true, true⟩ (by simp)).2.2.1
  have annual : CalendarTime.oneYearAfter 0 = 31536000 := by decide +kernel
  rw [annual] at bad
  contradiction

-- Re-registration for a future version before publication is rejected.
example : ¬ VersionDeadlines
    ⟨"solution", "next", 1, 100, 101, 1000, CalendarTime.sixMonthsAfter 101,
      100, ⟨"solution", "next", 99⟩⟩ := by
  simp [VersionDeadlines]

-- A different solution's timely registration cannot discharge the change.
example : ¬ VersionDeadlines
    ⟨"solution", "next", 1, 100, 101, 1000, CalendarTime.sixMonthsAfter 101,
      102, ⟨"other", "next", 103⟩⟩ := by
  simp [VersionDeadlines]
