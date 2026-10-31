import TDN.Semantics.RecordCoverage
import TDN.Semantics.CalendarTime
import TDN.Targets.Administration

namespace TDN.Targets

/-- Calendar intervals come from the actual annual or quarterly schedule.
Times are UTC seconds. No fixed 365-day year or 90-day quarter is silently substituted. -/
structure AuditWindow where
  id : Nat
  start : Nat
  finish : Nat
  deriving DecidableEq, Repr

inductive AuditActivity where
  | inspection | testing | observation | interviewing | other
  deriving DecidableEq, Repr

structure AuthorizedAuditRequest where
  id : Nat
  nsaOrAuthorizedAgent : Bool
  activities : List AuditActivity
  deriving DecidableEq, Repr

structure AuditCooperation where
  request : Nat
  permittedActivities : List AuditActivity
  fullyCooperated : Bool
  deriving DecidableEq, Repr

structure ComplianceAudit where
  window : Nat
  performedAt : Nat
  cpVersion : String
  deliveredToAO : Bool
  reviewedByAO : Bool
  deriving DecidableEq, Repr

def msc_compliance_audits (requests : List AuthorizedAuditRequest)
    (cooperation : List AuditCooperation) (annualWindows : List AuditWindow)
    (audits : List ComplianceAudit) (latestVersionAt : Nat → String) : Prop :=
  (∀ request ∈ requests, request.nsaOrAuthorizedAgent = true →
    ∃ response ∈ cooperation, response.request = request.id ∧ response.fullyCooperated = true ∧
      ∀ activity ∈ request.activities, activity ∈ response.permittedActivities) ∧
  ∀ window ∈ annualWindows, ∃ audit ∈ audits, audit.window = window.id ∧
    window.start ≤ audit.performedAt ∧ audit.performedAt ≤ window.finish ∧
    audit.cpVersion = latestVersionAt audit.performedAt ∧
    audit.deliveredToAO = true ∧ audit.reviewedByAO = true

/-- A schedule-indexed construction covers every annual window and checks the version
at each actual audit time. NSA-request cooperation is an independent obligation. -/
theorem generated_audits_cover_annual_windows (windows : List AuditWindow)
    (build : AuditWindow → ComplianceAudit) (latestVersionAt : Nat → String)
    (checked : ∀ w ∈ windows, (build w).window = w.id ∧
      w.start ≤ (build w).performedAt ∧ (build w).performedAt ≤ w.finish ∧
      (build w).cpVersion = latestVersionAt (build w).performedAt ∧
      (build w).deliveredToAO = true ∧ (build w).reviewedByAO = true) :
    ∀ window ∈ windows, ∃ audit ∈ windows.map build, audit.window = window.id ∧
      window.start ≤ audit.performedAt ∧ audit.performedAt ≤ window.finish ∧
      audit.cpVersion = latestVersionAt audit.performedAt ∧
      audit.deliveredToAO = true ∧ audit.reviewedByAO = true := by
  intro window member
  exact ⟨build window, List.mem_map.mpr ⟨window, member, rfl⟩, checked window member⟩

structure AuditLogRecord where
  id : Nat
  createdAt : Nat
  oneYearAnniversary : Nat
  /-- First permanent loss of the logical audit data across every maintained copy.
  Removing a local copy after a verified protected offload does not set this field.
  An application must justify complete copy coverage and continuous availability. -/
  deletedAt : Option Nat
  deriving DecidableEq, Repr

structure StorageAssessment where
  window : Nat
  administrator : Nat
  time : Nat
  remainingBytes : Nat
  adequateForContinuedRecording : Bool
  deriving DecidableEq, Repr

structure AuditBackup where
  window : Nat
  time : Nat
  backupMedium : String
  coveredLogIds : List Nat
  deriving DecidableEq, Repr

inductive AuditProcedure where
  | identifyIncidents | reportAuthorities | reportDataOwners
  | capacityDetection | longTermOffload | overflowResponse | powerContinuity
  deriving DecidableEq, Repr

def RequiredAuditProcedures : List AuditProcedure :=
  [.identifyIncidents, .reportAuthorities, .reportDataOwners,
    .capacityDetection, .longTermOffload, .overflowResponse, .powerContinuity]

/-- RG062 uses a recorded calendar anniversary for the minimum year and actual quarterly
assessment windows. Frequent backup windows are supplied by the documented operational policy. -/
def msc_audit_log_retention_and_continuity (now : Nat) (logs : List AuditLogRecord)
    (quarterlyWindows backupWindows : List AuditWindow)
    (assessments : List StorageAssessment) (backups : List AuditBackup)
    (administrator : Nat → Prop) (procedures : List AuditProcedure) : Prop :=
  (∀ log ∈ logs, log.oneYearAnniversary = CalendarTime.oneYearAfter log.createdAt ∧
    log.createdAt < log.oneYearAnniversary ∧
    ∀ time, log.deletedAt = some time → log.oneYearAnniversary ≤ time ∧ time ≤ now) ∧
  (∀ window ∈ quarterlyWindows, ∃ assessment ∈ assessments, assessment.window = window.id ∧
    window.start ≤ assessment.time ∧ assessment.time ≤ window.finish ∧
    administrator assessment.administrator ∧ assessment.adequateForContinuedRecording = true) ∧
  (∀ window ∈ backupWindows, ∃ backup ∈ backups, backup.window = window.id ∧
    window.start ≤ backup.time ∧ backup.time ≤ window.finish ∧ backup.backupMedium ≠ "" ∧
    ∀ log ∈ logs, log.createdAt ≤ window.start →
      (log.deletedAt = none ∨ ∃ time, log.deletedAt = some time ∧ window.start < time) →
        log.id ∈ backup.coveredLogIds) ∧
  ∀ procedure ∈ RequiredAuditProcedures, procedure ∈ procedures

/-- The encompassing history condition implies present availability during the
retention window. A late inspection cannot excuse an earlier destructive deletion. -/
theorem audit_retention_spec_implies_current_presence
    (now : Nat) (logs : List AuditLogRecord)
    (quarterlyWindows backupWindows : List AuditWindow)
    (assessments : List StorageAssessment) (backups : List AuditBackup)
    (administrator : Nat → Prop) (procedures : List AuditProcedure)
    (compliant : msc_audit_log_retention_and_continuity now logs quarterlyWindows
      backupWindows assessments backups administrator procedures) :
    ∀ log ∈ logs, log.createdAt ≤ now → now < log.oneYearAnniversary →
      log.deletedAt = none := by
  intro log member created within
  have retention := compliant.1 log member
  exact RecordCoverage.not_deleted_during_retention log.createdAt log.oneYearAnniversary now
    log.deletedAt ⟨created, within⟩
    (fun time deleted => (retention.2.2 time deleted).1)
    (fun time deleted => (retention.2.2 time deleted).2)

theorem retention_from_enforced_deletion_guard (now : Nat) (logs : List AuditLogRecord)
    (guard : ∀ log ∈ logs, ∀ time, log.deletedAt = some time → log.oneYearAnniversary ≤ time)
    (recorded : ∀ log ∈ logs, ∀ time, log.deletedAt = some time → time ≤ now) :
    ∀ log ∈ logs, log.createdAt ≤ now → now < log.oneYearAnniversary → log.deletedAt = none := by
  intro log member created within
  exact RecordCoverage.not_deleted_during_retention log.createdAt log.oneYearAnniversary now
    log.deletedAt ⟨created, within⟩ (guard log member) (recorded log member)

end TDN.Targets
