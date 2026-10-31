import TDN.Semantics.Admission
import TDN.Semantics.RecordCoverage
import TDN.Targets.Cryptography

namespace TDN.Targets

inductive AdminEventKind where
  | authentication | operation | logout | credentialRevocation
  deriving DecidableEq, Repr

/-- Order is recorded causal sequence position, not elapsed seconds. The session
identifier names one authentication instance and must not be recycled. An operation's
credential field records the actual request token, which may differ from a certificate. -/
structure AdminEvent where
  kind : AdminEventKind
  person : Nat
  component : Nat
  order : Nat
  credential : String
  certificateCNSA : Bool
  nist80063 : Bool
  session : String
  deriving DecidableEq, Repr

structure AdministrativeAccount where
  person : Nat
  component : Nat
  credential : String
  groupAccount : Bool
  workstationAccount : Bool
  createdOrder : Nat
  deriving DecidableEq, Repr

/-- A concrete session binding connects an authenticated credential to the
request token used by operations. Certificate fingerprints, connection identifiers
and bearer tokens need not be equal strings. Their actual binding is imported. -/
structure AdministrativeSession where
  id : String
  person : Nat
  component : Nat
  authenticationOrder : Nat
  credential : String
  operationToken : String
  deriving DecidableEq, Repr

def AdministrativeSessionActive (events : List AdminEvent)
    (session : AdministrativeSession) (operation : AdminEvent) : Prop :=
  ∀ event ∈ events, event.order ≤ operation.order →
    ¬ ((event.kind = .logout ∧ event.component = session.component ∧ event.session = session.id) ∨
       (event.kind = .credentialRevocation ∧ event.credential = session.credential))

def MatchingAdministratorAuthentication (certificateObjective nistObjective : Bool)
    (events : List AdminEvent) (accounts : List AdministrativeAccount)
    (sessions : List AdministrativeSession) (before operation : AdminEvent) : Prop :=
  before.kind = .authentication ∧ before.person = operation.person ∧
  before.component = operation.component ∧ before.order < operation.order ∧
  (certificateObjective = true → before.certificateCNSA = true) ∧
  (nistObjective = true → before.nist80063 = true) ∧
  ∃ account ∈ accounts, account.person = before.person ∧ account.component = before.component ∧
    account.credential = before.credential ∧ account.createdOrder ≤ before.order ∧
    ∃ session ∈ sessions, session.id ≠ "" ∧ session.operationToken ≠ "" ∧
      session.id = before.session ∧ session.id = operation.session ∧
      session.person = before.person ∧ session.component = before.component ∧
      session.authenticationOrder = before.order ∧ session.credential = before.credential ∧
      session.operationToken = operation.credential ∧ AdministrativeSessionActive events session operation

/-- RG047 binds each action to its actual active authenticated session and account.
DM29 specifically requires individual AW accounts, including the complete supplied AW
administrator roster. Historical revocation and logout records constrain session use.
The session/credential inventories and actual event completeness are application obligations. -/
def msc_administrator_authentication (certificateObjective nistObjective : Bool)
    (events : List AdminEvent) (accounts : List AdministrativeAccount)
    (sessions : List AdministrativeSession) (awAdministrators : List Nat) : Prop :=
  (∀ event ∈ events, event.kind = .operation →
    ∃ authentication ∈ events,
      MatchingAdministratorAuthentication certificateObjective nistObjective events accounts sessions
        authentication event) ∧
  (∀ account ∈ accounts, account.credential ≠ "" ∧
    (account.workstationAccount = true → account.groupAccount = false)) ∧
  (∀ person ∈ awAdministrators, ∃ account ∈ accounts,
    account.person = person ∧ account.workstationAccount = true) ∧
  ∀ a ∈ accounts, a.workstationAccount = true →
    ∀ b ∈ accounts, b.workstationAccount = true →
      a.person ≠ b.person → a.credential ≠ b.credential

/-- Checked session admission supplies a matching active authentication for every
operation. A separate credential-owner function prevents two AW administrators
from sharing the same login credential. Inventory coverage includes inactive users
who have not generated an operation in the observed interval. -/
theorem administrator_authentication_from_admitted_operations
    (certificateObjective nistObjective : Bool) (events actions : List AdminEvent)
    (accounts : List AdministrativeAccount) (sessions : List AdministrativeSession)
    (awAdministrators : List Nat) (credentialOwner : String → Nat)
    (run : (Admission.lts (fun e : AdminEvent => e.kind = .operation)
      (MatchingAdministratorAuthentication certificateObjective nistObjective events accounts sessions)).MTr
        [] actions events)
    (individual : ∀ account ∈ accounts,
      account.credential ≠ "" ∧ (account.workstationAccount = true →
        account.groupAccount = false ∧ credentialOwner account.credential = account.person))
    (roster : ∀ person ∈ awAdministrators, ∃ account ∈ accounts,
      account.person = person ∧ account.workstationAccount = true) :
    msc_administrator_authentication certificateObjective nistObjective events accounts sessions
      awAdministrators := by
  refine ⟨Admission.all_admitted_events_have_prerequisites _ _ run, ?_, roster, ?_⟩
  · intro account member
    exact ⟨(individual account member).1, fun aw => ((individual account member).2 aw).1⟩
  · intro a memberA awA b memberB awB different same
    apply different
    rw [← ((individual a memberA).2 awA).2, ← ((individual b memberB).2 awB).2, same]

inductive PersonnelRole where
  | administrator | auditor | integrator | blackAdministrator
  deriving DecidableEq, Repr

structure PersonnelClearance where
  person : Nat
  role : PersonnelRole
  clearance : Nat
  deriving DecidableEq, Repr

structure OuterAdministration where
  person : Nat
  outer : Nat
  siteSupportedClassifications : List Nat
  deriving DecidableEq, Repr

/-- Classification order is supplied explicitly. Compartments and other access restrictions
remain part of the independent authorization policy. Black-only administrators retain the exception. -/
def msc_personnel_clearance (personnel : List PersonnelClearance)
    (solutionClassifications : List Nat) (blackClassification : Nat)
    (outerAdministration : List OuterAdministration) : Prop :=
  (∀ person ∈ personnel,
    if person.role = .blackAdministrator then blackClassification ≤ person.clearance
    else ∀ classification ∈ solutionClassifications, classification ≤ person.clearance) ∧
  ∀ assignment ∈ outerAdministration, ∃ person ∈ personnel,
    person.person = assignment.person ∧ person.role = .administrator ∧
    ∀ classification ∈ assignment.siteSupportedClassifications, classification ≤ person.clearance

lemma solution_clearance_covers_site (clearance : Nat) (solution site : List Nat)
    (global : ∀ level ∈ solution, level ≤ clearance)
    (included : ∀ level ∈ site, level ∈ solution) :
    ∀ level ∈ site, level ≤ clearance :=
  fun level member => global level (included level member)

structure PhysicalComponent where
  id : Nat
  outerFirewall : Bool
  protectedAt : Nat
  connectedAndInterconnectedLevels : List Nat
  disposed : Bool
  disposedAsClassified : Bool
  declassificationProcedure : Option Nat
  deriving DecidableEq, Repr

structure PhysicalAccess where
  person : Nat
  component : Nat
  authorized : Bool
  administratorOrSecurityPersonnel : Bool
  clearance : Nat
  escorted : Bool
  deriving DecidableEq, Repr

structure ConfigurationCopy where
  device : Nat
  protectedAt : Nat
  cakClassifications : List Nat
  deriving DecidableEq, Repr

def msc_physical_protection_access_and_disposal (components : List PhysicalComponent)
    (accesses : List PhysicalAccess) (copies : List ConfigurationCopy)
    (aoApprovedProcedure : Nat → Prop) : Prop :=
  (∀ component ∈ components, component.outerFirewall = false →
    ∀ level ∈ component.connectedAndInterconnectedLevels, level ≤ component.protectedAt) ∧
  (∀ access ∈ accesses, access.authorized = true ∧ access.administratorOrSecurityPersonnel = true ∧
    ∃ component ∈ components, component.id = access.component ∧
      (access.escorted = true ∨ ∀ level ∈ component.connectedAndInterconnectedLevels, level ≤ access.clearance)) ∧
  (∀ copy ∈ copies, ∀ level ∈ copy.cakClassifications, level ≤ copy.protectedAt) ∧
  ∀ component ∈ components, component.disposed = true →
    component.disposedAsClassified = true ∨
      ∃ procedure, component.declassificationProcedure = some procedure ∧ aoApprovedProcedure procedure

inductive MaintenanceKind where
  | patchTest | patchInstall | signatureUpdate
  deriving DecidableEq, Repr

/-- Time and deadlines are UTC seconds; order separately records causal precedence. -/
structure MaintenanceEvent where
  kind : MaintenanceKind
  component : Nat
  item : Nat
  actor : Nat
  order : Nat
  time : Nat
  deriving DecidableEq, Repr

def MatchingPatchTest (test installation : MaintenanceEvent) : Prop :=
  test.kind = .patchTest ∧ test.component = installation.component ∧
  test.item = installation.item ∧ test.order < installation.order

structure RequiredMaintenance where
  component : Nat
  item : Nat
  kind : MaintenanceKind
  deadline : Nat
  deriving DecidableEq, Repr

def msc_patches_virus_updates_and_tempest (components : List Nat)
    (events : List MaintenanceEvent) (required : List RequiredMaintenance)
    (localInstallPolicy : MaintenanceEvent → Prop) (tempestPolicy : Nat → Prop) : Prop :=
  (∀ installation ∈ events, installation.kind = .patchInstall →
    localInstallPolicy installation ∧ ∃ test ∈ events, MatchingPatchTest test installation) ∧
  (∀ obligation ∈ required, ∃ event ∈ events, event.component = obligation.component ∧
    event.item = obligation.item ∧ event.kind = obligation.kind ∧ event.time ≤ obligation.deadline) ∧
  ∀ component ∈ components, tempestPolicy component

/-- Local guards enforce test-before-install for every patch, independently of the
organization's policy content and its separate obligation to install every required patch. -/
theorem every_admitted_patch_was_tested (events actions : List MaintenanceEvent)
    (run : (Admission.lts (fun e : MaintenanceEvent => e.kind = .patchInstall)
      MatchingPatchTest).MTr [] actions events) :
    ∀ installation ∈ events, installation.kind = .patchInstall →
      ∃ test ∈ events, MatchingPatchTest test installation :=
  Admission.all_admitted_events_have_prerequisites _ _ run

structure InventoryRecord where
  component : Nat
  solution : String
  process : Nat
  model : String
  serial : String
  deriving DecidableEq, Repr

structure BaselineRecord where
  component : Nat
  configurationDigest : String
  softwareVersion : String
  maintainedBy : Nat
  auditorReadable : Bool
  deriving DecidableEq, Repr

def msc_inventory_and_baseline_configuration (hardware components : List Nat)
    (inventory : List InventoryRecord) (baselines : List BaselineRecord)
    (solution : String) (aoApprovedProcess : Nat → Prop) (administrator : Nat → Prop) : Prop :=
  (∀ component ∈ hardware, ∃ record ∈ inventory,
    record.component = component ∧ record.solution = solution ∧ aoApprovedProcess record.process) ∧
  ∀ component ∈ components, ∃ record ∈ baselines, record.component = component ∧
    record.configurationDigest ≠ "" ∧ administrator record.maintainedBy ∧ record.auditorReadable = true

theorem generated_baselines_cover_components (components : List Nat)
    (build : Nat → BaselineRecord) (identity : ∀ c ∈ components, (build c).component = c) :
    RecordCoverage.Covers BaselineRecord.component components (components.map build) :=
  RecordCoverage.map_covers _ _ _ identity

structure ProcurementDocument where
  id : Nat
  revealsEquipmentPurpose : Bool
  revealsClassifiedProtectionPurpose : Bool
  deriving DecidableEq, Repr

def msc_procurement_purpose_nondisclosure (documents : List ProcurementDocument) : Prop :=
  ∀ document ∈ documents,
    document.revealsEquipmentPurpose = false ∧ document.revealsClassifiedProtectionPurpose = false

structure PersonnelTraining where
  person : Nat
  role : PersonnelRole
  meetsLocalIATraining : Bool
  deriving DecidableEq, Repr

structure InspectionWindow where
  component : Nat
  start : Nat
  finish : Nat
  deriving DecidableEq, Repr

structure PhysicalInspection where
  component : Nat
  administrator : Nat
  time : Nat
  inspectedTampering : Bool
  inspectedUnauthorizedChanges : Bool
  deriving DecidableEq, Repr

def msc_training_and_hardware_inspection (personnel : List PersonnelTraining)
    (windows : List InspectionWindow) (inspections : List PhysicalInspection)
    (authorizedAdministrator : Nat → Prop) : Prop :=
  (∀ person ∈ personnel, person.role = .administrator ∨ person.role = .auditor →
    person.meetsLocalIATraining = true) ∧
  ∀ window ∈ windows, ∃ inspection ∈ inspections, inspection.component = window.component ∧
    window.start ≤ inspection.time ∧ inspection.time ≤ window.finish ∧
    authorizedAdministrator inspection.administrator ∧ inspection.inspectedTampering = true ∧
    inspection.inspectedUnauthorizedChanges = true

end TDN.Targets
