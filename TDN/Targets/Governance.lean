import TDN.Targets.Administration
import TDN.Targets.Incidents
import TDN.Targets.Testing

namespace TDN.Targets

inductive AdministratorDuty where
  | maintainSecurity | monitorSecurity | controlSecurity | applySecurityUpdates
  | documentIncidents | reportIncidents | supportLogistics | escortUncleared
  | defendAuxiliaryDevices | maintainCurrentCP
  deriving DecidableEq, Repr

structure AdministrativeDutyRecord where
  administrator : Nat
  component : Nat
  duty : AdministratorDuty
  completed : Bool
  deriving DecidableEq, Repr

def CoreAdministratorDuties : List AdministratorDuty :=
  [.maintainSecurity, .monitorSecurity, .controlSecurity, .applySecurityUpdates,
    .maintainCurrentCP]

/-- The applicability inventory distinguishes incidents, auxiliary devices and logistical
work that requires an escort. A complete component inventory is required for an application. -/
def msc_security_administrator_duties (components auxiliaryDevices : List Nat)
    (incidentComponents logisticsComponents unclearedLogisticsComponents : List Nat)
    (records : List AdministrativeDutyRecord) (administrator : Nat → Prop) : Prop :=
  let completed := fun component duty =>
    ∃ record ∈ records, record.component = component ∧ record.duty = duty ∧
      record.completed = true ∧ administrator record.administrator
  (∀ component ∈ components, ∀ duty ∈ CoreAdministratorDuties, completed component duty) ∧
  (∀ component ∈ auxiliaryDevices, completed component .defendAuxiliaryDevices) ∧
  (∀ component ∈ incidentComponents,
    completed component .documentIncidents ∧ completed component .reportIncidents) ∧
  (∀ component ∈ logisticsComponents, completed component .supportLogistics) ∧
  (∀ component ∈ unclearedLogisticsComponents, completed component .escortUncleared)

/-- Constructing the duty matrix covers every component and every required core action.
Completion and administrator identity remain separately checked fields. -/
theorem generated_administration_matrix_covers (components : List Nat) (person : Nat)
    (done : Nat → AdministratorDuty → Bool) :
    ∀ component ∈ components, ∀ duty ∈ CoreAdministratorDuties,
      ∃ record ∈ components.flatMap (fun component =>
        CoreAdministratorDuties.map (fun duty =>
          (⟨person, component, duty, done component duty⟩ : AdministrativeDutyRecord))),
        record.component = component ∧ record.duty = duty := by
  intro component member duty required
  refine ⟨⟨person, component, duty, done component duty⟩, ?_, rfl, rfl⟩
  exact List.mem_flatMap.mpr ⟨component, member, List.mem_map.mpr ⟨duty, required, rfl⟩⟩

inductive AuditorDuty where
  | review | manage | control | maintain | documentIncident | reportIncident
  | developSurvey | maintainSurvey | reportSurvey
  deriving DecidableEq, Repr

structure AuditorRecord where
  auditor : Nat
  duty : AuditorDuty
  object : Nat
  completed : Bool
  deriving DecidableEq, Repr

structure SecurityReview where
  event : Nat
  auditor : Nat
  assessedForCompromise : Bool
  compromiseFound : Bool
  incidentDocumented : Bool
  incidentReported : Bool
  deriving DecidableEq, Repr

def msc_auditor_duties_and_access (administratorActions auditEvents : List Nat)
    (reviews : List SecurityReview) (records : List AuditorRecord)
    (auditData : List Nat) (survey : Nat) (auditor : Nat → Prop)
    (authorizedAccess : Nat → Nat → Prop) (innerOrOuterAdministration : Nat → Prop) : Prop :=
  (∀ event ∈ administratorActions ++ auditEvents, ∃ review ∈ reviews,
    review.event = event ∧ auditor review.auditor ∧ review.assessedForCompromise = true ∧
    (review.compromiseFound = true →
      review.incidentDocumented = true ∧ review.incidentReported = true)) ∧
  (∀ person component, auditor person → authorizedAccess person component →
    innerOrOuterAdministration component) ∧
  (∀ data ∈ auditData, ∀ duty ∈ [AuditorDuty.review, .manage, .control, .maintain],
    ∃ record ∈ records, record.object = data ∧ record.duty = duty ∧
      record.completed = true ∧ auditor record.auditor) ∧
  ∀ duty ∈ [AuditorDuty.developSurvey, .maintainSurvey, .reportSurvey],
    ∃ record ∈ records, record.object = survey ∧ record.duty = duty ∧
      record.completed = true ∧ auditor record.auditor

theorem generated_reviews_cover_actions_and_events (actions events : List Nat)
    (review : Nat → SecurityReview)
    (identity : ∀ event ∈ actions ++ events, (review event).event = event) :
    RecordCoverage.Covers SecurityReview.event (actions ++ events)
      ((actions ++ events).map review) :=
  RecordCoverage.map_covers _ _ _ identity

inductive IntegratorDuty where
  | acquire | configure | document | test | maintain | incidentResponse
  deriving DecidableEq, Repr

def ListedIntegratorDuties : List IntegratorDuty :=
  [.acquire, .configure, .document, .test, .maintain, .incidentResponse]

/-- RG070 is permission/context: hiring is optional and the listed duties are not exhaustive.
The specification describes a permission policy, not an obligation to hire an integrator. -/
def msc_integrator_permitted_duties (hired : Bool)
    (permitted : IntegratorDuty → Prop) : Prop :=
  hired = true → ∀ duty ∈ ListedIntegratorDuties, permitted duty

theorem integrator_permissions_allow_listed_and_additional (hired : Bool)
    (additional : IntegratorDuty → Prop) :
    msc_integrator_permitted_duties hired
      (fun duty => duty ∈ ListedIntegratorDuties ∨ additional duty) := by
  intro _ duty listed
  exact Or.inl listed

structure AuthorizationAssessment where
  id : Nat
  riskAssessmentDocument : String
  securityControlAssessment : String
  systemAuthorization : String
  resultsDeliveredToAO : Bool
  riskAssessmentDeliveredToAO : Bool
  deriving DecidableEq, Repr

structure RevocationUpdate where
  compromise : Nat
  component : Nat
  certificateRevocationUpdated : Bool
  cakRevocationUpdated : Bool
  deriving DecidableEq, Repr

structure LifecycleConfiguration where
  component : Nat
  approvedConfiguration : String
  observedConfiguration : String
  requiredSecurityUpdates : List String
  installedSecurityUpdates : List String
  aoControlsConfiguration : Bool
  deriving DecidableEq, Repr

/-- Assessment documents and AO authorization are external records. A variant requires
the specified contact to determine an approval path, not an invented automatic approval. -/
def msc_ao_authorization_and_lifecycle_control (assessment : AuthorizationAssessment)
    (variantSelected : Bool) (contactedNSAExternalEngagement : Bool)
    (components compromises : List Nat) (revocation : List RevocationUpdate)
    (configurations : List LifecycleConfiguration) (allApplicableCPImplemented : Prop) : Prop :=
  assessment.riskAssessmentDocument ≠ "" ∧ assessment.securityControlAssessment ≠ "" ∧
  assessment.systemAuthorization ≠ "" ∧ assessment.resultsDeliveredToAO = true ∧
  assessment.riskAssessmentDeliveredToAO = true ∧ allApplicableCPImplemented ∧
  (variantSelected = true → contactedNSAExternalEngagement = true) ∧
  (∀ compromise ∈ compromises, ∀ component ∈ components,
    ∃ update ∈ revocation, update.compromise = compromise ∧ update.component = component ∧
      update.certificateRevocationUpdated = true ∧ update.cakRevocationUpdated = true) ∧
  ∀ component ∈ components, ∃ configuration ∈ configurations,
    configuration.component = component ∧ configuration.aoControlsConfiguration = true ∧
    configuration.observedConfiguration = configuration.approvedConfiguration ∧
    ∀ patch ∈ configuration.requiredSecurityUpdates, patch ∈ configuration.installedSecurityUpdates

/-- A per-compromise, per-component update construction cannot omit a solution component.
Actual update results remain inputs, so coverage alone does not establish successful revocation. -/
theorem revocation_matrix_covers_all_components (compromises components : List Nat)
    (update : Nat → Nat → RevocationUpdate)
    (identity : ∀ compromise ∈ compromises, ∀ component ∈ components,
      (update compromise component).compromise = compromise ∧
      (update compromise component).component = component) :
    ∀ compromise ∈ compromises, ∀ component ∈ components,
      ∃ record ∈ compromises.flatMap (fun c => components.map (update c)),
        record.compromise = compromise ∧ record.component = component := by
  intro compromise memberC component memberD
  exact ⟨update compromise component,
    List.mem_flatMap.mpr ⟨compromise, memberC,
      List.mem_map.mpr ⟨component, memberD, rfl⟩⟩,
    identity compromise memberC component memberD⟩

structure CrossDomainSolution where
  id : Nat
  selected : Bool
  dodi8540Assessment : String
  disnConnectionAssessment : String
  baselineIdentity : String
  deriving DecidableEq, Repr

/-- RG051 delegates to named external policies and the CDS Baseline. Each predicate must
use a versioned official source and actual product identity; a nonempty string is insufficient. -/
def msc_cross_domain_solution_conditions (solutions : List CrossDomainSolution)
    (validDoDIAssessment validDISNAssessment listedCDSIdentity : String → Prop) : Prop :=
  ∀ solution ∈ solutions, solution.selected = true →
    validDoDIAssessment solution.dodi8540Assessment ∧
    validDISNAssessment solution.disnConnectionAssessment ∧
    listedCDSIdentity solution.baselineIdentity

lemma no_selected_cds_excludes_cds_obligations (solutions : List CrossDomainSolution)
    (noneSelected : ∀ solution ∈ solutions, solution.selected = false)
    (validDoDI validDISN listed : String → Prop) :
    msc_cross_domain_solution_conditions solutions validDoDI validDISN listed := by
  intro solution member selected
  rw [noneSelected solution member] at selected
  cases selected

/-- RG076's warranties and nonendorsement text describe the document. The user's undertaking
is a legal agreement; no network execution or configuration check establishes its legal effect. -/
structure CPUserUndertaking where
  user : String
  documentVersion : String
  acceptsHoldHarmless : Bool
  acceptsIndemnification : Bool
  includesGovernmentAgentsAndEmployees : Bool
  includesFeesCostsExpenses : Bool
  includesAllDirectUseClaims : Bool
  deriving DecidableEq, Repr

def msc_cp_user_legal_undertaking (undertaking : CPUserUndertaking) : Prop :=
  undertaking.user ≠ "" ∧ undertaking.documentVersion = "MSC CP 1.3.0" ∧
  undertaking.acceptsHoldHarmless = true ∧ undertaking.acceptsIndemnification = true ∧
  undertaking.includesGovernmentAgentsAndEmployees = true ∧
  undertaking.includesFeesCostsExpenses = true ∧ undertaking.includesAllDirectUseClaims = true

end TDN.Targets
