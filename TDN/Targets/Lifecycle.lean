import TDN.Semantics.GuardedEvents
import TDN.Semantics.CalendarTime
import Mathlib.Data.Finset.Basic

namespace TDN.Targets

inductive KeyingMethod where
  | certificate | cak
  deriving DecidableEq, Repr

structure ComponentDisposal where
  component : Nat
  method : KeyingMethod
  disposedAt : Nat
  administrator : Nat
  deriving DecidableEq, Repr

def DisposalPrerequisite : KeyingMethod → String
  | .certificate => "certificate_revocation_initiated"
  | .cak => "cak_destruction_initiated"

/-- RG-067 asks for initiation before disposal, not completed revocation after disposal. -/
def msc_predisposal_key_revocation (disposals : List ComponentDisposal)
    (events : List Temporal.Event) (authorizedAdministrator : Nat → Prop) : Prop :=
  ∀ disposal ∈ disposals, ∃ event ∈ events,
    event.object = disposal.component ∧
    event.kind = DisposalPrerequisite disposal.method ∧
    event.time < disposal.disposedAt ∧
    event.actor = disposal.administrator ∧ authorizedAdministrator event.actor

/-- A checked event-admission mechanism supplies temporal witnesses; identity and authorization
are independent recorded facts. The theorem is conditional until actual histories are supplied. -/
theorem predisposal_revocation_from_guarded_history
    (disposals : List ComponentDisposal) (events : List Temporal.Event)
    (method : KeyingMethod) (authorizedAdministrator : Nat → Prop)
    (history : GuardedEvents.History "disposed" (DisposalPrerequisite method) events)
    (recorded : ∀ disposal ∈ disposals, disposal.method = method ∧
      ∃ event ∈ events, event.kind = "disposed" ∧ event.object = disposal.component ∧
        event.time = disposal.disposedAt)
    (actors : ∀ event ∈ events, event.kind = DisposalPrerequisite method →
      authorizedAdministrator event.actor ∧
      ∀ disposal ∈ disposals, disposal.component = event.object →
        disposal.administrator = event.actor) :
    msc_predisposal_key_revocation disposals events authorizedAdministrator := by
  intro disposal member
  obtain ⟨sameMethod, event, inEvents, kind, object, time⟩ := recorded disposal member
  obtain ⟨prior, inPrior, priorKind, priorObject, priorTime⟩ :=
    GuardedEvents.all_recorded_events_have_prerequisites history event inEvents kind
  have authorization := actors prior inPrior priorKind
  refine ⟨prior, inPrior, priorObject.trans object, ?_, ?_, ?_, authorization.1⟩
  · simpa [sameMethod] using priorKind
  · simpa [time] using priorTime
  · exact (authorization.2 disposal member (priorObject.trans object).symm).symm

structure RoleAssignments (Person : Type) where
  administrators : Finset Person
  auditors : Finset Person
  innerAdministrators : Finset Person
  outerAdministrators : Finset Person
  integratorRed : Finset Person
  integratorGray : Finset Person
  separateIntegratorSelected : Bool
  macObjectiveSelected : Bool
  macDefinesAdministrator : Bool
  macDefinesAuditor : Bool

/-- RG-065 keeps optional MAC and Integrator separation conditional on selection. -/
def msc_separation_of_personnel_roles {Person : Type} (r : RoleAssignments Person) : Prop :=
  Disjoint r.administrators r.auditors ∧
  Disjoint r.innerAdministrators r.outerAdministrators ∧
  (r.macObjectiveSelected = true →
    r.macDefinesAdministrator = true ∧ r.macDefinesAuditor = true) ∧
  (r.separateIntegratorSelected = true → Disjoint r.integratorRed r.integratorGray)

/-- Independent assignment tables are disjoint when their enforced person labels differ. -/
lemma disjoint_assignments_from_distinct_labels {Person Label : Type}
    (assignment : Person → Label) (left right : Finset Person) (a b : Label)
    (different : a ≠ b) (leftLabel : ∀ p ∈ left, assignment p = a)
    (rightLabel : ∀ p ∈ right, assignment p = b) : Disjoint left right := by
  apply Finset.disjoint_left.mpr
  intro p hl hr
  exact different ((leftLabel p hl).symm.trans (rightLabel p hr))

inductive InfrastructureCredential where
  | password (randomEntropyBits : Nat)
  | service (componentDomain serviceDomain : Nat)
  deriving DecidableEq, Repr

/-- RG-063 uses random entropy, not password character count. Generator approval is a recommendation. -/
def msc_infrastructure_authentication_choice (credentials : List InfrastructureCredential) : Prop :=
  ∀ credential ∈ credentials, match credential with
    | .password entropy => 112 ≤ entropy
    | .service componentDomain serviceDomain => componentDomain = serviceDomain

/-- A re-registration event identifies the solution and version it actually registers.
Times are nonnegative Unix seconds in UTC; organizational authenticity is external. -/
structure VersionRegistrationEvent where
  solution : String
  cpVersion : String
  time : Nat
  deriving DecidableEq, Repr

structure VersionChange where
  solution : String
  cpVersion : String
  priorRegistration : Nat
  publishedAt : Nat
  notifiedAt : Nat
  nextRenewal : Nat
  notificationDeadline : Nat
  compliantAt : Nat
  reregistration : VersionRegistrationEvent
  deriving DecidableEq, Repr

/-- INT-061 retains both deadlines. Calendar computation fixes the six-month
notification deadline. The actual new-version registration follows compliance,
and notification follows publication. -/
def VersionDeadlines (change : VersionChange) : Prop :=
  change.publishedAt ≤ change.notifiedAt ∧
  change.notificationDeadline = CalendarTime.sixMonthsAfter change.notifiedAt ∧
  change.publishedAt ≤ change.compliantAt ∧
  change.compliantAt ≤ change.nextRenewal ∧
  change.compliantAt ≤ change.notificationDeadline ∧
  change.compliantAt ≤ change.reregistration.time ∧
  change.reregistration.time ≤ change.notificationDeadline ∧
  change.reregistration.solution = change.solution ∧
  change.reregistration.cpVersion = change.cpVersion

/-- Meeting the earlier source deadline establishes both upper bounds.
Event identities, calendar conversion and chronological order remain explicit. -/
theorem version_deadlines_of_earlier_limit (change : VersionChange)
    (notified : change.publishedAt ≤ change.notifiedAt)
    (calendar : change.notificationDeadline = CalendarTime.sixMonthsAfter change.notifiedAt)
    (publication : change.publishedAt ≤ change.compliantAt)
    (earlier : change.compliantAt ≤ min change.nextRenewal change.notificationDeadline)
    (registration : change.compliantAt ≤ change.reregistration.time ∧
      change.reregistration.time ≤ change.notificationDeadline)
    (identity : change.reregistration.solution = change.solution ∧
      change.reregistration.cpVersion = change.cpVersion) :
    VersionDeadlines change :=
  ⟨notified, calendar, publication, le_trans earlier (min_le_left _ _),
    le_trans earlier (min_le_right _ _), registration.1, registration.2, identity⟩

structure RegistrationRecord where
  id : Nat
  solution : String
  cpVersion : String
  approvedAt : Nat
  operationalUseAt : Nat
  expiresAt : Nat
  nextRenewalAt : Nat
  packageComplete : Bool
  aoMatrixSubmitted : Bool
  annualInformationUpdated : Bool
  changedInformationUpdated : Bool
  deriving DecidableEq, Repr

/-- RG-061 binds annual expiry to the approval's Gregorian anniversary. Each
record describes operational use during that approval and its annual renewal.
A new approval supplies a new record for later use. Changes are tied to the
same solution and approval record; their deadline is that record's next renewal. -/
def msc_registration_and_version_updates (registrations : List RegistrationRecord)
    (changes : List VersionChange) : Prop :=
  (∀ r ∈ registrations, r.approvedAt < r.operationalUseAt ∧
    r.operationalUseAt < r.expiresAt ∧
    r.expiresAt = CalendarTime.oneYearAfter r.approvedAt ∧
    r.approvedAt < r.nextRenewalAt ∧ r.nextRenewalAt ≤ r.expiresAt ∧
    r.packageComplete = true ∧ r.aoMatrixSubmitted = true ∧
    r.annualInformationUpdated = true ∧ r.changedInformationUpdated = true) ∧
  ∀ change ∈ changes, VersionDeadlines change ∧
    ∃ r ∈ registrations, r.id = change.priorRegistration ∧
      r.solution = change.solution ∧ change.nextRenewal = r.nextRenewalAt

end TDN.Targets
