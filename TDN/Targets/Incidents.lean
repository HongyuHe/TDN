import TDN.Semantics.RecordCoverage
import TDN.Targets.Architecture

namespace TDN.Targets

inductive IncidentKind where
  | componentSecurityFailure | classifiedCompromiseOrSpillage | grayTraffic
  | unauthorizedAccess | unauthorizedDestination | configurationChange
  | privilegeEscalation | simultaneousCertificateReuse | physicalTampering
  | protectionLayerFailure | significantServiceDegradation
  | outerConnectionDiscrepancy | innerConnectionDiscrepancy
  deriving DecidableEq, Repr

inductive Attribution where
  | adversarial | unexplained | knownNonMalicious
  deriving DecidableEq, Repr

structure Incident where
  id : Nat
  kind : IncidentKind
  attribution : Attribution
  confirmed : Bool
  detectedAt : Nat
  occurredAt : Nat
  blackConnectivityOnly : Bool
  fullSecurityLevel : SecurityLevel
  networkNames : List String
  componentIds : List Nat
  description : String
  remediation : String

/-- RP5, RP8, RP11, RP14 and RP15 use the document's malicious-activity condition.
Unexplained activity is included. The Black connectivity exception applies only to RP13. -/
def Reportable (incident : Incident) : Prop :=
  incident.confirmed = true ∧
  (incident.kind ∈ [.grayTraffic, .configurationChange, .physicalTampering,
    .outerConnectionDiscrepancy, .innerConnectionDiscrepancy] →
      incident.attribution ≠ .knownNonMalicious) ∧
  (incident.kind = .significantServiceDegradation → incident.blackConnectivityOnly = false)

lemma unexplained_satisfies_malicious_condition :
    Attribution.unexplained ≠ .knownNonMalicious := by decide

structure IncidentContact where
  name : String
  phone : String
  email : String

def CompleteContact (contact : IncidentContact) : Prop :=
  contact.name ≠ "" ∧ contact.phone ≠ "" ∧ contact.email ≠ ""

structure AffectedProduct where
  component : Nat
  manufacturer : String
  model : String
  version : String

def CompleteProduct (product : AffectedProduct) : Prop :=
  product.manufacturer ≠ "" ∧ product.model ≠ "" ∧ product.version ≠ ""

inductive IncidentChannel where
  | jointIncidentManagementSystem | acknowledgementLetterContact
  deriving DecidableEq, Repr

structure IncidentReport where
  incident : Incident
  registrationNumber : String
  primary : IncidentContact
  alternate : IncidentContact
  products : List AffectedProduct
  sentAt : Nat
  channel : IncidentChannel
  nsaTechnicalSupportRequested : Bool

/-- The incident's level, networks, date, description and remediation are carried into
the report itself. Product identity coverage cannot be satisfied by omitting an affected device. -/
def CompleteIncidentReport (report : IncidentReport) : Prop :=
  report.registrationNumber ≠ "" ∧ CompleteContact report.primary ∧
  CompleteContact report.alternate ∧ report.incident.networkNames ≠ [] ∧
  report.incident.description ≠ "" ∧ report.incident.remediation ≠ "" ∧
  ∀ component ∈ report.incident.componentIds,
    ∃ product ∈ report.products, product.component = component ∧ CompleteProduct product

/-- Times are seconds. Existing organizational procedures remain separately applicable.
Detection requirements from the Continuous Monitoring Annex are accounted in RG061. -/
def msc_incident_reporting (incidents : List Incident) (reports : List IncidentReport)
    (organizationalProcedureRequired followedProcedures : List String) : Prop :=
  (∀ incident ∈ incidents, Reportable incident →
    ∃ report ∈ reports, report.incident = incident ∧ CompleteIncidentReport report ∧
      incident.detectedAt ≤ report.sentAt ∧ report.sentAt ≤ incident.detectedAt + 86400) ∧
  ∀ procedure ∈ organizationalProcedureRequired, procedure ∈ followedProcedures

/-- Generating a report for each detected incident preserves complete incident data.
A bounded reporting delay and complete registry entries establish the reporting obligation. -/
theorem incident_reporting_from_generated_reports
    (incidents : List Incident) (registration : String)
    (primary alternate : IncidentContact) (product : Nat → AffectedProduct)
    (delay : Incident → Nat) (channel : IncidentChannel)
    (support : Bool) (required followed : List String)
    (registrationPresent : registration ≠ "")
    (primaryComplete : CompleteContact primary) (alternateComplete : CompleteContact alternate)
    (details : ∀ incident ∈ incidents, Reportable incident →
      incident.networkNames ≠ [] ∧ incident.description ≠ "" ∧ incident.remediation ≠ "")
    (products : ∀ incident ∈ incidents, Reportable incident →
      ∀ component ∈ incident.componentIds,
        (product component).component = component ∧ CompleteProduct (product component))
    (bounded : ∀ incident ∈ incidents, Reportable incident → delay incident ≤ 86400)
    (procedures : ∀ procedure ∈ required, procedure ∈ followed) :
    msc_incident_reporting incidents
      (incidents.map fun incident =>
        ⟨incident, registration, primary, alternate, incident.componentIds.map product,
          incident.detectedAt + delay incident, channel, support⟩)
      required followed := by
  refine ⟨?_, procedures⟩
  intro incident member reportable
  refine ⟨⟨incident, registration, primary, alternate, incident.componentIds.map product,
    incident.detectedAt + delay incident, channel, support⟩,
    List.mem_map.mpr ⟨incident, member, rfl⟩, rfl, ?_, ?_, ?_⟩
  · obtain ⟨networks, description, remediation⟩ := details incident member reportable
    refine ⟨registrationPresent, primaryComplete, alternateComplete, networks,
      description, remediation, ?_⟩
    intro component affected
    exact ⟨product component, List.mem_map.mpr ⟨component, affected, rfl⟩,
      products incident member reportable component affected⟩
  · exact Nat.le_add_right _ _
  · exact Nat.add_le_add_left (bounded incident member reportable) _

end TDN.Targets
