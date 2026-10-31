import TDN.Targets.Management

namespace TDN.Targets

structure SIEMEndpoint where
  id : Nat
  zone : ManagementZone
  deriving DecidableEq, Repr

structure SIEMSource where
  component : Nat
  zone : ManagementZone
  innerOrOuterEncryption : Bool
  firewall : Bool
  managementService : Bool
  deriving DecidableEq, Repr

structure CollectedSecurityData where
  source : Nat
  siem : Nat
  logData : Bool
  flowData : Bool
  analyzed : Bool
  protection : ManagementProtection
  cds : Option Nat
  deriving DecidableEq, Repr

structure SecurityAlertRule where
  siem : Nat
  eventKind : String
  enabled : Bool
  deriving DecidableEq, Repr

/-- SIEM placement is optional. If selected, Gray sources use a Gray SIEM or a Red SIEM
through an approved CDS. Log encryption is tracked as a selected recommendation here;
the general management-transport requirement remains independently applicable. -/
def msc_siem_collection_alerting_and_protection (selected encryptionRecommendationSelected : Bool)
    (endpoints : List SIEMEndpoint) (sources : List SIEMSource)
    (collections : List CollectedSecurityData) (rules : List SecurityAlertRule)
    (approvedCDS : Nat → Prop) (requiredEvents : Nat → List String)
    (continuousMonitoringAnnexSatisfied : Prop) : Prop :=
  selected = true →
  continuousMonitoringAnnexSatisfied ∧
  (∀ source ∈ sources, ∃ collection ∈ collections, collection.source = source.component ∧
    collection.logData = true ∧ collection.analyzed = true ∧
    (source.zone = .red → collection.flowData = true) ∧
    (encryptionRecommendationSelected = true → ApprovedManagementProtocol collection.protection) ∧
    ∃ endpoint ∈ endpoints, endpoint.id = collection.siem ∧
      (endpoint.zone = source.zone ∨
        (source.zone = .gray ∧ endpoint.zone = .red ∧
          ∃ cds, collection.cds = some cds ∧ approvedCDS cds))) ∧
  (∀ endpoint ∈ endpoints, ∀ event ∈ requiredEvents endpoint.id,
    ∃ rule ∈ rules, rule.siem = endpoint.id ∧ rule.eventKind = event ∧ rule.enabled = true) ∧
  ∀ source ∈ sources, source.zone = .gray →
    source.innerOrOuterEncryption = true ∨ source.firewall = true →
    ∃ collection ∈ collections, collection.source = source.component ∧
      ∃ rule ∈ rules, rule.siem = collection.siem ∧
        rule.eventKind = "unexpected-traffic-received-and-dropped" ∧ rule.enabled = true

theorem generated_siem_rules_cover_required_events (endpoints : List SIEMEndpoint)
    (requiredEvents : Nat → List String) :
    ∀ endpoint ∈ endpoints, ∀ event ∈ requiredEvents endpoint.id,
      ∃ rule ∈ endpoints.flatMap (fun endpoint =>
        (requiredEvents endpoint.id).map (fun event =>
          (⟨endpoint.id, event, true⟩ : SecurityAlertRule))),
        rule.siem = endpoint.id ∧ rule.eventKind = event ∧ rule.enabled = true := by
  intro endpoint member event required
  exact ⟨⟨endpoint.id, event, true⟩,
    List.mem_flatMap.mpr ⟨endpoint, member, List.mem_map.mpr ⟨event, required, rfl⟩⟩,
    rfl, rfl, rfl⟩

end TDN.Targets
