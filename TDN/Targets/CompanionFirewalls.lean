import TDN.Targets.EnterpriseGray

namespace TDN.Targets.Complete
open Compliance

inductive CompanionCP where
  | mobileAccess | campusWLAN
  deriving DecidableEq

structure CompanionFirewall where
  package : CompanionCP
  innerFirewall : String
  innerEndpoints : List String
  redNetworks : List String
  externalInterfaces : List String
  internalInterfaces : List String
  sourceFilterRecommendationSelected : Bool

def CompanionFirewall.AttachmentPaths (configuration : CompanionFirewall)
    (d : Deployment) : Prop :=
  d.RedAttachmentsWellFormed ∧
  (∀ network ∈ configuration.redNetworks,
    (∃ red ∈ d.networks, red.id = network ∧
      ∃ endpoint ∈ configuration.innerEndpoints, endpoint ∈ red.innerComponents) ∧
    ∃ target, d.RedAttachmentDevice network target) ∧
  (∀ endpoint ∈ configuration.innerEndpoints,
    ∃ red ∈ d.networks, red.id ∈ configuration.redNetworks ∧ endpoint ∈ red.innerComponents) ∧
  (∀ endpoint ∈ configuration.innerEndpoints, ∀ red ∈ d.networks,
    red.id ∈ configuration.redNetworks → endpoint ∈ red.innerComponents →
    ∀ target, d.RedAttachmentDevice red.id target →
      Relation.ReflTransGen d.DeviceAdjacent endpoint target) ∧
  (∀ endpoint ∈ configuration.innerEndpoints, ∀ network ∈ configuration.redNetworks,
    ∀ target, d.RedAttachmentDevice network target →
    ¬ Relation.ReflTransGen
      (Waypointing.Avoiding d.DeviceAdjacent (fun node => node = configuration.innerFirewall))
        endpoint target)

def CompanionFirewall.Bound (configuration : CompanionFirewall) (d : Deployment) : Prop :=
  configuration.innerEndpoints ≠ [] ∧ configuration.redNetworks ≠ [] ∧
  configuration.externalInterfaces ≠ [] ∧ configuration.internalInterfaces ≠ [] ∧
  d.IsDevice configuration.innerFirewall .innerFirewall ∧
  (∀ endpoint ∈ configuration.innerEndpoints,
    d.IsLayer endpoint .inner) ∧
  (∀ network ∈ configuration.redNetworks,
    ∃ red ∈ d.networks, red.id = network) ∧
  (∀ interface ∈ d.interfaces, interface.device = configuration.innerFirewall →
    interface.id ∈ configuration.externalInterfaces ++ configuration.internalInterfaces) ∧
  (∀ id ∈ configuration.externalInterfaces, ∃ interface ∈ d.interfaces,
    interface.id = id ∧ interface.device = configuration.innerFirewall ∧ interface.zone = .red) ∧
  (∀ id ∈ configuration.internalInterfaces, ∃ interface ∈ d.interfaces,
    interface.id = id ∧ interface.device = configuration.innerFirewall ∧ interface.zone = .red) ∧
  configuration.AttachmentPaths d

def CompanionFirewall.ACL (configuration : CompanionFirewall) (d : Deployment) : Prop :=
  ∀ interface ∈ d.interfaces, interface.id ∈ configuration.externalInterfaces →
    d.PolicyCoverage interface ∧
    ∀ direction traffic, d.Accepts interface.id direction traffic →
      (direction = .inbound →
        ∃ endpoint ∈ configuration.innerEndpoints, traffic.sourceDevice = some endpoint) ∧
      (direction = .outbound →
        ∃ endpoint ∈ configuration.innerEndpoints, traffic.destinationDevice = some endpoint)

def CompanionFirewall.Eligibility (configuration : CompanionFirewall)
    (d : Deployment) (records : TechnicalDutyRecords) : Prop :=
  ∀ firewall ∈ records.components, firewall.component = configuration.innerFirewall →
    records.external.Confirms
      (match configuration.package with
      | .mobileAccess => .companionMAFirewallEligibility
      | .campusWLAN => .companionWLANFirewallEligibility)
      (.product firewall.component firewall.product firewall.version .innerFirewall) ∧
    records.external.Confirms .companionFirewallPhysicalSeparation
      (.component configuration.innerFirewall) ∧
    ∀ other ∈ d.devices,
      other.id ≠ configuration.innerFirewall →
      (other.layer.isSome = true ∨ other.kind ∈ [.grayFirewall, .outerFirewall]) →
      ∀ component ∈ records.components, component.component = other.id →
        firewall.physicalDevice ≠ component.physicalDevice

def CompanionFirewall.GeneralSharedConfiguration (configuration : CompanionFirewall)
    (records : TechnicalDutyRecords) (d : Deployment) : Prop :=
  ∀ record ∈ records.components, record.component = configuration.innerFirewall →
    DefaultAndDNSConfiguration record ∧
      TimeConfigurationForClient records.time d
        ⟨configuration.innerFirewall, .companionFirewall⟩ .red

def CompanionFirewall.Requirements (configuration : CompanionFirewall)
    (d : Deployment) (records : TechnicalDutyRecords) : Prop :=
  configuration.Bound d ∧ configuration.ACL d ∧
  configuration.Eligibility d records ∧ configuration.GeneralSharedConfiguration records d ∧
  ∃ firewall ∈ d.devices, firewall.kind = .grayFirewall

end TDN.Targets.Complete
