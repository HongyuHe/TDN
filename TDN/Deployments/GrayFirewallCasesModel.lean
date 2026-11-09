import TDN.Deployments.DeviceForwardingEligibility
import TDN.Deployments.GrayFirewallIptablesChecks

namespace TDN.Deployments.GrayFirewallCasesModel
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel DeviceForwardingEligibility Perimeter_ForwardCases

def PositiveChecks (sample : ForwardCase) (records : Records) (d : Deployment) : Prop :=
  ForwardEligibilityChecks sample records d .inbound ∧
  d.ForwardIngressSourceAllowed sample.interface.device (sample.packet records) ∧
  ∀ policy ∈ d.policies, policy.interface = sample.interface.id →
    policy.direction = .inbound → policy.hook = .forward →
      policy.Accepts (d.Observe (sample.packet records))

set_option synthInstance.maxSize 8192 in
instance (sample : ForwardCase) (records : Records) (d : Deployment)
    [∀ name, DecidablePred (d.reachableSource name)] :
    Decidable (PositiveChecks sample records d) := by
  unfold PositiveChecks InterfacePolicy.Accepts
  infer_instance

theorem checked_positive_case (sample : ForwardCase) (records : Records) (d : Deployment)
    (present : d.processing = some records.inventory) (interfaces : d.interfaces = records.interfaces)
    (policies : d.policies = records.projectedPolicies)
    (unique : InterfaceIDsUnique records.interfaces) (checks : PositiveChecks sample records d) :
    d.PacketEligibleAt sample.interface .inbound .forward (d.Observe (sample.packet records)) ∧
      d.GrayForwardPermission sample.interface .forward (d.Observe (sample.packet records)) ∧
      d.AcceptsAt sample.interface.id .inbound .forward (d.Observe (sample.packet records)) := by
  refine ⟨checked_forward_context_is_eligible sample records d present interfaces .inbound checks.1,
    fun _ => checks.2.1, ?_⟩
  exact checked_forward_context_is_accepted sample records d present interfaces policies unique .inbound
    checks.1.1 checks.2.2

end TDN.Deployments.GrayFirewallCasesModel

namespace TDN.Deployments.GrayFirewallCasesModel
open Compliance Requirements Requirements.Msc

def ClassificationPairChecks (d : Deployment) (traffic : Traffic)
    (source destination : Device) : Prop :=
  source ∈ d.devices ∧ destination ∈ d.devices ∧
  source.kind = .vpn ∧ destination.kind = .vpn ∧
  source.layer = some .inner ∧ destination.layer = some .inner ∧
  source.level.classification ≠ destination.level.classification ∧
  traffic.sourceDevice = some source.id ∧ traffic.destinationDevice = some destination.id ∧
  (∃ interface ∈ d.interfaces, interface.device = source.id ∧ interface.zone = .gray ∧
    interface.PacketAddress traffic.packet = some traffic.packet.source) ∧
  ∃ interface ∈ d.interfaces, interface.device = destination.id ∧ interface.zone = .gray ∧
    interface.PacketAddress traffic.packet = some traffic.packet.destination

instance (d : Deployment) (traffic : Traffic) (source destination : Device) :
    Decidable (ClassificationPairChecks d traffic source destination) := by
  unfold ClassificationPairChecks
  infer_instance

lemma checked_classification_pair (d : Deployment) (traffic : Traffic)
    (source destination : Device) (checks : ClassificationPairChecks d traffic source destination) :
    DifferentClassificationVPNs d traffic := by
  obtain ⟨sourceMember, destinationMember, sourceKind, destinationKind, sourceLayer,
    destinationLayer, different, sourceMetadata, destinationMetadata, sourceInterface,
    destinationInterface⟩ := checks
  exact ⟨source, sourceMember, destination, destinationMember, sourceKind, destinationKind,
    sourceLayer, destinationLayer, different,
    Or.inl ⟨sourceMetadata, destinationMetadata, sourceInterface, destinationInterface⟩⟩

end TDN.Deployments.GrayFirewallCasesModel
