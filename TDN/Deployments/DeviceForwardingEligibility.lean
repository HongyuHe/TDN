import TDN.Deployments.Perimeter_ForwardCases

namespace TDN.Deployments.DeviceForwardingEligibility
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_ForwardCases

def ForwardEligibilityChecks (sample : ForwardCase) (records : Records)
    (d : Deployment) (direction : Direction) : Prop :=
  ForwardHookChecks sample records d direction ∧
    DeviceIngressAttachment records.inventory sample.entryIface ∧
    ¬ d.InboundIPsecRequired records.inventory sample.entryIface (sample.context records).header ∧
    (sample.packet records).networkBytes = some sample.bytes ∧
    (∃ interface ∈ records.interfaces, interface.id = records.ifaceName sample.entryIface ∧
      interface.mtu = some sample.entryMtu) ∧ sample.bytes ≤ sample.entryMtu ∧
    (∃ interface ∈ records.interfaces, interface.id = records.ifaceName sample.route.egress ∧
      interface.mtu = some sample.exitMtu) ∧ sample.bytes ≤ sample.exitMtu ∧
    ∀ policy ∈ DataPlaneForwarding.lookupSpdPolicies
        (records.configuration.ip.egressPolicies sample.route.egress) (sample.context records).header,
      ∃ size ∈ records.ipsecSizes, size.Valid ∧ size.iface = sample.route.egress ∧
        size.policy = policy ∧ size.EncodedSize sample.bytes ≤ sample.exitMtu

instance (sample : ForwardCase) (records : Records) (d : Deployment) (direction : Direction) :
    Decidable (ForwardEligibilityChecks sample records d direction) := by
  unfold ForwardEligibilityChecks Deployment.InboundIPsecRequired
  infer_instance

theorem checked_forward_context_is_eligible (sample : ForwardCase) (records : Records)
    (d : Deployment) (present : d.processing = some records.inventory)
    (interfaces : d.interfaces = records.interfaces) (direction : Direction)
    (checks : ForwardEligibilityChecks sample records d direction) :
    d.PacketEligibleAt sample.interface direction .forward (d.Observe (sample.packet records)) := by
  obtain ⟨hook, attachment, noRequired, bytes, receiveMtu, receiveBound, sendMtu, sendBound, sizes⟩ := checks
  have supported := checked_forward_context_is_supported sample records d present interfaces direction hook
  refine Or.inl ⟨sample.context records, rfl, supported, ?_, ?_⟩
  · refine ⟨records.inventory, present, sample.bytes, bytes, ?_, ?_⟩
    · intro _
      refine ⟨sample.entryMtu, ?_, receiveBound⟩
      change d.IfaceMtu records.inventory sample.entryIface sample.entryMtu
      change ∃ interface ∈ d.interfaces, interface.id = records.ifaceName sample.entryIface ∧
        interface.mtu = some sample.entryMtu
      rw [interfaces]
      exact receiveMtu
    · intro _
      refine ⟨sample.exitMtu, ?_, sendBound, sizes⟩
      change d.IfaceMtu records.inventory sample.route.egress sample.exitMtu
      change ∃ interface ∈ d.interfaces, interface.id = records.ifaceName sample.route.egress ∧
        interface.mtu = some sample.exitMtu
      rw [interfaces]
      exact sendMtu
  · refine ⟨records.inventory, present, ?_, fun _ => Or.inl attachment, ?_⟩
    · exact ⟨⟨rfl, hook.2.2.2.2.2.1⟩, rfl⟩
    · intro _ required
      exact False.elim (noRequired required)

end TDN.Deployments.DeviceForwardingEligibility
