import TDN.Deployments.OuterToGray_BaselineChecks
import TDN.Deployments.OuterToGray_BaselineBlockedTrafficTests

namespace TDN.Deployments.OuterToGray_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

theorem complete_Outer_gray_policy (base : Deployment) :
    msc_outer_gray_interface_policy (records.deployment base) false := by
  have workstationRole := gray_workstation_role_is_empty (records.deployment base) no_workstations rfl
  have coherence := records.processing_coherent_from_structure base (device_structure_checked base)
    interface_iface_selection_checked device_program_atoms_checked
  have udpCoherence : (records.deployment base).UDPBindingsCoherent := of_decide_eq_true rfl
  exact outer_gray_IPsec_policy_from_native_checks (records.deployment base) records.inventory rfl
    ⟨fun _ => 64, fun _ => 64⟩ rfl (by intro iface; exact ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩) records.pairs
    (address_inventory_checked base) workstationRole coherence udpCoherence
    (records.policy_indices_from_unique_interfaces base interface_ids_unique)
    (inner_pair_bindings_checked base) ⟨rfl, no_workstations⟩ rfl rfl all_inner_tunnels_IPsec
    (inner_address_coverage_checked base) (fun _ _ impossible => impossible)
    (fun _ _ impossible => impossible) (local_endpoints_separate base) inner_endpoints_IPv4
    (Outer_VPN_options_checked base) (Outer_gray_ifaces_routed base) (Outer_gray_allow_rules_checked base)
    (Outer_gray_mtu_checked base)
    (fun interface member outer gray direction => Outer_gray_forward_coverage_checked base interface member outer gray
      direction (by cases direction <;> simp))


theorem useful_framed_reply_is_eligible_and_accepted (base : Deployment) :
    (records.deployment base).PacketEligibleAt replyCase.interface .inbound .forward
        ((records.deployment base).Observe (replyCase.packet records)) ∧
      (records.deployment base).AcceptsAt replyCase.interface.id .inbound .forward
        ((records.deployment base).Observe (replyCase.packet records)) :=
  framed_reply_is_eligible_and_accepted base interface_ids_unique

theorem useful_IKE_with_Radius_port_is_eligible_and_accepted (base : Deployment) :
    (records.deployment base).PacketEligibleAt collisionCase.interface .inbound .forward
        ((records.deployment base).Observe (collisionCase.packet records)) ∧
      (records.deployment base).AcceptsAt collisionCase.interface.id .inbound .forward
        ((records.deployment base).Observe (collisionCase.packet records)) :=
  framed_IKE_with_Radius_port_is_eligible_and_accepted base interface_ids_unique

end TDN.Deployments.OuterToGray_Baseline
