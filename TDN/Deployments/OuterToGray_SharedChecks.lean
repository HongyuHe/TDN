import TDN.Deployments.OuterToGray_SharedFlow0
import TDN.Deployments.OuterToGray_SharedFlow1
import TDN.Deployments.OuterToGray_SharedFlow2
import TDN.Deployments.OuterToGray_SharedFlow3
import TDN.Deployments.OuterToGray_SharedFlow4
import TDN.Deployments.OuterToGray_SharedFlow5
import TDN.Deployments.OuterToGray_SharedFlow6
import TDN.Deployments.OuterToGray_SharedFlow7
import TDN.Deployments.OuterToGray_SharedMasks
import TDN.Deployments.OuterToGray_SharedInventory
import TDN.Deployments.OuterToGray_SharedEndpoints
import TDN.Deployments.OuterToGray_SharedIptablesChains
import TDN.Deployments.OuterToGray_PreEncapRouteLookup

namespace TDN.Deployments.OuterToGray_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma all_listed_Gray_interfaces_have_flow_checks (base : Deployment) :
    ∀ interface ∈ outerGrayInterfaces, ∀ direction,
      records.RouteFirstMaskLookup base interface direction := by
  intro interface member direction
  simp only [outerGrayInterfaces, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · cases direction with
    | inbound => exact gray0_inbound_lookup base
    | outbound => exact gray0_outbound_lookup base
  · cases direction with
    | inbound => exact gray1_inbound_lookup base
    | outbound => exact gray1_outbound_lookup base
  · cases direction with
    | inbound => exact gray2_inbound_lookup base
    | outbound => exact gray2_outbound_lookup base
  · cases direction with
    | inbound => exact gray3_inbound_lookup base
    | outbound => exact gray3_outbound_lookup base
  · cases direction with
    | inbound => exact gray4_inbound_lookup base
    | outbound => exact gray4_outbound_lookup base
  · cases direction with
    | inbound => exact gray5_inbound_lookup base
    | outbound => exact gray5_outbound_lookup base
  · cases direction with
    | inbound => exact gray6_inbound_lookup base
    | outbound => exact gray6_outbound_lookup base
  · cases direction with
    | inbound => exact gray7_inbound_lookup base
    | outbound => exact gray7_outbound_lookup base

lemma Outer_gray_forward_masks_checked (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        ∀ direction ∈ [Direction.inbound, .outbound],
          records.ForwardMaskLookup base interface direction := by
  intro interface member outer gray direction _
  exact (records.route_first_lookup_iff base interface direction).mp
    (all_listed_Gray_interfaces_have_flow_checks base interface
      (all_applicable_Gray_interfaces_are_listed base interface member outer gray) direction)

lemma Outer_gray_forward_coverage_checked (base : Deployment) :
    ∀ interface ∈ (records.deployment base).interfaces,
      (records.deployment base).IsLayer interface.device .outer → interface.zone = .gray →
        ∀ direction ∈ [Direction.inbound, .outbound],
          OuterGrayForwardChecks (records.deployment base) records.inventory records.pairs interface direction := by
  intro interface member outer gray direction allowedDirection
  exact records.forward_checks_from_mask_lookup base interface_ids_unique
    every_packet_mask_has_an_ordered_allowance interface member direction
    (Outer_gray_forward_masks_checked base interface member outer gray direction allowedDirection)

lemma no_workstations : ∀ device ∈ records.components, device.kind ≠ .workstation := by
  exact of_decide_eq_true rfl

lemma all_inner_tunnels_IPsec :
    ∀ tunnel ∈ records.tunnels, tunnel.layer = .inner → tunnel.mechanism = .ipsec := by
  exact of_decide_eq_true rfl

end TDN.Deployments.OuterToGray_Shared
