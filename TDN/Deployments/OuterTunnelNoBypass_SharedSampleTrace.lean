import TDN.Deployments.OuterTunnelNoBypass_SharedDeliveryPath
import TDN.Deployments.OuterTunnelNoBypass_SharedModeChecks

namespace TDN.Deployments.OuterTunnelNoBypass_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 8000000

load_network_records deliveryPath : SizingPath from "../../data/evidence/outerTunnelNoBypass/SharedIPsecDelivery.json" ["path"]
load_network_records deliveryMoves : List DeliveryMove from "../../data/evidence/outerTunnelNoBypass/SharedIPsecDelivery.json" ["moves"]

lemma delivery_path_checked : DeliveryPathChecks deliveryPath.start deliveryMoves := by native_decide

lemma delivery_source_checked : deliveryPath.SourceChecks records entries roles networks := by native_decide

lemma delivery_path_has_two_tunnel_layers :
    (deliveryMoves.filter (fun move => move.step.operation == .encryptIPsec)).length = 2 ∧
    (deliveryMoves.filter (fun move => move.step.operation == .decryptIPsec)).length = 2 ∧
    deliveryMoves.length = 54 := by native_decide

lemma delivery_path_reaches_red_host :
    (deliveryFinish deliveryPath.start deliveryMoves).datapathStage = .delivered ∧
    (deliveryFinish deliveryPath.start deliveryMoves).iface = 196 ∧
    (deliveryFinish deliveryPath.start deliveryMoves).frame.originDomain = 1 ∧
    (deliveryFinish deliveryPath.start deliveryMoves).frame.body.protectionLayers = [] := by native_decide

theorem snapshot_RG030_shared_nonempty_payload_delivered (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ∃ start actions last, (interpretedForwarding primitive).initial start ∧
      (interpretedForwarding primitive).system.MTr start actions last ∧
      last.native.datapathStage = .delivered ∧ last.native.iface = 196 ∧
      last.native.frame.originDomain = 1 ∧ last.native.frame.payload ≠ 0 ∧
      last.native.frame.body.protectionLayers = [] := by
  obtain ⟨network, networkMember, entry, origin⟩ := delivery_source_checked.1
  have name := red_network_of_recorded_origin deliveryPath.flow.domain network.id origin
  have allowed : (binding (deviceBinding primitive) records.inventory.ifaces).SourceRequestAllowed
      (interpretedDeployment primitive) deliveryPath.flow.request := by
    refine ⟨Or.inl ⟨deliveryPath.template, rfl⟩, rfl, ?_⟩
    change sourceEntry entries deliveryPath.flow.iface = some (redNetwork deliveryPath.flow.domain) ∧
      ∃ network ∈ networks, network.id = redNetwork deliveryPath.flow.domain
    rw [name]
    exact ⟨entry, network, networkMember, rfl⟩
  have sourceState : (binding (deviceBinding primitive) records.inventory.ifaces).SourceState
      deliveryPath.flow.request deliveryPath.datagram = deliveryPath.start := by
    change (DeviceExecutionBinding.SourceState (deviceBinding primitive) deliveryPath.flow.request deliveryPath.datagram) = _
    unfold DeviceExecutionBinding.SourceState
    rfl
  obtain ⟨_, start, initialized, sameStart, _⟩ := (interpreted_deployment_covered primitive).2.2.2.1.2.1
    deliveryPath.flow.request [deliveryPath.datagram] deliveryPath.datagram allowed delivery_source_checked.2 (by simp)
  have same : start.native = deliveryPath.start := sameStart.trans sourceState
  obtain ⟨actions, last, run, finish, payload⟩ := delivery_path_reaches primitive deliveryMoves start start []
    initialized Cslib.LTS.MTr.refl (by rw [same]; exact delivery_path_checked)
  rw [same] at finish payload
  have result := delivery_path_reaches_red_host
  rw [← finish] at result
  refine ⟨start, actions, last, initialized, run, result.1, result.2.1, result.2.2.1, ?_, result.2.2.2⟩
  rw [payload]
  change PayloadCode ([71,69,84,32,47,32,72,84,84,80] : List UInt8) ≠ 0
  native_decide
lemma delivery_path_applies_outer_protection :
    (deliveryMoves.filter (fun move => move.step.operation == .encryptIPsec && move.step.policy.tag == 2)).length = 1 ∧
    (deliveryMoves.filter (fun move => move.step.operation == .decryptIPsec && move.step.policy.tag == 2)).length = 1 := by native_decide

end TDN.Deployments.OuterTunnelNoBypass_Shared
