import TDN.Deployments.InnerTunnelNoBypass_IPsecDeliveryPath
import TDN.Deployments.InnerTunnelNoBypass_IPsecTunnelBindings

namespace TDN.Deployments.InnerTunnelNoBypass_IPsec
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000
set_option maxHeartbeats 8000000

load_network_records deliveryPath : SizingPath from "../../data/evidence/outerTunnelNoBypass/BaselineIPsecDelivery.json" ["path"]
load_network_records deliveryMoves : List DeliveryMove from "../../data/evidence/outerTunnelNoBypass/BaselineIPsecDelivery.json" ["moves"]

lemma delivery_path_checked : deliveryPathChecked deliveryPath.start deliveryMoves := by decide

lemma delivery_source_checked : deliveryPath.SourceChecks records entries roles networks := by decide

lemma delivery_path_has_two_tunnel_layers :
    (deliveryMoves.filter (fun move => move.step.operation == .encryptIPsec)).length = 2 ∧
    (deliveryMoves.filter (fun move => move.step.operation == .decryptIPsec)).length = 2 ∧
    deliveryMoves.length = 44 := by decide

lemma delivery_path_reaches_red_host :
    (deliveryFinish deliveryPath.start deliveryMoves).datapathStage = .delivered ∧
    (deliveryFinish deliveryPath.start deliveryMoves).iface = 142 ∧
    (deliveryFinish deliveryPath.start deliveryMoves).frame.originDomain = 1 ∧
    (deliveryFinish deliveryPath.start deliveryMoves).frame.body.protectionLayers = [] := by decide

theorem snapshot_RG029_ipsec_nonempty_payload_delivered (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial) :
    ∃ start actions last, (interpretedForwarding primitive).initial start ∧
      (interpretedForwarding primitive).system.MTr start actions last ∧
      last.native.datapathStage = .delivered ∧ last.native.iface = 142 ∧
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
  decide

lemma red_endpoint_network_ids_checked :
    ∀ entry ∈ entries, records.configuration.ip.ifaceSecurityDomain entry.hostIface = some entry.originDomain ∧
      ((entries.find? (fun selected => selected.originDomain == entry.originDomain)).map SourceEntry.network) = some entry.network := by
  intro entry member
  have checked := OuterTunnelNoBypass_BaselineNetwork.red_endpoint_network_ids_checked.1 entry member
  exact ⟨checked.2.1, checked.2.2⟩

lemma delivery_recipient_network_id_checked :
    records.configuration.ip.ifaceSecurityDomain 142 = some 3 ∧
      redNetwork 3 = "V31B_I_B1/red-network" := by decide

end TDN.Deployments.InnerTunnelNoBypass_IPsec
