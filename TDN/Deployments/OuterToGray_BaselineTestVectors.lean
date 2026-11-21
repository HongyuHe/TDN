import TDN.Import.CompiledDecide
import TDN.Deployments.OuterToGray_BaselineData
import TDN.Deployments.OuterToGray_ForwardingTestVectors
import TDN.Models.SwapLocalAddressBindings

namespace TDN.Deployments.OuterToGray_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel

set_option maxRecDepth 1000000
set_option synthInstance.maxSize 2048

load_network_records replyCase : ForwardCase from "../../data/evidence/continuation/OuterToGray_BaselineCases.json" ["reply"]

load_network_records collisionCase : ForwardCase from "../../data/evidence/continuation/OuterToGray_BaselineCases.json" ["serviceCollision"]

load_network_records rawInterfaces : List Interface from "../../data/evidence/continuation/OuterToGray_BaselineCases.json" ["rawInterfaces"]

lemma every_gray_interface_is_preserved :
    rawInterfaces.filter (fun interface => interface.zone == .gray) =
      records.interfaces.filter (fun interface => interface.zone == .gray) := by
  native_decide

lemma every_raw_interface_identifier_is_preserved :
    rawInterfaces.map Interface.id = records.interfaces.map Interface.id := by
  native_decide

lemma reply_case_checked (base : Deployment) : replyCase.Checks records base := by
  unfold_check_parameters; native_decide

lemma collision_case_checked (base : Deployment) : collisionCase.Checks records base := by
  unfold_check_parameters; native_decide

theorem framed_reply_is_eligible_and_accepted (base : Deployment)
    (unique : InterfaceIDsUnique records.interfaces) :
    (records.deployment base).PacketEligibleAt replyCase.interface .inbound .forward
        ((records.deployment base).Observe (replyCase.packet records)) ∧
      (records.deployment base).PermitsAtHook replyCase.interface.id .inbound .forward
        ((records.deployment base).Observe (replyCase.packet records)) :=
  checked_forward_case_is_eligible_and_accepted replyCase records base unique (reply_case_checked base)

theorem framed_ike_with_radius_port_is_eligible_and_accepted (base : Deployment)
    (unique : InterfaceIDsUnique records.interfaces) :
    (records.deployment base).PacketEligibleAt collisionCase.interface .inbound .forward
        ((records.deployment base).Observe (collisionCase.packet records)) ∧
      (records.deployment base).PermitsAtHook collisionCase.interface.id .inbound .forward
        ((records.deployment base).Observe (collisionCase.packet records)) :=
  checked_forward_case_is_eligible_and_accepted collisionCase records base unique (collision_case_checked base)

def rawLocalConfiguration : MultiProtocolForwarding.TunnelForwardingModel :=
  records.configuration.withLocalAddresses (fun iface address =>
    ∃ interface ∈ rawInterfaces,
      interface.device = records.componentName (records.configuration.ip.owner iface) ∧
        interface.address = some address)

theorem raw_local_addresses_preserve_gray_forward_decision
    (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.forwardRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (rawLocalConfiguration.ip.forwardFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.forwardRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (records.configuration.ip.forwardFallback iface) (context.Packet records.configuration) :=
  MultiProtocolForwarding.local_address_projection_preserves_forward_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_encrypted_input (state : MultiProtocolForwarding.TunnelForwardingState) :
    PacketProcessing.InputAdmitted rawLocalConfiguration state ↔
      PacketProcessing.InputAdmitted records.configuration state :=
  MultiProtocolForwarding.local_address_projection_preserves_input_admission records.configuration _ state


lemma every_native_link_has_recorded_endpoints :
    ∀ edge ∈ records.links, edge.1 ∈ records.inventory.ifaces ∧ edge.2 ∈ records.inventory.ifaces := by
  native_decide

theorem every_captured_wire_arrival_has_native_path (base : Deployment)
    (before after : MultiProtocolForwarding.TunnelForwardingState)
    (arrival : MultiProtocolForwarding.TunnelForwardingStep records.configuration before .linkTransmit after) :
    (records.deployment base).DeviceArrivalEligible records.inventory after := by
  cases arrival with
  | linkTransmit next datapathStage linked =>
    exact Or.inl (Or.inl ⟨before.iface, (every_native_link_has_recorded_endpoints _ linked).1, linked⟩)

end TDN.Deployments.OuterToGray_Baseline
