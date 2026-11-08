import TDN.Evidence.OuterGraySharedData
import TDN.Evidence.OuterGrayNativeCases
import TDN.Semantics.LocalAddressProjection

namespace TDN.Imported.OuterGrayShared
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 2048

tdn_data replyCase : ForwardCase from "../../data/evidence/continuation/OuterGraySharedCases.json" ["reply"]

tdn_data collisionCase : ForwardCase from "../../data/evidence/continuation/OuterGraySharedCases.json" ["serviceCollision"]

tdn_data rawInterfaces : List Interface from "../../data/evidence/continuation/OuterGraySharedCases.json" ["rawInterfaces"]

lemma every_Gray_interface_is_preserved :
    rawInterfaces.filter (fun interface => interface.zone == .gray) =
      records.interfaces.filter (fun interface => interface.zone == .gray) := by
  exact of_decide_eq_true rfl

lemma every_raw_interface_identifier_is_preserved :
    rawInterfaces.map Interface.id = records.interfaces.map Interface.id := by
  exact of_decide_eq_true rfl

lemma reply_case_checked (base : Deployment) : replyCase.Checks records base := by
  exact of_decide_eq_true rfl

lemma collision_case_checked (base : Deployment) : collisionCase.Checks records base := by
  exact of_decide_eq_true rfl

theorem framed_reply_is_eligible_and_accepted (base : Deployment)
    (unique : InterfaceIDsUnique records.interfaces) :
    (records.deployment base).PacketEligibleAt replyCase.interface .inbound .forward
        ((records.deployment base).Observe (replyCase.packet records)) ∧
      (records.deployment base).AcceptsAt replyCase.interface.id .inbound .forward
        ((records.deployment base).Observe (replyCase.packet records)) :=
  checked_forward_case_is_eligible_and_accepted replyCase records base unique (reply_case_checked base)

theorem framed_IKE_with_Radius_port_is_eligible_and_accepted (base : Deployment)
    (unique : InterfaceIDsUnique records.interfaces) :
    (records.deployment base).PacketEligibleAt collisionCase.interface .inbound .forward
        ((records.deployment base).Observe (collisionCase.packet records)) ∧
      (records.deployment base).AcceptsAt collisionCase.interface.id .inbound .forward
        ((records.deployment base).Observe (collisionCase.packet records)) :=
  checked_forward_case_is_eligible_and_accepted collisionCase records base unique (collision_case_checked base)

def rawLocalConfiguration : MultiProtocolExecution.Config :=
  records.configuration.withLocalAddresses (fun iface address =>
    ∃ interface ∈ rawInterfaces,
      interface.device = records.componentName (records.configuration.ip.owner iface) ∧
        interface.address = some address)

theorem raw_local_addresses_preserve_Gray_forward_decision
    (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.forwardRules iface).map PacketPolicy.Rule.toFilter)
        (rawLocalConfiguration.ip.forwardFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.forwardRules iface).map PacketPolicy.Rule.toFilter)
        (records.configuration.ip.forwardFallback iface) (context.Packet records.configuration) :=
  MultiProtocolExecution.local_address_projection_preserves_forward_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_encrypted_INPUT (state : MultiProtocolExecution.State) :
    PacketProcessing.InputAdmitted rawLocalConfiguration state ↔
      PacketProcessing.InputAdmitted records.configuration state :=
  MultiProtocolExecution.local_address_projection_preserves_input_admission records.configuration _ state


lemma every_native_link_has_recorded_endpoints :
    ∀ edge ∈ records.links, edge.1 ∈ records.inventory.ifaces ∧ edge.2 ∈ records.inventory.ifaces := by
  exact of_decide_eq_true rfl

theorem every_captured_wire_arrival_has_native_path (base : Deployment)
    (before after : MultiProtocolExecution.State)
    (arrival : MultiProtocolExecution.Step records.configuration before .linkTransmit after) :
    (records.deployment base).NativeArrivalEligible records.inventory after := by
  cases arrival with
  | linkTransmit next datapathStage linked =>
    exact Or.inl (Or.inl ⟨before.iface, (every_native_link_has_recorded_endpoints _ linked).1, linked⟩)

end TDN.Imported.OuterGrayShared
