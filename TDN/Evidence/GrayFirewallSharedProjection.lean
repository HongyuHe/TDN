import TDN.Evidence.GrayFirewallSharedData
import TDN.Semantics.LocalAddressProjection

namespace TDN.Imported.GrayFirewallShared
open Compliance
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data rawInterfaces : List Interface from "../../data/evidence/continuation/GrayFirewallSharedProjection.json" ["rawInterfaces"]

lemma every_raw_interface_identifier_is_preserved :
    rawInterfaces.map Interface.id = records.interfaces.map Interface.id := by
  exact of_decide_eq_true rfl

lemma every_Gray_and_Black_interface_is_preserved :
    rawInterfaces.filter (fun interface => interface.zone == .gray || interface.zone == .black) =
      records.interfaces.filter (fun interface => interface.zone == .gray || interface.zone == .black) := by
  exact of_decide_eq_true rfl

lemma every_attached_Red_interface_is_preserved :
    rawInterfaces.filter (fun interface => interface.zone == .red && interface.physical) =
      records.interfaces.filter (fun interface => interface.zone == .red && interface.physical) := by
  exact of_decide_eq_true rfl

def rawLocalConfiguration : MultiProtocolExecution.Config :=
  records.configuration.withLocalAddresses (fun iface address =>
    ∃ interface ∈ rawInterfaces,
      interface.device = records.componentName (records.configuration.ip.owner iface) ∧
        interface.address = some address)

theorem raw_local_addresses_preserve_all_hook_packets (context : PacketProcessing.Context) :
    context.Packet rawLocalConfiguration = context.Packet records.configuration :=
  MultiProtocolExecution.local_address_projection_preserves_policy_packet records.configuration _ context

theorem raw_local_addresses_preserve_FORWARD (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.forwardRules iface).map PacketPolicy.Rule.toFilter)
        (rawLocalConfiguration.ip.forwardFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.forwardRules iface).map PacketPolicy.Rule.toFilter)
        (records.configuration.ip.forwardFallback iface) (context.Packet records.configuration) :=
  MultiProtocolExecution.local_address_projection_preserves_forward_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_INPUT (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.inputRules iface).map PacketPolicy.Rule.toFilter)
        (rawLocalConfiguration.ip.inputFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.inputRules iface).map PacketPolicy.Rule.toFilter)
        (records.configuration.ip.inputFallback iface) (context.Packet records.configuration) :=
  MultiProtocolExecution.local_address_projection_preserves_input_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_OUTPUT (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.outputRules iface).map PacketPolicy.Rule.toFilter)
        (rawLocalConfiguration.ip.outputFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.outputRules iface).map PacketPolicy.Rule.toFilter)
        (records.configuration.ip.outputFallback iface) (context.Packet records.configuration) :=
  MultiProtocolExecution.local_address_projection_preserves_output_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_encrypted_INPUT (state : MultiProtocolExecution.State) :
    PacketProcessing.InputAdmitted rawLocalConfiguration state ↔
      PacketProcessing.InputAdmitted records.configuration state :=
  MultiProtocolExecution.local_address_projection_preserves_input_admission records.configuration _ state

end TDN.Imported.GrayFirewallShared
