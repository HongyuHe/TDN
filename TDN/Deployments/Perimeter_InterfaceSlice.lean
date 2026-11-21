import TDN.Deployments.Perimeter_BaselineData
import TDN.Deployments.Perimeter_SharedData
import TDN.Models.SwapLocalAddressBindings

namespace TDN.Deployments.Perimeter_Baseline
open Compliance
set_option maxRecDepth 1000000

load_network_records rawInterfaces : List Interface from "../../data/evidence/continuation/BoundaryProjectionBaseline.json" ["rawInterfaces"]

lemma every_raw_interface_identifier_is_preserved :
    rawInterfaces.map Interface.id = records.interfaces.map Interface.id := by
  native_decide

lemma every_gray_and_black_interface_is_preserved :
    rawInterfaces.filter (fun interface => interface.zone == .gray || interface.zone == .black) =
      records.interfaces.filter (fun interface => interface.zone == .gray || interface.zone == .black) := by
  native_decide

lemma every_attached_red_interface_is_preserved :
    rawInterfaces.filter (fun interface => interface.zone == .red && interface.physical) =
      records.interfaces.filter (fun interface => interface.zone == .red && interface.physical) := by
  native_decide

def rawLocalConfiguration : MultiProtocolForwarding.TunnelForwardingModel :=
  records.configuration.withLocalAddresses (fun iface address =>
    ∃ interface ∈ rawInterfaces,
      interface.device = records.componentName (records.configuration.ip.owner iface) ∧
        interface.address = some address)

theorem raw_local_addresses_preserve_all_hook_packets (context : PacketProcessing.Context) :
    context.Packet rawLocalConfiguration = context.Packet records.configuration :=
  MultiProtocolForwarding.local_address_projection_preserves_policy_packet records.configuration _ context

theorem raw_local_addresses_preserve_forward (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.forwardRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (rawLocalConfiguration.ip.forwardFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.forwardRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (records.configuration.ip.forwardFallback iface) (context.Packet records.configuration) :=
  MultiProtocolForwarding.local_address_projection_preserves_forward_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_input (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.inputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (rawLocalConfiguration.ip.inputFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.inputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (records.configuration.ip.inputFallback iface) (context.Packet records.configuration) :=
  MultiProtocolForwarding.local_address_projection_preserves_input_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_output (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.outputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (rawLocalConfiguration.ip.outputFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.outputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (records.configuration.ip.outputFallback iface) (context.Packet records.configuration) :=
  MultiProtocolForwarding.local_address_projection_preserves_output_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_encrypted_input (state : MultiProtocolForwarding.TunnelForwardingState) :
    PacketProcessing.InputAdmitted rawLocalConfiguration state ↔
      PacketProcessing.InputAdmitted records.configuration state :=
  MultiProtocolForwarding.local_address_projection_preserves_input_admission records.configuration _ state

end TDN.Deployments.Perimeter_Baseline

namespace TDN.Deployments.Perimeter_Shared
open Compliance
set_option maxRecDepth 1000000

load_network_records rawInterfaces : List Interface from "../../data/evidence/continuation/BoundaryProjectionShared.json" ["rawInterfaces"]

lemma every_raw_interface_identifier_is_preserved :
    rawInterfaces.map Interface.id = records.interfaces.map Interface.id := by
  native_decide

lemma every_gray_and_black_interface_is_preserved :
    rawInterfaces.filter (fun interface => interface.zone == .gray || interface.zone == .black) =
      records.interfaces.filter (fun interface => interface.zone == .gray || interface.zone == .black) := by
  native_decide

lemma every_attached_red_interface_is_preserved :
    rawInterfaces.filter (fun interface => interface.zone == .red && interface.physical) =
      records.interfaces.filter (fun interface => interface.zone == .red && interface.physical) := by
  native_decide

def rawLocalConfiguration : MultiProtocolForwarding.TunnelForwardingModel :=
  records.configuration.withLocalAddresses (fun iface address =>
    ∃ interface ∈ rawInterfaces,
      interface.device = records.componentName (records.configuration.ip.owner iface) ∧
        interface.address = some address)

theorem raw_local_addresses_preserve_all_hook_packets (context : PacketProcessing.Context) :
    context.Packet rawLocalConfiguration = context.Packet records.configuration :=
  MultiProtocolForwarding.local_address_projection_preserves_policy_packet records.configuration _ context

theorem raw_local_addresses_preserve_forward (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.forwardRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (rawLocalConfiguration.ip.forwardFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.forwardRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (records.configuration.ip.forwardFallback iface) (context.Packet records.configuration) :=
  MultiProtocolForwarding.local_address_projection_preserves_forward_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_input (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.inputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (rawLocalConfiguration.ip.inputFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.inputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (records.configuration.ip.inputFallback iface) (context.Packet records.configuration) :=
  MultiProtocolForwarding.local_address_projection_preserves_input_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_output (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate ((rawLocalConfiguration.ip.outputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (rawLocalConfiguration.ip.outputFallback iface) (context.Packet rawLocalConfiguration) =
      Filter.evaluate ((records.configuration.ip.outputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (records.configuration.ip.outputFallback iface) (context.Packet records.configuration) :=
  MultiProtocolForwarding.local_address_projection_preserves_output_decision records.configuration _ context iface

theorem raw_local_addresses_preserve_encrypted_input (state : MultiProtocolForwarding.TunnelForwardingState) :
    PacketProcessing.InputAdmitted rawLocalConfiguration state ↔
      PacketProcessing.InputAdmitted records.configuration state :=
  MultiProtocolForwarding.local_address_projection_preserves_input_admission records.configuration _ state

end TDN.Deployments.Perimeter_Shared
