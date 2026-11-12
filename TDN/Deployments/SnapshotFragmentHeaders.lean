import TDN.Models.NonInitialFragmentFilterLemmas
import TDN.Deployments.ProfileShared_EnclaveIsolation
import TDN.Deployments.ProfileBaseline_EnclaveIsolation

namespace TDN.Deployments.ProfileShared_EnclaveIsolation
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma device_all_hooks_only_allow : ∀ device ∈ ({} : DeviceData) :: taggedDevices,
    ∀ rules ∈ [device.inputRules, device.forwardRules, device.outputRules],
      ∀ rule ∈ rules, rule.verdict = .allow := by
  native_decide
theorem noninitial_input_accepted_by_header_completion (iface : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.inputRules iface).map FragmentHeaders.rule)
      (config.inputFallback iface) packet = .allow) :
    accepts (config.inputRules iface) (config.inputFallback iface) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.inputRules iface) ?_ (config.inputFallback iface) packet accepted
  exact device_all_hooks_only_allow (deviceAt taggedDevices (ifaceAt TDN.Deployments.ProfileShared_DataPlane.ifaces iface).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, dataPlaneModelFromRecords])

theorem noninitial_forward_accepted_by_header_completion (iface : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.forwardRules iface).map FragmentHeaders.rule)
      (config.forwardFallback iface) packet = .allow) :
    accepts (config.forwardRules iface) (config.forwardFallback iface) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.forwardRules iface) ?_ (config.forwardFallback iface) packet accepted
  exact device_all_hooks_only_allow (deviceAt taggedDevices (ifaceAt TDN.Deployments.ProfileShared_DataPlane.ifaces iface).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, dataPlaneModelFromRecords])

theorem noninitial_output_accepted_by_header_completion (iface : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.outputRules iface).map FragmentHeaders.rule)
      (config.outputFallback iface) packet = .allow) :
    accepts (config.outputRules iface) (config.outputFallback iface) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.outputRules iface) ?_ (config.outputFallback iface) packet accepted
  exact device_all_hooks_only_allow (deviceAt taggedDevices (ifaceAt TDN.Deployments.ProfileShared_DataPlane.ifaces iface).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, dataPlaneModelFromRecords])

end TDN.Deployments.ProfileShared_EnclaveIsolation

namespace TDN.Deployments.ProfileBaseline_EnclaveIsolation
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma device_all_hooks_only_allow : ∀ device ∈ ({} : DeviceData) :: taggedDevices,
    ∀ rules ∈ [device.inputRules, device.forwardRules, device.outputRules],
      ∀ rule ∈ rules, rule.verdict = .allow := by
  native_decide
theorem noninitial_input_accepted_by_header_completion (iface : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.inputRules iface).map FragmentHeaders.rule)
      (config.inputFallback iface) packet = .allow) :
    accepts (config.inputRules iface) (config.inputFallback iface) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.inputRules iface) ?_ (config.inputFallback iface) packet accepted
  exact device_all_hooks_only_allow (deviceAt taggedDevices (ifaceAt TDN.Deployments.ProfileBaseline_DataPlane.ifaces iface).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, dataPlaneModelFromRecords])

theorem noninitial_forward_accepted_by_header_completion (iface : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.forwardRules iface).map FragmentHeaders.rule)
      (config.forwardFallback iface) packet = .allow) :
    accepts (config.forwardRules iface) (config.forwardFallback iface) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.forwardRules iface) ?_ (config.forwardFallback iface) packet accepted
  exact device_all_hooks_only_allow (deviceAt taggedDevices (ifaceAt TDN.Deployments.ProfileBaseline_DataPlane.ifaces iface).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, dataPlaneModelFromRecords])

theorem noninitial_output_accepted_by_header_completion (iface : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.outputRules iface).map FragmentHeaders.rule)
      (config.outputFallback iface) packet = .allow) :
    accepts (config.outputRules iface) (config.outputFallback iface) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.outputRules iface) ?_ (config.outputFallback iface) packet accepted
  exact device_all_hooks_only_allow (deviceAt taggedDevices (ifaceAt TDN.Deployments.ProfileBaseline_DataPlane.ifaces iface).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, dataPlaneModelFromRecords])

end TDN.Deployments.ProfileBaseline_EnclaveIsolation

