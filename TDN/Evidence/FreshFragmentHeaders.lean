import TDN.Semantics.FragmentHeaders
import TDN.Evidence.FreshSharedIsolation
import TDN.Evidence.FreshBaselineIsolation

namespace TDN.Imported.FreshSharedIsolation
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma native_all_hooks_only_allow : ∀ device ∈ ({} : DeviceData) :: taggedDevices,
    ∀ rules ∈ [device.inputRules, device.forwardRules, device.outputRules],
      ∀ rule ∈ rules, rule.verdict = .allow := by
  decide

theorem noninitial_input_accepted_by_header_completion (port : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.inputRules port).map FragmentHeaders.rule)
      (config.inputFallback port) packet = .allow) :
    accepts (config.inputRules port) (config.inputFallback port) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.inputRules port) ?_ (config.inputFallback port) packet accepted
  exact native_all_hooks_only_allow (deviceAt taggedDevices (portAt TDN.Imported.FreshSharedExecution.ports port).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, finiteConfig])

theorem noninitial_forward_accepted_by_header_completion (port : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.forwardRules port).map FragmentHeaders.rule)
      (config.forwardFallback port) packet = .allow) :
    accepts (config.forwardRules port) (config.forwardFallback port) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.forwardRules port) ?_ (config.forwardFallback port) packet accepted
  exact native_all_hooks_only_allow (deviceAt taggedDevices (portAt TDN.Imported.FreshSharedExecution.ports port).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, finiteConfig])

theorem noninitial_output_accepted_by_header_completion (port : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.outputRules port).map FragmentHeaders.rule)
      (config.outputFallback port) packet = .allow) :
    accepts (config.outputRules port) (config.outputFallback port) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.outputRules port) ?_ (config.outputFallback port) packet accepted
  exact native_all_hooks_only_allow (deviceAt taggedDevices (portAt TDN.Imported.FreshSharedExecution.ports port).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, finiteConfig])

end TDN.Imported.FreshSharedIsolation

namespace TDN.Imported.FreshBaselineIsolation
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma native_all_hooks_only_allow : ∀ device ∈ ({} : DeviceData) :: taggedDevices,
    ∀ rules ∈ [device.inputRules, device.forwardRules, device.outputRules],
      ∀ rule ∈ rules, rule.verdict = .allow := by
  decide

theorem noninitial_input_accepted_by_header_completion (port : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.inputRules port).map FragmentHeaders.rule)
      (config.inputFallback port) packet = .allow) :
    accepts (config.inputRules port) (config.inputFallback port) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.inputRules port) ?_ (config.inputFallback port) packet accepted
  exact native_all_hooks_only_allow (deviceAt taggedDevices (portAt TDN.Imported.FreshBaselineExecution.ports port).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, finiteConfig])

theorem noninitial_forward_accepted_by_header_completion (port : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.forwardRules port).map FragmentHeaders.rule)
      (config.forwardFallback port) packet = .allow) :
    accepts (config.forwardRules port) (config.forwardFallback port) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.forwardRules port) ?_ (config.forwardFallback port) packet accepted
  exact native_all_hooks_only_allow (deviceAt taggedDevices (portAt TDN.Imported.FreshBaselineExecution.ports port).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, finiteConfig])

theorem noninitial_output_accepted_by_header_completion (port : Nat)
    (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((config.outputRules port).map FragmentHeaders.rule)
      (config.outputFallback port) packet = .allow) :
    accepts (config.outputRules port) (config.outputFallback port) packet := by
  apply FragmentHeaders.allow_only_rules_cover_noninitial_fragments
    (config.outputRules port) ?_ (config.outputFallback port) packet accepted
  exact native_all_hooks_only_allow (deviceAt taggedDevices (portAt TDN.Imported.FreshBaselineExecution.ports port).owner)
    (device_at_member_or_default taggedDevices _) _ (by simp [config, finiteConfig])

end TDN.Imported.FreshBaselineIsolation

