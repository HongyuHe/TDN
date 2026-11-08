import TDN.Semantics.KernelResponses

namespace TDN.KernelResponses

theorem strict_response_result_has_network_execution {S A : Type}
    (network : Cslib.LTS S A) (config : Config S)
    (checked : ∀ source, config.generates source → ∀ iface,
      config.outputFallback source iface = .deny ∧
      ∀ rule ∈ config.outputRules source iface,
        rule.verdict = .allow → SafeResponseRule rule)
    {before after : S} {actions : List (Action A)}
    (run : (lts network config).MTr (.network before) actions (.network after)) :
    ∃ networkActions, network.MTr before networkActions after := by
  let reachable := fun state => ∃ labels, network.MTr before labels state
  have preserved : network.TrInv reachable := by
    intro first label last step earlier
    obtain ⟨labels, trace⟩ := earlier
    exact ⟨labels ++ [label], Cslib.LTS.MTr.stepR network trace step⟩
  exact network_observations_remain_safe_with_kernel_responses network config reachable
    preserved checked run ⟨[], Cslib.LTS.MTr.refl⟩

end TDN.KernelResponses
