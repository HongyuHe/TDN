import TDN.Semantics.KernelResponses

namespace TDN.KernelResponses

theorem strict_response_result_has_network_execution {S A : Type}
    (network : Cslib.LTS S A) (config : Config S)
    (checked : ∀ source, config.generates source → ∀ port,
      config.outputFallback source port = .deny ∧
      ∀ rule ∈ config.outputRules source port,
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
