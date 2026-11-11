import TDN.Requirements.IPsecForwardRuleGuards

namespace TDN.Requirements.Msc
open MultiProtocolForwarding PacketPolicy

def ForwardChainRequiresIPsecAcross (config : Config) (iface : Nat) (outside : String) : Prop :=
  config.ip.forwardFallback iface = .deny ∧ ∀ rule ∈ config.ip.forwardRules iface,
    rule.verdict = .allow → ∃ inside, inside ≠ outside ∧ RequiresIpsecPolicyMatch rule inside outside

lemma accepted_forward_across_has_policy_evidence (config : Config) (state : MultiProtocolForwarding.State)
    (header : Packet) (outside : String) (checks : ForwardChainRequiresIPsecAcross config state.iface outside)
    (accepted : DataPlaneForwarding.accepts (config.ip.forwardRules state.iface)
      (config.ip.forwardFallback state.iface) (policyHeader config state header)) :
    ∃ inside, inside ≠ outside ∧ ProtectedForward inside outside (policyHeader config state header) := by
  rw [checks.1] at accepted
  apply Filter.default_deny_sound ((config.ip.forwardRules state.iface).map Rule.toFilter)
    (fun packet => ∃ inside, inside ≠ outside ∧ ProtectedForward inside outside packet) ?_
    (policyHeader config state header) accepted
  intro rule member allow packet matched
  obtain ⟨source, stored, rfl⟩ := List.mem_map.mp member
  obtain ⟨inside, different, guarded⟩ := checks.2 source stored allow
  exact ⟨inside, different, guarded_rule_protects guarded matched⟩

lemma unauthenticated_external_ingress_across_cannot_forward (config : Config)
    (state : MultiProtocolForwarding.State) (header : Packet) (outside : String)
    (checks : ForwardChainRequiresIPsecAcross config state.iface outside)
    (ingress : config.ip.interfaceName state.enteredIface = outside) (unauthenticated : state.authenticated = []) :
    ¬ DataPlaneForwarding.accepts (config.ip.forwardRules state.iface)
      (config.ip.forwardFallback state.iface) (policyHeader config state header) := by
  intro accepted
  obtain ⟨inside, different, evidence⟩ := accepted_forward_across_has_policy_evidence config state header outside checks accepted
  rcases evidence with ⟨entered, _, _⟩ | ⟨_, _, request, installed⟩
  · exact different (entered.symm.trans ingress)
  · simpa only [policyHeader, unauthenticated, List.not_mem_nil] using installed

lemma accepted_external_output_across_requires_policy (config : Config)
    (state : MultiProtocolForwarding.State) (header : Packet) (outside : String)
    (checks : ForwardChainRequiresIPsecAcross config state.iface outside)
    (egress : config.ip.interfaceName state.iface = outside)
    (accepted : DataPlaneForwarding.accepts (config.ip.forwardRules state.iface)
      (config.ip.forwardFallback state.iface) (policyHeader config state header)) :
    DataPlaneForwarding.lookupSpdPolicies (config.ip.egressPolicies state.iface) header ≠ [] := by
  obtain ⟨inside, different, evidence⟩ := accepted_forward_across_has_policy_evidence config state header outside checks accepted
  rcases evidence with ⟨_, _, request, selected⟩ | ⟨_, entered, _⟩
  · intro empty
    simpa only [policyHeader, empty, List.map_nil, List.not_mem_nil] using selected
  · exact False.elim (different (entered.symm.trans egress))

end TDN.Requirements.Msc
