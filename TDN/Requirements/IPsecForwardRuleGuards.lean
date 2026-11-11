import TDN.Models.MultiProtocolForwarding

namespace TDN.Requirements.Msc
open MultiProtocolForwarding PacketPolicy

def ForwardChainRequiresIPsec (config : Config) (iface : Nat) (inside outside : String) : Prop :=
  config.ip.forwardFallback iface = .deny ∧
    ∀ rule ∈ config.ip.forwardRules iface, rule.verdict = .allow → RequiresIpsecPolicyMatch rule inside outside

lemma accepted_forward_has_policy_evidence (config : Config) (state : MultiProtocolForwarding.State)
    (header : Packet) (inside outside : String)
    (checks : ForwardChainRequiresIPsec config state.iface inside outside)
    (accepted : DataPlaneForwarding.accepts (config.ip.forwardRules state.iface)
      (config.ip.forwardFallback state.iface) (policyHeader config state header)) :
    ProtectedForward inside outside (policyHeader config state header) := by
  rw [checks.1] at accepted
  exact forwarding_policy_protects _ _ _ checks.2 _ accepted

lemma unauthenticated_external_ingress_cannot_forward (config : Config)
    (state : MultiProtocolForwarding.State) (header : Packet) (inside outside : String)
    (different : inside ≠ outside)
    (checks : ForwardChainRequiresIPsec config state.iface inside outside)
    (ingress : config.ip.interfaceName state.enteredIface = outside)
    (unauthenticated : state.authenticated = []) :
    ¬ DataPlaneForwarding.accepts (config.ip.forwardRules state.iface)
      (config.ip.forwardFallback state.iface) (policyHeader config state header) := by
  intro accepted
  have evidence := accepted_forward_has_policy_evidence config state header inside outside checks accepted
  rcases evidence with ⟨entered, _, _⟩ | ⟨_, _, request, installed⟩
  · exact different (entered.symm.trans ingress)
  · simpa only [policyHeader, unauthenticated, List.not_mem_nil] using installed

lemma accepted_external_output_requires_policy (config : Config)
    (state : MultiProtocolForwarding.State) (header : Packet) (inside outside : String)
    (different : inside ≠ outside)
    (checks : ForwardChainRequiresIPsec config state.iface inside outside)
    (egress : config.ip.interfaceName state.iface = outside)
    (accepted : DataPlaneForwarding.accepts (config.ip.forwardRules state.iface)
      (config.ip.forwardFallback state.iface) (policyHeader config state header)) :
    DataPlaneForwarding.lookupSpdPolicies (config.ip.egressPolicies state.iface) header ≠ [] := by
  have evidence := accepted_forward_has_policy_evidence config state header inside outside checks accepted
  rcases evidence with ⟨_, _, request, selected⟩ | ⟨_, entered, _⟩
  · intro empty
    simpa only [policyHeader, empty, List.map_nil, List.not_mem_nil] using selected
  · exact False.elim (different (entered.symm.trans egress))

end TDN.Requirements.Msc
