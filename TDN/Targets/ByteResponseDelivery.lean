import TDN.Semantics.ResponseByteFlows
import TDN.Targets.ByteDomainDelivery
import TDN.Targets.KernelResponses
import TDN.Semantics.UniformDomainResponses

namespace TDN.Targets

theorem bytes_with_plaintext_assembly_and_gateway_responses_keep_domains {Byte : Type}
    (c : Execution.Config) (sources domains gateways : List Nat)
    (layout : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, Execution.LocalDomainConditions c (layout d) (allowed d))
    (sourceCoverage : ∀ port ∈ sources, ∀ d,
      c.recipientDomain port = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ port ∈ sources,
      c.recipientDomain port = some d →
      layout d port = [] ∧ c.payloadOrigin port ∧ allowed d port)
    (guards : GatewayResponseGuards c gateways)
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (Execution.lts c) (nativeKernelResponses c gateways)
      (RedByteOrigin c sources) Execution.PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.Invariant (nativeKernelResponses c gateways)
      (ByteDomainInvariant c domains layout allowed byte)) after := by
  refine ResponseByteFlows.all_fragment_and_response_histories_preserve_bytes
    (Execution.lts c) (nativeKernelResponses c gateways)
    (RedByteOrigin c sources) Execution.PlaintextAssembly
    (ByteDomainInvariant c domains layout allowed) ?_ ?_ ?_ ?_ run
  · intro state byte origin
    have supported := sourceCoverage state.port origin.1.1 byte.domain origin.2.1
    exact ⟨supported, red_origin_has_domain_invariant c (layout byte.domain) (allowed byte.domain)
      sources byte.domain (sourceChecks byte.domain supported) origin.1 origin.2.1⟩
  · intro byte before action after step safe
    exact ⟨safe.1, Execution.step_preserves_domain_invariant
      (conditions byte.domain safe.1) step safe.2⟩
  · intro before after byte compatible safe
    exact ⟨safe.1, Execution.plaintext_assembly_preserves_domain c
      (layout byte.domain) (allowed byte.domain) compatible safe.2⟩
  · intro state enabled port
    exact guards state.port enabled

theorem bytes_with_plaintext_assembly_and_component_responses_keep_domains {Byte : Type}
    (c : Execution.Config) (sources domains gateways uniformOwners : List Nat)
    (layout : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, Execution.LocalDomainConditions c (layout d) (allowed d))
    (sourceCoverage : ∀ port ∈ sources, ∀ d,
      c.recipientDomain port = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ port ∈ sources,
      c.recipientDomain port = some d →
      layout d port = [] ∧ c.payloadOrigin port ∧ allowed d port)
    (guards : GatewayResponseGuards c gateways)
    (uniform : ∀ d ∈ domains, ∀ owner ∈ uniformOwners,
      UniformDomainResponses.Uniform c (layout d) (allowed d) owner)
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (Execution.lts c) (UniformDomainResponses.responseConfig c gateways uniformOwners)
      (RedByteOrigin c sources) Execution.PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.ProvenanceInvariant (UniformDomainResponses.responseConfig c gateways uniformOwners)
      (ByteDomainInvariant c domains layout allowed byte)) after := by
  refine ResponseByteFlows.all_fragment_and_permitted_response_histories_preserve_bytes
    (Execution.lts c) (UniformDomainResponses.responseConfig c gateways uniformOwners)
    (RedByteOrigin c sources) Execution.PlaintextAssembly
    (ByteDomainInvariant c domains layout allowed) ?_ ?_ ?_ ?_ run
  · intro state byte origin
    have supported := sourceCoverage state.port origin.1.1 byte.domain origin.2.1
    exact ⟨supported, red_origin_has_domain_invariant c (layout byte.domain) (allowed byte.domain)
      sources byte.domain (sourceChecks byte.domain supported) origin.1 origin.2.1⟩
  · intro byte before action after step safe
    exact ⟨safe.1, Execution.step_preserves_domain_invariant
      (conditions byte.domain safe.1) step safe.2⟩
  · intro before after byte compatible safe
    exact ⟨safe.1, Execution.plaintext_assembly_preserves_domain c
      (layout byte.domain) (allowed byte.domain) compatible safe.2⟩
  · intro byte state header port safe enabled protocol selected accepted external
    exact ⟨safe.1, UniformDomainResponses.reply_preserves_domain c (layout byte.domain)
      (allowed byte.domain) gateways uniformOwners (conditions byte.domain safe.1) guards
      (uniform byte.domain safe.1) state header port safe.2 enabled protocol selected accepted external⟩

end TDN.Targets
