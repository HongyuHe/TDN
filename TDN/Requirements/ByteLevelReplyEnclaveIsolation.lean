import TDN.Models.ByteFlowsWithKernelReplies
import TDN.Requirements.ByteLevelEnclaveIsolation
import TDN.Requirements.MscKernelReplyIsolation
import TDN.Models.SingleEnclaveDeviceReplies

namespace TDN.Requirements

theorem bytes_with_plaintext_assembly_and_gateway_responses_keep_domains {Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (sources domains gateways : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, DataPlaneForwarding.LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d,
      c.ifaceSecurityDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.ifaceSecurityDomain iface = some d →
      expectedEncapStack d iface = [] ∧ c.canOriginateTraffic iface ∧ allowed d iface)
    (guards : GatewayResponseGuards c gateways)
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (DataPlaneForwarding.lts c) (nativeKernelResponses c gateways)
      (RedByteOrigin c sources) DataPlaneForwarding.PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.Invariant (nativeKernelResponses c gateways)
      (ByteDomainInvariant c domains expectedEncapStack allowed byte)) after := by
  refine ResponseByteFlows.all_fragment_and_response_histories_preserve_bytes
    (DataPlaneForwarding.lts c) (nativeKernelResponses c gateways)
    (RedByteOrigin c sources) DataPlaneForwarding.PlaintextAssembly
    (ByteDomainInvariant c domains expectedEncapStack allowed) ?_ ?_ ?_ ?_ run
  · intro state byte origin
    have supported := sourceCoverage state.iface origin.1.1 byte.domain origin.2.1
    exact ⟨supported, red_origin_has_domain_invariant c (expectedEncapStack byte.domain) (allowed byte.domain)
      sources byte.domain (sourceChecks byte.domain supported) origin.1 origin.2.1⟩
  · intro byte before action after step safe
    exact ⟨safe.1, DataPlaneForwarding.step_preserves_domain_invariant
      (conditions byte.domain safe.1) step safe.2⟩
  · intro before after byte compatible safe
    exact ⟨safe.1, DataPlaneForwarding.plaintext_assembly_preserves_domain c
      (expectedEncapStack byte.domain) (allowed byte.domain) compatible safe.2⟩
  · intro state enabled iface
    exact guards state.iface enabled

theorem bytes_with_plaintext_assembly_and_component_responses_keep_domains {Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (sources domains gateways uniformOwners : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, DataPlaneForwarding.LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d,
      c.ifaceSecurityDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.ifaceSecurityDomain iface = some d →
      expectedEncapStack d iface = [] ∧ c.canOriginateTraffic iface ∧ allowed d iface)
    (guards : GatewayResponseGuards c gateways)
    (uniform : ∀ d ∈ domains, ∀ owner ∈ uniformOwners,
      UniformDomainResponses.Uniform c (expectedEncapStack d) (allowed d) owner)
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (DataPlaneForwarding.lts c) (UniformDomainResponses.responseConfig c gateways uniformOwners)
      (RedByteOrigin c sources) DataPlaneForwarding.PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.ProvenanceInvariant (UniformDomainResponses.responseConfig c gateways uniformOwners)
      (ByteDomainInvariant c domains expectedEncapStack allowed byte)) after := by
  refine ResponseByteFlows.all_fragment_and_permitted_response_histories_preserve_bytes
    (DataPlaneForwarding.lts c) (UniformDomainResponses.responseConfig c gateways uniformOwners)
    (RedByteOrigin c sources) DataPlaneForwarding.PlaintextAssembly
    (ByteDomainInvariant c domains expectedEncapStack allowed) ?_ ?_ ?_ ?_ run
  · intro state byte origin
    have supported := sourceCoverage state.iface origin.1.1 byte.domain origin.2.1
    exact ⟨supported, red_origin_has_domain_invariant c (expectedEncapStack byte.domain) (allowed byte.domain)
      sources byte.domain (sourceChecks byte.domain supported) origin.1 origin.2.1⟩
  · intro byte before action after step safe
    exact ⟨safe.1, DataPlaneForwarding.step_preserves_domain_invariant
      (conditions byte.domain safe.1) step safe.2⟩
  · intro before after byte compatible safe
    exact ⟨safe.1, DataPlaneForwarding.plaintext_assembly_preserves_domain c
      (expectedEncapStack byte.domain) (allowed byte.domain) compatible safe.2⟩
  · intro byte state header iface safe enabled protocol selected accepted external
    exact ⟨safe.1, UniformDomainResponses.reply_preserves_domain c (expectedEncapStack byte.domain)
      (allowed byte.domain) gateways uniformOwners (conditions byte.domain safe.1) guards
      (uniform byte.domain safe.1) state header iface safe.2 enabled protocol selected accepted external⟩

end TDN.Requirements
