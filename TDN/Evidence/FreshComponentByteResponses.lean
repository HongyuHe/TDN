import TDN.Targets.ByteResponseDelivery
import TDN.Evidence.FreshByteDomains
import TDN.Evidence.FreshNativeResponseIsolation

namespace TDN.Imported.FreshSharedIsolation
open Execution

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def uniformResponseOwners : List Nat :=
  (List.range TDN.Imported.FreshSharedExecution.devices.length).filter (fun owner => !(owner ∈ TDN.Imported.FreshSharedExecution.responseGateways))

lemma every_retained_owner_has_response_case :
    ∀ port ∈ ({} : PortData) :: TDN.Imported.FreshSharedExecution.ports,
      port.owner ∈ TDN.Imported.FreshSharedExecution.responseGateways ∨ port.owner ∈ uniformResponseOwners := by
  decide

lemma every_active_component_can_generate (state : Execution.State)
    (active : state.phase ≠ .dropped) :
    (UniformDomainResponses.responseConfig config TDN.Imported.FreshSharedExecution.responseGateways
      uniformResponseOwners).generates state := by
  exact ⟨active, every_retained_owner_has_response_case (portAt TDN.Imported.FreshSharedExecution.ports state.port)
    (port_at_member_or_default TDN.Imported.FreshSharedExecution.ports state.port)⟩

lemma uniform_domain_response_checks1 :
    UniformDomainResponses.FiniteUniform taggedDevices domainPorts1
      (allowedRecord 1) uniformResponseOwners := by
  decide

lemma uniform_domain_responses1 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout1 domainAllowed1 owner := by
  intro owner member
  have checked := UniformDomainResponses.finite_uniform_sound taggedDevices domainPorts1
    TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
    (allowedRecord 1) uniformResponseOwners uniform_domain_response_checks1 owner member
  rw [config_same1] at checked
  exact checked

lemma uniform_domain_response_checks2 :
    UniformDomainResponses.FiniteUniform taggedDevices domainPorts2
      (allowedRecord 2) uniformResponseOwners := by
  decide

lemma uniform_domain_responses2 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout2 domainAllowed2 owner := by
  intro owner member
  have checked := UniformDomainResponses.finite_uniform_sound taggedDevices domainPorts2
    TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
    (allowedRecord 2) uniformResponseOwners uniform_domain_response_checks2 owner member
  rw [config_same2] at checked
  exact checked

lemma uniform_domain_response_checks3 :
    UniformDomainResponses.FiniteUniform taggedDevices domainPorts3
      (allowedRecord 3) uniformResponseOwners := by
  decide

lemma uniform_domain_responses3 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout3 domainAllowed3 owner := by
  intro owner member
  have checked := UniformDomainResponses.finite_uniform_sound taggedDevices domainPorts3
    TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
    (allowedRecord 3) uniformResponseOwners uniform_domain_response_checks3 owner member
  rw [config_same3] at checked
  exact checked

lemma uniform_domain_response_checks4 :
    UniformDomainResponses.FiniteUniform taggedDevices domainPorts4
      (allowedRecord 4) uniformResponseOwners := by
  decide

lemma uniform_domain_responses4 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout4 domainAllowed4 owner := by
  intro owner member
  have checked := UniformDomainResponses.finite_uniform_sound taggedDevices domainPorts4
    TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
    (allowedRecord 4) uniformResponseOwners uniform_domain_response_checks4 owner member
  rw [config_same4] at checked
  exact checked

lemma all_uniform_domain_responses : ∀ d ∈ domains, ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config (byteLayout d) (byteAllowed d) owner := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl
  · exact uniform_domain_responses1
  · exact uniform_domain_responses2
  · exact uniform_domain_responses3
  · exact uniform_domain_responses4

theorem all_assembled_component_response_bytes_keep_domains {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.ProvenanceInvariant
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners)
      (Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte)) after :=
  Targets.bytes_with_plaintext_assembly_and_component_responses_keep_domains
    config redSources domains TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners byteLayout byteAllowed
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses run

theorem assembled_component_response_delivery_keeps_full_labels {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (delivered : finish.phase = .delivered)
    (recipientDomain : Nat) (recipient : config.recipientDomain finish.port = some recipientDomain) :
    ∀ byte ∈ bytes, fullLevel byte.domain = fullLevel recipientDomain := by
  intro byte member
  have preserved := all_assembled_component_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, delivered] at safe
  have permitted : byteAllowed byte.domain finish.port := by simpa [safe.2] using safe.1.2
  rcases all_byte_recipient_checks byte.domain supported finish.port permitted with absent | same
  · simp [recipient] at absent
  · exact congrArg fullLevel (Option.some.inj (same.symm.trans recipient))

theorem assembled_component_response_black_bytes_keep_both_layers {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.phase = .ready) (black : finish.port ∈ TDN.Imported.FreshSharedExecution.blackPorts) :
    ∀ byte ∈ bytes, finish.frame.tags = [2, byte.domain + 10] := by
  intro byte member
  have preserved := all_assembled_component_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, ready] at safe
  exact safe.1.trans (all_byte_black_checks byte.domain supported finish.port black)

end TDN.Imported.FreshSharedIsolation

namespace TDN.Imported.FreshBaselineIsolation
open Execution

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def uniformResponseOwners : List Nat :=
  (List.range TDN.Imported.FreshBaselineExecution.devices.length).filter (fun owner => !(owner ∈ TDN.Imported.FreshBaselineExecution.responseGateways))

lemma every_retained_owner_has_response_case :
    ∀ port ∈ ({} : PortData) :: TDN.Imported.FreshBaselineExecution.ports,
      port.owner ∈ TDN.Imported.FreshBaselineExecution.responseGateways ∨ port.owner ∈ uniformResponseOwners := by
  decide

lemma every_active_component_can_generate (state : Execution.State)
    (active : state.phase ≠ .dropped) :
    (UniformDomainResponses.responseConfig config TDN.Imported.FreshBaselineExecution.responseGateways
      uniformResponseOwners).generates state := by
  exact ⟨active, every_retained_owner_has_response_case (portAt TDN.Imported.FreshBaselineExecution.ports state.port)
    (port_at_member_or_default TDN.Imported.FreshBaselineExecution.ports state.port)⟩

lemma uniform_domain_response_checks1 :
    UniformDomainResponses.FiniteUniform taggedDevices domainPorts1
      (allowedRecord 1) uniformResponseOwners := by
  decide

lemma uniform_domain_responses1 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout1 domainAllowed1 owner := by
  intro owner member
  have checked := UniformDomainResponses.finite_uniform_sound taggedDevices domainPorts1
    TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches
    (allowedRecord 1) uniformResponseOwners uniform_domain_response_checks1 owner member
  rw [config_same1] at checked
  exact checked

lemma uniform_domain_response_checks2 :
    UniformDomainResponses.FiniteUniform taggedDevices domainPorts2
      (allowedRecord 2) uniformResponseOwners := by
  decide

lemma uniform_domain_responses2 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout2 domainAllowed2 owner := by
  intro owner member
  have checked := UniformDomainResponses.finite_uniform_sound taggedDevices domainPorts2
    TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches
    (allowedRecord 2) uniformResponseOwners uniform_domain_response_checks2 owner member
  rw [config_same2] at checked
  exact checked

lemma all_uniform_domain_responses : ∀ d ∈ domains, ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config (byteLayout d) (byteAllowed d) owner := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl
  · exact uniform_domain_responses1
  · exact uniform_domain_responses2

theorem all_assembled_component_response_bytes_keep_domains {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshBaselineExecution.responseGateways uniformResponseOwners)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.ProvenanceInvariant
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshBaselineExecution.responseGateways uniformResponseOwners)
      (Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte)) after :=
  Targets.bytes_with_plaintext_assembly_and_component_responses_keep_domains
    config redSources domains TDN.Imported.FreshBaselineExecution.responseGateways uniformResponseOwners byteLayout byteAllowed
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses run

theorem assembled_component_response_delivery_keeps_full_labels {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshBaselineExecution.responseGateways uniformResponseOwners)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (delivered : finish.phase = .delivered)
    (recipientDomain : Nat) (recipient : config.recipientDomain finish.port = some recipientDomain) :
    ∀ byte ∈ bytes, fullLevel byte.domain = fullLevel recipientDomain := by
  intro byte member
  have preserved := all_assembled_component_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, delivered] at safe
  have permitted : byteAllowed byte.domain finish.port := by simpa [safe.2] using safe.1.2
  rcases all_byte_recipient_checks byte.domain supported finish.port permitted with absent | same
  · simp [recipient] at absent
  · exact congrArg fullLevel (Option.some.inj (same.symm.trans recipient))

theorem assembled_component_response_black_bytes_keep_both_layers {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshBaselineExecution.responseGateways uniformResponseOwners)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.phase = .ready) (black : finish.port ∈ TDN.Imported.FreshBaselineExecution.blackPorts) :
    ∀ byte ∈ bytes, finish.frame.tags = [2, byte.domain + 10] := by
  intro byte member
  have preserved := all_assembled_component_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Targets.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, ready] at safe
  exact safe.1.trans (all_byte_black_checks byte.domain supported finish.port black)

end TDN.Imported.FreshBaselineIsolation

