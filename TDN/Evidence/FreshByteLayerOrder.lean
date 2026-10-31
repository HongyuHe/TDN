import TDN.Targets.ByteLayerOrder
import TDN.Evidence.FreshComponentByteResponses

namespace TDN.Imported.FreshSharedIsolation
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma byte_outer_placement1 : ∀ port,
    (domainLayout1 port).head? = some 2 →
      domainLayout1 port = [2, 11] := by
  have checked : ∀ record ∈ ({} : PortData) :: domainPorts1,
      record.stack.head? = some 2 → record.stack = [2, 11] := by decide
  intro port head
  exact checked (portAt domainPorts1 port) (port_at_member_or_default domainPorts1 port) head

lemma byte_outer_placement2 : ∀ port,
    (domainLayout2 port).head? = some 2 →
      domainLayout2 port = [2, 12] := by
  have checked : ∀ record ∈ ({} : PortData) :: domainPorts2,
      record.stack.head? = some 2 → record.stack = [2, 12] := by decide
  intro port head
  exact checked (portAt domainPorts2 port) (port_at_member_or_default domainPorts2 port) head

lemma byte_outer_placement3 : ∀ port,
    (domainLayout3 port).head? = some 2 →
      domainLayout3 port = [2, 13] := by
  have checked : ∀ record ∈ ({} : PortData) :: domainPorts3,
      record.stack.head? = some 2 → record.stack = [2, 13] := by decide
  intro port head
  exact checked (portAt domainPorts3 port) (port_at_member_or_default domainPorts3 port) head

lemma byte_outer_placement4 : ∀ port,
    (domainLayout4 port).head? = some 2 →
      domainLayout4 port = [2, 14] := by
  have checked : ∀ record ∈ ({} : PortData) :: domainPorts4,
      record.stack.head? = some 2 → record.stack = [2, 14] := by decide
  intro port head
  exact checked (portAt domainPorts4 port) (port_at_member_or_default domainPorts4 port) head

lemma all_byte_outer_placement : ∀ d ∈ domains, ∀ port,
    (byteLayout d port).head? = some 2 → byteLayout d port = [2, d + 10] := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl
  · exact byte_outer_placement1
  · exact byte_outer_placement2
  · exact byte_outer_placement3
  · exact byte_outer_placement4

theorem every_assembled_black_byte_has_inner_before_outer {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (packetPresent : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.phase = .ready) (black : finish.port ∈ TDN.Imported.FreshSharedExecution.blackPorts)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (bytePresent : byte ∈ bytes) :
    ∃ start labels, Targets.RedByteOrigin config redSources start byte ∧
      Targets.BytePathOrderedEncryptions config TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners
        (byte.domain + 10) 2 (.network start) labels (.network finish) :=
  Targets.every_black_byte_has_ordered_encryption_path config redSources domains
    TDN.Imported.FreshSharedExecution.responseGateways uniformResponseOwners TDN.Imported.FreshSharedExecution.blackPorts
    byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses (fun d => d + 10) 2
    all_byte_black_checks all_byte_outer_placement run finish bytes packetPresent ready black byte bytePresent

end TDN.Imported.FreshSharedIsolation

namespace TDN.Imported.FreshBaselineIsolation
open Execution
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma byte_outer_placement1 : ∀ port,
    (domainLayout1 port).head? = some 2 →
      domainLayout1 port = [2, 11] := by
  have checked : ∀ record ∈ ({} : PortData) :: domainPorts1,
      record.stack.head? = some 2 → record.stack = [2, 11] := by decide
  intro port head
  exact checked (portAt domainPorts1 port) (port_at_member_or_default domainPorts1 port) head

lemma byte_outer_placement2 : ∀ port,
    (domainLayout2 port).head? = some 2 →
      domainLayout2 port = [2, 12] := by
  have checked : ∀ record ∈ ({} : PortData) :: domainPorts2,
      record.stack.head? = some 2 → record.stack = [2, 12] := by decide
  intro port head
  exact checked (portAt domainPorts2 port) (port_at_member_or_default domainPorts2 port) head

lemma all_byte_outer_placement : ∀ d ∈ domains, ∀ port,
    (byteLayout d port).head? = some 2 → byteLayout d port = [2, d + 10] := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl
  · exact byte_outer_placement1
  · exact byte_outer_placement2

theorem every_assembled_black_byte_has_inner_before_outer {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Imported.FreshBaselineExecution.responseGateways uniformResponseOwners)
      (Targets.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (packetPresent : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.phase = .ready) (black : finish.port ∈ TDN.Imported.FreshBaselineExecution.blackPorts)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (bytePresent : byte ∈ bytes) :
    ∃ start labels, Targets.RedByteOrigin config redSources start byte ∧
      Targets.BytePathOrderedEncryptions config TDN.Imported.FreshBaselineExecution.responseGateways uniformResponseOwners
        (byte.domain + 10) 2 (.network start) labels (.network finish) :=
  Targets.every_black_byte_has_ordered_encryption_path config redSources domains
    TDN.Imported.FreshBaselineExecution.responseGateways uniformResponseOwners TDN.Imported.FreshBaselineExecution.blackPorts
    byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses (fun d => d + 10) 2
    all_byte_black_checks all_byte_outer_placement run finish bytes packetPresent ready black byte bytePresent

end TDN.Imported.FreshBaselineIsolation

