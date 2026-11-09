import TDN.Requirements.ByteLevelDoubleEncryptionOrder
import TDN.Deployments.SnapshotComponentByteResponses

namespace TDN.Deployments.ProfileShared_EnclaveIsolation
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma byte_outer_placement1 : ∀ iface,
    (domainLayout1 iface).head? = some 2 →
      domainLayout1 iface = [2, 11] := by
  have checked : ∀ record ∈ ({} : IfaceData) :: domainIfaces1,
      record.stack.head? = some 2 → record.stack = [2, 11] := by decide
  intro iface head
  exact checked (ifaceAt domainIfaces1 iface) (iface_at_member_or_default domainIfaces1 iface) head

lemma byte_outer_placement2 : ∀ iface,
    (domainLayout2 iface).head? = some 2 →
      domainLayout2 iface = [2, 12] := by
  have checked : ∀ record ∈ ({} : IfaceData) :: domainIfaces2,
      record.stack.head? = some 2 → record.stack = [2, 12] := by decide
  intro iface head
  exact checked (ifaceAt domainIfaces2 iface) (iface_at_member_or_default domainIfaces2 iface) head

lemma byte_outer_placement3 : ∀ iface,
    (domainLayout3 iface).head? = some 2 →
      domainLayout3 iface = [2, 13] := by
  have checked : ∀ record ∈ ({} : IfaceData) :: domainIfaces3,
      record.stack.head? = some 2 → record.stack = [2, 13] := by decide
  intro iface head
  exact checked (ifaceAt domainIfaces3 iface) (iface_at_member_or_default domainIfaces3 iface) head

lemma byte_outer_placement4 : ∀ iface,
    (domainLayout4 iface).head? = some 2 →
      domainLayout4 iface = [2, 14] := by
  have checked : ∀ record ∈ ({} : IfaceData) :: domainIfaces4,
      record.stack.head? = some 2 → record.stack = [2, 14] := by decide
  intro iface head
  exact checked (ifaceAt domainIfaces4 iface) (iface_at_member_or_default domainIfaces4 iface) head

lemma all_byte_outer_placement : ∀ d ∈ domains, ∀ iface,
    (byteLayout d iface).head? = some 2 → byteLayout d iface = [2, d + 10] := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl
  · exact byte_outer_placement1
  · exact byte_outer_placement2
  · exact byte_outer_placement3
  · exact byte_outer_placement4

theorem every_assembled_black_byte_has_inner_before_outer {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (packetPresent : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ TDN.Deployments.ProfileShared_DataPlane.blackIfaces)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (bytePresent : byte ∈ bytes) :
    ∃ start labels, Requirements.RedByteOrigin config redSources start byte ∧
      Requirements.BytePathOrderedEncryptions config TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners
        (byte.domain + 10) 2 (.network start) labels (.network finish) :=
  Requirements.every_black_byte_has_ordered_encryption_path config redSources domains
    TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners TDN.Deployments.ProfileShared_DataPlane.blackIfaces
    byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses (fun d => d + 10) 2
    all_byte_black_checks all_byte_outer_placement run finish bytes packetPresent ready black byte bytePresent

end TDN.Deployments.ProfileShared_EnclaveIsolation

namespace TDN.Deployments.ProfileBaseline_EnclaveIsolation
open DataPlaneForwarding
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma byte_outer_placement1 : ∀ iface,
    (domainLayout1 iface).head? = some 2 →
      domainLayout1 iface = [2, 11] := by
  have checked : ∀ record ∈ ({} : IfaceData) :: domainIfaces1,
      record.stack.head? = some 2 → record.stack = [2, 11] := by decide
  intro iface head
  exact checked (ifaceAt domainIfaces1 iface) (iface_at_member_or_default domainIfaces1 iface) head

lemma byte_outer_placement2 : ∀ iface,
    (domainLayout2 iface).head? = some 2 →
      domainLayout2 iface = [2, 12] := by
  have checked : ∀ record ∈ ({} : IfaceData) :: domainIfaces2,
      record.stack.head? = some 2 → record.stack = [2, 12] := by decide
  intro iface head
  exact checked (ifaceAt domainIfaces2 iface) (iface_at_member_or_default domainIfaces2 iface) head

lemma all_byte_outer_placement : ∀ d ∈ domains, ∀ iface,
    (byteLayout d iface).head? = some 2 → byteLayout d iface = [2, d + 10] := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl
  · exact byte_outer_placement1
  · exact byte_outer_placement2

theorem every_assembled_black_byte_has_inner_before_outer {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (packetPresent : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ TDN.Deployments.ProfileBaseline_DataPlane.blackIfaces)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (bytePresent : byte ∈ bytes) :
    ∃ start labels, Requirements.RedByteOrigin config redSources start byte ∧
      Requirements.BytePathOrderedEncryptions config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways uniformResponseOwners
        (byte.domain + 10) 2 (.network start) labels (.network finish) :=
  Requirements.every_black_byte_has_ordered_encryption_path config redSources domains
    TDN.Deployments.ProfileBaseline_DataPlane.responseGateways uniformResponseOwners TDN.Deployments.ProfileBaseline_DataPlane.blackIfaces
    byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses (fun d => d + 10) 2
    all_byte_black_checks all_byte_outer_placement run finish bytes packetPresent ready black byte bytePresent

end TDN.Deployments.ProfileBaseline_EnclaveIsolation

