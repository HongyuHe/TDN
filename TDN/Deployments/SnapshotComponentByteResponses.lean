import TDN.Requirements.ByteLevelReplyEnclaveIsolation
import TDN.Deployments.SnapshotByteEnclaveIsolation
import TDN.Deployments.SnapshotDeviceResponseIsolation

namespace TDN.Deployments.ProfileShared_EnclaveIsolation
open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def uniformResponseOwners : List Nat :=
  (List.range TDN.Deployments.ProfileShared_DataPlane.devices.length).filter (fun owner => !(owner ∈ TDN.Deployments.ProfileShared_DataPlane.responseGateways))

lemma every_retained_owner_has_response_case :
    ∀ iface ∈ ({} : IfaceData) :: TDN.Deployments.ProfileShared_DataPlane.ifaces,
      iface.owner ∈ TDN.Deployments.ProfileShared_DataPlane.responseGateways ∨ iface.owner ∈ uniformResponseOwners := by
  native_decide
lemma every_active_component_can_generate (state : DataPlaneForwarding.State)
    (active : state.datapathStage ≠ .dropped) :
    (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileShared_DataPlane.responseGateways
      uniformResponseOwners).generates state := by
  exact ⟨active, every_retained_owner_has_response_case (ifaceAt TDN.Deployments.ProfileShared_DataPlane.ifaces state.iface)
    (iface_at_member_or_default TDN.Deployments.ProfileShared_DataPlane.ifaces state.iface)⟩

lemma uniform_domain_response_checks1 :
    UniformDomainResponses.TableDrivenUniform taggedDevices domainIfaces1
      (allowedRecord 1) uniformResponseOwners := by
  native_decide
lemma uniform_domain_responses1 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout1 domainAllowed1 owner := by
  intro owner member
  have checked := UniformDomainResponses.table_driven_uniform_sound taggedDevices domainIfaces1
    TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
    (allowedRecord 1) uniformResponseOwners uniform_domain_response_checks1 owner member
  rw [config_same1] at checked
  exact checked

lemma uniform_domain_response_checks2 :
    UniformDomainResponses.TableDrivenUniform taggedDevices domainIfaces2
      (allowedRecord 2) uniformResponseOwners := by
  native_decide
lemma uniform_domain_responses2 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout2 domainAllowed2 owner := by
  intro owner member
  have checked := UniformDomainResponses.table_driven_uniform_sound taggedDevices domainIfaces2
    TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
    (allowedRecord 2) uniformResponseOwners uniform_domain_response_checks2 owner member
  rw [config_same2] at checked
  exact checked

lemma uniform_domain_response_checks3 :
    UniformDomainResponses.TableDrivenUniform taggedDevices domainIfaces3
      (allowedRecord 3) uniformResponseOwners := by
  native_decide
lemma uniform_domain_responses3 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout3 domainAllowed3 owner := by
  intro owner member
  have checked := UniformDomainResponses.table_driven_uniform_sound taggedDevices domainIfaces3
    TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
    (allowedRecord 3) uniformResponseOwners uniform_domain_response_checks3 owner member
  rw [config_same3] at checked
  exact checked

lemma uniform_domain_response_checks4 :
    UniformDomainResponses.TableDrivenUniform taggedDevices domainIfaces4
      (allowedRecord 4) uniformResponseOwners := by
  native_decide
lemma uniform_domain_responses4 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout4 domainAllowed4 owner := by
  intro owner member
  have checked := UniformDomainResponses.table_driven_uniform_sound taggedDevices domainIfaces4
    TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
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
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.ProvenanceInvariant
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte)) after :=
  Requirements.bytes_with_plaintext_assembly_and_component_responses_keep_domains
    config redSources domains TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners byteLayout byteAllowed
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses run

theorem assembled_component_response_delivery_keeps_full_labels {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (delivered : finish.datapathStage = .delivered)
    (destinationDomain : Nat) (recipient : config.ifaceSecurityDomain finish.iface = some destinationDomain) :
    ∀ byte ∈ bytes, fullLevel byte.domain = fullLevel destinationDomain := by
  intro byte member
  have preserved := all_assembled_component_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, delivered] at safe
  have permitted : byteAllowed byte.domain finish.iface := by simpa [safe.2] using safe.1.2
  rcases all_byte_recipient_checks byte.domain supported finish.iface permitted with absent | same
  · simp [recipient] at absent
  · exact congrArg fullLevel (Option.some.inj (same.symm.trans recipient))

theorem assembled_component_response_black_bytes_keep_both_layers {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileShared_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ TDN.Deployments.ProfileShared_DataPlane.blackIfaces) :
    ∀ byte ∈ bytes, finish.frame.encapLayerIds = [2, byte.domain + 10] := by
  intro byte member
  have preserved := all_assembled_component_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, ready] at safe
  exact safe.1.trans (all_byte_black_checks byte.domain supported finish.iface black)

end TDN.Deployments.ProfileShared_EnclaveIsolation

namespace TDN.Deployments.ProfileBaseline_EnclaveIsolation
open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def uniformResponseOwners : List Nat :=
  (List.range TDN.Deployments.ProfileBaseline_DataPlane.devices.length).filter (fun owner => !(owner ∈ TDN.Deployments.ProfileBaseline_DataPlane.responseGateways))

lemma every_retained_owner_has_response_case :
    ∀ iface ∈ ({} : IfaceData) :: TDN.Deployments.ProfileBaseline_DataPlane.ifaces,
      iface.owner ∈ TDN.Deployments.ProfileBaseline_DataPlane.responseGateways ∨ iface.owner ∈ uniformResponseOwners := by
  native_decide
lemma every_active_component_can_generate (state : DataPlaneForwarding.State)
    (active : state.datapathStage ≠ .dropped) :
    (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways
      uniformResponseOwners).generates state := by
  exact ⟨active, every_retained_owner_has_response_case (ifaceAt TDN.Deployments.ProfileBaseline_DataPlane.ifaces state.iface)
    (iface_at_member_or_default TDN.Deployments.ProfileBaseline_DataPlane.ifaces state.iface)⟩

lemma uniform_domain_response_checks1 :
    UniformDomainResponses.TableDrivenUniform taggedDevices domainIfaces1
      (allowedRecord 1) uniformResponseOwners := by
  native_decide
lemma uniform_domain_responses1 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout1 domainAllowed1 owner := by
  intro owner member
  have checked := UniformDomainResponses.table_driven_uniform_sound taggedDevices domainIfaces1
    TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches
    (allowedRecord 1) uniformResponseOwners uniform_domain_response_checks1 owner member
  rw [config_same1] at checked
  exact checked

lemma uniform_domain_response_checks2 :
    UniformDomainResponses.TableDrivenUniform taggedDevices domainIfaces2
      (allowedRecord 2) uniformResponseOwners := by
  native_decide
lemma uniform_domain_responses2 : ∀ owner ∈ uniformResponseOwners,
    UniformDomainResponses.Uniform config domainLayout2 domainAllowed2 owner := by
  intro owner member
  have checked := UniformDomainResponses.table_driven_uniform_sound taggedDevices domainIfaces2
    TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches
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
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (fun byte => KernelResponses.ProvenanceInvariant
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte)) after :=
  Requirements.bytes_with_plaintext_assembly_and_component_responses_keep_domains
    config redSources domains TDN.Deployments.ProfileBaseline_DataPlane.responseGateways uniformResponseOwners byteLayout byteAllowed
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    tagged_gateway_response_guards all_uniform_domain_responses run

theorem assembled_component_response_delivery_keeps_full_labels {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (delivered : finish.datapathStage = .delivered)
    (destinationDomain : Nat) (recipient : config.ifaceSecurityDomain finish.iface = some destinationDomain) :
    ∀ byte ∈ bytes, fullLevel byte.domain = fullLevel destinationDomain := by
  intro byte member
  have preserved := all_assembled_component_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, delivered] at safe
  have permitted : byteAllowed byte.domain finish.iface := by simpa [safe.2] using safe.1.2
  rcases all_byte_recipient_checks byte.domain supported finish.iface permitted with absent | same
  · simp [recipient] at absent
  · exact congrArg fullLevel (Option.some.inj (same.symm.trans recipient))

theorem assembled_component_response_black_bytes_keep_both_layers {Byte : Type}
    {after : List (ByteFlows.Carrier (KernelResponses.State DataPlaneForwarding.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action DataPlaneForwarding.Action))}
    (run : (ResponseByteFlows.system (lts config)
      (UniformDomainResponses.responseConfig config TDN.Deployments.ProfileBaseline_DataPlane.responseGateways uniformResponseOwners)
      (Requirements.RedByteOrigin config redSources) PlaintextAssembly).MTr [] actions after)
    (finish : DataPlaneForwarding.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.datapathStage = .egressReady) (black : finish.iface ∈ TDN.Deployments.ProfileBaseline_DataPlane.blackIfaces) :
    ∀ byte ∈ bytes, finish.frame.encapLayerIds = [2, byte.domain + 10] := by
  intro byte member
  have preserved := all_assembled_component_response_bytes_keep_domains run
    ⟨.network finish, bytes⟩ present byte member
  change Requirements.ByteDomainInvariant config domains byteLayout byteAllowed byte finish at preserved
  obtain ⟨supported, safe⟩ := preserved
  simp only [DomainInvariant, ready] at safe
  exact safe.1.trans (all_byte_black_checks byte.domain supported finish.iface black)

end TDN.Deployments.ProfileBaseline_EnclaveIsolation
