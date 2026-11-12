import TDN.Requirements.ByteLevelEnclaveIsolation
import TDN.Deployments.ProfileShared_EnclaveIsolation
import TDN.Deployments.ProfileBaseline_EnclaveIsolation

namespace TDN.Deployments.ProfileShared_EnclaveIsolation
open DataPlaneForwarding

def byteLayout : Nat → Nat → List Nat
  | 1 => domainLayout1
  | 2 => domainLayout2
  | 3 => domainLayout3
  | 4 => domainLayout4
  | _ => domainLayout1

def byteAllowed : Nat → Nat → Prop
  | 1 => domainAllowed1
  | 2 => domainAllowed2
  | 3 => domainAllowed3
  | 4 => domainAllowed4
  | _ => domainAllowed1

lemma all_byte_domain_conditions : ∀ d ∈ domains,
    LocalDomainConditions config (byteLayout d) (byteAllowed d) := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl
  · exact local_domain_conditions1
  · exact local_domain_conditions2
  · exact local_domain_conditions3
  · exact local_domain_conditions4

lemma all_byte_source_checks : ∀ d ∈ domains, ∀ iface ∈ redSources,
    config.ifaceSecurityDomain iface = some d →
    byteLayout d iface = [] ∧ config.canOriginateTraffic iface ∧ byteAllowed d iface := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl
  · exact source_checks1
  · exact source_checks2
  · exact source_checks3
  · exact source_checks4

lemma all_byte_recipient_checks : ∀ d ∈ domains, ∀ iface, byteAllowed d iface →
    config.ifaceSecurityDomain iface = none ∨ config.ifaceSecurityDomain iface = some d := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl
  · exact recipient_checks1
  · exact recipient_checks2
  · exact recipient_checks3
  · exact recipient_checks4

lemma all_byte_source_domains : ∀ iface ∈ redSources, ∀ d,
    config.ifaceSecurityDomain iface = some d → d ∈ domains := by
  intro iface member d assigned
  have present := source_domains_checked iface member
  rw [assigned] at present
  simpa using present

theorem every_assembled_delivered_byte_preserves_full_label {Byte : Type}
    {after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action DataPlaneForwarding.Action)}
    (run : (ByteFlows.lts (lts config) (Requirements.RedByteOrigin config redSources)
      PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (delivered : packet.state.datapathStage = .delivered)
    (destinationDomain : Nat) (recipient : config.ifaceSecurityDomain packet.state.iface = some destinationDomain) :
    ∀ byte ∈ packet.bytes, fullLevel byte.domain = fullLevel destinationDomain := by
  have checked := Requirements.assembled_packet_delivery_preserves_each_byte_domain
    config redSources domains byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains
    all_byte_source_checks all_byte_recipient_checks run packet present delivered destinationDomain recipient
  exact fun byte member => congrArg fullLevel (checked byte member)

lemma all_byte_black_checks : ∀ d ∈ domains, ∀ iface ∈ TDN.Deployments.ProfileShared_DataPlane.blackIfaces,
    byteLayout d iface = [2, d + 10] := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl
  · simp only [TDN.Deployments.ProfileShared_DataPlane.blackIfaces, List.mem_cons, List.not_mem_nil,
      or_false, forall_eq, or_imp, forall_and]
    all_goals native_decide
  · simp only [TDN.Deployments.ProfileShared_DataPlane.blackIfaces, List.mem_cons, List.not_mem_nil,
      or_false, forall_eq, or_imp, forall_and]
    all_goals native_decide
  · simp only [TDN.Deployments.ProfileShared_DataPlane.blackIfaces, List.mem_cons, List.not_mem_nil,
      or_false, forall_eq, or_imp, forall_and]
    all_goals native_decide
  · simp only [TDN.Deployments.ProfileShared_DataPlane.blackIfaces, List.mem_cons, List.not_mem_nil,
      or_false, forall_eq, or_imp, forall_and]
    all_goals native_decide

theorem every_assembled_black_byte_has_both_layers {Byte : Type}
    {after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action DataPlaneForwarding.Action)}
    (run : (ByteFlows.lts (lts config) (Requirements.RedByteOrigin config redSources)
      PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (ready : packet.state.datapathStage = .egressReady)
    (black : packet.state.iface ∈ TDN.Deployments.ProfileShared_DataPlane.blackIfaces) :
    ∀ byte ∈ packet.bytes, packet.state.frame.encapLayerIds = [2, byte.domain + 10] :=
  Requirements.assembled_packet_at_black_keeps_each_byte_protected config redSources domains
    TDN.Deployments.ProfileShared_DataPlane.blackIfaces byteLayout byteAllowed (fun d => d + 10) 2
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    all_byte_black_checks run packet present ready black

end TDN.Deployments.ProfileShared_EnclaveIsolation

namespace TDN.Deployments.ProfileBaseline_EnclaveIsolation
open DataPlaneForwarding

def byteLayout : Nat → Nat → List Nat
  | 1 => domainLayout1
  | 2 => domainLayout2
  | _ => domainLayout1

def byteAllowed : Nat → Nat → Prop
  | 1 => domainAllowed1
  | 2 => domainAllowed2
  | _ => domainAllowed1

lemma all_byte_domain_conditions : ∀ d ∈ domains,
    LocalDomainConditions config (byteLayout d) (byteAllowed d) := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl
  · exact local_domain_conditions1
  · exact local_domain_conditions2

lemma all_byte_source_checks : ∀ d ∈ domains, ∀ iface ∈ redSources,
    config.ifaceSecurityDomain iface = some d →
    byteLayout d iface = [] ∧ config.canOriginateTraffic iface ∧ byteAllowed d iface := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl
  · exact source_checks1
  · exact source_checks2

lemma all_byte_recipient_checks : ∀ d ∈ domains, ∀ iface, byteAllowed d iface →
    config.ifaceSecurityDomain iface = none ∨ config.ifaceSecurityDomain iface = some d := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl
  · exact recipient_checks1
  · exact recipient_checks2

lemma all_byte_source_domains : ∀ iface ∈ redSources, ∀ d,
    config.ifaceSecurityDomain iface = some d → d ∈ domains := by
  intro iface member d assigned
  have present := source_domains_checked iface member
  rw [assigned] at present
  simpa using present

theorem every_assembled_delivered_byte_preserves_full_label {Byte : Type}
    {after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action DataPlaneForwarding.Action)}
    (run : (ByteFlows.lts (lts config) (Requirements.RedByteOrigin config redSources)
      PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (delivered : packet.state.datapathStage = .delivered)
    (destinationDomain : Nat) (recipient : config.ifaceSecurityDomain packet.state.iface = some destinationDomain) :
    ∀ byte ∈ packet.bytes, fullLevel byte.domain = fullLevel destinationDomain := by
  have checked := Requirements.assembled_packet_delivery_preserves_each_byte_domain
    config redSources domains byteLayout byteAllowed all_byte_domain_conditions all_byte_source_domains
    all_byte_source_checks all_byte_recipient_checks run packet present delivered destinationDomain recipient
  exact fun byte member => congrArg fullLevel (checked byte member)

lemma all_byte_black_checks : ∀ d ∈ domains, ∀ iface ∈ TDN.Deployments.ProfileBaseline_DataPlane.blackIfaces,
    byteLayout d iface = [2, d + 10] := by
  intro d member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl
  · simp only [TDN.Deployments.ProfileBaseline_DataPlane.blackIfaces, List.mem_cons, List.not_mem_nil,
      or_false, forall_eq, or_imp, forall_and]
    all_goals native_decide
  · simp only [TDN.Deployments.ProfileBaseline_DataPlane.blackIfaces, List.mem_cons, List.not_mem_nil,
      or_false, forall_eq, or_imp, forall_and]
    all_goals native_decide

theorem every_assembled_black_byte_has_both_layers {Byte : Type}
    {after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action DataPlaneForwarding.Action)}
    (run : (ByteFlows.lts (lts config) (Requirements.RedByteOrigin config redSources)
      PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (ready : packet.state.datapathStage = .egressReady)
    (black : packet.state.iface ∈ TDN.Deployments.ProfileBaseline_DataPlane.blackIfaces) :
    ∀ byte ∈ packet.bytes, packet.state.frame.encapLayerIds = [2, byte.domain + 10] :=
  Requirements.assembled_packet_at_black_keeps_each_byte_protected config redSources domains
    TDN.Deployments.ProfileBaseline_DataPlane.blackIfaces byteLayout byteAllowed (fun d => d + 10) 2
    all_byte_domain_conditions all_byte_source_domains all_byte_source_checks
    all_byte_black_checks run packet present ready black

end TDN.Deployments.ProfileBaseline_EnclaveIsolation

