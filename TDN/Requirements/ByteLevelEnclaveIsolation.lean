import TDN.Models.PlaintextReassemblyPreservesEnclave
import TDN.Requirements.PacketEnclaveIsolation
import TDN.Models.ReassemblyBufferDomainSafety

namespace TDN.Requirements

def RedByteOrigin {Byte : Type} (c : DataPlaneForwarding.DataPlaneModel) (sources : List Nat)
    (state : DataPlaneForwarding.State) (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) : Prop :=
  RedPayloadOrigin c sources state ∧
  c.ifaceSecurityDomain state.iface = some byte.domain ∧ byte.packet = state.frame.payload

def ByteDomainInvariant {Byte : Type} (c : DataPlaneForwarding.DataPlaneModel) (domains : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (state : DataPlaneForwarding.State) : Prop :=
  byte.domain ∈ domains ∧ DataPlaneForwarding.DomainInvariant c (expectedEncapStack byte.domain) (allowed byte.domain) state

theorem all_packet_and_plaintext_assembly_histories_preserve_domains {Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (sources domains : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, DataPlaneForwarding.LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d,
      c.ifaceSecurityDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.ifaceSecurityDomain iface = some d →
      expectedEncapStack d iface = [] ∧ c.canOriginateTraffic iface ∧ allowed d iface)
    {after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action DataPlaneForwarding.Action)}
    (run : (ByteFlows.lts (DataPlaneForwarding.lts c) (RedByteOrigin c sources)
      DataPlaneForwarding.PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (ByteDomainInvariant c domains expectedEncapStack allowed) after := by
  refine ByteFlows.all_traces_preserve_byte_properties (DataPlaneForwarding.lts c)
    (RedByteOrigin c sources) DataPlaneForwarding.PlaintextAssembly
    (ByteDomainInvariant c domains expectedEncapStack allowed) ?_ ?_ ?_ run ?_
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
  · simp [ByteFlows.Safe]

theorem assembled_packet_delivery_preserves_each_byte_domain {Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (sources domains : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, DataPlaneForwarding.LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d,
      c.ifaceSecurityDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.ifaceSecurityDomain iface = some d →
      expectedEncapStack d iface = [] ∧ c.canOriginateTraffic iface ∧ allowed d iface)
    (recipientChecks : ∀ d ∈ domains, ∀ iface, allowed d iface →
      c.ifaceSecurityDomain iface = none ∨ c.ifaceSecurityDomain iface = some d)
    {after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action DataPlaneForwarding.Action)}
    (run : (ByteFlows.lts (DataPlaneForwarding.lts c) (RedByteOrigin c sources)
      DataPlaneForwarding.PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (delivered : packet.state.datapathStage = .delivered)
    (destinationDomain : Nat) (recipient : c.ifaceSecurityDomain packet.state.iface = some destinationDomain) :
    ∀ byte ∈ packet.bytes, byte.domain = destinationDomain := by
  have allSafe := all_packet_and_plaintext_assembly_histories_preserve_domains
    c sources domains expectedEncapStack allowed conditions sourceCoverage sourceChecks run
  intro byte contains
  obtain ⟨supported, safe⟩ := allSafe packet present byte contains
  simp only [DataPlaneForwarding.DomainInvariant, delivered] at safe
  have allowedIface : allowed byte.domain packet.state.iface := by
    simpa [safe.2] using safe.1.2
  rcases recipientChecks byte.domain supported packet.state.iface allowedIface with absent | same
  · simp [recipient] at absent
  · exact Option.some.inj (same.symm.trans recipient)

theorem assembled_packet_at_black_keeps_each_byte_protected {Byte : Type}
    (c : DataPlaneForwarding.DataPlaneModel) (sources domains blackIfaces : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (innerTag : Nat → Nat) (outerTag : Nat)
    (conditions : ∀ d ∈ domains, DataPlaneForwarding.LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d,
      c.ifaceSecurityDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.ifaceSecurityDomain iface = some d →
      expectedEncapStack d iface = [] ∧ c.canOriginateTraffic iface ∧ allowed d iface)
    (blackChecks : ∀ d ∈ domains, ∀ iface ∈ blackIfaces,
      expectedEncapStack d iface = [outerTag, innerTag d])
    {after : List (ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action DataPlaneForwarding.Action)}
    (run : (ByteFlows.lts (DataPlaneForwarding.lts c) (RedByteOrigin c sources)
      DataPlaneForwarding.PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier DataPlaneForwarding.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (ready : packet.state.datapathStage = .egressReady)
    (black : packet.state.iface ∈ blackIfaces) :
    ∀ byte ∈ packet.bytes, packet.state.frame.encapLayerIds = [outerTag, innerTag byte.domain] := by
  have allSafe := all_packet_and_plaintext_assembly_histories_preserve_domains
    c sources domains expectedEncapStack allowed conditions sourceCoverage sourceChecks run
  intro byte contains
  obtain ⟨supported, safe⟩ := allSafe packet present byte contains
  simp only [DataPlaneForwarding.DomainInvariant, ready] at safe
  exact safe.1.trans (blackChecks byte.domain supported packet.state.iface black)

end TDN.Requirements
