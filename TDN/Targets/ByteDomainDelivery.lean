import TDN.Semantics.PlaintextAssembly
import TDN.Targets.DeliveryIsolation
import TDN.Semantics.ReassemblyOrigins

namespace TDN.Targets

def RedByteOrigin {Byte : Type} (c : Execution.Environment) (sources : List Nat)
    (state : Execution.State) (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) : Prop :=
  RedPayloadOrigin c sources state ∧
  c.recipientDomain state.iface = some byte.domain ∧ byte.packet = state.frame.payload

def ByteDomainInvariant {Byte : Type} (c : Execution.Environment) (domains : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (state : Execution.State) : Prop :=
  byte.domain ∈ domains ∧ Execution.DomainInvariant c (expectedEncapStack byte.domain) (allowed byte.domain) state

theorem all_packet_and_plaintext_assembly_histories_preserve_domains {Byte : Type}
    (c : Execution.Environment) (sources domains : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, Execution.LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d,
      c.recipientDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.recipientDomain iface = some d →
      expectedEncapStack d iface = [] ∧ c.payloadOrigin iface ∧ allowed d iface)
    {after : List (ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action Execution.Action)}
    (run : (ByteFlows.lts (Execution.lts c) (RedByteOrigin c sources)
      Execution.PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (ByteDomainInvariant c domains expectedEncapStack allowed) after := by
  refine ByteFlows.all_executions_preserve_byte_properties (Execution.lts c)
    (RedByteOrigin c sources) Execution.PlaintextAssembly
    (ByteDomainInvariant c domains expectedEncapStack allowed) ?_ ?_ ?_ run ?_
  · intro state byte origin
    have supported := sourceCoverage state.iface origin.1.1 byte.domain origin.2.1
    exact ⟨supported, red_origin_has_domain_invariant c (expectedEncapStack byte.domain) (allowed byte.domain)
      sources byte.domain (sourceChecks byte.domain supported) origin.1 origin.2.1⟩
  · intro byte before action after step safe
    exact ⟨safe.1, Execution.step_preserves_domain_invariant
      (conditions byte.domain safe.1) step safe.2⟩
  · intro before after byte compatible safe
    exact ⟨safe.1, Execution.plaintext_assembly_preserves_domain c
      (expectedEncapStack byte.domain) (allowed byte.domain) compatible safe.2⟩
  · simp [ByteFlows.Safe]

theorem assembled_packet_delivery_preserves_each_byte_domain {Byte : Type}
    (c : Execution.Environment) (sources domains : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, Execution.LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d,
      c.recipientDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.recipientDomain iface = some d →
      expectedEncapStack d iface = [] ∧ c.payloadOrigin iface ∧ allowed d iface)
    (recipientChecks : ∀ d ∈ domains, ∀ iface, allowed d iface →
      c.recipientDomain iface = none ∨ c.recipientDomain iface = some d)
    {after : List (ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action Execution.Action)}
    (run : (ByteFlows.lts (Execution.lts c) (RedByteOrigin c sources)
      Execution.PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (delivered : packet.state.datapathStage = .delivered)
    (recipientDomain : Nat) (recipient : c.recipientDomain packet.state.iface = some recipientDomain) :
    ∀ byte ∈ packet.bytes, byte.domain = recipientDomain := by
  have allSafe := all_packet_and_plaintext_assembly_histories_preserve_domains
    c sources domains expectedEncapStack allowed conditions sourceCoverage sourceChecks run
  intro byte contains
  obtain ⟨supported, safe⟩ := allSafe packet present byte contains
  simp only [Execution.DomainInvariant, delivered] at safe
  have allowedIface : allowed byte.domain packet.state.iface := by
    simpa [safe.2] using safe.1.2
  rcases recipientChecks byte.domain supported packet.state.iface allowedIface with absent | same
  · simp [recipient] at absent
  · exact Option.some.inj (same.symm.trans recipient)

theorem assembled_packet_at_black_keeps_each_byte_protected {Byte : Type}
    (c : Execution.Environment) (sources domains blackIfaces : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (innerTag : Nat → Nat) (outerTag : Nat)
    (conditions : ∀ d ∈ domains, Execution.LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d,
      c.recipientDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.recipientDomain iface = some d →
      expectedEncapStack d iface = [] ∧ c.payloadOrigin iface ∧ allowed d iface)
    (blackChecks : ∀ d ∈ domains, ∀ iface ∈ blackIfaces,
      expectedEncapStack d iface = [outerTag, innerTag d])
    {after : List (ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action Execution.Action)}
    (run : (ByteFlows.lts (Execution.lts c) (RedByteOrigin c sources)
      Execution.PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (ready : packet.state.datapathStage = .ready)
    (black : packet.state.iface ∈ blackIfaces) :
    ∀ byte ∈ packet.bytes, packet.state.frame.tags = [outerTag, innerTag byte.domain] := by
  have allSafe := all_packet_and_plaintext_assembly_histories_preserve_domains
    c sources domains expectedEncapStack allowed conditions sourceCoverage sourceChecks run
  intro byte contains
  obtain ⟨supported, safe⟩ := allSafe packet present byte contains
  simp only [Execution.DomainInvariant, ready] at safe
  exact safe.1.trans (blackChecks byte.domain supported packet.state.iface black)

end TDN.Targets
