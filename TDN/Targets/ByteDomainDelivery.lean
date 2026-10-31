import TDN.Semantics.PlaintextAssembly
import TDN.Targets.DeliveryIsolation
import TDN.Semantics.ReassemblyOrigins

namespace TDN.Targets

/-- Source annotations are assigned at the actual Red interface, independently
of claimed IP source addresses. They follow copied or partitioned source bytes. -/
def RedByteOrigin {Byte : Type} (c : Execution.Config) (sources : List Nat)
    (state : Execution.State) (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) : Prop :=
  RedPayloadOrigin c sources state ∧
  c.recipientDomain state.port = some byte.domain ∧ byte.packet = state.frame.payload

def ByteDomainInvariant {Byte : Type} (c : Execution.Config) (domains : List Nat)
    (layout : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (state : Execution.State) : Prop :=
  byte.domain ∈ domains ∧ Execution.DomainInvariant c (layout byte.domain) (allowed byte.domain) state

/-- Per-domain route, filter, association and source checks cover any number of
simultaneous packets. Plaintext reassembly may mix different original packets at
any receiving interface and may change headers before further forwarding.
The model does not use equal packet IDs or domain labels as an assembly guard. -/
theorem all_packet_and_plaintext_assembly_histories_preserve_domains {Byte : Type}
    (c : Execution.Config) (sources domains : List Nat)
    (layout : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, Execution.LocalDomainConditions c (layout d) (allowed d))
    (sourceCoverage : ∀ port ∈ sources, ∀ d,
      c.recipientDomain port = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ port ∈ sources,
      c.recipientDomain port = some d →
      layout d port = [] ∧ c.payloadOrigin port ∧ allowed d port)
    {after : List (ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action Execution.Action)}
    (run : (ByteFlows.lts (Execution.lts c) (RedByteOrigin c sources)
      Execution.PlaintextAssembly).MTr [] actions after) :
    ByteFlows.Safe (ByteDomainInvariant c domains layout allowed) after := by
  refine ByteFlows.all_executions_preserve_byte_properties (Execution.lts c)
    (RedByteOrigin c sources) Execution.PlaintextAssembly
    (ByteDomainInvariant c domains layout allowed) ?_ ?_ ?_ run ?_
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
  · simp [ByteFlows.Safe]

/-- The recipient's full security domain matches every delivered source byte,
including bytes assembled from multiple original packets. Local recipient checks
derive the conclusion; assembly does not assume it. -/
theorem assembled_packet_delivery_preserves_each_byte_domain {Byte : Type}
    (c : Execution.Config) (sources domains : List Nat)
    (layout : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, Execution.LocalDomainConditions c (layout d) (allowed d))
    (sourceCoverage : ∀ port ∈ sources, ∀ d,
      c.recipientDomain port = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ port ∈ sources,
      c.recipientDomain port = some d →
      layout d port = [] ∧ c.payloadOrigin port ∧ allowed d port)
    (recipientChecks : ∀ d ∈ domains, ∀ port, allowed d port →
      c.recipientDomain port = none ∨ c.recipientDomain port = some d)
    {after : List (ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action Execution.Action)}
    (run : (ByteFlows.lts (Execution.lts c) (RedByteOrigin c sources)
      Execution.PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (delivered : packet.state.phase = .delivered)
    (recipientDomain : Nat) (recipient : c.recipientDomain packet.state.port = some recipientDomain) :
    ∀ byte ∈ packet.bytes, byte.domain = recipientDomain := by
  have allSafe := all_packet_and_plaintext_assembly_histories_preserve_domains
    c sources domains layout allowed conditions sourceCoverage sourceChecks run
  intro byte contains
  obtain ⟨supported, safe⟩ := allSafe packet present byte contains
  simp only [Execution.DomainInvariant, delivered] at safe
  have allowedPort : allowed byte.domain packet.state.port := by
    simpa [safe.2] using safe.1.2
  rcases recipientChecks byte.domain supported packet.state.port allowedPort with absent | same
  · simp [recipient] at absent
  · exact Option.some.inj (same.symm.trans recipient)


/-- Every Black transmission keeps the required two-layer stack for each source
byte, even after earlier plaintext assemblies mixed source packet identities. -/
theorem assembled_packet_at_black_keeps_each_byte_protected {Byte : Type}
    (c : Execution.Config) (sources domains blackPorts : List Nat)
    (layout : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (innerTag : Nat → Nat) (outerTag : Nat)
    (conditions : ∀ d ∈ domains, Execution.LocalDomainConditions c (layout d) (allowed d))
    (sourceCoverage : ∀ port ∈ sources, ∀ d,
      c.recipientDomain port = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ port ∈ sources,
      c.recipientDomain port = some d →
      layout d port = [] ∧ c.payloadOrigin port ∧ allowed d port)
    (blackChecks : ∀ d ∈ domains, ∀ port ∈ blackPorts,
      layout d port = [outerTag, innerTag d])
    {after : List (ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action Execution.Action)}
    (run : (ByteFlows.lts (Execution.lts c) (RedByteOrigin c sources)
      Execution.PlaintextAssembly).MTr [] actions after)
    (packet : ByteFlows.Carrier Execution.State (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (present : packet ∈ after) (ready : packet.state.phase = .ready)
    (black : packet.state.port ∈ blackPorts) :
    ∀ byte ∈ packet.bytes, packet.state.frame.tags = [outerTag, innerTag byte.domain] := by
  have allSafe := all_packet_and_plaintext_assembly_histories_preserve_domains
    c sources domains layout allowed conditions sourceCoverage sourceChecks run
  intro byte contains
  obtain ⟨supported, safe⟩ := allSafe packet present byte contains
  simp only [Execution.DomainInvariant, ready] at safe
  exact safe.1.trans (blackChecks byte.domain supported packet.state.port black)

end TDN.Targets
