import TDN.Semantics.ByteProtectionEvents
import TDN.Targets.ByteResponseDelivery

namespace TDN.Targets
open Execution

def BytePathOrderedEncryptions (c : Execution.Environment) (strict uniformOwners : List Nat)
    (innerTag outerTag : Nat) (before : KernelResponses.State Execution.State)
    (actions : List (Option (KernelResponses.Action Execution.Action)))
    (after : KernelResponses.State Execution.State) : Prop :=
  ∃ earlier later left action right,
    actions = earlier ++ action :: later ∧
    (ByteProtectionEvents.system c strict uniformOwners).MTr before earlier left ∧
    (ByteProtectionEvents.system c strict uniformOwners).Tr left action right ∧
    (ByteProtectionEvents.system c strict uniformOwners).MTr right later after ∧
    ByteProtectionEvents.EncryptionEvent c outerTag left action right ∧
    TraceEvents.Contains (ByteProtectionEvents.system c strict uniformOwners) before earlier left
      (ByteProtectionEvents.EncryptionEvent c innerTag)

theorem byte_path_nested_layers_require_ordered_encryptions
    (c : Execution.Environment) (expectedEncapStack : Nat → List Nat) (allowed : Nat → Prop)
    (strict uniformOwners : List Nat)
    (conditions : LocalDomainConditions c expectedEncapStack allowed)
    (guards : GatewayResponseGuards c strict)
    (uniform : ∀ owner ∈ uniformOwners, UniformDomainResponses.Uniform c expectedEncapStack allowed owner)
    (innerTag outerTag : Nat)
    (placement : ∀ iface, (expectedEncapStack iface).head? = some outerTag →
      expectedEncapStack iface = [outerTag, innerTag])
    {before after : KernelResponses.State Execution.State}
    {actions : List (Option (KernelResponses.Action Execution.Action))}
    (run : (ByteProtectionEvents.system c strict uniformOwners).MTr before actions after)
    (initial : KernelResponses.ProvenanceInvariant
      (UniformDomainResponses.responseConfig c strict uniformOwners)
      (DomainInvariant c expectedEncapStack allowed) before)
    (empty : ByteProtectionEvents.tags before = [])
    (present : outerTag ∈ ByteProtectionEvents.tags after) :
    BytePathOrderedEncryptions c strict uniformOwners innerTag outerTag before actions after := by
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, outerEvent⟩ :=
    ByteProtectionEvents.trace_tag_addition_has_encryption c strict uniformOwners outerTag run
      (by simp [empty]) present
  obtain ⟨encBefore, encAfter, rfl, rfl, label, operation, added⟩ := outerEvent
  have preservation := ByteProtectionEvents.domain_lineage_preservation
    c expectedEncapStack allowed strict uniformOwners conditions guards uniform
  have safe := Cslib.LTS.mtrInv_of_trInv preservation before _ (.network encAfter)
    (first.stepR (ByteProtectionEvents.system c strict uniformOwners) step) initial
  change DomainInvariant c expectedEncapStack allowed encAfter at safe
  have datapathStage : encAfter.datapathStage = .encapsulated := by cases operation; rfl
  simp only [DomainInvariant, datapathStage] at safe
  have head : (expectedEncapStack encAfter.iface).head? = some outerTag := by
    rw [← safe.1.1, added]
    rfl
  have inner : encBefore.frame.tags = [innerTag] :=
    (List.cons.inj (added.symm.trans (safe.1.1.trans (placement encAfter.iface head)))).2
  refine ⟨earlier, later, .network encBefore, action, .network encAfter,
    sequence, first, step, last, ⟨encBefore, encAfter, rfl, rfl, label, operation, added⟩, ?_⟩
  exact ByteProtectionEvents.trace_tag_addition_has_encryption c strict uniformOwners innerTag
    first (by simp [empty]) (by simp [ByteProtectionEvents.tags, inner])

theorem every_black_byte_has_ordered_encryption_path {Byte : Type}
    (c : Execution.Environment) (sources domains strict uniformOwners blackIfaces : List Nat)
    (expectedEncapStack : Nat → Nat → List Nat) (allowed : Nat → Nat → Prop)
    (conditions : ∀ d ∈ domains, LocalDomainConditions c (expectedEncapStack d) (allowed d))
    (sourceCoverage : ∀ iface ∈ sources, ∀ d, c.recipientDomain iface = some d → d ∈ domains)
    (sourceChecks : ∀ d ∈ domains, ∀ iface ∈ sources,
      c.recipientDomain iface = some d → expectedEncapStack d iface = [] ∧ c.payloadOrigin iface ∧ allowed d iface)
    (guards : GatewayResponseGuards c strict)
    (uniform : ∀ d ∈ domains, ∀ owner ∈ uniformOwners,
      UniformDomainResponses.Uniform c (expectedEncapStack d) (allowed d) owner)
    (innerTag : Nat → Nat) (outerTag : Nat)
    (blackChecks : ∀ d ∈ domains, ∀ iface ∈ blackIfaces, expectedEncapStack d iface = [outerTag, innerTag d])
    (placement : ∀ d ∈ domains, ∀ iface, (expectedEncapStack d iface).head? = some outerTag →
      expectedEncapStack d iface = [outerTag, innerTag d])
    {after : List (ByteFlows.Carrier (KernelResponses.State Execution.State)
      (ReassemblyOrigins.ByteOrigin Byte Nat Nat))}
    {actions : List (ByteFlows.Action (KernelResponses.Action Execution.Action))}
    (run : (ResponseByteFlows.system (Execution.lts c)
      (UniformDomainResponses.responseConfig c strict uniformOwners)
      (RedByteOrigin c sources) PlaintextAssembly).MTr [] actions after)
    (finish : Execution.State) (bytes : List (ReassemblyOrigins.ByteOrigin Byte Nat Nat))
    (packetPresent : ⟨.network finish, bytes⟩ ∈ after)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces)
    (byte : ReassemblyOrigins.ByteOrigin Byte Nat Nat) (bytePresent : byte ∈ bytes) :
    ∃ start labels, RedByteOrigin c sources start byte ∧
      BytePathOrderedEncryptions c strict uniformOwners (innerTag byte.domain) outerTag
        (.network start) labels (.network finish) := by
  have safe := bytes_with_plaintext_assembly_and_component_responses_keep_domains
    c sources domains strict uniformOwners expectedEncapStack allowed conditions sourceCoverage sourceChecks
    guards uniform run ⟨.network finish, bytes⟩ packetPresent byte bytePresent
  change ByteDomainInvariant c domains expectedEncapStack allowed byte finish at safe
  obtain ⟨supported, finalSafe⟩ := safe
  simp only [DomainInvariant, ready] at finalSafe
  have path := ByteLineage.every_byte_has_source_path
    (KernelResponses.lts (Execution.lts c)
      (UniformDomainResponses.responseConfig c strict uniformOwners))
    (ResponseByteFlows.source (RedByteOrigin c sources))
    (ResponseByteFlows.assembly PlaintextAssembly) run
      ⟨.network finish, bytes⟩ packetPresent byte bytePresent
  obtain ⟨start, labels, origin, history⟩ := path
  cases start <;> simp only [ResponseByteFlows.source] at origin <;> try contradiction
  rename_i start
  refine ⟨start, labels, origin, byte_path_nested_layers_require_ordered_encryptions
    c (expectedEncapStack byte.domain) (allowed byte.domain) strict uniformOwners
    (conditions byte.domain supported) guards (uniform byte.domain supported)
    (innerTag byte.domain) outerTag (placement byte.domain supported) history ?_ ?_ ?_⟩
  · exact red_origin_has_domain_invariant c (expectedEncapStack byte.domain) (allowed byte.domain)
      sources byte.domain (sourceChecks byte.domain supported) origin.1 origin.2.1
  · change start.frame.tags = []
    simp [Frame.tags, origin.1.2.2.2.1]
  · change outerTag ∈ finish.frame.tags
    rw [finalSafe.1, blackChecks byte.domain supported finish.iface black]
    simp

end TDN.Targets
