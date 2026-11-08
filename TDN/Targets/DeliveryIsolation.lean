import TDN.Targets.PacketExecution
import TDN.Semantics.FiniteDomains

namespace TDN.Targets

def msc_same_domain_plaintext_delivery (env : Execution.Environment)
    (redSourceIfaces : List Nat) : Prop :=
  ∀ initialState finalState actions sourceDomain destinationDomain,
    RedPayloadOrigin env redSourceIfaces initialState →
    env.recipientDomain initialState.iface = some sourceDomain →
    (Execution.lts env).MTr initialState actions finalState → finalState.datapathStage = .delivered →
    env.recipientDomain finalState.iface = some destinationDomain → sourceDomain = destinationDomain

lemma red_origin_has_domain_invariant (c : Execution.Environment) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) (sources : List Nat) (domain : Nat)
    (sourceCheck : ∀ iface ∈ sources, c.recipientDomain iface = some domain →
      expectedEncapStack iface = [] ∧ c.payloadOrigin iface ∧ allowed iface)
    {start : Execution.State} (origin : RedPayloadOrigin c sources start)
    (domainAtSource : c.recipientDomain start.iface = some domain) :
    Execution.DomainInvariant c expectedEncapStack allowed start := by
  obtain ⟨member, datapathStage, entry, empty, ingress, authentication⟩ := origin
  obtain ⟨stack, admitted, permitted⟩ := sourceCheck start.iface member domainAtSource
  simp only [Execution.DomainInvariant, datapathStage]
  refine ⟨⟨⟨?_, ?_, Or.inl authentication, ?_⟩, ?_⟩, ?_⟩
  · simp [Execution.Frame.tags, empty, Execution.encapStackAfterIngress, authentication, entry, stack]
  · simpa [entry] using ingress
  · simp [entry]
  · simpa [entry] using permitted
  · simpa [entry] using admitted

theorem delivered_domain_from_local_checks
    (c : Execution.Environment) (expectedEncapStack : Nat → List Nat) (allowed : Nat → Prop)
    (sources : List Nat) (domain : Nat)
    (conditions : Execution.LocalDomainConditions c expectedEncapStack allowed)
    (sourceCheck : ∀ iface ∈ sources, c.recipientDomain iface = some domain →
      expectedEncapStack iface = [] ∧ c.payloadOrigin iface ∧ allowed iface)
    (recipientCheck : ∀ iface, allowed iface →
      c.recipientDomain iface = none ∨ c.recipientDomain iface = some domain)
    {start finish : Execution.State} {actions : List Execution.Action} {recipient : Nat}
    (origin : RedPayloadOrigin c sources start)
    (domainAtSource : c.recipientDomain start.iface = some domain)
    (run : (Execution.lts c).MTr start actions finish)
    (delivered : finish.datapathStage = .delivered)
    (recipientAtEnd : c.recipientDomain finish.iface = some recipient) :
    domain = recipient := by
  have initial := red_origin_has_domain_invariant c expectedEncapStack allowed sources domain sourceCheck origin domainAtSource
  have permitted := Execution.delivered_iface_is_allowed c expectedEncapStack allowed conditions run initial delivered
  rcases recipientCheck finish.iface permitted with absent | same
  · simp [recipientAtEnd] at absent
  · exact Option.some.inj (same.symm.trans recipientAtEnd)

lemma equal_domains_have_equal_full_labels {Label : Type} (fullLabel : Nat → Label)
    {source destination : Nat} (same : source = destination) :
    fullLabel source = fullLabel destination :=
  congrArg fullLabel same

end TDN.Targets
