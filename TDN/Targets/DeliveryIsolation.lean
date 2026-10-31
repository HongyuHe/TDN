import TDN.Targets.PacketExecution
import TDN.Semantics.FiniteDomains

namespace TDN.Targets

/-- RG008's payload-delivery clause uses the actual source interface's declared domain.
The packet source address and the frame's caller-supplied originDomain do not determine the result. -/
def msc_same_domain_plaintext_delivery (c : Execution.Config) (sources : List Nat) : Prop :=
  ∀ start finish actions sourceDomain recipientDomain,
    RedPayloadOrigin c sources start → c.recipientDomain start.port = some sourceDomain →
    (Execution.lts c).MTr start actions finish → finish.phase = .delivered →
    c.recipientDomain finish.port = some recipientDomain → sourceDomain = recipientDomain

lemma red_origin_has_domain_invariant (c : Execution.Config) (layout : Nat → List Nat)
    (allowed : Nat → Prop) (sources : List Nat) (domain : Nat)
    (sourceCheck : ∀ port ∈ sources, c.recipientDomain port = some domain →
      layout port = [] ∧ c.payloadOrigin port ∧ allowed port)
    {start : Execution.State} (origin : RedPayloadOrigin c sources start)
    (domainAtSource : c.recipientDomain start.port = some domain) :
    Execution.DomainInvariant c layout allowed start := by
  obtain ⟨member, phase, entry, empty, ingress, authentication⟩ := origin
  obtain ⟨stack, admitted, permitted⟩ := sourceCheck start.port member domainAtSource
  simp only [Execution.DomainInvariant, phase]
  refine ⟨⟨⟨?_, ?_, Or.inl authentication, ?_⟩, ?_⟩, ?_⟩
  · simp [Execution.Frame.tags, empty, Execution.processingStack, authentication, entry, stack]
  · simpa [entry] using ingress
  · simp [entry]
  · simpa [entry] using permitted
  · simpa [entry] using admitted

/-- Local rule and SA checks prevent a payload from reaching a wrong-domain plaintext
recipient. Shared Gray and Black ports may remain allowed for every source domain. -/
theorem delivered_domain_from_local_checks
    (c : Execution.Config) (layout : Nat → List Nat) (allowed : Nat → Prop)
    (sources : List Nat) (domain : Nat)
    (conditions : Execution.LocalDomainConditions c layout allowed)
    (sourceCheck : ∀ port ∈ sources, c.recipientDomain port = some domain →
      layout port = [] ∧ c.payloadOrigin port ∧ allowed port)
    (recipientCheck : ∀ port, allowed port →
      c.recipientDomain port = none ∨ c.recipientDomain port = some domain)
    {start finish : Execution.State} {actions : List Execution.Action} {recipient : Nat}
    (origin : RedPayloadOrigin c sources start)
    (domainAtSource : c.recipientDomain start.port = some domain)
    (run : (Execution.lts c).MTr start actions finish)
    (delivered : finish.phase = .delivered)
    (recipientAtEnd : c.recipientDomain finish.port = some recipient) :
    domain = recipient := by
  have initial := red_origin_has_domain_invariant c layout allowed sources domain sourceCheck origin domainAtSource
  have permitted := Execution.delivered_port_is_allowed c layout allowed conditions run initial delivered
  rcases recipientCheck finish.port permitted with absent | same
  · simp [recipientAtEnd] at absent
  · exact Option.some.inj (same.symm.trans recipientAtEnd)

/-- Full security labels may include classification, compartments, dissemination and other
controls. Equal imported domain identities preserve every component of their label mapping. -/
lemma equal_domains_have_equal_full_labels {Label : Type} (fullLabel : Nat → Label)
    {source destination : Nat} (same : source = destination) :
    fullLabel source = fullLabel destination :=
  congrArg fullLabel same

end TDN.Targets
