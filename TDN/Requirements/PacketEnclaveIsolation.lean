import TDN.Requirements.DoubleEncryptionOnBlackLinks
import TDN.Models.TableDrivenEnclaveChecks

namespace TDN.Requirements

def plaintext_delivery_preserves_security_enclave (env : DataPlaneForwarding.DataPlaneModel)
    (redSourceIfaces : List Nat) : Prop :=
  ∀ initialState finalState actions sourceDomain destinationDomain,
    RedPayloadOrigin env redSourceIfaces initialState →
    env.ifaceSecurityDomain initialState.iface = some sourceDomain →
    DataPlaneForwarding.ForwardsAlongTrace env initialState actions finalState → finalState.datapathStage = .delivered →
    env.ifaceSecurityDomain finalState.iface = some destinationDomain → sourceDomain = destinationDomain

lemma red_origin_has_domain_invariant (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) (sources : List Nat) (domain : Nat)
    (sourceCheck : ∀ iface ∈ sources, c.ifaceSecurityDomain iface = some domain →
      expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface ∧ allowed iface)
    {start : DataPlaneForwarding.State} (origin : RedPayloadOrigin c sources start)
    (domainAtSource : c.ifaceSecurityDomain start.iface = some domain) :
    DataPlaneForwarding.DomainInvariant c expectedEncapStack allowed start := by
  obtain ⟨member, datapathStage, entry, empty, ingress, authentication⟩ := origin
  obtain ⟨stack, admitted, permitted⟩ := sourceCheck start.iface member domainAtSource
  simp only [DataPlaneForwarding.DomainInvariant, datapathStage]
  refine ⟨⟨⟨?_, ?_, Or.inl authentication, ?_⟩, ?_⟩, ?_⟩
  · simp [DataPlaneForwarding.Frame.encapLayerIds, empty, DataPlaneForwarding.encapStackAfterIngress, authentication, entry, stack]
  · simpa [entry] using ingress
  · simp [entry]
  · simpa [entry] using permitted
  · simpa [entry] using admitted

theorem delivered_domain_from_local_checks
    (c : DataPlaneForwarding.DataPlaneModel) (expectedEncapStack : Nat → List Nat) (allowed : Nat → Prop)
    (sources : List Nat) (domain : Nat)
    (conditions : DataPlaneForwarding.LocalDomainConditions c expectedEncapStack allowed)
    (sourceCheck : ∀ iface ∈ sources, c.ifaceSecurityDomain iface = some domain →
      expectedEncapStack iface = [] ∧ c.canOriginateTraffic iface ∧ allowed iface)
    (recipientCheck : ∀ iface, allowed iface →
      c.ifaceSecurityDomain iface = none ∨ c.ifaceSecurityDomain iface = some domain)
    {start finish : DataPlaneForwarding.State} {actions : List DataPlaneForwarding.Action} {recipient : Nat}
    (origin : RedPayloadOrigin c sources start)
    (domainAtSource : c.ifaceSecurityDomain start.iface = some domain)
    (run : DataPlaneForwarding.ForwardsAlongTrace c start actions finish)
    (delivered : finish.datapathStage = .delivered)
    (recipientAtEnd : c.ifaceSecurityDomain finish.iface = some recipient) :
    domain = recipient := by
  have initial := red_origin_has_domain_invariant c expectedEncapStack allowed sources domain sourceCheck origin domainAtSource
  have permitted := DataPlaneForwarding.delivered_iface_is_allowed c expectedEncapStack allowed conditions run initial delivered
  rcases recipientCheck finish.iface permitted with absent | same
  · simp [recipientAtEnd] at absent
  · exact Option.some.inj (same.symm.trans recipientAtEnd)

lemma equal_domains_have_equal_full_labels {Label : Type} (fullLabel : Nat → Label)
    {source destination : Nat} (same : source = destination) :
    fullLabel source = fullLabel destination :=
  congrArg fullLabel same

end TDN.Requirements
