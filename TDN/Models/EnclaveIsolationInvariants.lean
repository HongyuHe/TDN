import TDN.Models.TunnelSaOriginAttribution

namespace TDN.DataPlaneForwarding

def DomainProcessing (c : DataPlaneModel) (expectedEncapStack : Nat → List Nat) (allowed : Nat → Prop)
    (s : State) : Prop :=
  ProcessingInvariant c expectedEncapStack s ∧ allowed s.frame.enteredIface

structure LocalDomainConditions (c : DataPlaneModel) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) : Prop where
  routeOwner : ∀ r ∈ c.routes, c.owner r.egress = c.owner r.ingress
  link : ∀ a b, c.link a b → allowed a → expectedEncapStack a = expectedEncapStack b ∧ allowed b
  bridge : ∀ a b packet authenticated, c.bridging a b packet →
    LocalAuthentication c expectedEncapStack a authenticated → allowed a →
    encapStackAfterIngress expectedEncapStack a authenticated = expectedEncapStack b ∧ allowed b
  forward : ∀ iface frame authenticated,
    frame.packet.ingress = c.interfaceName frame.enteredIface →
    LocalAuthentication c expectedEncapStack frame.enteredIface authenticated →
    c.owner iface = c.owner frame.enteredIface → allowed frame.enteredIface →
    accepts (c.forwardRules iface) (c.forwardFallback iface) (policyPacket c iface frame authenticated) →
    ((lookupSpdPolicies (c.egressPolicies iface) frame.packet = [] →
      encapStackAfterIngress expectedEncapStack frame.enteredIface authenticated = expectedEncapStack iface) ∧
    (∀ a ∈ lookupSpdPolicies (c.egressPolicies iface) frame.packet,
      a.tag :: encapStackAfterIngress expectedEncapStack frame.enteredIface authenticated = expectedEncapStack iface)) ∧ allowed iface
  output : ∀ iface frame, c.canOriginateTraffic frame.enteredIface →
    frame.packet.ingress = c.interfaceName frame.enteredIface →
    c.owner iface = c.owner frame.enteredIface → allowed frame.enteredIface →
    accepts (c.outputRules iface) (c.outputFallback iface) (policyPacket c iface frame []) →
    ((lookupSpdPolicies (c.egressPolicies iface) frame.packet = [] →
      encapStackAfterIngress expectedEncapStack frame.enteredIface [] = expectedEncapStack iface) ∧
    (∀ a ∈ lookupSpdPolicies (c.egressPolicies iface) frame.packet,
      a.tag :: encapStackAfterIngress expectedEncapStack frame.enteredIface [] = expectedEncapStack iface)) ∧ allowed iface
  routeOuterPacket : ∀ iface a, a ∈ c.egressPolicies iface → (expectedEncapStack iface).head? = some a.tag →
    allowed iface → ∀ sa frame r,
    SelectedFibRoute c.routes r (encrypt a sa frame).packet → r.ingress = iface →
    expectedEncapStack iface = expectedEncapStack r.egress ∧ allowed r.egress

def DomainInvariant (c : DataPlaneModel) (expectedEncapStack : Nat → List Nat) (allowed : Nat → Prop)
    (s : State) : Prop :=
  match s.datapathStage with
  | .received | .egressReady => s.frame.encapLayerIds = expectedEncapStack s.iface ∧ allowed s.iface
  | .ingress | .localInput | .delivered =>
      DomainProcessing c expectedEncapStack allowed s ∧ s.frame.enteredIface = s.iface
  | .localOutput | .outputRouted =>
      DomainProcessing c expectedEncapStack allowed s ∧ c.canOriginateTraffic s.frame.enteredIface
  | .routed => DomainProcessing c expectedEncapStack allowed s
  | .filtered => DomainProcessing c expectedEncapStack allowed s ∧ AcceptedHook c s
  | .encapsulated => (s.frame.encapLayerIds = expectedEncapStack s.iface ∧ allowed s.iface) ∧
      ∃ a ∈ c.egressPolicies s.iface, ∃ sa previous, s.frame = encrypt a sa previous
  | .dropped => True

lemma accepted_hook_domain_effect {c : DataPlaneModel} {expectedEncapStack : Nat → List Nat}
    {allowed : Nat → Prop} (conditions : LocalDomainConditions c expectedEncapStack allowed)
    {s : State} (processing : DomainProcessing c expectedEncapStack allowed s)
    (accepted : AcceptedHook c s) :
    ((lookupSpdPolicies (c.egressPolicies s.iface) s.frame.packet = [] →
      encapStackAfterIngress expectedEncapStack s.frame.enteredIface s.authenticated = expectedEncapStack s.iface) ∧
    (∀ a ∈ lookupSpdPolicies (c.egressPolicies s.iface) s.frame.packet,
      a.tag :: encapStackAfterIngress expectedEncapStack s.frame.enteredIface s.authenticated = expectedEncapStack s.iface)) ∧
    allowed s.iface := by
  rcases accepted with forward | ⟨empty, origin, output⟩
  · exact conditions.forward s.iface s.frame s.authenticated processing.1.2.1
      processing.1.2.2.1 processing.1.2.2.2 processing.2 forward
  · simpa [empty] using conditions.output s.iface s.frame origin processing.1.2.1
      processing.1.2.2.2 processing.2 output

lemma step_preserves_domain_invariant {c : DataPlaneModel} {expectedEncapStack : Nat → List Nat}
    {allowed : Nat → Prop} (conditions : LocalDomainConditions c expectedEncapStack allowed)
    {a b : State} {action : Action} (step : Step c a action b)
    (before : DomainInvariant c expectedEncapStack allowed a) :
    DomainInvariant c expectedEncapStack allowed b := by
  cases step with
  | receive => exact ⟨⟨⟨before.1, rfl, Or.inl rfl, rfl⟩, before.2⟩, rfl⟩
  | route route chosen atIngress =>
    refine ⟨⟨before.1.1.1, before.1.1.2.1, before.1.1.2.2.1, ?_⟩, before.1.2⟩
    exact (conditions.routeOwner route chosen.1).trans
      (by simpa [atIngress] using before.1.1.2.2.2)
  | routeLocalOutput route chosen atOrigin =>
    refine ⟨⟨⟨before.1.1.1, before.1.1.2.1, before.1.1.2.2.1, ?_⟩, before.1.2⟩, before.2⟩
    exact (conditions.routeOwner route chosen.1).trans
      (by simpa [atOrigin] using before.1.1.2.2.2)
  | filter accepted => exact ⟨before, Or.inl accepted⟩
  | outputFilter accepted => exact ⟨before.1, Or.inr ⟨rfl, before.2, accepted⟩⟩
  | @encrypt iface frame authenticated association sa selected installed bound =>
    have effect := accepted_hook_domain_effect conditions before.1 before.2
    have tags : (encrypt association sa frame).encapLayerIds = association.tag :: frame.encapLayerIds := rfl
    refine ⟨⟨?_, effect.2⟩, association, (matched_policy_is_configured selected).1, sa, frame, rfl⟩
    exact tags.trans (congrArg (List.cons association.tag) before.1.1.1 |>.trans
      (effect.1.2 association selected))
  | @routeOuterPacket iface frame authenticated route chosen atEncryptor =>
    obtain ⟨⟨stack, permitted⟩, association, member, sa, previous, same⟩ := before
    change frame = encrypt association sa previous at same
    rw [same] at chosen
    have head : (expectedEncapStack iface).head? = some association.tag := by
      rw [← stack, same]
      rfl
    have effect := conditions.routeOuterPacket iface association member head permitted
      sa previous route chosen atEncryptor
    exact ⟨stack.trans effect.1, effect.2⟩
  | @bridge a b frame authenticated permitted =>
    have entered : frame.enteredIface = a := before.2
    have auth : LocalAuthentication c expectedEncapStack a authenticated := by
      simpa [entered] using before.1.1.2.2.1
    have permittedEntry : allowed a := by simpa [entered] using before.1.2
    have effect := conditions.bridge a b frame.packet authenticated permitted auth permittedEntry
    exact ⟨before.1.1.1.trans (by simpa [entered] using effect.1), effect.2⟩
  | @forwardWithoutEncap iface frame authenticated noPolicy =>
    have effect := accepted_hook_domain_effect conditions before.1 before.2
    exact ⟨before.1.1.1.trans (effect.1.1 noPolicy), effect.2⟩
  | @decrypt iface frame association sa header rest tracking configured installed bound received
      outerSource outerDestination esp selected =>
    have stackTail := congrArg List.tail before.1
    simp only [Frame.encapLayerIds, received, List.map_cons, List.tail_cons] at stackTail
    refine ⟨⟨⟨?_, rfl, Or.inr ⟨association, configured, rfl,
      rest.map (fun e => e.authentication.tag), ?_⟩, rfl⟩, before.2⟩, rfl⟩
    · simpa [Frame.encapLayerIds, encapStackAfterIngress] using stackTail
    · simpa [Frame.encapLayerIds, received, IpsecPolicy.seal] using before.1.symm
  | @linkTransmit a b frame authenticated linked =>
    have effect := conditions.link a b linked before.2
    exact ⟨before.1.trans effect.1, effect.2⟩
  | deliverToLocalHost => exact before
  | deliver => exact before
  | drop => trivial

theorem forwarding_preserves_enclave_invariant (c : DataPlaneModel) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) (conditions : LocalDomainConditions c expectedEncapStack allowed)
    {a b : State} {actions : List Action} (run : (lts c).MTr a actions b)
    (initial : DomainInvariant c expectedEncapStack allowed a) :
    DomainInvariant c expectedEncapStack allowed b := by
  have preservation : (lts c).TrInv (DomainInvariant c expectedEncapStack allowed) :=
    fun _ _ _ step before => step_preserves_domain_invariant conditions step before
  exact Cslib.LTS.mtrInv_of_trInv preservation a actions b run initial

theorem delivered_iface_is_allowed (c : DataPlaneModel) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) (conditions : LocalDomainConditions c expectedEncapStack allowed)
    {a b : State} {actions : List Action} (run : (lts c).MTr a actions b)
    (initial : DomainInvariant c expectedEncapStack allowed a) (delivered : b.datapathStage = .delivered) :
    allowed b.iface := by
  have preserved := forwarding_preserves_enclave_invariant c expectedEncapStack allowed conditions run initial
  simp only [DomainInvariant, delivered] at preserved
  simpa [preserved.2] using preserved.1.2

end TDN.DataPlaneForwarding
