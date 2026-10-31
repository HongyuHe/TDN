import TDN.Semantics.ExecutionProvenance

namespace TDN.Execution

def DomainProcessing (c : Config) (layout : Nat → List Nat) (allowed : Nat → Prop)
    (s : State) : Prop :=
  ProcessingInvariant c layout s ∧ allowed s.frame.enteredPort

structure LocalDomainConditions (c : Config) (layout : Nat → List Nat)
    (allowed : Nat → Prop) : Prop where
  routeOwner : ∀ r ∈ c.routes, c.owner r.egress = c.owner r.ingress
  link : ∀ a b, c.link a b → allowed a → layout a = layout b ∧ allowed b
  switch : ∀ a b packet authenticated, c.switching a b packet →
    LocalAuthentication c layout a authenticated → allowed a →
    processingStack layout a authenticated = layout b ∧ allowed b
  forward : ∀ port frame authenticated,
    frame.packet.ingress = c.interfaceName frame.enteredPort →
    LocalAuthentication c layout frame.enteredPort authenticated →
    c.owner port = c.owner frame.enteredPort → allowed frame.enteredPort →
    accepts (c.forwardRules port) (c.forwardFallback port) (policyPacket c port frame authenticated) →
    ((selectedAssociations (c.outbound port) frame.packet = [] →
      processingStack layout frame.enteredPort authenticated = layout port) ∧
    (∀ a ∈ selectedAssociations (c.outbound port) frame.packet,
      a.tag :: processingStack layout frame.enteredPort authenticated = layout port)) ∧ allowed port
  output : ∀ port frame, c.payloadOrigin frame.enteredPort →
    frame.packet.ingress = c.interfaceName frame.enteredPort →
    c.owner port = c.owner frame.enteredPort → allowed frame.enteredPort →
    accepts (c.outputRules port) (c.outputFallback port) (policyPacket c port frame []) →
    ((selectedAssociations (c.outbound port) frame.packet = [] →
      processingStack layout frame.enteredPort [] = layout port) ∧
    (∀ a ∈ selectedAssociations (c.outbound port) frame.packet,
      a.tag :: processingStack layout frame.enteredPort [] = layout port)) ∧ allowed port
  outerRoute : ∀ port a, a ∈ c.outbound port → (layout port).head? = some a.tag →
    allowed port → ∀ sa frame r,
    SelectedRoute c.routes r (encrypt a sa frame).packet → r.ingress = port →
    layout port = layout r.egress ∧ allowed r.egress

def DomainInvariant (c : Config) (layout : Nat → List Nat) (allowed : Nat → Prop)
    (s : State) : Prop :=
  match s.phase with
  | .received | .ready => s.frame.tags = layout s.port ∧ allowed s.port
  | .ingress | .localInput | .delivered =>
      DomainProcessing c layout allowed s ∧ s.frame.enteredPort = s.port
  | .localOutput | .outputRouted =>
      DomainProcessing c layout allowed s ∧ c.payloadOrigin s.frame.enteredPort
  | .routed => DomainProcessing c layout allowed s
  | .filtered => DomainProcessing c layout allowed s ∧ AcceptedHook c s
  | .encapsulated => (s.frame.tags = layout s.port ∧ allowed s.port) ∧
      ∃ a ∈ c.outbound s.port, ∃ sa previous, s.frame = encrypt a sa previous
  | .dropped => True

lemma accepted_hook_domain_effect {c : Config} {layout : Nat → List Nat}
    {allowed : Nat → Prop} (conditions : LocalDomainConditions c layout allowed)
    {s : State} (processing : DomainProcessing c layout allowed s)
    (accepted : AcceptedHook c s) :
    ((selectedAssociations (c.outbound s.port) s.frame.packet = [] →
      processingStack layout s.frame.enteredPort s.authenticated = layout s.port) ∧
    (∀ a ∈ selectedAssociations (c.outbound s.port) s.frame.packet,
      a.tag :: processingStack layout s.frame.enteredPort s.authenticated = layout s.port)) ∧
    allowed s.port := by
  rcases accepted with forward | ⟨empty, origin, output⟩
  · exact conditions.forward s.port s.frame s.authenticated processing.1.2.1
      processing.1.2.2.1 processing.1.2.2.2 processing.2 forward
  · simpa [empty] using conditions.output s.port s.frame origin processing.1.2.1
      processing.1.2.2.2 processing.2 output

lemma step_preserves_domain_invariant {c : Config} {layout : Nat → List Nat}
    {allowed : Nat → Prop} (conditions : LocalDomainConditions c layout allowed)
    {a b : State} {action : Action} (step : Step c a action b)
    (before : DomainInvariant c layout allowed a) :
    DomainInvariant c layout allowed b := by
  cases step with
  | receive => exact ⟨⟨⟨before.1, rfl, Or.inl rfl, rfl⟩, before.2⟩, rfl⟩
  | route route chosen atIngress =>
    refine ⟨⟨before.1.1.1, before.1.1.2.1, before.1.1.2.2.1, ?_⟩, before.1.2⟩
    exact (conditions.routeOwner route chosen.1).trans
      (by simpa [atIngress] using before.1.1.2.2.2)
  | outputRoute route chosen atOrigin =>
    refine ⟨⟨⟨before.1.1.1, before.1.1.2.1, before.1.1.2.2.1, ?_⟩, before.1.2⟩, before.2⟩
    exact (conditions.routeOwner route chosen.1).trans
      (by simpa [atOrigin] using before.1.1.2.2.2)
  | filter accepted => exact ⟨before, Or.inl accepted⟩
  | outputFilter accepted => exact ⟨before.1, Or.inr ⟨rfl, before.2, accepted⟩⟩
  | @encrypt port frame authenticated association sa selected installed bound =>
    have effect := accepted_hook_domain_effect conditions before.1 before.2
    have tags : (encrypt association sa frame).tags = association.tag :: frame.tags := rfl
    refine ⟨⟨?_, effect.2⟩, association, (matched_policy_is_configured selected).1, sa, frame, rfl⟩
    exact tags.trans (congrArg (List.cons association.tag) before.1.1.1 |>.trans
      (effect.1.2 association selected))
  | @outerRoute port frame authenticated route chosen atEncryptor =>
    obtain ⟨⟨stack, permitted⟩, association, member, sa, previous, same⟩ := before
    change frame = encrypt association sa previous at same
    rw [same] at chosen
    have head : (layout port).head? = some association.tag := by
      rw [← stack, same]
      rfl
    have effect := conditions.outerRoute port association member head permitted
      sa previous route chosen atEncryptor
    exact ⟨stack.trans effect.1, effect.2⟩
  | @switch a b frame authenticated permitted =>
    have entered : frame.enteredPort = a := before.2
    have auth : LocalAuthentication c layout a authenticated := by
      simpa [entered] using before.1.1.2.2.1
    have permittedEntry : allowed a := by simpa [entered] using before.1.2
    have effect := conditions.switch a b frame.packet authenticated permitted auth permittedEntry
    exact ⟨before.1.1.1.trans (by simpa [entered] using effect.1), effect.2⟩
  | @plain port frame authenticated noPolicy =>
    have effect := accepted_hook_domain_effect conditions before.1 before.2
    exact ⟨before.1.1.1.trans (effect.1.1 noPolicy), effect.2⟩
  | @decrypt port frame association sa header rest tracking configured installed bound received
      outerSource outerDestination esp selected =>
    have stackTail := congrArg List.tail before.1
    simp only [Frame.tags, received, List.map_cons, List.tail_cons] at stackTail
    refine ⟨⟨⟨?_, rfl, Or.inr ⟨association, configured, rfl,
      rest.map (fun e => e.authentication.tag), ?_⟩, rfl⟩, before.2⟩, rfl⟩
    · simpa [Frame.tags, processingStack] using stackTail
    · simpa [Frame.tags, received, Association.seal] using before.1.symm
  | @wire a b frame authenticated linked =>
    have effect := conditions.link a b linked before.2
    exact ⟨before.1.trans effect.1, effect.2⟩
  | «local» => exact before
  | deliver => exact before
  | drop => trivial

theorem execution_preserves_domain_invariant (c : Config) (layout : Nat → List Nat)
    (allowed : Nat → Prop) (conditions : LocalDomainConditions c layout allowed)
    {a b : State} {actions : List Action} (run : (lts c).MTr a actions b)
    (initial : DomainInvariant c layout allowed a) :
    DomainInvariant c layout allowed b := by
  have preservation : (lts c).TrInv (DomainInvariant c layout allowed) :=
    fun _ _ _ step before => step_preserves_domain_invariant conditions step before
  exact Cslib.LTS.mtrInv_of_trInv preservation a actions b run initial

theorem delivered_port_is_allowed (c : Config) (layout : Nat → List Nat)
    (allowed : Nat → Prop) (conditions : LocalDomainConditions c layout allowed)
    {a b : State} {actions : List Action} (run : (lts c).MTr a actions b)
    (initial : DomainInvariant c layout allowed a) (delivered : b.phase = .delivered) :
    allowed b.port := by
  have preserved := execution_preserves_domain_invariant c layout allowed conditions run initial
  simp only [DomainInvariant, delivered] at preserved
  simpa [preserved.2] using preserved.1.2

end TDN.Execution
