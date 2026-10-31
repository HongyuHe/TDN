import TDN.Semantics.Execution

namespace TDN.Execution

def Frame.tags (frame : Frame) : List Nat :=
  frame.envelopes.map (fun e => e.authentication.tag)

def processingStack (layout : Nat → List Nat) (entry : Nat) (authenticated : List Nat) :
    List Nat :=
  if authenticated = [] then layout entry else (layout entry).tail

def LocalAuthentication (c : Config) (layout : Nat → List Nat) (entry : Nat) (authenticated : List Nat) : Prop :=
  authenticated = [] ∨ ∃ a ∈ c.inbound entry, authenticated = [a.id] ∧
    ∃ rest, layout entry = a.tag :: rest

def ProcessingInvariant (c : Config) (layout : Nat → List Nat) (s : State) : Prop :=
  s.frame.tags = processingStack layout s.frame.enteredPort s.authenticated ∧
  s.frame.packet.ingress = c.interfaceName s.frame.enteredPort ∧
  LocalAuthentication c layout s.frame.enteredPort s.authenticated ∧
  c.owner s.port = c.owner s.frame.enteredPort

def AcceptedHook (c : Config) (s : State) : Prop :=
  accepts (c.forwardRules s.port) (c.forwardFallback s.port)
    (policyPacket c s.port s.frame s.authenticated) ∨
  (s.authenticated = [] ∧ c.payloadOrigin s.frame.enteredPort ∧ accepts (c.outputRules s.port) (c.outputFallback s.port)
    (policyPacket c s.port s.frame []))

def RoutedFrame (c : Config) (port : Nat) (frame : Frame) : Prop :=
  ∃ r, SelectedRoute c.routes r frame.packet ∧
    r.ingress = frame.enteredPort ∧ r.egress = port

structure LocalStackConditions (c : Config) (layout : Nat → List Nat) : Prop where
  routeOwner : ∀ r ∈ c.routes, c.owner r.egress = c.owner r.ingress
  link : ∀ a b, c.link a b → layout a = layout b
  switch : ∀ a b packet authenticated, c.switching a b packet →
    LocalAuthentication c layout a authenticated →
    processingStack layout a authenticated = layout b
  forward : ∀ port frame authenticated,
    RoutedFrame c port frame →
    frame.packet.ingress = c.interfaceName frame.enteredPort →
    LocalAuthentication c layout frame.enteredPort authenticated →
    c.owner port = c.owner frame.enteredPort →
    accepts (c.forwardRules port) (c.forwardFallback port)
      (policyPacket c port frame authenticated) →
    (selectedAssociations (c.outbound port) frame.packet = [] →
      processingStack layout frame.enteredPort authenticated = layout port) ∧
    (∀ a ∈ selectedAssociations (c.outbound port) frame.packet,
      a.tag :: processingStack layout frame.enteredPort authenticated = layout port)
  output : ∀ port frame, RoutedFrame c port frame → c.payloadOrigin frame.enteredPort →
    frame.packet.ingress = c.interfaceName frame.enteredPort →
    c.owner port = c.owner frame.enteredPort →
    accepts (c.outputRules port) (c.outputFallback port) (policyPacket c port frame []) →
    (selectedAssociations (c.outbound port) frame.packet = [] →
      processingStack layout frame.enteredPort [] = layout port) ∧
    (∀ a ∈ selectedAssociations (c.outbound port) frame.packet,
      a.tag :: processingStack layout frame.enteredPort [] = layout port)
  outerRoute : ∀ port a, a ∈ c.outbound port → (layout port).head? = some a.tag → ∀ sa frame r,
    SelectedRoute c.routes r (encrypt a sa frame).packet → r.ingress = port →
    layout port = layout r.egress

def StackInvariant (c : Config) (layout : Nat → List Nat) (s : State) : Prop :=
  match s.phase with
  | .received => s.frame.tags = layout s.port
  | .ingress => ProcessingInvariant c layout s ∧ s.frame.enteredPort = s.port
  | .localOutput =>
      (ProcessingInvariant c layout s ∧ c.payloadOrigin s.frame.enteredPort) ∧
        s.frame.enteredPort = s.port
  | .outputRouted =>
      (ProcessingInvariant c layout s ∧ c.payloadOrigin s.frame.enteredPort) ∧
        RoutedFrame c s.port s.frame
  | .routed => ProcessingInvariant c layout s ∧ RoutedFrame c s.port s.frame
  | .localInput | .delivered => ProcessingInvariant c layout s
  | .filtered => ProcessingInvariant c layout s ∧ AcceptedHook c s ∧ RoutedFrame c s.port s.frame
  | .encapsulated => s.frame.tags = layout s.port ∧
      ∃ a ∈ c.outbound s.port, ∃ sa previous, s.frame = encrypt a sa previous
  | .ready => s.frame.tags = layout s.port
  | .dropped => True

lemma accepted_hook_stack_effect {c : Config} {layout : Nat → List Nat}
    (conditions : LocalStackConditions c layout) {s : State}
    (processing : ProcessingInvariant c layout s) (accepted : AcceptedHook c s)
    (routed : RoutedFrame c s.port s.frame) :
    (selectedAssociations (c.outbound s.port) s.frame.packet = [] →
      processingStack layout s.frame.enteredPort s.authenticated = layout s.port) ∧
    (∀ a ∈ selectedAssociations (c.outbound s.port) s.frame.packet,
      a.tag :: processingStack layout s.frame.enteredPort s.authenticated = layout s.port) := by
  rcases accepted with forward | ⟨empty, origin, output⟩
  · exact conditions.forward s.port s.frame s.authenticated routed processing.2.1 processing.2.2.1 processing.2.2.2 forward
  · simpa [empty] using conditions.output s.port s.frame routed origin processing.2.1 processing.2.2.2 output

lemma step_preserves_stack_invariant {c : Config} {layout : Nat → List Nat}
    (conditions : LocalStackConditions c layout) {a b : State} {action : Action}
    (step : Step c a action b) (before : StackInvariant c layout a) :
    StackInvariant c layout b := by
  cases step with
  | receive =>
    exact ⟨⟨before, rfl, Or.inl rfl, rfl⟩, rfl⟩
  | route route chosen atIngress =>
    refine ⟨⟨before.1.1, before.1.2.1, before.1.2.2.1, ?_⟩,
      route, chosen, atIngress.trans before.2.symm, rfl⟩
    exact (conditions.routeOwner route chosen.1).trans (by simpa [atIngress] using before.1.2.2.2)
  | outputRoute route chosen atOrigin =>
    refine ⟨⟨⟨before.1.1.1, before.1.1.2.1, before.1.1.2.2.1, ?_⟩, before.1.2⟩,
      route, chosen, atOrigin.trans before.2.symm, rfl⟩
    exact (conditions.routeOwner route chosen.1).trans (by simpa [atOrigin] using before.1.1.2.2.2)
  | filter accepted => exact ⟨before.1, Or.inl accepted, before.2⟩
  | outputFilter accepted => exact ⟨before.1.1, Or.inr ⟨rfl, before.1.2, accepted⟩, before.2⟩
  | @encrypt port frame authenticated association sa selected installed bound =>
    have effect := accepted_hook_stack_effect conditions before.1 before.2.1 before.2.2
    have tags : (encrypt association sa frame).tags = association.tag :: frame.tags := rfl
    exact ⟨tags.trans (congrArg (List.cons association.tag) before.1.1 |>.trans
      (effect.2 association selected)),
      association, (matched_policy_is_configured selected).1, sa, frame, rfl⟩
  | @outerRoute port frame authenticated route chosen atEncryptor =>
    obtain ⟨stack, association, member, sa, previous, same⟩ := before
    change frame = encrypt association sa previous at same
    rw [same] at chosen
    have head : (layout port).head? = some association.tag := by
      rw [← stack, same]
      rfl
    exact stack.trans (conditions.outerRoute port association member head sa previous route chosen atEncryptor)
  | @switch a b frame authenticated permitted =>
    have effect := conditions.switch a b frame.packet authenticated permitted
    have entered : frame.enteredPort = a := before.2
    have auth : LocalAuthentication c layout a authenticated := by
      simpa [entered] using before.1.2.2.1
    exact before.1.1.trans (by simpa [entered] using effect auth)
  | @plain port frame authenticated noPolicy =>
    exact before.1.1.trans ((accepted_hook_stack_effect conditions before.1 before.2.1 before.2.2).1 noPolicy)
  | @decrypt port frame association sa header rest tracking configured installed bound received
      outerSource outerDestination esp selected =>
    have stackTail := congrArg List.tail before
    simp only [Frame.tags, received, List.map_cons, List.tail_cons] at stackTail
    refine ⟨⟨?_, rfl, Or.inr ⟨association, configured, rfl, rest.map (fun e => e.authentication.tag), ?_⟩, rfl⟩, rfl⟩
    · simpa [Frame.tags, processingStack] using stackTail
    · simpa [Frame.tags, received, Association.seal] using before.symm
  | @wire a b frame authenticated linked =>
    exact before.trans (conditions.link a b linked)
  | «local» => exact before.1
  | deliver => exact before
  | drop => trivial

theorem execution_preserves_stack_invariant (c : Config) (layout : Nat → List Nat)
    (conditions : LocalStackConditions c layout) {a b : State} {actions : List Action}
    (execution : (lts c).MTr a actions b) (initial : StackInvariant c layout a) :
    StackInvariant c layout b := by
  have localProof : (lts c).TrInv (StackInvariant c layout) := by
    intro x action y step before
    exact step_preserves_stack_invariant conditions step before
  exact Cslib.LTS.mtrInv_of_trInv localProof a actions b execution initial

theorem transmitted_stack (c : Config) (layout : Nat → List Nat)
    (conditions : LocalStackConditions c layout) {a b : State} {actions : List Action}
    (execution : (lts c).MTr a actions b) (initial : StackInvariant c layout a)
    (ready : b.phase = .ready) :
    b.frame.tags = layout b.port := by
  have preserved := execution_preserves_stack_invariant c layout conditions execution initial
  simpa [StackInvariant, ready] using preserved

end TDN.Execution
