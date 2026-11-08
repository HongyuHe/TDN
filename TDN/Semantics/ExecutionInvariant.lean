import TDN.Semantics.Execution

namespace TDN.Execution

def Frame.tags (frame : Frame) : List Nat :=
  frame.envelopes.map (fun e => e.authentication.tag)

def encapStackAfterIngress (expectedEncapStack : Nat → List Nat) (entry : Nat) (authenticated : List Nat) :
    List Nat :=
  if authenticated = [] then expectedEncapStack entry else (expectedEncapStack entry).tail

def LocalAuthentication (c : Environment) (expectedEncapStack : Nat → List Nat) (entry : Nat) (authenticated : List Nat) : Prop :=
  authenticated = [] ∨ ∃ a ∈ c.inbound entry, authenticated = [a.id] ∧
    ∃ rest, expectedEncapStack entry = a.tag :: rest

def ProcessingInvariant (c : Environment) (expectedEncapStack : Nat → List Nat) (s : State) : Prop :=
  s.frame.tags = encapStackAfterIngress expectedEncapStack s.frame.enteredIface s.authenticated ∧
  s.frame.packet.ingress = c.interfaceName s.frame.enteredIface ∧
  LocalAuthentication c expectedEncapStack s.frame.enteredIface s.authenticated ∧
  c.owner s.iface = c.owner s.frame.enteredIface

def AcceptedHook (c : Environment) (s : State) : Prop :=
  accepts (c.forwardRules s.iface) (c.forwardFallback s.iface)
    (policyPacket c s.iface s.frame s.authenticated) ∨
  (s.authenticated = [] ∧ c.payloadOrigin s.frame.enteredIface ∧ accepts (c.outputRules s.iface) (c.outputFallback s.iface)
    (policyPacket c s.iface s.frame []))

def RoutedFrame (c : Environment) (iface : Nat) (frame : Frame) : Prop :=
  ∃ r, SelectedRoute c.routes r frame.packet ∧
    r.ingress = frame.enteredIface ∧ r.egress = iface

structure LocalStackConditions (c : Environment) (expectedEncapStack : Nat → List Nat) : Prop where
  routeOwner : ∀ r ∈ c.routes, c.owner r.egress = c.owner r.ingress
  link : ∀ a b, c.link a b → expectedEncapStack a = expectedEncapStack b
  bridge : ∀ a b packet authenticated, c.bridging a b packet →
    LocalAuthentication c expectedEncapStack a authenticated →
    encapStackAfterIngress expectedEncapStack a authenticated = expectedEncapStack b
  forward : ∀ iface frame authenticated,
    RoutedFrame c iface frame →
    frame.packet.ingress = c.interfaceName frame.enteredIface →
    LocalAuthentication c expectedEncapStack frame.enteredIface authenticated →
    c.owner iface = c.owner frame.enteredIface →
    accepts (c.forwardRules iface) (c.forwardFallback iface)
      (policyPacket c iface frame authenticated) →
    (selectedAssociations (c.outbound iface) frame.packet = [] →
      encapStackAfterIngress expectedEncapStack frame.enteredIface authenticated = expectedEncapStack iface) ∧
    (∀ a ∈ selectedAssociations (c.outbound iface) frame.packet,
      a.tag :: encapStackAfterIngress expectedEncapStack frame.enteredIface authenticated = expectedEncapStack iface)
  output : ∀ iface frame, RoutedFrame c iface frame → c.payloadOrigin frame.enteredIface →
    frame.packet.ingress = c.interfaceName frame.enteredIface →
    c.owner iface = c.owner frame.enteredIface →
    accepts (c.outputRules iface) (c.outputFallback iface) (policyPacket c iface frame []) →
    (selectedAssociations (c.outbound iface) frame.packet = [] →
      encapStackAfterIngress expectedEncapStack frame.enteredIface [] = expectedEncapStack iface) ∧
    (∀ a ∈ selectedAssociations (c.outbound iface) frame.packet,
      a.tag :: encapStackAfterIngress expectedEncapStack frame.enteredIface [] = expectedEncapStack iface)
  routeOuterPacket : ∀ iface a, a ∈ c.outbound iface → (expectedEncapStack iface).head? = some a.tag → ∀ sa frame r,
    SelectedRoute c.routes r (encrypt a sa frame).packet → r.ingress = iface →
    expectedEncapStack iface = expectedEncapStack r.egress

def StackInvariant (c : Environment) (expectedEncapStack : Nat → List Nat) (s : State) : Prop :=
  match s.datapathStage with
  | .received => s.frame.tags = expectedEncapStack s.iface
  | .ingress => ProcessingInvariant c expectedEncapStack s ∧ s.frame.enteredIface = s.iface
  | .localOutput =>
      (ProcessingInvariant c expectedEncapStack s ∧ c.payloadOrigin s.frame.enteredIface) ∧
        s.frame.enteredIface = s.iface
  | .outputRouted =>
      (ProcessingInvariant c expectedEncapStack s ∧ c.payloadOrigin s.frame.enteredIface) ∧
        RoutedFrame c s.iface s.frame
  | .routed => ProcessingInvariant c expectedEncapStack s ∧ RoutedFrame c s.iface s.frame
  | .localInput | .delivered => ProcessingInvariant c expectedEncapStack s
  | .filtered => ProcessingInvariant c expectedEncapStack s ∧ AcceptedHook c s ∧ RoutedFrame c s.iface s.frame
  | .encapsulated => s.frame.tags = expectedEncapStack s.iface ∧
      ∃ a ∈ c.outbound s.iface, ∃ sa previous, s.frame = encrypt a sa previous
  | .ready => s.frame.tags = expectedEncapStack s.iface
  | .dropped => True

lemma accepted_hook_stack_effect {c : Environment} {expectedEncapStack : Nat → List Nat}
    (conditions : LocalStackConditions c expectedEncapStack) {s : State}
    (processing : ProcessingInvariant c expectedEncapStack s) (accepted : AcceptedHook c s)
    (routed : RoutedFrame c s.iface s.frame) :
    (selectedAssociations (c.outbound s.iface) s.frame.packet = [] →
      encapStackAfterIngress expectedEncapStack s.frame.enteredIface s.authenticated = expectedEncapStack s.iface) ∧
    (∀ a ∈ selectedAssociations (c.outbound s.iface) s.frame.packet,
      a.tag :: encapStackAfterIngress expectedEncapStack s.frame.enteredIface s.authenticated = expectedEncapStack s.iface) := by
  rcases accepted with forward | ⟨empty, origin, output⟩
  · exact conditions.forward s.iface s.frame s.authenticated routed processing.2.1 processing.2.2.1 processing.2.2.2 forward
  · simpa [empty] using conditions.output s.iface s.frame routed origin processing.2.1 processing.2.2.2 output

lemma step_preserves_stack_invariant {c : Environment} {expectedEncapStack : Nat → List Nat}
    (conditions : LocalStackConditions c expectedEncapStack) {a b : State} {action : Action}
    (step : Step c a action b) (before : StackInvariant c expectedEncapStack a) :
    StackInvariant c expectedEncapStack b := by
  cases step with
  | receive =>
    exact ⟨⟨before, rfl, Or.inl rfl, rfl⟩, rfl⟩
  | route route chosen atIngress =>
    refine ⟨⟨before.1.1, before.1.2.1, before.1.2.2.1, ?_⟩,
      route, chosen, atIngress.trans before.2.symm, rfl⟩
    exact (conditions.routeOwner route chosen.1).trans (by simpa [atIngress] using before.1.2.2.2)
  | routeLocalOutput route chosen atOrigin =>
    refine ⟨⟨⟨before.1.1.1, before.1.1.2.1, before.1.1.2.2.1, ?_⟩, before.1.2⟩,
      route, chosen, atOrigin.trans before.2.symm, rfl⟩
    exact (conditions.routeOwner route chosen.1).trans (by simpa [atOrigin] using before.1.1.2.2.2)
  | filter accepted => exact ⟨before.1, Or.inl accepted, before.2⟩
  | outputFilter accepted => exact ⟨before.1.1, Or.inr ⟨rfl, before.1.2, accepted⟩, before.2⟩
  | @encrypt iface frame authenticated association sa selected installed bound =>
    have effect := accepted_hook_stack_effect conditions before.1 before.2.1 before.2.2
    have tags : (encrypt association sa frame).tags = association.tag :: frame.tags := rfl
    exact ⟨tags.trans (congrArg (List.cons association.tag) before.1.1 |>.trans
      (effect.2 association selected)),
      association, (matched_policy_is_configured selected).1, sa, frame, rfl⟩
  | @routeOuterPacket iface frame authenticated route chosen atEncryptor =>
    obtain ⟨stack, association, member, sa, previous, same⟩ := before
    change frame = encrypt association sa previous at same
    rw [same] at chosen
    have head : (expectedEncapStack iface).head? = some association.tag := by
      rw [← stack, same]
      rfl
    exact stack.trans (conditions.routeOuterPacket iface association member head sa previous route chosen atEncryptor)
  | @bridge a b frame authenticated permitted =>
    have effect := conditions.bridge a b frame.packet authenticated permitted
    have entered : frame.enteredIface = a := before.2
    have auth : LocalAuthentication c expectedEncapStack a authenticated := by
      simpa [entered] using before.1.2.2.1
    exact before.1.1.trans (by simpa [entered] using effect auth)
  | @passWithoutTransform iface frame authenticated noPolicy =>
    exact before.1.1.trans ((accepted_hook_stack_effect conditions before.1 before.2.1 before.2.2).1 noPolicy)
  | @decrypt iface frame association sa header rest tracking configured installed bound received
      outerSource outerDestination esp selected =>
    have stackTail := congrArg List.tail before
    simp only [Frame.tags, received, List.map_cons, List.tail_cons] at stackTail
    refine ⟨⟨?_, rfl, Or.inr ⟨association, configured, rfl, rest.map (fun e => e.authentication.tag), ?_⟩, rfl⟩, rfl⟩
    · simpa [Frame.tags, encapStackAfterIngress] using stackTail
    · simpa [Frame.tags, received, Association.seal] using before.symm
  | @linkTransmit a b frame authenticated linked =>
    exact before.trans (conditions.link a b linked)
  | «local» => exact before.1
  | deliver => exact before
  | drop => trivial

theorem execution_preserves_stack_invariant (c : Environment) (expectedEncapStack : Nat → List Nat)
    (conditions : LocalStackConditions c expectedEncapStack) {a b : State} {actions : List Action}
    (execution : (lts c).MTr a actions b) (initial : StackInvariant c expectedEncapStack a) :
    StackInvariant c expectedEncapStack b := by
  have localProof : (lts c).TrInv (StackInvariant c expectedEncapStack) := by
    intro x action y step before
    exact step_preserves_stack_invariant conditions step before
  exact Cslib.LTS.mtrInv_of_trInv localProof a actions b execution initial

theorem transmitted_stack (c : Environment) (expectedEncapStack : Nat → List Nat)
    (conditions : LocalStackConditions c expectedEncapStack) {a b : State} {actions : List Action}
    (execution : (lts c).MTr a actions b) (initial : StackInvariant c expectedEncapStack a)
    (ready : b.datapathStage = .ready) :
    b.frame.tags = expectedEncapStack b.iface := by
  have preserved := execution_preserves_stack_invariant c expectedEncapStack conditions execution initial
  simpa [StackInvariant, ready] using preserved

end TDN.Execution
