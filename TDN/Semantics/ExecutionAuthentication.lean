import TDN.Semantics.ExecutionEvents
import TDN.Semantics.RestrictedExecution

namespace TDN.Execution

/-- Metadata established by receiving a packet. It makes no assertion about its envelopes. -/
def IngressMetadata (c : Config) (s : State) : Prop :=
  s.frame.packet.ingress = c.interfaceName s.frame.enteredPort ∧
  c.owner s.port = c.owner s.frame.enteredPort

/-- Without a decrypt operation, a traversal retains the boundary layer in its port layout.
The layout records the checked forwarding constraints, not an assumed tag on the input packet. -/
def UndecryptedRegion (c : Config) (layout : Nat → List Nat) (tag : Nat) (s : State) : Prop :=
  s.authenticated = [] ∧
  match s.phase with
  | .received | .ready => tag ∈ layout s.port
  | .ingress => IngressMetadata c s ∧ s.frame.enteredPort = s.port ∧ tag ∈ layout s.frame.enteredPort
  | .routed => IngressMetadata c s ∧ RoutedFrame c s.port s.frame ∧ tag ∈ layout s.frame.enteredPort
  | .filtered => IngressMetadata c s ∧ AcceptedHook c s ∧ RoutedFrame c s.port s.frame ∧
      tag ∈ layout s.frame.enteredPort
  | .encapsulated => tag ∈ layout s.port ∧
      ∃ a ∈ c.outbound s.port, ∃ sa previous, s.frame = encrypt a sa previous ∧
        (layout s.port).head? = some a.tag
  | .localInput | .delivered => IngressMetadata c s ∧ tag ∈ layout s.frame.enteredPort
  | .localOutput | .outputRouted => False
  | .dropped => True

lemma undecrypted_step_retains_region {c : Config} {layout : Nat → List Nat} {tag : Nat}
    (conditions : LocalStackConditions c layout) {before after : State} {action : Action}
    (step : Step c before action after) (notDecrypt : action ≠ .decrypt)
    (invariant : UndecryptedRegion c layout tag before) :
    UndecryptedRegion c layout tag after := by
  cases step with
  | receive => exact ⟨rfl, ⟨rfl, rfl⟩, rfl, invariant.2⟩
  | route route chosen atIngress =>
    refine ⟨invariant.1, ⟨invariant.2.1.1, ?_⟩,
      ⟨route, chosen, atIngress.trans invariant.2.2.1.symm, rfl⟩, invariant.2.2.2⟩
    exact (conditions.routeOwner route chosen.1).trans
      (by simpa [atIngress] using invariant.2.1.2)
  | outputRoute => exact False.elim invariant.2
  | filter accepted =>
    exact ⟨invariant.1, invariant.2.1, Or.inl accepted, invariant.2.2⟩
  | outputFilter => exact False.elim invariant.2
  | @encrypt port frame authenticated association sa selected installed bound =>
    have metadata := invariant.2.1
    have accepted := invariant.2.2.1
    have routed := invariant.2.2.2.1
    have member := invariant.2.2.2.2
    have auth : authenticated = [] := invariant.1
    have effect : association.tag :: layout frame.enteredPort = layout port := by
      rcases accepted with forward | ⟨empty, origin, output⟩
      · have result := conditions.forward port frame authenticated routed metadata.1
          (Or.inl auth) metadata.2 forward
        simpa [processingStack, auth] using result.2 association selected
      · have result := conditions.output port frame routed origin metadata.1 metadata.2 output
        simpa [processingStack] using result.2 association selected
    refine ⟨auth, ?_, association, (matched_policy_is_configured selected).1, sa, frame, rfl, ?_⟩
    · rw [← effect]
      exact List.mem_cons_of_mem _ member
    · rw [← effect]
      rfl
  | @outerRoute port frame authenticated route chosen atEncryptor =>
    obtain ⟨member, association, configured, sa, previous, same, head⟩ := invariant.2
    have routeChoice := chosen
    change frame = encrypt association sa previous at same
    rw [same] at routeChoice
    have equal := conditions.outerRoute port association configured head sa previous route
      routeChoice atEncryptor
    exact ⟨invariant.1, equal ▸ member⟩
  | @switch a b frame authenticated permitted =>
    have equal := conditions.switch a b frame.packet authenticated permitted (Or.inl invariant.1)
    have entry := invariant.2.2.1
    have member := invariant.2.2.2
    have auth : authenticated = [] := invariant.1
    simp only [processingStack, auth, ↓reduceIte] at equal
    rw [entry] at member
    exact ⟨invariant.1, equal ▸ member⟩
  | @plain port frame authenticated noPolicy =>
    have metadata := invariant.2.1
    have accepted := invariant.2.2.1
    have routed := invariant.2.2.2.1
    have member := invariant.2.2.2.2
    have auth : authenticated = [] := invariant.1
    have equal : layout frame.enteredPort = layout port := by
      rcases accepted with forward | ⟨empty, origin, output⟩
      · have result := conditions.forward port frame authenticated routed metadata.1
          (Or.inl auth) metadata.2 forward
        simpa [processingStack, auth] using result.1 noPolicy
      · have result := conditions.output port frame routed origin metadata.1 metadata.2 output
        simpa [processingStack] using result.1 noPolicy
    exact ⟨auth, equal ▸ member⟩
  | decrypt => exact False.elim (notDecrypt rfl)
  | wire linked => exact ⟨rfl, (conditions.link _ _ linked) ▸ invariant.2⟩
  | «local» => exact ⟨invariant.1, invariant.2.1, invariant.2.2.2⟩
  | deliver => exact invariant
  | drop => exact ⟨invariant.1, trivial⟩

/-- An arbitrary arriving packet cannot cross a checked boundary without a local decrypt.
No initial envelope or authentication claim is assumed. Configured inbound tags identify
which layer was actually removed at the receiving component. -/
theorem inbound_crossing_requires_local_decryption
    (c : Config) (layout : Nat → List Nat) (tag component : Nat)
    (conditions : LocalStackConditions c layout)
    (inboundTags : ∀ port, c.owner port = component → ∀ a ∈ c.inbound port, a.tag = tag)
    {before after : State} {actions : List Action}
    (run : (RestrictedExecution.within (lts c) (fun s => c.owner s.port = component)).MTr
      before actions after)
    (received : before.phase = .received) (unauthenticated : before.authenticated = [])
    (outside : tag ∈ layout before.port)
    (ready : after.phase = .ready) (inside : tag ∉ layout after.port) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => action = .decrypt ∧
        left.frame.tags = tag :: right.frame.tags ∧
        left.frame.payload = before.frame.payload ∧ c.owner left.port = component) := by
  have initial : UndecryptedRegion c layout tag before := by
    simpa [UndecryptedRegion, received] using And.intro unauthenticated outside
  have final : ¬ UndecryptedRegion c layout tag after := by
    intro invariant
    exact inside (by simpa [UndecryptedRegion, ready] using invariant.2)
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, good, bad⟩ :=
    TraceEvents.changing_predicate_has_event _
      (UndecryptedRegion c layout tag) run initial final
  have label : action = .decrypt := by
    by_contra different
    exact bad (undecrypted_step_retains_region conditions step.1 different good)
  have layer : left.frame.tags = tag :: right.frame.tags := by
    have actual := step.1
    have owner := step.2.1
    cases actual <;> try cases label
    case decrypt association sa header rest tracking configured installed bound received outerSource outerDestination esp selected =>
      have equal := inboundTags _ owner association configured
      simp only [Frame.tags, received, List.map_cons]
      simpa [Association.seal, equal]
  exact ⟨earlier, later, left, action, right, sequence,
    RestrictedExecution.project_trace _ _ first, step.1,
    RestrictedExecution.project_trace _ _ last, label, layer,
    execution_payload_identity c (RestrictedExecution.project_trace _ _ first), step.2.1⟩

end TDN.Execution
