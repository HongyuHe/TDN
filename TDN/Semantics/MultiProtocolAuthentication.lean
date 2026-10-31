import TDN.Semantics.MultiProtocolEvents
import TDN.Semantics.RestrictedExecution

namespace TDN.MultiProtocolExecution
open LayeredFrame

def carrierReceiveHeader (port : CarrierPort) : PacketPolicy.Packet :=
  outerHeader port.transmit.destination port.transmit.source "udp"
    port.transmit.destinationPort port.transmit.sourcePort

def carrierInputPacket (c : Config) (entry : Nat) (tracking : String)
    (port : CarrierPort) : PacketPolicy.Packet :=
  { carrierReceiveHeader port with
    ingress := c.ip.interfaceName entry, egress := c.ip.interfaceName entry,
    inboundPolicies := [],
    outboundPolicies := (Execution.selectedAssociations (c.ip.outbound entry)
      (carrierReceiveHeader port)).map Execution.Association.id,
    connectionState := tracking }

/-- A local carrier cannot remove a boundary through an unauthenticated INPUT path.
The check concerns one fixed carrier header and local hook, not a network execution. -/
def CarrierInputCheck (c : Config) (layout : Nat → List Nat) (tag : Nat) : Prop :=
  ∀ port ∈ c.carriers, ∀ entry tracking,
    c.ip.owner entry = c.ip.owner port.routingPort →
    tag ∈ layout entry →
    Execution.accepts (c.ip.inputRules entry) (c.ip.inputFallback entry)
      (carrierInputPacket c entry tracking port) →
    tag ∈ layout port.virtualPort

lemma successful_unwrap_has_receiving_header (port : CarrierPort) (before after : Body)
    (unwrapped : unwrapCarrier port.transmit.source port.transmit.destination
      port.transmit.destinationPort port.transmit.sourcePort port.localSession before = some after) :
    before.visibleHeader = some (carrierReceiveHeader port) := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched =>
      obtain ⟨destination, source, sourcePort, destinationPort, session⟩ := matched
      simp only [Body.visibleHeader, carrierReceiveHeader, destination, source, sourcePort, destinationPort]
    next missed => cases unwrapped

/-- The region is inferred from ports and accepted local rules. No initial encrypted
body, carrier provenance or successful authentication is assumed. -/
def UndecryptedRegion (c : Config) (layout : Nat → List Nat) (tag : Nat) (s : State) : Prop :=
  s.authenticated = [] ∧
  match s.phase with
  | .received | .ready => tag ∈ layout s.port
  | .ingress => ∃ header, s.frame.body.visibleHeader = some header ∧
      c.ip.owner s.port = c.ip.owner s.enteredPort ∧ s.enteredPort = s.port ∧
      tag ∈ layout s.enteredPort
  | .localOutput => ∃ header, s.frame.body.visibleHeader = some header ∧
      c.ip.owner s.port = c.ip.owner s.enteredPort ∧ s.enteredPort = s.port ∧
      LocalHeader c s.enteredPort header ∧ tag ∈ layout s.enteredPort
  | .routed | .outputRouted => ∃ header, s.frame.body.visibleHeader = some header ∧
      c.ip.owner s.port = c.ip.owner s.enteredPort ∧ Routed c s header ∧
      (s.phase = .outputRouted → LocalHeader c s.enteredPort header) ∧
      tag ∈ layout s.enteredPort
  | .filtered => ∃ header, s.frame.body.visibleHeader = some header ∧
      c.ip.owner s.port = c.ip.owner s.enteredPort ∧ Routed c s header ∧
      AcceptedHook c s header ∧ tag ∈ layout s.enteredPort
  | .encapsulated => tag ∈ layout s.port ∧
      ∃ policy ∈ c.ip.outbound s.port, ∃ association previous,
        Execution.StateBindsPolicy association policy ∧
        s.frame.body = .ipsec (policy.seal association) previous ∧
        (layout s.port).head? = some policy.tag
  | .localInput => ∃ header, s.frame.body.visibleHeader = some header ∧
      s.enteredPort = s.port ∧ tag ∈ layout s.enteredPort ∧
      Execution.accepts (c.ip.inputRules s.port) (c.ip.inputFallback s.port)
        (policyHeader c s header)
  | .delivered | .dropped => True

lemma nondecryption_preserves_region {c : Config} {layout : Nat → List Nat} {tag : Nat}
    (conditions : LocalConditions c layout) (carrierCheck : CarrierInputCheck c layout tag)
    {before after : State} {action : Action} (step : Step c before action after)
    (notDecrypt : ¬ IsDecryption action) (invariant : UndecryptedRegion c layout tag before) :
    UndecryptedRegion c layout tag after := by
  cases step with
  | @receive header phase visible tracking =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    exact ⟨trivial, header, visible, trivial, trivial, invariant.2⟩
  | @route header route phase visible chosen entry =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, h, hv, owner, entered, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨empty, header, visible, ?_, ⟨route, chosen, entry.trans entered.symm, rfl⟩,
      (fun impossible => by cases impossible), member⟩
    exact (conditions.ip.routeOwner route chosen.1).trans (entry ▸ owner)
  | @outputRoute header route phase visible chosen entry =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, h, hv, owner, entered, origin, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨empty, header, visible, ?_, ⟨route, chosen, entry.trans entered.symm, rfl⟩,
      (fun _ => origin), member⟩
    exact (conditions.ip.routeOwner route chosen.1).trans (entry ▸ owner)
  | @forwardFilter header phase visible accepted =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, h, hv, owner, routed, origin, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨empty, header, visible, owner, routed, Or.inl accepted, member⟩
  | @outputFilter header phase visible accepted =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, h, hv, owner, routed, origin, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨empty, header, visible, owner, routed, Or.inr ⟨empty, origin trivial, accepted⟩, member⟩
  | @encryptIPsec header policy association phase visible selected installed bound =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, h, hv, owner, routed, accepted, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    have effect := (hook_stack_effect_from_metadata conditions before header (Or.inl empty)
      owner routed accepted).2 policy selected
    have equal : policy.tag :: layout before.enteredPort = layout before.port := by
      simpa [Execution.processingStack, empty] using effect
    refine ⟨empty, ?_, policy, (Execution.matched_policy_is_configured selected).1,
      association, before.frame.body, bound, rfl, ?_⟩
    · rw [← equal]; exact List.mem_cons_of_mem _ member
    · rw [← equal]; rfl
  | @outerRoute header route phase visible chosen entry =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, member, policy, configured, association, body, bound, encrypted, head⟩ := invariant
    have destination : header.destination = policy.receiver := by
      simp only [encrypted, Body.visibleHeader, Option.some.injEq] at visible
      rw [← visible]
      exact bound.2.2.1
    have selectedView : Execution.SelectedRoute c.ip.routes route
        (Execution.encrypt policy association (ipFrame c before header)).packet :=
      (selected_route_metadata _ _ _ _ (by simpa [Execution.encrypt] using destination)).mp chosen
    exact ⟨empty, (conditions.ip.outerRoute before.port policy configured head association
      (ipFrame c before header) route selectedView entry) ▸ member⟩
  | @plain header phase visible noPolicy =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, h, hv, owner, routed, accepted, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    have effect := (hook_stack_effect_from_metadata conditions before header (Or.inl empty)
      owner routed accepted).1 noPolicy
    have equal : layout before.enteredPort = layout before.port := by
      simpa [Execution.processingStack, empty] using effect
    exact ⟨empty, equal ▸ member⟩
  | decryptIPsec => exact False.elim (notDecrypt (Or.inl rfl))
  | @inputFilter header phase visible addressed accepted =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, h, hv, owner, entered, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨empty, header, visible, entered, member, accepted⟩
  | deliver => exact ⟨invariant.1, trivial⟩
  | deliverEthernet => exact ⟨invariant.1, trivial⟩
  | @wire next phase linked =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    exact ⟨trivial, (conditions.wire before.port next linked) ▸ invariant.2⟩
  | @bridge next phase member =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    exact ⟨invariant.1, (conditions.bridge before.port next member) ▸ invariant.2⟩
  | @bridgeOutput next phase member =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    exact ⟨invariant.1, (conditions.bridge before.port next member) ▸ invariant.2⟩
  | @encryptMACsec port association configured phase logical emits =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    have member : tag ∈ layout port.logicalPort := logical ▸ invariant.2
    rw [← conditions.macTransmit port configured association emits.1]
    exact ⟨invariant.1, List.mem_cons_of_mem _ member⟩
  | @unprotectedMACsec port configured phase logical enabled unprotected =>
    obtain ⟨protect, encrypt, zero, _⟩ := conditions.macSecure port configured
    rcases unprotected with impossible | impossible | impossible
    · simp [protect] at impossible
    · simp [encrypt] at impossible
    · exact False.elim (impossible zero)
  | decryptMACsec => exact False.elim (notDecrypt (Or.inr rfl))
  | @uncheckedMACsec port configured phase physical unchecked =>
    have strict := (conditions.macSecure port configured).2.2.2
    simp [strict] at unchecked
  | @encapsulate port configured phase virtualPort =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    refine ⟨trivial, carrierHeader port, rfl, trivial, trivial, ?_, ?_⟩
    · exact Or.inr ⟨port, configured, rfl, rfl⟩
    · exact (conditions.carrierOutput port configured) ▸ (virtualPort ▸ invariant.2)
  | @decapsulate port body configured phase owner unwrapped =>
    simp only [UndecryptedRegion, phase] at invariant ⊢
    obtain ⟨empty, header, visible, entered, member, accepted⟩ := invariant
    have same : header = carrierReceiveHeader port :=
      Option.some.inj (visible.symm.trans (successful_unwrap_has_receiving_header port _ _ unwrapped))
    subst header
    have input : Execution.accepts (c.ip.inputRules before.port) (c.ip.inputFallback before.port)
        (carrierInputPacket c before.port before.tracking port) := by
      simpa only [policyHeader, carrierInputPacket, entered, empty] using accepted
    exact ⟨trivial, carrierCheck port configured before.port before.tracking owner (entered ▸ member) input⟩
  | drop => exact ⟨invariant.1, trivial⟩

/-- The actual receiving association identifies the boundary layer. A MACsec role
annotation on an arbitrary incoming frame is not treated as an extra wire field. -/
def BoundaryDecryption (c : Config) (tag : Nat) (left : State)
    (action : Action) (right : State) : Prop :=
  (action = .decryptIPsec ∧ ∃ policy ∈ c.ip.inbound left.port,
    policy.tag = tag ∧ left.frame.body.protectionLayers = tag :: right.frame.body.protectionLayers) ∨
  (action = .decryptMACsec ∧ ∃ port ∈ c.macPorts,
    left.port = port.physicalPort ∧ right.port = port.logicalPort ∧
    ∃ association ∈ port.receiveAssociations, association.tag = tag ∧
      ∃ transmitted body, left.frame.body = .macsec transmitted body ∧
        right.frame.body = body ∧ SameMACWireIdentity transmitted association)

/-- An arbitrary arriving body cannot cross the component boundary without the
actual IPsec or MACsec receiving operation for that layer on the same payload.
The carrier premise is a local INPUT/header condition, checked separately. -/
theorem inbound_crossing_has_actual_boundary_decryption
    (c : Config) (layout : Nat → List Nat) (tag component : Nat)
    (conditions : LocalConditions c layout) (carrierCheck : CarrierInputCheck c layout tag)
    (ipTags : ∀ entry, c.ip.owner entry = component →
      ∀ policy ∈ c.ip.inbound entry, policy.tag = tag)
    (macTags : ∀ port ∈ c.macPorts, c.ip.owner port.physicalPort = component →
      ∀ association ∈ port.receiveAssociations, association.tag = tag)
    {before after : State} {actions : List Action}
    (run : (RestrictedExecution.within (lts c)
      (fun state => c.ip.owner state.port = component)).MTr before actions after)
    (received : before.phase = .received) (empty : before.authenticated = [])
    (outside : tag ∈ layout before.port) (ready : after.phase = .ready)
    (inside : tag ∉ layout after.port) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => BoundaryDecryption c tag left action right ∧
        c.ip.owner left.port = component ∧ left.frame.payload = before.frame.payload) := by
  have initial : UndecryptedRegion c layout tag before := by
    simpa [UndecryptedRegion, received] using And.intro empty outside
  have final : ¬ UndecryptedRegion c layout tag after := by
    intro valid
    exact inside (by simpa [UndecryptedRegion, ready] using valid.2)
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, good, bad⟩ :=
    TraceEvents.changing_predicate_has_event _
      (UndecryptedRegion c layout tag) run initial final
  have label : IsDecryption action := by
    by_contra absent
    exact bad (nondecryption_preserves_region conditions carrierCheck step.1 absent good)
  have boundary : BoundaryDecryption c tag left action right := by
    have actual := step.1
    have owner := step.2.1
    cases actual <;> simp only [IsDecryption, reduceCtorEq, false_or, or_false] at label
    case decryptIPsec policy association body header phase encrypted configured installed bound visible selected tracking =>
      have same := ipTags _ owner policy configured
      refine Or.inl ⟨rfl, policy, configured, same, ?_⟩
      simp [encrypted, Body.protectionLayers, Execution.Association.seal, same]
    case decryptMACsec port association transmitted body configured phase physical encrypted installed wireIdentity =>
      refine Or.inr ⟨rfl, port, configured, physical, rfl, association, installed, ?_,
        transmitted, body, encrypted, rfl, wireIdentity⟩
      exact macTags port configured (physical ▸ owner) association installed
  exact ⟨earlier, later, left, action, right, sequence,
    RestrictedExecution.project_trace _ _ first, step.1,
    RestrictedExecution.project_trace _ _ last, boundary, step.2.1,
    (all_executions_preserve_payload c (RestrictedExecution.project_trace _ _ first)).1⟩

end TDN.MultiProtocolExecution
