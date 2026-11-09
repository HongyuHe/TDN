import TDN.Models.MultiProtocolEncryptionEvents
import TDN.Models.SubgraphScopedTraces

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def carrierReceiveHeader (iface : CarrierIface) : PacketPolicy.Packet :=
  outerHeader iface.transmit.destination iface.transmit.source iface.transmit.networkProtocol
    iface.transmit.destinationPort iface.transmit.sourcePort

def carrierInputPacket (c : Config) (entry : Nat) (tracking : String)
    (networkBytes : Option Nat) (iface : CarrierIface) : PacketPolicy.Packet :=
  { carrierReceiveHeader iface with
    ingress := c.ip.interfaceName entry, egress := c.ip.interfaceName entry,
    matchedInboundPolicyIds := [],
    matchedOutboundPolicyIds := (DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies entry)
      (carrierReceiveHeader iface)).map DataPlaneForwarding.IpsecPolicy.id,
    connectionState := tracking, networkBytes := networkBytes }

def CarrierInputCheck (c : Config) (expectedEncapStack : Nat → List Nat) (tag : Nat) : Prop :=
  ∀ iface ∈ c.carriers, ∀ entry tracking networkBytes,
    c.ip.owner entry = c.ip.owner iface.routingIface →
    tag ∈ expectedEncapStack entry →
    DataPlaneForwarding.accepts (c.ip.inputRules entry) (c.ip.inputFallback entry)
      (carrierInputPacket c entry tracking networkBytes iface) →
    tag ∈ expectedEncapStack iface.virtualIface

lemma successful_unwrap_has_receiving_header (iface : CarrierIface) (before after : Body)
    (unwrapped : unwrapCarrier iface.transmit.source iface.transmit.destination
      iface.transmit.destinationPort iface.transmit.sourcePort iface.localSession before iface.transmit.protocol iface.transmit.networkProtocol = some after) :
    before.visibleHeader = some (carrierReceiveHeader iface) := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched =>
      obtain ⟨destination, source, sourcePort, destinationPort, session, protocol, networkProtocol⟩ := matched
      simp only [Body.visibleHeader, carrierReceiveHeader, destination, source, sourcePort, destinationPort, networkProtocol]
    next missed => cases unwrapped

def UndecryptedRegion (c : Config) (expectedEncapStack : Nat → List Nat) (tag : Nat) (s : State) : Prop :=
  s.authenticated = [] ∧
  match s.datapathStage with
  | .received | .egressReady => tag ∈ expectedEncapStack s.iface
  | .ingress => ∃ header, s.frame.body.visibleHeader = some header ∧
      c.ip.owner s.iface = c.ip.owner s.enteredIface ∧ s.enteredIface = s.iface ∧
      tag ∈ expectedEncapStack s.enteredIface
  | .localOutput => ∃ header, s.frame.body.visibleHeader = some header ∧
      c.ip.owner s.iface = c.ip.owner s.enteredIface ∧ s.enteredIface = s.iface ∧
      LocalHeader c s.enteredIface header ∧ tag ∈ expectedEncapStack s.enteredIface
  | .routed | .outputRouted => ∃ header, s.frame.body.visibleHeader = some header ∧
      c.ip.owner s.iface = c.ip.owner s.enteredIface ∧ Routed c s header ∧
      (s.datapathStage = .outputRouted → LocalHeader c s.enteredIface header) ∧
      tag ∈ expectedEncapStack s.enteredIface
  | .filtered => ∃ header, s.frame.body.visibleHeader = some header ∧
      c.ip.owner s.iface = c.ip.owner s.enteredIface ∧ Routed c s header ∧
      AcceptedHook c s header ∧ tag ∈ expectedEncapStack s.enteredIface
  | .encapsulated => tag ∈ expectedEncapStack s.iface ∧
      ∃ policy ∈ c.ip.egressPolicies s.iface, ∃ association previous,
        DataPlaneForwarding.saMatchesPolicy association policy ∧
        s.frame.body = .ipsec (policy.seal association) previous ∧
        (expectedEncapStack s.iface).head? = some policy.tag
  | .localInput => ∃ header, s.frame.body.visibleHeader = some header ∧
      s.enteredIface = s.iface ∧ tag ∈ expectedEncapStack s.enteredIface ∧
      DataPlaneForwarding.accepts (c.ip.inputRules s.iface) (c.ip.inputFallback s.iface)
        (policyHeader c s header)
  | .delivered | .dropped => True

lemma nondecryption_preserves_region {c : Config} {expectedEncapStack : Nat → List Nat} {tag : Nat}
    (conditions : LocalConditions c expectedEncapStack) (carrierCheck : CarrierInputCheck c expectedEncapStack tag)
    {before after : State} {action : Action} (step : Step c before action after)
    (notDecrypt : ¬ IsDecryption action) (invariant : UndecryptedRegion c expectedEncapStack tag before) :
    UndecryptedRegion c expectedEncapStack tag after := by
  have mode := conditions.legacyHeaders
  cases step with
  | @receive header datapathStage visible tracking =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    exact ⟨trivial, header, visible, trivial, trivial, invariant.2⟩
  | @route header route datapathStage visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [Config.forwardedFrame, mode]

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, h, hv, owner, entered, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨empty, header, visible, ?_, ⟨route, chosen, entry.trans entered.symm, rfl⟩,
      (fun impossible => by cases impossible), member⟩
    exact (conditions.ip.routeOwner route chosen.1).trans (entry ▸ owner)
  | @routeLocalOutput header route datapathStage visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, h, hv, owner, entered, origin, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨empty, header, visible, ?_, ⟨route, chosen, entry.trans entered.symm, rfl⟩,
      (fun _ => origin), member⟩
    exact (conditions.ip.routeOwner route chosen.1).trans (entry ▸ owner)
  | @forwardFilter header datapathStage visible accepted =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, h, hv, owner, routed, origin, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨empty, header, visible, owner, routed, Or.inl accepted, member⟩
  | @outputFilter header datapathStage visible accepted =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, h, hv, owner, routed, origin, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨empty, header, visible, owner, routed, Or.inr ⟨empty, origin trivial, accepted⟩, member⟩
  | @encryptIPsec header policy association datapathStage visible selected installed bound =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [Config.ipsecFrame, mode]

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, h, hv, owner, routed, accepted, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    have effect := (hook_stack_effect_from_metadata conditions before header (Or.inl empty)
      owner routed accepted).2 policy selected
    have equal : policy.tag :: expectedEncapStack before.enteredIface = expectedEncapStack before.iface := by
      simpa [DataPlaneForwarding.encapStackAfterIngress, empty] using effect
    refine ⟨empty, ?_, policy, (DataPlaneForwarding.matched_policy_is_configured selected).1,
      association, before.frame.body, bound, rfl, ?_⟩
    · rw [← equal]; exact List.mem_cons_of_mem _ member
    · rw [← equal]; rfl
  | @routeOuterPacket header route datapathStage visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, member, policy, configured, association, body, bound, encrypted, head⟩ := invariant
    have destination : header.destination = policy.receiver := by
      simp only [encrypted, Body.visibleHeader, Option.some.injEq] at visible
      rw [← visible]
      exact bound.2.2.1
    have selectedView : DataPlaneForwarding.SelectedFibRoute c.ip.routes route
        (DataPlaneForwarding.encrypt policy association (ipFrame c before header)).packet :=
      (selected_route_metadata _ _ _ _ (by simpa [DataPlaneForwarding.encrypt] using destination)).mp chosen
    exact ⟨empty, (conditions.ip.routeOuterPacket before.iface policy configured head association
      (ipFrame c before header) route selectedView entry) ▸ member⟩
  | @forwardWithoutEncap header datapathStage visible noPolicy =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, h, hv, owner, routed, accepted, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    have effect := (hook_stack_effect_from_metadata conditions before header (Or.inl empty)
      owner routed accepted).1 noPolicy
    have equal : expectedEncapStack before.enteredIface = expectedEncapStack before.iface := by
      simpa [DataPlaneForwarding.encapStackAfterIngress, empty] using effect
    exact ⟨empty, equal ▸ member⟩
  | decryptIPsec => exact False.elim (notDecrypt (Or.inl rfl))
  | @inputFilter header datapathStage visible addressed accepted =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, h, hv, owner, entered, member⟩ := invariant
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨empty, header, visible, entered, member, accepted⟩
  | deliver => exact ⟨invariant.1, trivial⟩
  | deliverEthernet => exact ⟨invariant.1, trivial⟩
  | @linkTransmit next datapathStage linked =>
    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    exact ⟨trivial, (conditions.linkTransmit before.iface next linked) ▸ invariant.2⟩
  | @bridge next datapathStage member =>
    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    exact ⟨invariant.1, (conditions.bridge before.iface next member) ▸ invariant.2⟩
  | @bridgeOutput next datapathStage member =>
    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    exact ⟨invariant.1, (conditions.bridge before.iface next member) ▸ invariant.2⟩
  | @encryptMACsec iface association configured datapathStage logical emits =>
    simp only [Config.macsecFrame, mode]

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    have member : tag ∈ expectedEncapStack iface.logicalIface := logical ▸ invariant.2
    rw [← conditions.macTransmit iface configured association emits.1]
    exact ⟨invariant.1, List.mem_cons_of_mem _ member⟩
  | @unprotectedMACsec iface configured datapathStage logical enabled unprotected =>
    obtain ⟨protect, encrypt, zero, _⟩ := conditions.macSecure iface configured
    rcases unprotected with impossible | impossible | impossible
    · simp [protect] at impossible
    · simp [encrypt] at impossible
    · exact False.elim (impossible zero)
  | decryptMACsec => exact False.elim (notDecrypt (Or.inr rfl))
  | @uncheckedMACsec iface configured datapathStage physical unchecked =>
    have strict := (conditions.macSecure iface configured).2.2.2
    simp [strict] at unchecked
  | @encapsulate iface configured datapathStage virtualIface =>
    simp only [Config.carrierFrame, mode]

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    refine ⟨trivial, carrierHeader iface, rfl, trivial, trivial, ?_, ?_⟩
    · exact Or.inr ⟨iface, configured, rfl, rfl⟩
    · exact (conditions.carrierOutput iface configured) ▸ (virtualIface ▸ invariant.2)
  | @decapsulate iface body configured datapathStage owner unwrapped =>
    simp only [Config.restoredFrame, mode]

    simp only [UndecryptedRegion, datapathStage] at invariant ⊢
    obtain ⟨empty, header, visible, entered, member, accepted⟩ := invariant
    have same : header = carrierReceiveHeader iface :=
      Option.some.inj (visible.symm.trans (successful_unwrap_has_receiving_header iface _ _ unwrapped))
    subst header
    have input : DataPlaneForwarding.accepts (c.ip.inputRules before.iface) (c.ip.inputFallback before.iface)
        (carrierInputPacket c before.iface before.tracking
          (c.networkBytes before.frame.body before.frame.payload) iface) := by
      simpa only [policyHeader, carrierInputPacket, entered, empty] using accepted
    exact ⟨trivial, carrierCheck iface configured before.iface before.tracking
      (c.networkBytes before.frame.body before.frame.payload) owner (entered ▸ member) input⟩
  | drop => exact ⟨invariant.1, trivial⟩

def BoundaryDecryption (c : Config) (tag : Nat) (left : State)
    (action : Action) (right : State) : Prop :=
  (action = .decryptIPsec ∧ ∃ policy ∈ c.ip.ingressPolicies left.iface,
    policy.tag = tag ∧ left.frame.body.protectionLayers = tag :: right.frame.body.protectionLayers) ∨
  (action = .decryptMACsec ∧ ∃ iface ∈ c.macIfaces,
    left.iface = iface.physicalIface ∧ right.iface = iface.logicalIface ∧
    ∃ association ∈ iface.receiveAssociations, association.tag = tag ∧
      ∃ transmitted body, left.frame.body = .macsec transmitted body ∧
        right.frame.body = body ∧ SameMACWireIdentity transmitted association)

theorem inbound_crossing_has_actual_boundary_decryption
    (c : Config) (expectedEncapStack : Nat → List Nat) (tag component : Nat)
    (conditions : LocalConditions c expectedEncapStack) (carrierCheck : CarrierInputCheck c expectedEncapStack tag)
    (ipTags : ∀ entry, c.ip.owner entry = component →
      ∀ policy ∈ c.ip.ingressPolicies entry, policy.tag = tag)
    (macTags : ∀ iface ∈ c.macIfaces, c.ip.owner iface.physicalIface = component →
      ∀ association ∈ iface.receiveAssociations, association.tag = tag)
    {before after : State} {actions : List Action}
    (run : (RestrictedExecution.within (lts c)
      (fun state => c.ip.owner state.iface = component)).MTr before actions after)
    (received : before.datapathStage = .received) (empty : before.authenticated = [])
    (outside : tag ∈ expectedEncapStack before.iface) (ready : after.datapathStage = .egressReady)
    (inside : tag ∉ expectedEncapStack after.iface) :
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => BoundaryDecryption c tag left action right ∧
        c.ip.owner left.iface = component ∧ left.frame.payload = before.frame.payload) := by
  have initial : UndecryptedRegion c expectedEncapStack tag before := by
    simpa [UndecryptedRegion, received] using And.intro empty outside
  have final : ¬ UndecryptedRegion c expectedEncapStack tag after := by
    intro valid
    exact inside (by simpa [UndecryptedRegion, ready] using valid.2)
  obtain ⟨earlier, later, left, action, right, sequence, first, step, last, good, bad⟩ :=
    TraceEvents.changing_predicate_has_event _
      (UndecryptedRegion c expectedEncapStack tag) run initial final
  have label : IsDecryption action := by
    by_contra absent
    exact bad (nondecryption_preserves_region conditions carrierCheck step.1 absent good)
  have boundary : BoundaryDecryption c tag left action right := by
    have actual := step.1
    have owner := step.2.1
    cases actual <;> simp only [IsDecryption, reduceCtorEq, false_or, or_false] at label
    case decryptIPsec policy association body header datapathStage encrypted configured installed bound visible selected tracking =>
      have same := ipTags _ owner policy configured
      refine Or.inl ⟨rfl, policy, configured, same, ?_⟩
      simp [encrypted, Body.protectionLayers, DataPlaneForwarding.IpsecPolicy.seal, same]
    case decryptMACsec iface association transmitted body configured datapathStage physical encrypted installed spi =>
      refine Or.inr ⟨rfl, iface, configured, physical, rfl, association, installed, ?_,
        transmitted, body, encrypted, (by simp), spi⟩
      exact macTags iface configured (physical ▸ owner) association installed
  exact ⟨earlier, later, left, action, right, sequence,
    RestrictedExecution.project_trace _ _ first, step.1,
    RestrictedExecution.project_trace _ _ last, boundary, step.2.1,
    (all_traces_preserve_payload c (RestrictedExecution.project_trace _ _ first)).1⟩

end TDN.MultiProtocolForwarding
