import TDN.Semantics.MultiProtocolHeaders
import TDN.Semantics.MultiProtocolInvariant

namespace TDN.LayeredFrame

lemma HeaderIdentity.source {actual nominal : PacketPolicy.Packet}
    (identity : HeaderIdentity actual nominal) : actual.source = nominal.source := by
  have same := congrArg PacketPolicy.Packet.source identity.1
  exact same

lemma HeaderIdentity.destination {actual nominal : PacketPolicy.Packet}
    (identity : HeaderIdentity actual nominal) : actual.destination = nominal.destination := by
  have same := congrArg PacketPolicy.Packet.destination identity.1
  exact same

lemma Frame.forwarded_visible {frame : Frame} {header : PacketPolicy.Packet}
    (visible : frame.visibleHeader = some header) :
    frame.forwarded.visibleHeader = some { header with hopLimit := header.hopLimit - 1 } := by
  cases nominal : frame.body.visibleHeader with
  | none => simp [Frame.visibleHeader, nominal] at visible
  | some packet =>
    have same : frame.activeHeader.getD packet = header := by
      simpa [Frame.visibleHeader, nominal] using visible
    simp [Frame.forwarded, Frame.visibleHeader, nominal, same]

lemma Frame.pop_visible (frame : Frame) (body : Body) (header : PacketPolicy.Packet)
    (visible : body.visibleHeader = some header) :
    (frame.popHeader body).visibleHeader =
      some ((frame.hiddenHeaders.head?.getD none).getD header) := by
  simp [Frame.visibleHeader, Frame.popHeader, visible]

end TDN.LayeredFrame

namespace TDN.MultiProtocolExecution
open LayeredFrame

abbrev withoutHeaderProcessing (c : Config) : Config := { c with headerProcessing := none }

abbrev HeaderedLocalConditions (c : Config) (layout : Nat → List Nat) :=
  LocalConditions (withoutHeaderProcessing c) layout

lemma carrier_bodies_without_headers (c : Config) (layout : Nat → List Nat) (body : Body) :
    CarrierBodies (withoutHeaderProcessing c) layout body ↔ CarrierBodies c layout body := by
  induction body <;> simp_all [CarrierBodies, withoutHeaderProcessing]

def HeaderedLocalHeader (c : Config) (entry : Nat) (header : PacketPolicy.Packet) : Prop :=
  c.ip.payloadOrigin entry ∨
  ∃ port ∈ c.carriers, port.routingPort = entry ∧ HeaderIdentity header (carrierHeader port)

def HeaderedAcceptedHook (c : Config) (s : State) (header : PacketPolicy.Packet) : Prop :=
  Execution.accepts (c.ip.forwardRules s.port) (c.ip.forwardFallback s.port)
    (policyHeader c s header) ∨
  (s.authenticated = [] ∧ HeaderedLocalHeader c s.enteredPort header ∧
    Execution.accepts (c.ip.outputRules s.port) (c.ip.outputFallback s.port)
      (policyHeader c s header))

def HeaderedStackInvariant (c : Config) (layout : Nat → List Nat) (s : State) : Prop :=
  s.frame.HeadersCoherent ∧ CarrierBodies c layout s.frame.body ∧
  match s.phase with
  | .received | .ready => s.frame.body.protectionLayers = layout s.port
  | .ingress => ∃ header, s.frame.visibleHeader = some header ∧
      Processing c layout s ∧ s.enteredPort = s.port
  | .localOutput => ∃ header, s.frame.visibleHeader = some header ∧
      Processing c layout s ∧ HeaderedLocalHeader c s.enteredPort header ∧
      s.authenticated = [] ∧ s.enteredPort = s.port
  | .routed | .outputRouted => ∃ header, s.frame.visibleHeader = some header ∧
      Processing c layout s ∧ Routed c s header ∧
      (s.phase = .outputRouted → HeaderedLocalHeader c s.enteredPort header ∧ s.authenticated = [])
  | .filtered => ∃ header, s.frame.visibleHeader = some header ∧
      Processing c layout s ∧ Routed c s header ∧ HeaderedAcceptedHook c s header
  | .encapsulated => s.frame.body.protectionLayers = layout s.port ∧
      ∃ policy ∈ c.ip.outbound s.port, ∃ association previous,
        Execution.StateBindsPolicy association policy ∧ s.frame.body = .ipsec (policy.seal association) previous
  | .localInput => ∃ header, s.frame.visibleHeader = some header ∧ Processing c layout s
  | .delivered => s.frame.body.protectionLayers = []
  | .dropped => True

lemma selected_associations_same_header {actual nominal : PacketPolicy.Packet}
    (identity : HeaderIdentity actual nominal) (associations : List Execution.Association) :
    Execution.selectedAssociations associations actual =
      Execution.selectedAssociations associations nominal := by
  simp only [Execution.selectedAssociations, Execution.Association.matches,
    identity.source, identity.destination]

lemma headered_hook_stack_effect {c : Config} {layout : Nat → List Nat}
    (conditions : HeaderedLocalConditions c layout) (s : State) (header : PacketPolicy.Packet)
    (processing : Processing c layout s) (routed : Routed c s header)
    (accepted : HeaderedAcceptedHook c s header) :
    (Execution.selectedAssociations (c.ip.outbound s.port) header = [] →
      Execution.processingStack layout s.enteredPort s.authenticated = layout s.port) ∧
    (∀ policy ∈ Execution.selectedAssociations (c.ip.outbound s.port) header,
      policy.tag :: Execution.processingStack layout s.enteredPort s.authenticated = layout s.port) := by
  rcases accepted with forward | ⟨empty, origin, output⟩
  · exact hook_stack_effect_from_metadata conditions s header processing.2.1 processing.2.2 routed (Or.inl forward)
  · rcases origin with host | ⟨carrier, member, entry, identity⟩
    · exact hook_stack_effect_from_metadata conditions s header processing.2.1 processing.2.2 routed
        (Or.inr ⟨empty, Or.inl host, output⟩)
    · obtain ⟨route, selected, routeEntry, routeExit⟩ := routed
      have nominalRoute : Execution.SelectedRoute c.ip.routes route (carrierHeader carrier) :=
        (selected_route_metadata _ _ _ _ identity.destination).mp selected
      have effect := conditions.carrierPolicy carrier member route nominalRoute
        (routeEntry.trans entry.symm)
      have selectors := selected_associations_same_header identity (c.ip.outbound s.port)
      simpa [Execution.processingStack, empty, entry, routeExit, selectors, withoutHeaderProcessing] using effect

lemma headered_step_preserves_stack {c : Config} {layout : Nat → List Nat}
    (conditions : HeaderedLocalConditions c layout) (processing : HeaderProcessing)
    (mode : c.headerProcessing = some processing) (bounds : HeaderBounds processing)
    {before after : State} {action : Action} (step : Step c before action after)
    (invariant : HeaderedStackInvariant c layout before) :
    HeaderedStackInvariant c layout after := by
  have coherent := invariant.1
  refine ⟨step_preserves_headers processing mode bounds step coherent, ?_⟩
  obtain ⟨wellformed, valid⟩ := invariant.2
  cases step with
  | @receive header phase visible tracking =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [phase] at valid
    exact ⟨wellformed, header, visible,
      ⟨by simpa [Execution.processingStack] using valid, Or.inl rfl, rfl⟩, rfl⟩
  | @route header route phase visible chosen entry =>
    simp only [Config.forwardedFrame_body]
    simp only [Config.visibleHeader, mode] at visible
    simp only [phase] at valid
    obtain ⟨h, hv, current, entered⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨wellformed, { header with hopLimit := header.hopLimit - 1 }, ?_,
      ⟨?_, current.2.1, ?_⟩, ⟨route, ?_, entry.trans entered.symm, rfl⟩, ?_⟩
    · simpa [Config.forwardedFrame, mode] using Frame.forwarded_visible visible
    · simpa [Config.forwardedFrame, mode] using current.1
    · exact (conditions.ip.routeOwner route chosen.1).trans
        (by simpa [entry] using current.2.2)
    · exact (selected_route_metadata _ _ _ _ rfl).mp chosen
    · intro impossible
      cases impossible
  | @outputRoute header route phase visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [phase] at valid
    obtain ⟨h, hv, current, origin, empty, entered⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨wellformed, header, visible, ⟨current.1, current.2.1, ?_⟩,
      ⟨route, chosen, entry.trans entered.symm, rfl⟩, fun _ => ⟨origin, empty⟩⟩
    exact (conditions.ip.routeOwner route chosen.1).trans
      (by simpa [entry] using current.2.2)
  | @forwardFilter header phase visible accepted =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [phase] at valid
    obtain ⟨h, hv, current, routed, _⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨wellformed, header, visible, current, routed, Or.inl accepted⟩
  | @outputFilter header phase visible accepted =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [phase] at valid
    obtain ⟨h, hv, current, routed, origin⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    obtain ⟨origin, empty⟩ := origin trivial
    exact ⟨wellformed, header, visible, current, routed, Or.inr ⟨empty, origin, accepted⟩⟩
  | @encryptIPsec header policy association phase visible selected installed bound =>
    simp only [Config.ipsecFrame_body, CarrierBodies]
    simp only [Config.visibleHeader, mode] at visible
    simp only [phase] at valid
    obtain ⟨h, hv, current, routed, accepted⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    have effect := (headered_hook_stack_effect conditions before header current routed accepted).2 policy selected
    refine ⟨wellformed, ?_, policy, (Execution.matched_policy_is_configured selected).1,
      association, before.frame.body, bound, ?_⟩
    · simpa [Body.protectionLayers, Execution.Association.seal] using (congrArg (List.cons policy.tag) current.1).trans effect
    · rfl
  | @outerRoute header route phase visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [phase] at valid
    obtain ⟨stack, policy, member, association, body, bound, encrypted⟩ := valid
    obtain ⟨nominal, nominalVisible, identity⟩ := before.frame.coherent_visible coherent header visible
    have generated : nominal = outerHeader (policy.seal association).sender
        (policy.seal association).receiver "esp" 0 0 := by
      apply Option.some.inj
      simpa [encrypted, Body.visibleHeader] using nominalVisible.symm
    have destination : header.destination = policy.receiver := by
      rw [identity.destination, generated]
      exact bound.2.2.1
    have selectedView : Execution.SelectedRoute c.ip.routes route
        (Execution.encrypt policy association (ipFrame c before header)).packet :=
      (selected_route_metadata _ _ _ _ (by simpa [Execution.encrypt] using destination)).mp chosen
    have head : (layout before.port).head? = some policy.tag := by
      rw [← stack, encrypted]
      rfl
    exact ⟨wellformed, stack.trans
      (conditions.ip.outerRoute before.port policy member head association (ipFrame c before header)
        route selectedView entry)⟩
  | @plain header phase visible noPolicy =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [phase] at valid
    obtain ⟨h, hv, current, routed, accepted⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨wellformed, current.1.trans
      ((headered_hook_stack_effect conditions before header current routed accepted).1 noPolicy)⟩
  | @decryptIPsec policy association body header phase encrypted configured installed bound visible selected tracking =>
    simp only [Config.restoredFrame_body]
    simp only [phase] at valid
    have recursive : CarrierBodies c layout body := by
      simpa [encrypted, CarrierBodies] using wellformed
    have stack : policy.tag :: body.protectionLayers = layout before.port := by
      simpa [encrypted, Body.protectionLayers, Execution.Association.seal] using valid
    refine ⟨recursive, (before.frame.hiddenHeaders.head?.getD none).getD header, ?_,
      ⟨?_, Or.inr ⟨policy, configured, rfl, body.protectionLayers, stack.symm⟩, rfl⟩, trivial⟩
    · simpa [Config.restoredFrame, mode] using before.frame.pop_visible body header visible
    · simpa [Execution.processingStack] using congrArg List.tail stack
  | @inputFilter header phase visible addressed accepted =>
    simp only [phase] at valid
    obtain ⟨h, hv, current, _⟩ := valid
    exact ⟨wellformed, h, hv, current⟩
  | @deliver header domain phase plain recipient =>
    exact ⟨wellformed, by simp [plain, Body.protectionLayers]⟩
  | @deliverEthernet header domain phase plain recipient =>
    exact ⟨wellformed, by simp [plain, Body.protectionLayers]⟩
  | @wire next phase linked =>
    simp only [phase] at valid
    exact ⟨wellformed, valid.trans (conditions.wire before.port next linked)⟩
  | @bridge next phase member =>
    simp only [phase] at valid
    exact ⟨wellformed, valid.trans (conditions.bridge before.port next member)⟩
  | @bridgeOutput next phase member =>
    simp only [phase] at valid
    exact ⟨wellformed, valid.trans (conditions.bridge before.port next member)⟩
  | @encryptMACsec port association configured phase logical emits =>
    simp only [phase, Config.macsecFrame_body, Body.protectionLayers]
    simp only [phase] at valid
    refine ⟨?_, ?_⟩
    · simpa [CarrierBodies] using (show CarrierBodies c layout before.frame.body ∧
        ∃ port ∈ c.macPorts, port.transmitAssociation = some association from
          ⟨wellformed, port, configured, emits.1⟩)
    · exact (congrArg (List.cons association.tag) valid).trans
        (by simpa [logical] using conditions.macTransmit port configured association emits.1)
  | @unprotectedMACsec port configured phase logical enabled unprotected =>
    obtain ⟨protect, encrypt, zero, _⟩ := conditions.macSecure port configured
    rcases unprotected with impossible | impossible | impossible
    · simp [protect] at impossible
    · simp [encrypt] at impossible
    · exact False.elim (impossible zero)
  | @decryptMACsec port association transmitted body configured phase physical encrypted installed wireIdentity =>
    simp only [phase] at valid
    have records : CarrierBodies c layout body ∧
        ∃ sender ∈ c.macPorts, sender.transmitAssociation = some transmitted := by
      simpa [encrypted, CarrierBodies] using wellformed
    obtain ⟨recursive, sender, member, produced⟩ := records
    have sameTag := conditions.macRoleAgreement sender member transmitted produced port configured
      association installed wireIdentity
    have stack : association.tag :: body.protectionLayers = association.tag :: layout port.logicalPort := by
      calc
        association.tag :: body.protectionLayers = layout before.port := by
          simpa [encrypted, Body.protectionLayers, sameTag] using valid
        _ = association.tag :: layout port.logicalPort := by
          rw [physical, conditions.macReceive port configured association installed]
    refine ⟨?_, ?_⟩
    · simpa using recursive
    · simpa [phase] using congrArg List.tail stack
  | @uncheckedMACsec port configured phase physical unchecked =>
    have checked := (conditions.macSecure port configured).2.2.2
    simp [checked] at unchecked
  | @encapsulate port configured phase virtualPort =>
    simp only [phase] at valid
    have same := conditions.carrierOutput port configured
    have atVirtual : before.frame.body.protectionLayers = layout port.virtualPort := by
      simpa [virtualPort] using valid
    let header := { carrierHeader port with hopLimit := processing.carrierHopLimit port.routingPort }
    refine ⟨?_, header, ?_, ⟨?_, Or.inl rfl, rfl⟩,
      Or.inr ⟨port, configured, rfl, ?_⟩, rfl, rfl⟩
    · simpa [CarrierBodies] using (show CarrierBodies c layout before.frame.body ∧
        ∃ sender ∈ c.carriers, port.transmit = sender.transmit ∧
          before.frame.body.protectionLayers = layout sender.virtualPort from
          ⟨wellformed, port, configured, rfl, atVirtual⟩)
    · simp [Config.carrierFrame, mode, Frame.pushHeader, Frame.visibleHeader,
        Body.visibleHeader, header, carrierHeader]
    · simpa [Execution.processingStack, Body.protectionLayers] using atVirtual.trans same
    · exact ⟨rfl, (bounds port.routingPort).2⟩
  | @decapsulate port body configured phase owner unwrapped =>
    simp only [Config.restoredFrame_body]
    obtain ⟨recursive, layers⟩ := unwrap_carrier_preserves_record conditions port configured
      before.frame.body body
      ((carrier_bodies_without_headers c layout before.frame.body).mpr wellformed) unwrapped
    exact ⟨(carrier_bodies_without_headers c layout body).mp recursive, layers⟩
  | drop => exact ⟨wellformed, trivial⟩

theorem headered_executions_preserve_stack (c : Config) (layout : Nat → List Nat)
    (conditions : HeaderedLocalConditions c layout) (processing : HeaderProcessing)
    (mode : c.headerProcessing = some processing) (bounds : HeaderBounds processing)
    {start finish : State} {actions : List Action}
    (run : (lts c).MTr start actions finish) (initial : HeaderedStackInvariant c layout start) :
    HeaderedStackInvariant c layout finish := by
  have preserved : (lts c).TrInv (HeaderedStackInvariant c layout) := by
    intro before action after step valid
    exact headered_step_preserves_stack conditions processing mode bounds step valid
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initial

end TDN.MultiProtocolExecution
