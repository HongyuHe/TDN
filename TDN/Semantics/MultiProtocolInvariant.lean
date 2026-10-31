import TDN.Semantics.MultiProtocolExecution
import TDN.Semantics.ExecutionInvariant

namespace TDN.MultiProtocolExecution
open LayeredFrame

def Processing (c : Config) (layout : Nat → List Nat) (s : State) : Prop :=
  s.frame.body.protectionLayers = Execution.processingStack layout s.enteredPort s.authenticated ∧
  Execution.LocalAuthentication c.ip layout s.enteredPort s.authenticated ∧
  c.ip.owner s.port = c.ip.owner s.enteredPort

def Routed (c : Config) (s : State) (header : PacketPolicy.Packet) : Prop :=
  ∃ route, Execution.SelectedRoute c.ip.routes route header ∧
    route.ingress = s.enteredPort ∧ route.egress = s.port

def carrierHeader (port : CarrierPort) : PacketPolicy.Packet :=
  outerHeader port.transmit.source port.transmit.destination "udp"
    port.transmit.sourcePort port.transmit.destinationPort

def LocalHeader (c : Config) (entry : Nat) (header : PacketPolicy.Packet) : Prop :=
  c.ip.payloadOrigin entry ∨
  ∃ port ∈ c.carriers, port.routingPort = entry ∧ header = carrierHeader port

def AcceptedHook (c : Config) (s : State) (header : PacketPolicy.Packet) : Prop :=
  Execution.accepts (c.ip.forwardRules s.port) (c.ip.forwardFallback s.port)
    (policyHeader c s header) ∨
  (s.authenticated = [] ∧ LocalHeader c s.enteredPort header ∧
    Execution.accepts (c.ip.outputRules s.port) (c.ip.outputFallback s.port)
      (policyHeader c s header))

def CarrierBodies (c : Config) (layout : Nat → List Nat) : Body → Prop
  | .datagram _ | .ethernet _ => True
  | .ipsec _ body => CarrierBodies c layout body
  | .macsec association body => CarrierBodies c layout body ∧
      ∃ port ∈ c.macPorts, port.transmitAssociation = some association
  | .carrier endpoint body => CarrierBodies c layout body ∧
      ∃ port ∈ c.carriers, endpoint = port.transmit ∧
        body.protectionLayers = layout port.virtualPort

def CarrierPeers (sender receiver : CarrierPort) : Prop :=
  sender.transmit.destination = receiver.transmit.source ∧
  sender.transmit.source = receiver.transmit.destination ∧
  sender.transmit.sourcePort = receiver.transmit.destinationPort ∧
  sender.transmit.destinationPort = receiver.transmit.sourcePort ∧
  sender.transmit.peerSession = receiver.localSession

structure LocalConditions (c : Config) (layout : Nat → List Nat) : Prop where
  ip : Execution.LocalStackConditions c.ip layout
  wire : ∀ a b, c.physicalLink a b → layout a = layout b
  bridge : ∀ a b, c.bridge a b → layout a = layout b
  macTransmit : ∀ port ∈ c.macPorts, ∀ association,
    port.transmitAssociation = some association →
    association.tag :: layout port.logicalPort = layout port.physicalPort
  macReceive : ∀ port ∈ c.macPorts, ∀ association ∈ port.receiveAssociations,
    association.tag :: layout port.logicalPort = layout port.physicalPort
  macRoleAgreement : ∀ sender ∈ c.macPorts, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ c.macPorts,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag
  macSecure : ∀ port ∈ c.macPorts,
    port.settings.protectFrames = true ∧ port.settings.encryptFrames = true ∧
    port.settings.confidentialityOffset = 0 ∧ port.validateStrict = true
  carrierOutput : ∀ port ∈ c.carriers,
    layout port.virtualPort = layout port.routingPort
  carrierPolicy : ∀ carrier ∈ c.carriers, ∀ route,
    Execution.SelectedRoute c.ip.routes route (carrierHeader carrier) →
    route.ingress = carrier.routingPort →
    (Execution.selectedAssociations (c.ip.outbound route.egress) (carrierHeader carrier) = [] →
      layout carrier.routingPort = layout route.egress) ∧
    (∀ policy ∈ Execution.selectedAssociations (c.ip.outbound route.egress) (carrierHeader carrier),
      policy.tag :: layout carrier.routingPort = layout route.egress)
  carrierPeers : ∀ sender ∈ c.carriers, ∀ receiver ∈ c.carriers,
    CarrierPeers sender receiver → layout sender.virtualPort = layout receiver.virtualPort

def StackInvariant (c : Config) (layout : Nat → List Nat) (s : State) : Prop :=
  CarrierBodies c layout s.frame.body ∧
  match s.phase with
  | .received | .ready => s.frame.body.protectionLayers = layout s.port
  | .ingress => ∃ header, s.frame.body.visibleHeader = some header ∧
      Processing c layout s ∧ s.enteredPort = s.port
  | .localOutput => ∃ header, s.frame.body.visibleHeader = some header ∧
      Processing c layout s ∧ LocalHeader c s.enteredPort header ∧ s.authenticated = [] ∧ s.enteredPort = s.port
  | .routed | .outputRouted => ∃ header, s.frame.body.visibleHeader = some header ∧
      Processing c layout s ∧ Routed c s header ∧
      (s.phase = .outputRouted → LocalHeader c s.enteredPort header ∧ s.authenticated = [])
  | .filtered => ∃ header, s.frame.body.visibleHeader = some header ∧
      Processing c layout s ∧ Routed c s header ∧ AcceptedHook c s header
  | .encapsulated => s.frame.body.protectionLayers = layout s.port ∧
      ∃ policy ∈ c.ip.outbound s.port, ∃ association previous,
        Execution.StateBindsPolicy association policy ∧ s.frame.body = .ipsec (policy.seal association) previous
  | .localInput => ∃ header, s.frame.body.visibleHeader = some header ∧ Processing c layout s
  | .delivered => s.frame.body.protectionLayers = []
  | .dropped => True

def ipFrame (c : Config) (s : State) (header : PacketPolicy.Packet) : Execution.Frame :=
  { payload := s.frame.payload, originDomain := s.frame.originDomain,
    packet := { header with ingress := c.ip.interfaceName s.enteredPort, connectionState := s.tracking },
    envelopes := [], enteredPort := s.enteredPort }

lemma selected_route_metadata (routes : List Execution.Route) (route : Execution.Route)
    (first second : PacketPolicy.Packet) (same : first.destination = second.destination) :
    Execution.SelectedRoute routes route first ↔ Execution.SelectedRoute routes route second := by
  simp only [Execution.SelectedRoute, Execution.Route.matches, same]

lemma hook_stack_effect_from_metadata {c : Config} {layout : Nat → List Nat}
    (conditions : LocalConditions c layout) (s : State) (header : PacketPolicy.Packet)
    (authentication : Execution.LocalAuthentication c.ip layout s.enteredPort s.authenticated)
    (owner : c.ip.owner s.port = c.ip.owner s.enteredPort) (routed : Routed c s header)
    (accepted : AcceptedHook c s header) :
    (Execution.selectedAssociations (c.ip.outbound s.port) header = [] →
      Execution.processingStack layout s.enteredPort s.authenticated = layout s.port) ∧
    (∀ policy ∈ Execution.selectedAssociations (c.ip.outbound s.port) header,
      policy.tag :: Execution.processingStack layout s.enteredPort s.authenticated = layout s.port) := by
  have routedView : Execution.RoutedFrame c.ip s.port (ipFrame c s header) := by
    obtain ⟨route, chosen, entry, exit⟩ := routed
    exact ⟨route, (selected_route_metadata _ _ _ _ rfl).mp chosen, entry, exit⟩
  have enteredView : (ipFrame c s header).enteredPort = s.enteredPort := rfl
  have selectors : Execution.selectedAssociations (c.ip.outbound s.port) (ipFrame c s header).packet =
      Execution.selectedAssociations (c.ip.outbound s.port) header := rfl
  have viewed : Execution.policyPacket c.ip s.port (ipFrame c s header) s.authenticated =
      policyHeader c s header := rfl
  rcases accepted with forward | ⟨empty, origin, output⟩
  · have effect := conditions.ip.forward s.port (ipFrame c s header) s.authenticated routedView rfl
      authentication owner (viewed.symm ▸ forward)
    simpa only [selectors, enteredView] using effect
  · have outputView : Execution.policyPacket c.ip s.port (ipFrame c s header) [] =
        policyHeader c s header := by simpa only [empty] using viewed
    rcases origin with host | ⟨carrier, member, entry, same⟩
    · have effect := conditions.ip.output s.port (ipFrame c s header) routedView host rfl
        owner (outputView.symm ▸ output)
      simpa only [selectors, empty, enteredView] using effect
    · obtain ⟨route, selected, routeEntry, routeExit⟩ := routed
      subst header
      have effect := conditions.carrierPolicy carrier member route selected (routeEntry.trans entry.symm)
      simpa [Execution.processingStack, empty, entry, routeExit] using effect

lemma hook_stack_effect {c : Config} {layout : Nat → List Nat}
    (conditions : LocalConditions c layout) (s : State) (header : PacketPolicy.Packet)
    (processing : Processing c layout s) (routed : Routed c s header)
    (accepted : AcceptedHook c s header) :
    (Execution.selectedAssociations (c.ip.outbound s.port) header = [] →
      Execution.processingStack layout s.enteredPort s.authenticated = layout s.port) ∧
    (∀ policy ∈ Execution.selectedAssociations (c.ip.outbound s.port) header,
      policy.tag :: Execution.processingStack layout s.enteredPort s.authenticated = layout s.port) :=
  hook_stack_effect_from_metadata conditions s header processing.2.1 processing.2.2 routed accepted

lemma unwrap_carrier_preserves_record {c : Config} {layout : Nat → List Nat}
    (conditions : LocalConditions c layout) (receiver : CarrierPort)
    (configured : receiver ∈ c.carriers) (before after : Body)
    (valid : CarrierBodies c layout before)
    (unwrapped : unwrapCarrier receiver.transmit.source receiver.transmit.destination
      receiver.transmit.destinationPort receiver.transmit.sourcePort receiver.localSession before = some after) :
    CarrierBodies c layout after ∧ after.protectionLayers = layout receiver.virtualPort := by
  cases before <;> simp only [unwrapCarrier] at unwrapped
  all_goals try cases unwrapped
  case carrier endpoint body =>
    split at unwrapped
    next matched =>
      cases unwrapped
      obtain ⟨recursive, sender, member, same, layers⟩ := valid
      subst endpoint
      exact ⟨recursive, layers.trans (conditions.carrierPeers sender member receiver configured matched)⟩
    next missed => cases unwrapped

lemma step_preserves_stack {c : Config} {layout : Nat → List Nat}
    (conditions : LocalConditions c layout) {before after : State} {action : Action}
    (step : Step c before action after) (invariant : StackInvariant c layout before) :
    StackInvariant c layout after := by
  obtain ⟨wellformed, valid⟩ := invariant
  cases step with
  | @receive header phase visible tracking =>
    simp only [phase] at valid
    refine ⟨wellformed, header, visible, ?_, rfl⟩
    exact ⟨by simpa [Execution.processingStack] using valid, Or.inl rfl, rfl⟩
  | @route header route phase visible chosen entry =>
    simp only [phase] at valid
    obtain ⟨h, hv, processing, entered⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨wellformed, header, visible, ⟨processing.1, processing.2.1, ?_⟩,
      ⟨route, chosen, entry.trans entered.symm, rfl⟩, ?_⟩
    · exact (conditions.ip.routeOwner route chosen.1).trans
        (by simpa [entry] using processing.2.2)
    · intro impossible; cases impossible
  | @outputRoute header route phase visible chosen entry =>
    simp only [phase] at valid
    obtain ⟨h, hv, processing, origin, empty, entered⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨wellformed, header, visible, ⟨processing.1, processing.2.1, ?_⟩,
      ⟨route, chosen, entry.trans entered.symm, rfl⟩, fun _ => ⟨origin, empty⟩⟩
    exact (conditions.ip.routeOwner route chosen.1).trans
      (by simpa [entry] using processing.2.2)
  | @forwardFilter header phase visible accepted =>
    simp only [phase] at valid
    obtain ⟨h, hv, processing, routed, _⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨wellformed, header, visible, processing, routed, Or.inl accepted⟩
  | @outputFilter header phase visible accepted =>
    simp only [phase] at valid
    obtain ⟨h, hv, processing, routed, origin⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    obtain ⟨origin, empty⟩ := origin trivial
    exact ⟨wellformed, header, visible, processing, routed, Or.inr ⟨empty, origin, accepted⟩⟩
  | @encryptIPsec header policy association phase visible selected installed bound =>
    simp only [phase] at valid
    obtain ⟨h, hv, processing, routed, accepted⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    have effect := (hook_stack_effect conditions before header processing routed accepted).2 policy selected
    refine ⟨wellformed, ?_, policy, (Execution.matched_policy_is_configured selected).1,
      association, before.frame.body, bound, rfl⟩
    exact (congrArg (List.cons policy.tag) processing.1).trans effect
  | @outerRoute header route phase visible chosen entry =>
    simp only [phase] at valid
    obtain ⟨stack, policy, member, association, body, bound, encrypted⟩ := valid
    have destination : header.destination = policy.receiver := by
      simp only [encrypted, Body.visibleHeader, Option.some.injEq] at visible
      rw [← visible]
      exact bound.2.2.1
    have selectedView : Execution.SelectedRoute c.ip.routes route
        (Execution.encrypt policy association (ipFrame c before header)).packet :=
      (selected_route_metadata _ _ _ _ (by simpa [Execution.encrypt] using destination)).mp chosen
    have head : (layout before.port).head? = some policy.tag := by
      rw [← stack, encrypted]
      rfl
    exact ⟨wellformed, stack.trans
      (conditions.ip.outerRoute before.port policy member head association (ipFrame c before header) route selectedView entry)⟩
  | @plain header phase visible noPolicy =>
    simp only [phase] at valid
    obtain ⟨h, hv, processing, routed, accepted⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨wellformed, processing.1.trans
      ((hook_stack_effect conditions before header processing routed accepted).1 noPolicy)⟩
  | @decryptIPsec policy association body header phase encrypted configured installed bound visible selected tracking =>
    simp only [phase] at valid
    have recursive : CarrierBodies c layout body := by simpa [encrypted, CarrierBodies] using wellformed
    have stack : policy.tag :: body.protectionLayers = layout before.port := by
      simpa [encrypted, Body.protectionLayers, Execution.Association.seal] using valid
    refine ⟨recursive, header, visible, ⟨?_, ?_, rfl⟩, rfl⟩
    · simpa [Execution.processingStack] using congrArg List.tail stack
    · exact Or.inr ⟨policy, configured, rfl, body.protectionLayers, stack.symm⟩
  | @inputFilter header phase visible addressed accepted =>
    simp only [phase] at valid
    obtain ⟨h, hv, processing, _⟩ := valid
    exact ⟨wellformed, h, hv, processing⟩
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
    simp only [phase] at valid
    refine ⟨⟨wellformed, port, configured, emits.1⟩, ?_⟩
    simp only [phase]
    exact (congrArg (List.cons association.tag) valid).trans
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
    refine ⟨recursive, ?_⟩
    simpa [phase] using congrArg List.tail stack
  | @uncheckedMACsec port configured phase physical unchecked =>
    have checked := (conditions.macSecure port configured).2.2.2
    simp [checked] at unchecked
  | @encapsulate port configured phase virtualPort =>
    simp only [phase] at valid
    have same := conditions.carrierOutput port configured
    have atVirtual : before.frame.body.protectionLayers = layout port.virtualPort := by simpa [virtualPort] using valid
    refine ⟨⟨wellformed, port, configured, rfl, atVirtual⟩,
      outerHeader port.transmit.source port.transmit.destination "udp"
        port.transmit.sourcePort port.transmit.destinationPort, rfl,
      ⟨?_, Or.inl rfl, rfl⟩, Or.inr ⟨port, configured, rfl, rfl⟩, rfl, rfl⟩
    simpa [Execution.processingStack, Body.protectionLayers] using atVirtual.trans same
  | @decapsulate port body configured phase owner unwrapped =>
    obtain ⟨recursive, layers⟩ := unwrap_carrier_preserves_record conditions port configured
      before.frame.body body wellformed unwrapped
    exact ⟨recursive, layers⟩
  | drop => exact ⟨wellformed, trivial⟩

theorem all_executions_preserve_stack (c : Config) (layout : Nat → List Nat)
    (conditions : LocalConditions c layout) {start finish : State} {actions : List Action}
    (run : (lts c).MTr start actions finish) (initial : StackInvariant c layout start) :
    StackInvariant c layout finish := by
  have preserved : (lts c).TrInv (StackInvariant c layout) :=
    fun _ _ _ step valid => step_preserves_stack conditions step valid
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initial

end TDN.MultiProtocolExecution
