import TDN.Semantics.MultiProtocolExecution
import TDN.Semantics.ExecutionInvariant

namespace TDN.MultiProtocolExecution
open LayeredFrame

def Processing (c : Config) (expectedEncapStack : Nat → List Nat) (s : State) : Prop :=
  s.frame.body.protectionLayers = Execution.encapStackAfterIngress expectedEncapStack s.enteredIface s.authenticated ∧
  Execution.LocalAuthentication c.ip expectedEncapStack s.enteredIface s.authenticated ∧
  c.ip.owner s.iface = c.ip.owner s.enteredIface

def Routed (c : Config) (s : State) (header : PacketPolicy.Packet) : Prop :=
  ∃ route, Execution.SelectedRoute c.ip.routes route header ∧
    route.ingress = s.enteredIface ∧ route.egress = s.iface

def carrierHeader (iface : CarrierIface) : PacketPolicy.Packet :=
  outerHeader iface.transmit.source iface.transmit.destination iface.transmit.networkProtocol
    iface.transmit.sourcePort iface.transmit.destinationPort

def LocalHeader (c : Config) (entry : Nat) (header : PacketPolicy.Packet) : Prop :=
  c.ip.payloadOrigin entry ∨
  ∃ iface ∈ c.carriers, iface.routingIface = entry ∧ header = carrierHeader iface

def AcceptedHook (c : Config) (s : State) (header : PacketPolicy.Packet) : Prop :=
  Execution.accepts (c.ip.forwardRules s.iface) (c.ip.forwardFallback s.iface)
    (policyHeader c s header) ∨
  (s.authenticated = [] ∧ LocalHeader c s.enteredIface header ∧
    Execution.accepts (c.ip.outputRules s.iface) (c.ip.outputFallback s.iface)
      (policyHeader c s header))

def CarrierBodies (c : Config) (expectedEncapStack : Nat → List Nat) : Body → Prop
  | .datagram _ | .ethernet _ => True
  | .ipsec _ body => CarrierBodies c expectedEncapStack body
  | .macsec association body => CarrierBodies c expectedEncapStack body ∧
      ∃ iface ∈ c.macIfaces, iface.transmitAssociation = some association
  | .carrier endpoint body => CarrierBodies c expectedEncapStack body ∧
      ∃ iface ∈ c.carriers, endpoint = iface.transmit ∧
        body.protectionLayers = expectedEncapStack iface.virtualIface

def CarrierPeers (sender receiver : CarrierIface) : Prop :=
  sender.transmit.destination = receiver.transmit.source ∧
  sender.transmit.source = receiver.transmit.destination ∧
  sender.transmit.sourcePort = receiver.transmit.destinationPort ∧
  sender.transmit.destinationPort = receiver.transmit.sourcePort ∧
  sender.transmit.peerSession = receiver.localSession ∧
  sender.transmit.protocol = receiver.transmit.protocol ∧
  sender.transmit.networkProtocol = receiver.transmit.networkProtocol

structure LocalConditions (c : Config) (expectedEncapStack : Nat → List Nat) : Prop where
  legacyHeaders : c.headerProcessing = none
  ip : Execution.LocalStackConditions c.ip expectedEncapStack
  linkTransmit : ∀ a b, c.physicalLink a b → expectedEncapStack a = expectedEncapStack b
  bridge : ∀ a b, c.bridge a b → expectedEncapStack a = expectedEncapStack b
  macTransmit : ∀ iface ∈ c.macIfaces, ∀ association,
    iface.transmitAssociation = some association →
    association.tag :: expectedEncapStack iface.logicalIface = expectedEncapStack iface.physicalIface
  macReceive : ∀ iface ∈ c.macIfaces, ∀ association ∈ iface.receiveAssociations,
    association.tag :: expectedEncapStack iface.logicalIface = expectedEncapStack iface.physicalIface
  macRoleAgreement : ∀ sender ∈ c.macIfaces, ∀ transmitted,
    sender.transmitAssociation = some transmitted → ∀ receiver ∈ c.macIfaces,
    ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
    transmitted.tag = association.tag
  macSecure : ∀ iface ∈ c.macIfaces,
    iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
    iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true
  carrierOutput : ∀ iface ∈ c.carriers,
    expectedEncapStack iface.virtualIface = expectedEncapStack iface.routingIface
  carrierPolicy : ∀ carrier ∈ c.carriers, ∀ route,
    Execution.SelectedRoute c.ip.routes route (carrierHeader carrier) →
    route.ingress = carrier.routingIface →
    (Execution.selectedAssociations (c.ip.outbound route.egress) (carrierHeader carrier) = [] →
      expectedEncapStack carrier.routingIface = expectedEncapStack route.egress) ∧
    (∀ policy ∈ Execution.selectedAssociations (c.ip.outbound route.egress) (carrierHeader carrier),
      policy.tag :: expectedEncapStack carrier.routingIface = expectedEncapStack route.egress)
  carrierPeers : ∀ sender ∈ c.carriers, ∀ receiver ∈ c.carriers,
    CarrierPeers sender receiver → expectedEncapStack sender.virtualIface = expectedEncapStack receiver.virtualIface

def StackInvariant (c : Config) (expectedEncapStack : Nat → List Nat) (s : State) : Prop :=
  CarrierBodies c expectedEncapStack s.frame.body ∧
  match s.datapathStage with
  | .received | .ready => s.frame.body.protectionLayers = expectedEncapStack s.iface
  | .ingress => ∃ header, s.frame.body.visibleHeader = some header ∧
      Processing c expectedEncapStack s ∧ s.enteredIface = s.iface
  | .localOutput => ∃ header, s.frame.body.visibleHeader = some header ∧
      Processing c expectedEncapStack s ∧ LocalHeader c s.enteredIface header ∧ s.authenticated = [] ∧ s.enteredIface = s.iface
  | .routed | .outputRouted => ∃ header, s.frame.body.visibleHeader = some header ∧
      Processing c expectedEncapStack s ∧ Routed c s header ∧
      (s.datapathStage = .outputRouted → LocalHeader c s.enteredIface header ∧ s.authenticated = [])
  | .filtered => ∃ header, s.frame.body.visibleHeader = some header ∧
      Processing c expectedEncapStack s ∧ Routed c s header ∧ AcceptedHook c s header
  | .encapsulated => s.frame.body.protectionLayers = expectedEncapStack s.iface ∧
      ∃ policy ∈ c.ip.outbound s.iface, ∃ association previous,
        Execution.StateBindsPolicy association policy ∧ s.frame.body = .ipsec (policy.seal association) previous
  | .localInput => ∃ header, s.frame.body.visibleHeader = some header ∧ Processing c expectedEncapStack s
  | .delivered => s.frame.body.protectionLayers = []
  | .dropped => True

def ipFrame (c : Config) (s : State) (header : PacketPolicy.Packet) : Execution.Frame :=
  { payload := s.frame.payload, originDomain := s.frame.originDomain,
    packet := { header with ingress := c.ip.interfaceName s.enteredIface, connectionState := s.tracking, networkBytes := c.networkBytes s.frame.body s.frame.payload },
    envelopes := [], enteredIface := s.enteredIface }

lemma selected_route_metadata (routes : List Execution.Route) (route : Execution.Route)
    (first second : PacketPolicy.Packet) (same : first.destination = second.destination) :
    Execution.SelectedRoute routes route first ↔ Execution.SelectedRoute routes route second := by
  simp only [Execution.SelectedRoute, Execution.Route.matches, same]

lemma hook_stack_effect_from_metadata {c : Config} {expectedEncapStack : Nat → List Nat}
    (conditions : LocalConditions c expectedEncapStack) (s : State) (header : PacketPolicy.Packet)
    (authentication : Execution.LocalAuthentication c.ip expectedEncapStack s.enteredIface s.authenticated)
    (owner : c.ip.owner s.iface = c.ip.owner s.enteredIface) (routed : Routed c s header)
    (accepted : AcceptedHook c s header) :
    (Execution.selectedAssociations (c.ip.outbound s.iface) header = [] →
      Execution.encapStackAfterIngress expectedEncapStack s.enteredIface s.authenticated = expectedEncapStack s.iface) ∧
    (∀ policy ∈ Execution.selectedAssociations (c.ip.outbound s.iface) header,
      policy.tag :: Execution.encapStackAfterIngress expectedEncapStack s.enteredIface s.authenticated = expectedEncapStack s.iface) := by
  have routedView : Execution.RoutedFrame c.ip s.iface (ipFrame c s header) := by
    obtain ⟨route, chosen, entry, exit⟩ := routed
    exact ⟨route, (selected_route_metadata _ _ _ _ rfl).mp chosen, entry, exit⟩
  have enteredView : (ipFrame c s header).enteredIface = s.enteredIface := rfl
  have selectors : Execution.selectedAssociations (c.ip.outbound s.iface) (ipFrame c s header).packet =
      Execution.selectedAssociations (c.ip.outbound s.iface) header := rfl
  have viewed : Execution.policyPacket c.ip s.iface (ipFrame c s header) s.authenticated =
      policyHeader c s header := rfl
  rcases accepted with forward | ⟨empty, origin, output⟩
  · have effect := conditions.ip.forward s.iface (ipFrame c s header) s.authenticated routedView rfl
      authentication owner (viewed.symm ▸ forward)
    simpa only [selectors, enteredView] using effect
  · have outputView : Execution.policyPacket c.ip s.iface (ipFrame c s header) [] =
        policyHeader c s header := by simpa only [empty] using viewed
    rcases origin with host | ⟨carrier, member, entry, same⟩
    · have effect := conditions.ip.output s.iface (ipFrame c s header) routedView host rfl
        owner (outputView.symm ▸ output)
      simpa only [selectors, empty, enteredView] using effect
    · obtain ⟨route, selected, routeEntry, routeExit⟩ := routed
      subst header
      have effect := conditions.carrierPolicy carrier member route selected (routeEntry.trans entry.symm)
      simpa [Execution.encapStackAfterIngress, empty, entry, routeExit] using effect

lemma hook_stack_effect {c : Config} {expectedEncapStack : Nat → List Nat}
    (conditions : LocalConditions c expectedEncapStack) (s : State) (header : PacketPolicy.Packet)
    (processing : Processing c expectedEncapStack s) (routed : Routed c s header)
    (accepted : AcceptedHook c s header) :
    (Execution.selectedAssociations (c.ip.outbound s.iface) header = [] →
      Execution.encapStackAfterIngress expectedEncapStack s.enteredIface s.authenticated = expectedEncapStack s.iface) ∧
    (∀ policy ∈ Execution.selectedAssociations (c.ip.outbound s.iface) header,
      policy.tag :: Execution.encapStackAfterIngress expectedEncapStack s.enteredIface s.authenticated = expectedEncapStack s.iface) :=
  hook_stack_effect_from_metadata conditions s header processing.2.1 processing.2.2 routed accepted

lemma unwrap_carrier_preserves_record {c : Config} {expectedEncapStack : Nat → List Nat}
    (conditions : LocalConditions c expectedEncapStack) (receiver : CarrierIface)
    (configured : receiver ∈ c.carriers) (before after : Body)
    (valid : CarrierBodies c expectedEncapStack before)
    (unwrapped : unwrapCarrier receiver.transmit.source receiver.transmit.destination
      receiver.transmit.destinationPort receiver.transmit.sourcePort receiver.localSession before receiver.transmit.protocol receiver.transmit.networkProtocol = some after) :
    CarrierBodies c expectedEncapStack after ∧ after.protectionLayers = expectedEncapStack receiver.virtualIface := by
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

lemma step_preserves_stack {c : Config} {expectedEncapStack : Nat → List Nat}
    (conditions : LocalConditions c expectedEncapStack) {before after : State} {action : Action}
    (step : Step c before action after) (invariant : StackInvariant c expectedEncapStack before) :
    StackInvariant c expectedEncapStack after := by
  have mode := conditions.legacyHeaders
  obtain ⟨wellformed, valid⟩ := invariant
  cases step with
  | @receive header datapathStage visible tracking =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [datapathStage] at valid
    refine ⟨wellformed, header, visible, ?_, rfl⟩
    exact ⟨by simpa [Execution.encapStackAfterIngress] using valid, Or.inl rfl, rfl⟩
  | @route header route datapathStage visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [Config.forwardedFrame, mode]

    simp only [datapathStage] at valid
    obtain ⟨h, hv, processing, entered⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨wellformed, header, visible, ⟨processing.1, processing.2.1, ?_⟩,
      ⟨route, chosen, entry.trans entered.symm, rfl⟩, ?_⟩
    · exact (conditions.ip.routeOwner route chosen.1).trans
        (by simpa [entry] using processing.2.2)
    · intro impossible; cases impossible
  | @routeLocalOutput header route datapathStage visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [datapathStage] at valid
    obtain ⟨h, hv, processing, origin, empty, entered⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨wellformed, header, visible, ⟨processing.1, processing.2.1, ?_⟩,
      ⟨route, chosen, entry.trans entered.symm, rfl⟩, fun _ => ⟨origin, empty⟩⟩
    exact (conditions.ip.routeOwner route chosen.1).trans
      (by simpa [entry] using processing.2.2)
  | @forwardFilter header datapathStage visible accepted =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [datapathStage] at valid
    obtain ⟨h, hv, processing, routed, _⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨wellformed, header, visible, processing, routed, Or.inl accepted⟩
  | @outputFilter header datapathStage visible accepted =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [datapathStage] at valid
    obtain ⟨h, hv, processing, routed, origin⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    obtain ⟨origin, empty⟩ := origin trivial
    exact ⟨wellformed, header, visible, processing, routed, Or.inr ⟨empty, origin, accepted⟩⟩
  | @encryptIPsec header policy association datapathStage visible selected installed bound =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [Config.ipsecFrame, mode]

    simp only [datapathStage] at valid
    obtain ⟨h, hv, processing, routed, accepted⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    have effect := (hook_stack_effect conditions before header processing routed accepted).2 policy selected
    refine ⟨wellformed, ?_, policy, (Execution.matched_policy_is_configured selected).1,
      association, before.frame.body, bound, rfl⟩
    exact (congrArg (List.cons policy.tag) processing.1).trans effect
  | @routeOuterPacket header route datapathStage visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [datapathStage] at valid
    obtain ⟨stack, policy, member, association, body, bound, encrypted⟩ := valid
    have destination : header.destination = policy.receiver := by
      simp only [encrypted, Body.visibleHeader, Option.some.injEq] at visible
      rw [← visible]
      exact bound.2.2.1
    have selectedView : Execution.SelectedRoute c.ip.routes route
        (Execution.encrypt policy association (ipFrame c before header)).packet :=
      (selected_route_metadata _ _ _ _ (by simpa [Execution.encrypt] using destination)).mp chosen
    have head : (expectedEncapStack before.iface).head? = some policy.tag := by
      rw [← stack, encrypted]
      rfl
    exact ⟨wellformed, stack.trans
      (conditions.ip.routeOuterPacket before.iface policy member head association (ipFrame c before header) route selectedView entry)⟩
  | @passWithoutTransform header datapathStage visible noPolicy =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [datapathStage] at valid
    obtain ⟨h, hv, processing, routed, accepted⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨wellformed, processing.1.trans
      ((hook_stack_effect conditions before header processing routed accepted).1 noPolicy)⟩
  | @decryptIPsec policy association body header datapathStage encrypted configured installed bound visible selected tracking =>
    simp only [Config.restoredFrame, mode]

    simp only [datapathStage] at valid
    have recursive : CarrierBodies c expectedEncapStack body := by simpa [encrypted, CarrierBodies] using wellformed
    have stack : policy.tag :: body.protectionLayers = expectedEncapStack before.iface := by
      simpa [encrypted, Body.protectionLayers, Execution.Association.seal] using valid
    refine ⟨recursive, header, visible, ⟨?_, ?_, rfl⟩, rfl⟩
    · simpa [Execution.encapStackAfterIngress] using congrArg List.tail stack
    · exact Or.inr ⟨policy, configured, rfl, body.protectionLayers, stack.symm⟩
  | @inputFilter header datapathStage visible addressed accepted =>
    simp only [Config.visibleHeader, mode] at visible

    simp only [datapathStage] at valid
    obtain ⟨h, hv, processing, _⟩ := valid
    exact ⟨wellformed, h, hv, processing⟩
  | @deliver header domain datapathStage plain recipient =>
    exact ⟨wellformed, by simp [plain, Body.protectionLayers]⟩
  | @deliverEthernet header domain datapathStage plain recipient =>
    exact ⟨wellformed, by simp [plain, Body.protectionLayers]⟩
  | @linkTransmit next datapathStage linked =>
    simp only [datapathStage] at valid
    exact ⟨wellformed, valid.trans (conditions.linkTransmit before.iface next linked)⟩
  | @bridge next datapathStage member =>
    simp only [datapathStage] at valid
    exact ⟨wellformed, valid.trans (conditions.bridge before.iface next member)⟩
  | @bridgeOutput next datapathStage member =>
    simp only [datapathStage] at valid
    exact ⟨wellformed, valid.trans (conditions.bridge before.iface next member)⟩
  | @encryptMACsec iface association configured datapathStage logical emits =>
    simp only [Config.macsecFrame, mode]

    simp only [datapathStage] at valid
    refine ⟨⟨wellformed, iface, configured, emits.1⟩, ?_⟩
    simp only [datapathStage]
    exact (congrArg (List.cons association.tag) valid).trans
      (by simpa [logical] using conditions.macTransmit iface configured association emits.1)
  | @unprotectedMACsec iface configured datapathStage logical enabled unprotected =>
    obtain ⟨protect, encrypt, zero, _⟩ := conditions.macSecure iface configured
    rcases unprotected with impossible | impossible | impossible
    · simp [protect] at impossible
    · simp [encrypt] at impossible
    · exact False.elim (impossible zero)
  | @decryptMACsec iface association transmitted body configured datapathStage physical encrypted installed wireIdentity =>
    simp only [Config.restoredFrame, mode]

    simp only [datapathStage] at valid
    have records : CarrierBodies c expectedEncapStack body ∧
        ∃ sender ∈ c.macIfaces, sender.transmitAssociation = some transmitted := by
      simpa [encrypted, CarrierBodies] using wellformed
    obtain ⟨recursive, sender, member, produced⟩ := records
    have sameTag := conditions.macRoleAgreement sender member transmitted produced iface configured
      association installed wireIdentity
    have stack : association.tag :: body.protectionLayers = association.tag :: expectedEncapStack iface.logicalIface := by
      calc
        association.tag :: body.protectionLayers = expectedEncapStack before.iface := by
          simpa [encrypted, Body.protectionLayers, sameTag] using valid
        _ = association.tag :: expectedEncapStack iface.logicalIface := by
          rw [physical, conditions.macReceive iface configured association installed]
    refine ⟨recursive, ?_⟩
    simpa [datapathStage] using congrArg List.tail stack
  | @uncheckedMACsec iface configured datapathStage physical unchecked =>
    have checked := (conditions.macSecure iface configured).2.2.2
    simp [checked] at unchecked
  | @encapsulate iface configured datapathStage virtualIface =>
    simp only [Config.carrierFrame, mode]

    simp only [datapathStage] at valid
    have same := conditions.carrierOutput iface configured
    have atVirtual : before.frame.body.protectionLayers = expectedEncapStack iface.virtualIface := by simpa [virtualIface] using valid
    refine ⟨⟨wellformed, iface, configured, rfl, atVirtual⟩,
      outerHeader iface.transmit.source iface.transmit.destination iface.transmit.networkProtocol
        iface.transmit.sourcePort iface.transmit.destinationPort, rfl,
      ⟨?_, Or.inl rfl, rfl⟩, Or.inr ⟨iface, configured, rfl, rfl⟩, rfl, rfl⟩
    simpa [Execution.encapStackAfterIngress, Body.protectionLayers] using atVirtual.trans same
  | @decapsulate iface body configured datapathStage owner unwrapped =>
    simp only [Config.restoredFrame, mode]

    obtain ⟨recursive, layers⟩ := unwrap_carrier_preserves_record conditions iface configured
      before.frame.body body wellformed unwrapped
    exact ⟨recursive, layers⟩
  | drop => exact ⟨wellformed, trivial⟩

theorem all_executions_preserve_stack (c : Config) (expectedEncapStack : Nat → List Nat)
    (conditions : LocalConditions c expectedEncapStack) {start finish : State} {actions : List Action}
    (run : (lts c).MTr start actions finish) (initial : StackInvariant c expectedEncapStack start) :
    StackInvariant c expectedEncapStack finish := by
  have preserved : (lts c).TrInv (StackInvariant c expectedEncapStack) :=
    fun _ _ _ step valid => step_preserves_stack conditions step valid
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initial

end TDN.MultiProtocolExecution
