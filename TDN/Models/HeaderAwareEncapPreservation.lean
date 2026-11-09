import TDN.Models.MultiProtocolHeaderCoherence
import TDN.Models.MultiProtocolEncapPreservation

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

namespace TDN.MultiProtocolForwarding
open LayeredFrame

abbrev withoutHeaderProcessing (c : Config) : Config := { c with headerProcessing := none }

abbrev HeaderedLocalConditions (c : Config) (expectedEncapStack : Nat → List Nat) :=
  LocalConditions (withoutHeaderProcessing c) expectedEncapStack

lemma carrier_bodies_without_headers (c : Config) (expectedEncapStack : Nat → List Nat) (body : Body) :
    CarrierBodies (withoutHeaderProcessing c) expectedEncapStack body ↔ CarrierBodies c expectedEncapStack body := by
  induction body <;> simp_all [CarrierBodies, withoutHeaderProcessing]

def HeaderedLocalHeader (c : Config) (entry : Nat) (header : PacketPolicy.Packet) : Prop :=
  c.ip.canOriginateTraffic entry ∨
  ∃ iface ∈ c.carriers, iface.routingIface = entry ∧ HeaderIdentity header (carrierHeader iface)

def HeaderedAcceptedHook (c : Config) (s : State) (header : PacketPolicy.Packet) : Prop :=
  DataPlaneForwarding.accepts (c.ip.forwardRules s.iface) (c.ip.forwardFallback s.iface)
    (policyHeader c s header) ∨
  (s.authenticated = [] ∧ HeaderedLocalHeader c s.enteredIface header ∧
    DataPlaneForwarding.accepts (c.ip.outputRules s.iface) (c.ip.outputFallback s.iface)
      (policyHeader c s header))

def HeaderedStackInvariant (c : Config) (expectedEncapStack : Nat → List Nat) (s : State) : Prop :=
  s.frame.HeadersCoherent ∧ CarrierBodies c expectedEncapStack s.frame.body ∧
  match s.datapathStage with
  | .received | .egressReady => s.frame.body.protectionLayers = expectedEncapStack s.iface
  | .ingress => ∃ header, s.frame.visibleHeader = some header ∧
      Processing c expectedEncapStack s ∧ s.enteredIface = s.iface
  | .localOutput => ∃ header, s.frame.visibleHeader = some header ∧
      Processing c expectedEncapStack s ∧ HeaderedLocalHeader c s.enteredIface header ∧
      s.authenticated = [] ∧ s.enteredIface = s.iface
  | .routed | .outputRouted => ∃ header, s.frame.visibleHeader = some header ∧
      Processing c expectedEncapStack s ∧ Routed c s header ∧
      (s.datapathStage = .outputRouted → HeaderedLocalHeader c s.enteredIface header ∧ s.authenticated = [])
  | .filtered => ∃ header, s.frame.visibleHeader = some header ∧
      Processing c expectedEncapStack s ∧ Routed c s header ∧ HeaderedAcceptedHook c s header
  | .encapsulated => s.frame.body.protectionLayers = expectedEncapStack s.iface ∧
      ∃ policy ∈ c.ip.egressPolicies s.iface, ∃ association previous,
        DataPlaneForwarding.saMatchesPolicy association policy ∧ s.frame.body = .ipsec (policy.seal association) previous
  | .localInput => ∃ header, s.frame.visibleHeader = some header ∧ Processing c expectedEncapStack s
  | .delivered => s.frame.body.protectionLayers = []
  | .dropped => True

lemma selected_associations_same_header {actual nominal : PacketPolicy.Packet}
    (identity : HeaderIdentity actual nominal) (associations : List DataPlaneForwarding.IpsecPolicy) :
    DataPlaneForwarding.lookupSpdPolicies associations actual =
      DataPlaneForwarding.lookupSpdPolicies associations nominal := by
  simp only [DataPlaneForwarding.lookupSpdPolicies, DataPlaneForwarding.IpsecPolicy.matches,
    identity.source, identity.destination]

lemma headered_hook_stack_effect {c : Config} {expectedEncapStack : Nat → List Nat}
    (conditions : HeaderedLocalConditions c expectedEncapStack) (s : State) (header : PacketPolicy.Packet)
    (processing : Processing c expectedEncapStack s) (routed : Routed c s header)
    (accepted : HeaderedAcceptedHook c s header) :
    (DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies s.iface) header = [] →
      DataPlaneForwarding.encapStackAfterIngress expectedEncapStack s.enteredIface s.authenticated = expectedEncapStack s.iface) ∧
    (∀ policy ∈ DataPlaneForwarding.lookupSpdPolicies (c.ip.egressPolicies s.iface) header,
      policy.tag :: DataPlaneForwarding.encapStackAfterIngress expectedEncapStack s.enteredIface s.authenticated = expectedEncapStack s.iface) := by
  rcases accepted with forward | ⟨empty, origin, output⟩
  · exact hook_stack_effect_from_metadata conditions s header processing.2.1 processing.2.2 routed (Or.inl forward)
  · rcases origin with host | ⟨carrier, member, entry, identity⟩
    · exact hook_stack_effect_from_metadata conditions s header processing.2.1 processing.2.2 routed
        (Or.inr ⟨empty, Or.inl host, output⟩)
    · obtain ⟨route, selected, routeEntry, routeExit⟩ := routed
      have nominalRoute : DataPlaneForwarding.SelectedFibRoute c.ip.routes route (carrierHeader carrier) :=
        (selected_route_metadata _ _ _ _ identity.destination).mp selected
      have effect := conditions.carrierPolicy carrier member route nominalRoute
        (routeEntry.trans entry.symm)
      have selectors := selected_associations_same_header identity (c.ip.egressPolicies s.iface)
      simpa [DataPlaneForwarding.encapStackAfterIngress, empty, entry, routeExit, selectors, withoutHeaderProcessing] using effect

lemma headered_step_preserves_stack {c : Config} {expectedEncapStack : Nat → List Nat}
    (conditions : HeaderedLocalConditions c expectedEncapStack) (processing : HeaderProcessing)
    (mode : c.headerProcessing = some processing) (bounds : HeaderBounds processing)
    {before after : State} {action : Action} (step : Step c before action after)
    (invariant : HeaderedStackInvariant c expectedEncapStack before) :
    HeaderedStackInvariant c expectedEncapStack after := by
  have coherent := invariant.1
  refine ⟨step_preserves_headers processing mode bounds step coherent, ?_⟩
  obtain ⟨wellformed, valid⟩ := invariant.2
  cases step with
  | @receive header datapathStage visible tracking =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [datapathStage] at valid
    exact ⟨wellformed, header, visible,
      ⟨by simpa [DataPlaneForwarding.encapStackAfterIngress] using valid, Or.inl rfl, rfl⟩, rfl⟩
  | @route header route datapathStage visible chosen entry =>
    simp only [Config.forwardedFrame_body]
    simp only [Config.visibleHeader, mode] at visible
    simp only [datapathStage] at valid
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
  | @routeLocalOutput header route datapathStage visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [datapathStage] at valid
    obtain ⟨h, hv, current, origin, empty, entered⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    refine ⟨wellformed, header, visible, ⟨current.1, current.2.1, ?_⟩,
      ⟨route, chosen, entry.trans entered.symm, rfl⟩, fun _ => ⟨origin, empty⟩⟩
    exact (conditions.ip.routeOwner route chosen.1).trans
      (by simpa [entry] using current.2.2)
  | @forwardFilter header datapathStage visible accepted =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [datapathStage] at valid
    obtain ⟨h, hv, current, routed, _⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨wellformed, header, visible, current, routed, Or.inl accepted⟩
  | @outputFilter header datapathStage visible accepted =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [datapathStage] at valid
    obtain ⟨h, hv, current, routed, origin⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    obtain ⟨origin, empty⟩ := origin trivial
    exact ⟨wellformed, header, visible, current, routed, Or.inr ⟨empty, origin, accepted⟩⟩
  | @encryptIPsec header policy association datapathStage visible selected installed bound =>
    simp only [Config.ipsecFrame_body, CarrierBodies]
    simp only [Config.visibleHeader, mode] at visible
    simp only [datapathStage] at valid
    obtain ⟨h, hv, current, routed, accepted⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    have effect := (headered_hook_stack_effect conditions before header current routed accepted).2 policy selected
    refine ⟨wellformed, ?_, policy, (DataPlaneForwarding.matched_policy_is_configured selected).1,
      association, before.frame.body, bound, ?_⟩
    · simpa [Body.protectionLayers, DataPlaneForwarding.IpsecPolicy.seal] using (congrArg (List.cons policy.tag) current.1).trans effect
    · rfl
  | @routeOuterPacket header route datapathStage visible chosen entry =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [datapathStage] at valid
    obtain ⟨stack, policy, member, association, body, bound, encrypted⟩ := valid
    obtain ⟨nominal, nominalVisible, identity⟩ := before.frame.coherent_visible coherent header visible
    have generated : nominal = outerHeader (policy.seal association).sender
        (policy.seal association).receiver "esp" 0 0 := by
      apply Option.some.inj
      simpa [encrypted, Body.visibleHeader] using nominalVisible.symm
    have destination : header.destination = policy.receiver := by
      rw [identity.destination, generated]
      exact bound.2.2.1
    have selectedView : DataPlaneForwarding.SelectedFibRoute c.ip.routes route
        (DataPlaneForwarding.encrypt policy association (ipFrame c before header)).packet :=
      (selected_route_metadata _ _ _ _ (by simpa [DataPlaneForwarding.encrypt] using destination)).mp chosen
    have head : (expectedEncapStack before.iface).head? = some policy.tag := by
      rw [← stack, encrypted]
      rfl
    exact ⟨wellformed, stack.trans
      (conditions.ip.routeOuterPacket before.iface policy member head association (ipFrame c before header)
        route selectedView entry)⟩
  | @forwardWithoutEncap header datapathStage visible noPolicy =>
    simp only [Config.visibleHeader, mode] at visible
    simp only [datapathStage] at valid
    obtain ⟨h, hv, current, routed, accepted⟩ := valid
    have same : h = header := Option.some.inj (hv.symm.trans visible)
    subst h
    exact ⟨wellformed, current.1.trans
      ((headered_hook_stack_effect conditions before header current routed accepted).1 noPolicy)⟩
  | @decryptIPsec policy association body header datapathStage encrypted configured installed bound visible selected tracking =>
    simp only [Config.restoredFrame_body]
    simp only [datapathStage] at valid
    have recursive : CarrierBodies c expectedEncapStack body := by
      simpa [encrypted, CarrierBodies] using wellformed
    have stack : policy.tag :: body.protectionLayers = expectedEncapStack before.iface := by
      simpa [encrypted, Body.protectionLayers, DataPlaneForwarding.IpsecPolicy.seal] using valid
    refine ⟨recursive, (before.frame.hiddenHeaders.head?.getD none).getD header, ?_,
      ⟨?_, Or.inr ⟨policy, configured, rfl, body.protectionLayers, stack.symm⟩, rfl⟩, trivial⟩
    · simpa [Config.restoredFrame, mode] using before.frame.pop_visible body header visible
    · simpa [DataPlaneForwarding.encapStackAfterIngress] using congrArg List.tail stack
  | @inputFilter header datapathStage visible addressed accepted =>
    simp only [datapathStage] at valid
    obtain ⟨h, hv, current, _⟩ := valid
    exact ⟨wellformed, h, hv, current⟩
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
    simp only [datapathStage, Config.macsecFrame_body, Body.protectionLayers]
    simp only [datapathStage] at valid
    refine ⟨?_, ?_⟩
    · simpa [CarrierBodies] using (show CarrierBodies c expectedEncapStack before.frame.body ∧
        ∃ iface ∈ c.macIfaces, iface.transmitAssociation = some association from
          ⟨wellformed, iface, configured, emits.1⟩)
    · exact (congrArg (List.cons association.tag) valid).trans
        (by simpa [logical] using conditions.macTransmit iface configured association emits.1)
  | @unprotectedMACsec iface configured datapathStage logical enabled unprotected =>
    obtain ⟨protect, encrypt, zero, _⟩ := conditions.macSecure iface configured
    rcases unprotected with impossible | impossible | impossible
    · simp [protect] at impossible
    · simp [encrypt] at impossible
    · exact False.elim (impossible zero)
  | @decryptMACsec iface association transmitted body configured datapathStage physical encrypted installed spi =>
    simp only [datapathStage] at valid
    have records : CarrierBodies c expectedEncapStack body ∧
        ∃ sender ∈ c.macIfaces, sender.transmitAssociation = some transmitted := by
      simpa [encrypted, CarrierBodies] using wellformed
    obtain ⟨recursive, sender, member, produced⟩ := records
    have sameTag := conditions.macRoleAgreement sender member transmitted produced iface configured
      association installed spi
    have stack : association.tag :: body.protectionLayers = association.tag :: expectedEncapStack iface.logicalIface := by
      calc
        association.tag :: body.protectionLayers = expectedEncapStack before.iface := by
          simpa [encrypted, Body.protectionLayers, sameTag] using valid
        _ = association.tag :: expectedEncapStack iface.logicalIface := by
          rw [physical, conditions.macReceive iface configured association installed]
    refine ⟨?_, ?_⟩
    · simpa using recursive
    · simpa [datapathStage] using congrArg List.tail stack
  | @uncheckedMACsec iface configured datapathStage physical unchecked =>
    have checked := (conditions.macSecure iface configured).2.2.2
    simp [checked] at unchecked
  | @encapsulate iface configured datapathStage virtualIface =>
    simp only [datapathStage] at valid
    have same := conditions.carrierOutput iface configured
    have atVirtual : before.frame.body.protectionLayers = expectedEncapStack iface.virtualIface := by
      simpa [virtualIface] using valid
    let header := { carrierHeader iface with hopLimit := processing.carrierHopLimit iface.routingIface }
    refine ⟨?_, header, ?_, ⟨?_, Or.inl rfl, rfl⟩,
      Or.inr ⟨iface, configured, rfl, ?_⟩, rfl, rfl⟩
    · simpa [CarrierBodies] using (show CarrierBodies c expectedEncapStack before.frame.body ∧
        ∃ sender ∈ c.carriers, iface.transmit = sender.transmit ∧
          before.frame.body.protectionLayers = expectedEncapStack sender.virtualIface from
          ⟨wellformed, iface, configured, rfl, atVirtual⟩)
    · simp [Config.carrierFrame, mode, Frame.pushHeader, Frame.visibleHeader,
        Body.visibleHeader, header, carrierHeader]
    · simpa [DataPlaneForwarding.encapStackAfterIngress, Body.protectionLayers] using atVirtual.trans same
    · exact ⟨rfl, (bounds iface.routingIface).2⟩
  | @decapsulate iface body configured datapathStage owner unwrapped =>
    simp only [Config.restoredFrame_body]
    obtain ⟨recursive, layers⟩ := unwrap_carrier_preserves_record conditions iface configured
      before.frame.body body
      ((carrier_bodies_without_headers c expectedEncapStack before.frame.body).mpr wellformed) unwrapped
    exact ⟨(carrier_bodies_without_headers c expectedEncapStack body).mp recursive, layers⟩
  | drop => exact ⟨wellformed, trivial⟩

theorem headered_traces_preserve_stack (c : Config) (expectedEncapStack : Nat → List Nat)
    (conditions : HeaderedLocalConditions c expectedEncapStack) (processing : HeaderProcessing)
    (mode : c.headerProcessing = some processing) (bounds : HeaderBounds processing)
    {start finish : State} {actions : List Action}
    (run : (lts c).MTr start actions finish) (initial : HeaderedStackInvariant c expectedEncapStack start) :
    HeaderedStackInvariant c expectedEncapStack finish := by
  have preserved : (lts c).TrInv (HeaderedStackInvariant c expectedEncapStack) := by
    intro before action after step valid
    exact headered_step_preserves_stack conditions processing mode bounds step valid
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initial

end TDN.MultiProtocolForwarding
