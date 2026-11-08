import TDN.Semantics.OrderedSizeGuards
import TDN.Semantics.IPsecFrameEncoding
import TDN.Semantics.HeaderedStack
import TDN.Semantics.DecodedHeaderProperties

namespace TDN.MultiProtocolExecution
open LayeredFrame IPsecFrameEncoding PacketSource

def BodySizeBudget (plaintextLimit : Nat → Nat) : Body → Prop
  | .datagram header => NetworkTemplate header ∧ ∃ bytes,
      header.networkBytes = some bytes ∧ bytes ≤ networkProtocolLimit header
  | .ethernet _ => True
  | .ipsec association contents => KnownIPv4Seal association ∧
      BodySizeBudget plaintextLimit contents ∧ ∃ bytes,
        networkLength contents = some bytes ∧ bytes ≤ plaintextLimit association.tag ∧
        PacketLength.alignedWireLength 4 2 52 (plaintextLimit association.tag) ≤ 65535
  | .macsec _ _ | .carrier _ _ => False

lemma body_budget_has_length {limit : Nat → Nat} {body : Body}
    (budget : BodySizeBudget limit body) (header : PacketPolicy.Packet)
    (visible : body.visibleHeader = some header) :
    ∃ bytes, networkLength body = some bytes ∧ (header.destination < 2^32 → bytes ≤ 65535) := by
  cases body with
  | datagram nominal =>
    have same : nominal = header := Option.some.inj visible
    subst nominal
    obtain ⟨bytes, length, upper⟩ := budget.2
    refine ⟨bytes, length, ?_⟩
    intro ipv4
    have source : header.source < 2^32 := by
      rcases budget.1 with first | second
      · exact first.1
      · have destination := second.2.2.1
        omega
    simpa only [networkProtocolLimit, source, ↓reduceIte] using upper
  | ethernet nominal => cases visible
  | ipsec association contents =>
    obtain ⟨known, inner, bytes, length, bound, maximum⟩ := budget
    refine ⟨PacketLength.alignedWireLength 4 2 52 bytes, ?_, ?_⟩
    · simp only [networkLength, length, Option.map_some]
    · intro _
      apply Nat.le_trans _ maximum
      unfold PacketLength.alignedWireLength
      omega
  | macsec association contents => cases budget
  | carrier endpoint contents => cases budget

lemma decoded_source_body_budget (source : Datagram) (decoded : source.Decoded)
    (limit : Nat → Nat) : BodySizeBudget limit source.body := by
  cases body : source.body with
  | datagram header =>
    obtain ⟨network, _, _, _, length⟩ := decoded_IP_header_properties source header body decoded
    have same := decoded
    simp only [Datagram.Decoded, body] at same
    exact ⟨network, source.Raw.length, same.2.1, length⟩
  | ethernet header => trivial
  | ipsec association contents => simp [Datagram.Decoded, body] at decoded
  | macsec association contents => simp [Datagram.Decoded, body] at decoded
  | carrier endpoint contents => simp [Datagram.Decoded, body] at decoded


def AuthenticationSizeBound (configuration : Config) (limit : Nat → Nat) (state : State) : Prop :=
  ∀ bytes, configuration.networkBytes state.frame.body state.frame.payload = some bytes →
    ∀ requestId ∈ state.authenticated, bytes ≤ limit requestId


def FilteredSizeBound (configuration : Config) (required : Nat → Bool)
    (mtu plaintextLimit : Nat → Nat) (state : State) (header : PacketPolicy.Packet) : Prop :=
  ∀ bytes, configuration.networkBytes state.frame.body state.frame.payload = some bytes →
    (required state.iface = true → bytes ≤ mtu state.iface) ∧
    ∀ policy ∈ configuration.ip.outbound state.iface,
      policy.matches header = true → bytes ≤ plaintextLimit policy.tag


def SizeRouted (configuration : Config) (state : State) (header : PacketPolicy.Packet) : Prop :=
  ∃ route ∈ configuration.ip.routes,
    route.ingress = state.enteredIface ∧ route.egress = state.iface ∧ route.matches header


def ReadySizeBound (configuration : Config) (required : Nat → Bool)
    (mtu : Nat → Nat) (state : State) : Prop :=
  required state.iface = true → ∀ bytes,
    configuration.networkBytes state.frame.body state.frame.payload = some bytes → bytes ≤ mtu state.iface


def SizeInvariant (configuration : Config) (required : Nat → Bool)
    (mtu plaintextLimit authenticationLimit : Nat → Nat) (state : State) : Prop :=
  BodySizeBudget plaintextLimit state.frame.body ∧
  match state.datapathStage with
  | .ingress | .localOutput =>
      (∃ header, configuration.visibleHeader state.frame = some header) ∧
      AuthenticationSizeBound configuration authenticationLimit state ∧ state.enteredIface = state.iface
  | .routed | .outputRouted =>
      ∃ header, configuration.visibleHeader state.frame = some header ∧
        AuthenticationSizeBound configuration authenticationLimit state ∧ SizeRouted configuration state header
  | .filtered => ∃ header, configuration.visibleHeader state.frame = some header ∧
      FilteredSizeBound configuration required mtu plaintextLimit state header
  | .encapsulated => ∃ policy ∈ configuration.ip.outbound state.iface,
      ∃ association ∈ configuration.ip.outboundStates state.iface,
        Execution.StateBindsPolicy association policy ∧
        ∃ contents, state.frame.body = .ipsec (policy.seal association) contents
  | .ready => ReadySizeBound configuration required mtu state
  | _ => True

structure SizeChecks (configuration : Config) (required : Nat → Bool)
    (mtu plaintextLimit authenticationLimit : Nat → Nat) : Prop where
  noMAC : configuration.macIfaces = []
  noCarriers : configuration.carriers = []
  networkDefinition : ∀ body payload, configuration.networkBytes body payload = networkLength body
  routeIPv4 : ∀ route ∈ configuration.ip.routes, route.high < 2^32
  outboundIPv4 : ∀ iface policy association,
    policy ∈ configuration.ip.outbound iface → association ∈ configuration.ip.outboundStates iface →
    Execution.StateBindsPolicy association policy → KnownIPv4Seal (policy.seal association)
  plaintextMaximum : ∀ iface policy, policy ∈ configuration.ip.outbound iface →
    PacketLength.alignedWireLength 4 2 52 (plaintextLimit policy.tag) ≤ 65535
  inboundLimit : ∀ iface policy, policy ∈ configuration.ip.inbound iface →
    plaintextLimit policy.tag ≤ authenticationLimit policy.id
  bridgeTarget : ∀ first last, configuration.bridge first last → required last = false
  forward : ∀ route ∈ configuration.ip.routes,
    (required route.egress = true ∨ configuration.ip.outbound route.egress ≠ []) →
    configuration.ip.forwardFallback route.egress = .deny ∧
    Execution.SizedProgramChecks [] (configuration.ip.forwardRules route.egress) route
      (configuration.ip.interfaceName route.ingress) (configuration.ip.interfaceName route.egress)
      (required route.egress) (mtu route.egress) (configuration.ip.outbound route.egress)
      authenticationLimit plaintextLimit
  output : ∀ route ∈ configuration.ip.routes,
    (required route.egress = true ∨ configuration.ip.outbound route.egress ≠ []) →
    configuration.ip.outputFallback route.egress = .deny ∧
    Execution.SizedProgramChecks [] (configuration.ip.outputRules route.egress) route
      (configuration.ip.interfaceName route.ingress) (configuration.ip.interfaceName route.egress)
      (required route.egress) (mtu route.egress) (configuration.ip.outbound route.egress)
      authenticationLimit plaintextLimit
  routeOuterPacket : ∀ iface policy, policy ∈ configuration.ip.outbound iface →
    ∀ route ∈ configuration.ip.routes, route.ingress = iface →
    route.low ≤ policy.receiver → policy.receiver ≤ route.high → required route.egress = true →
    PacketLength.alignedWireLength 4 2 52 (plaintextLimit policy.tag) ≤ mtu route.egress

lemma filtered_size_from_checks {configuration : Config} {required : Nat → Bool}
    {mtu plaintextLimit authenticationLimit : Nat → Nat}
    (checks : SizeChecks configuration required mtu plaintextLimit authenticationLimit)
    (processing : HeaderProcessing) (mode : configuration.headerProcessing = some processing)
    (state : State) (header : PacketPolicy.Packet) (coherent : state.frame.HeadersCoherent)
    (budget : BodySizeBudget plaintextLimit state.frame.body)
    (visible : configuration.visibleHeader state.frame = some header)
    (authenticated : AuthenticationSizeBound configuration authenticationLimit state)
    (routed : SizeRouted configuration state header)
    (rules : List PacketPolicy.Rule) (fallback : Filter.Verdict)
    (checked : ∀ route ∈ configuration.ip.routes, route.egress = state.iface →
      (required route.egress = true ∨ configuration.ip.outbound route.egress ≠ []) →
      fallback = .deny ∧ Execution.SizedProgramChecks [] rules route
        (configuration.ip.interfaceName route.ingress) (configuration.ip.interfaceName route.egress)
        (required route.egress) (mtu route.egress) (configuration.ip.outbound route.egress)
        authenticationLimit plaintextLimit)
    (accepted : Execution.accepts rules fallback (policyHeader configuration state header)) :
    FilteredSizeBound configuration required mtu plaintextLimit state header := by
  intro bytes length
  by_cases relevant : required state.iface = true ∨ configuration.ip.outbound state.iface ≠ []
  · obtain ⟨route, member, entry, exit, matched⟩ := routed
    have certificate := checked route member exit (by simpa only [exit] using relevant)
    have destination : header.destination < 2^32 :=
      lt_of_le_of_lt matched.2 (checks.routeIPv4 route member)
    have actualVisible : state.frame.visibleHeader = some header := by
      simpa only [Config.visibleHeader, mode] using visible
    obtain ⟨nominal, nominalVisible, identity⟩ := state.frame.coherent_visible coherent header actualVisible
    obtain ⟨actualBytes, actualLength, upper⟩ := body_budget_has_length budget nominal nominalVisible
    have sameBytes : actualBytes = bytes :=
      Option.some.inj (actualLength.symm.trans ((checks.networkDefinition _ _).symm.trans length))
    subst actualBytes
    have maximum : bytes ≤ 65535 := upper (by rw [← identity.destination]; exact destination)
    have result := Execution.checked_program_size_bounds [] rules route
      (configuration.ip.interfaceName route.ingress) (configuration.ip.interfaceName route.egress)
      (required route.egress) (mtu route.egress) (configuration.ip.outbound route.egress)
      authenticationLimit plaintextLimit certificate.2 (policyHeader configuration state header) bytes
      (by simp only [policyHeader, entry]) (by simp only [policyHeader, exit])
      (by simpa only [Execution.Route.matches, policyHeader] using matched) length maximum
      (authenticated bytes length) (by simp) (by simpa only [certificate.1] using accepted)
    refine ⟨by simpa only [exit] using result.1, ?_⟩
    intro policy member selected
    exact result.2 policy (by simpa only [exit] using member)
      (by
        unfold Execution.Association.matches at selected ⊢
        apply decide_eq_true
        have holds := of_decide_eq_true selected
        exact holds)
  · have notRequired : required state.iface ≠ true := fun needed => relevant (Or.inl needed)
    have empty : configuration.ip.outbound state.iface = [] := by
      by_contra nonempty
      exact relevant (Or.inr nonempty)
    exact ⟨fun needed => False.elim (notRequired needed), by simp [empty]⟩

lemma authentication_bound_empty (configuration : Config) (limit : Nat → Nat) (state : State)
    (empty : state.authenticated = []) : AuthenticationSizeBound configuration limit state := by
  intro bytes length requestId member
  simp only [empty, List.not_mem_nil] at member

lemma size_ready_if_not_required (configuration : Config) (required : Nat → Bool)
    (mtu : Nat → Nat) (state : State) (irrelevant : required state.iface = false) :
    ReadySizeBound configuration required mtu state := by
  intro needed
  rw [irrelevant] at needed
  contradiction


theorem native_step_preserves_size_budget {configuration : Config} {required : Nat → Bool}
    {mtu plaintextLimit authenticationLimit : Nat → Nat}
    (checks : SizeChecks configuration required mtu plaintextLimit authenticationLimit)
    (processing : HeaderProcessing) (mode : configuration.headerProcessing = some processing)
    {before after : State} {action : Action} (step : Step configuration before action after)
    (coherent : before.frame.HeadersCoherent)
    (invariant : SizeInvariant configuration required mtu plaintextLimit authenticationLimit before) :
    SizeInvariant configuration required mtu plaintextLimit authenticationLimit after := by
  obtain ⟨bodyBudget, phaseBudget⟩ := invariant
  cases step with
  | @receive header datapathStage visible tracking =>
    exact ⟨bodyBudget, ⟨header, visible⟩, authentication_bound_empty _ _ _ rfl, rfl⟩
  | @route header route datapathStage visible chosen entry =>
    simp only [datapathStage] at phaseBudget
    have actualVisible : before.frame.visibleHeader = some header := by
      simpa only [Config.visibleHeader, mode] using visible
    refine ⟨by simpa only [Config.forwardedFrame_body] using bodyBudget,
      { header with hopLimit := header.hopLimit - 1 }, ?_, ?_, ?_⟩
    · simpa only [Config.visibleHeader, mode, Config.forwardedFrame] using Frame.forwarded_visible actualVisible
    · simpa only [AuthenticationSizeBound, Config.forwardedFrame_body, Frame.forwarded_payload,
        Config.forwardedFrame, mode, Frame.forwarded_body] using phaseBudget.2.1
    · exact ⟨route, chosen.1, entry.trans phaseBudget.2.2.symm, rfl, chosen.2.1⟩
  | @routeLocalOutput header route datapathStage visible chosen entry =>
    simp only [datapathStage] at phaseBudget
    exact ⟨bodyBudget, header, visible, phaseBudget.2.1,
      route, chosen.1, entry.trans phaseBudget.2.2.symm, rfl, chosen.2.1⟩
  | @forwardFilter header datapathStage visible accepted =>
    simp only [datapathStage] at phaseBudget
    obtain ⟨priorHeader, priorVisible, authenticated, routed⟩ := phaseBudget
    have same := Option.some.inj (priorVisible.symm.trans visible)
    subst priorHeader
    refine ⟨bodyBudget, header, visible, ?_⟩
    exact filtered_size_from_checks checks processing mode before header coherent bodyBudget
      visible authenticated routed _ _
      (fun route member exit relevant => by simpa only [exit] using checks.forward route member relevant) accepted
  | @outputFilter header datapathStage visible accepted =>
    simp only [datapathStage] at phaseBudget
    obtain ⟨priorHeader, priorVisible, authenticated, routed⟩ := phaseBudget
    have same := Option.some.inj (priorVisible.symm.trans visible)
    subst priorHeader
    refine ⟨bodyBudget, header, visible, ?_⟩
    exact filtered_size_from_checks checks processing mode before header coherent bodyBudget
      visible authenticated routed _ _
      (fun route member exit relevant => by simpa only [exit] using checks.output route member relevant) accepted
  | @encryptIPsec header policy association datapathStage visible selected installed bound =>
    simp only [datapathStage] at phaseBudget
    obtain ⟨priorHeader, priorVisible, filtered⟩ := phaseBudget
    have same := Option.some.inj (priorVisible.symm.trans visible)
    subst priorHeader
    have configured := Execution.matched_policy_is_configured selected
    obtain ⟨nominal, nominalVisible, identity⟩ := before.frame.coherent_visible coherent header
      (by simpa only [Config.visibleHeader, mode] using visible)
    obtain ⟨bytes, length, maximum⟩ := body_budget_has_length bodyBudget nominal nominalVisible
    have checkedLength : configuration.networkBytes before.frame.body before.frame.payload = some bytes :=
      (checks.networkDefinition _ _).trans length
    refine ⟨?_, policy, configured.1, association, installed, bound, before.frame.body, ?_⟩
    · simp only [Config.ipsecFrame_body, BodySizeBudget]
      exact ⟨checks.outboundIPv4 _ policy association configured.1 installed bound, bodyBudget,
        bytes, length, (filtered bytes checkedLength).2 policy configured.1 configured.2,
        checks.plaintextMaximum _ policy configured.1⟩
    · exact Config.ipsecFrame_body ..
  | @routeOuterPacket header route datapathStage visible chosen entry =>
    simp only [datapathStage] at phaseBudget
    obtain ⟨policy, configured, association, installed, bound, contents, body⟩ := phaseBudget
    have bodyFacts := bodyBudget
    rw [body] at bodyFacts
    obtain ⟨known, innerBudget, bytes, innerLength, innerBound, maximum⟩ := bodyFacts
    have actualVisible : before.frame.visibleHeader = some header := by
      simpa only [Config.visibleHeader, mode] using visible
    obtain ⟨nominal, nominalVisible, identity⟩ := before.frame.coherent_visible coherent header actualVisible
    have nominalHeader : nominal = outerHeader policy.sender policy.receiver "esp" 0 0 := by
      rw [body] at nominalVisible
      simpa only [Body.visibleHeader, Execution.Association.seal, outerHeader, bound.2.1,
        bound.2.2.1] using Option.some.inj nominalVisible.symm
    have destination : header.destination = policy.receiver := by
      rw [identity.destination, nominalHeader]
      rfl
    refine ⟨bodyBudget, ?_⟩
    intro needed actualBytes actualLength
    have limit := checks.routeOuterPacket before.iface policy configured route chosen.1 entry
      (by simpa only [← destination] using chosen.2.1.1)
      (by simpa only [← destination] using chosen.2.1.2) needed
    have exactLength : actualBytes = PacketLength.alignedWireLength 4 2 52 bytes := by
      rw [checks.networkDefinition, body, networkLength, innerLength, Option.map_some] at actualLength
      exact (Option.some.inj actualLength).symm
    rw [exactLength]
    change bytes ≤ plaintextLimit policy.tag at innerBound
    apply Nat.le_trans _ limit
    unfold PacketLength.alignedWireLength
    omega
  | @passWithoutTransform header datapathStage visible noPolicy =>
    simp only [datapathStage] at phaseBudget
    obtain ⟨priorHeader, priorVisible, filtered⟩ := phaseBudget
    refine ⟨bodyBudget, ?_⟩
    intro needed bytes length
    exact (filtered bytes length).1 needed
  | decryptIPsec policy association contents header datapathStage encrypted configured installed bound visible selected tracking =>
    rw [encrypted] at bodyBudget
    obtain ⟨known, innerBudget, bytes, innerLength, innerBound, maximum⟩ := bodyBudget
    refine ⟨by simpa only [Config.restoredFrame_body] using innerBudget, ?_, ?_, rfl⟩
    · simp only [Config.visibleHeader, mode, Config.restoredFrame, Frame.pop_visible _ _ _ visible]
      exact ⟨_, rfl⟩
    · intro actualBytes actualLength requestId member
      have sameId : requestId = policy.id := List.mem_singleton.mp member
      have sameLength : bytes = actualBytes := by
        rw [checks.networkDefinition, Config.restoredFrame_body] at actualLength
        exact Option.some.inj (innerLength.symm.trans actualLength)
      rw [sameId, ← sameLength]
      exact innerBound.trans (checks.inboundLimit _ policy configured)
  | inputFilter => exact ⟨bodyBudget, True.intro⟩
  | deliver => exact ⟨bodyBudget, True.intro⟩
  | deliverEthernet => exact ⟨bodyBudget, True.intro⟩
  | linkTransmit => exact ⟨bodyBudget, True.intro⟩
  | bridge next datapathStage member =>
    exact ⟨bodyBudget, size_ready_if_not_required _ _ _ _ (checks.bridgeTarget _ _ member)⟩
  | bridgeOutput next datapathStage member =>
    exact ⟨bodyBudget, size_ready_if_not_required _ _ _ _ (checks.bridgeTarget _ _ member)⟩
  | encryptMACsec iface association configured => simp only [checks.noMAC, List.not_mem_nil] at configured
  | unprotectedMACsec iface configured => simp only [checks.noMAC, List.not_mem_nil] at configured
  | decryptMACsec iface association transmitted contents configured => simp only [checks.noMAC, List.not_mem_nil] at configured
  | uncheckedMACsec iface configured => simp only [checks.noMAC, List.not_mem_nil] at configured
  | encapsulate iface configured => simp only [checks.noCarriers, List.not_mem_nil] at configured
  | decapsulate iface contents configured => simp only [checks.noCarriers, List.not_mem_nil] at configured
  | drop => exact ⟨bodyBudget, True.intro⟩

end TDN.MultiProtocolExecution
