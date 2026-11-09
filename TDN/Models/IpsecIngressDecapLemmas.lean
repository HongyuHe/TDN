import TDN.Models.NetfilterToRoutingLemmas

namespace TDN.MultiProtocolForwarding

lemma coherent_IPsec_visible_fields {frame : LayeredFrame.Frame}
    {envelope : DataPlaneForwarding.TunnelSAStamp} {body : LayeredFrame.Body} {header : PacketPolicy.Packet}
    (coherent : frame.HeadersCoherent) (shape : frame.body = .ipsec envelope body)
    (visible : frame.visibleHeader = some header) :
    header.source = envelope.sender ∧ header.destination = envelope.receiver ∧ header.protocol = "esp" := by
  obtain ⟨nominal, bodyVisible, identity⟩ := LayeredFrame.Frame.coherent_visible coherent header visible
  have same : nominal = LayeredFrame.outerHeader envelope.sender envelope.receiver "esp" 0 0 := by
    rw [shape, LayeredFrame.Body.visibleHeader] at bodyVisible
    exact Option.some.inj bodyVisible.symm
  subst nominal
  refine ⟨?_, ?_, ?_⟩
  · simpa [LayeredFrame.outerHeader] using congrArg (fun packet : PacketPolicy.Packet => packet.source) identity.1
  · simpa [LayeredFrame.outerHeader] using congrArg (fun packet : PacketPolicy.Packet => packet.destination) identity.1
  · simpa [LayeredFrame.outerHeader] using congrArg (fun packet : PacketPolicy.Packet => packet.protocol) identity.1

def IPsecInputAtom (configuration : Config) (iface : Nat) (policy : DataPlaneForwarding.IpsecPolicy) :
    PacketPolicy.MatchCondition → Prop
  | .sourceRange low high => low ≤ policy.sender ∧ policy.sender ≤ high
  | .destinationRange low high => low ≤ policy.receiver ∧ policy.receiver ≤ high
  | .protocol name => name = "esp"
  | .ingress name => configuration.ip.interfaceName iface = name
  | .egress name => name = ""
  | _ => True

instance (configuration : Config) (iface : Nat) (policy : DataPlaneForwarding.IpsecPolicy)
    (atom : PacketPolicy.MatchCondition) : Decidable (IPsecInputAtom configuration iface policy atom) := by
  cases atom <;> unfold IPsecInputAtom <;> infer_instance

def IPsecInputPossible (configuration : Config) (iface : Nat) (policy : DataPlaneForwarding.IpsecPolicy) : Prop :=
  configuration.ip.inputFallback iface = .allow ∨
    ∃ rule ∈ configuration.ip.inputRules iface, rule.verdict = .allow ∧
      ∀ atom ∈ rule.atoms, IPsecInputAtom configuration iface policy atom

instance (configuration : Config) (iface : Nat) (policy : DataPlaneForwarding.IpsecPolicy) :
    Decidable (IPsecInputPossible configuration iface policy) := by
  unfold IPsecInputPossible
  infer_instance

lemma admitted_decryption_has_possible_rule {configuration : Config} {entry : State}
    (policy : DataPlaneForwarding.IpsecPolicy) (association : DataPlaneForwarding.InstalledSA)
    (body : LayeredFrame.Body) (coherent : entry.frame.HeadersCoherent)
    (encrypted : entry.frame.body = .ipsec (policy.seal association) body)
    (bound : DataPlaneForwarding.saMatchesPolicy association policy)
    (admitted : PacketProcessing.InputAdmitted configuration entry) :
    IPsecInputPossible configuration entry.iface policy := by
  obtain ⟨header, visible, accepts⟩ := admitted
  have fields := coherent_IPsec_visible_fields coherent encrypted visible
  have source : header.source = policy.sender := fields.1.trans bound.2.1
  have destination : header.destination = policy.receiver := fields.2.1.trans bound.2.2.1
  by_cases fallback : configuration.ip.inputFallback entry.iface = .allow
  · exact Or.inl fallback
  · have denying : configuration.ip.inputFallback entry.iface = .deny := by
      cases value : configuration.ip.inputFallback entry.iface <;> simp_all
    rw [DataPlaneForwarding.accepts, denying] at accepts
    obtain ⟨matchedRule, member, matched, allow⟩ := Filter.allowed_has_matching_allow _ _ accepts
    obtain ⟨rule, ruleMember, rfl⟩ := List.mem_map.mp member
    refine Or.inr ⟨rule, ruleMember, allow, ?_⟩
    intro atom atomMember
    have holds := PacketPolicy.matching_atom matched atomMember
    cases atom <;> simp only [IPsecInputAtom]
    all_goals try trivial
    case sourceRange low high =>
      simpa [PacketPolicy.MatchCondition.matchesPacket, PacketProcessing.inputPacket, policyHeader, source] using holds
    case destinationRange low high =>
      simpa [PacketPolicy.MatchCondition.matchesPacket, PacketProcessing.inputPacket, policyHeader, destination] using holds
    case protocol name =>
      have same : header.protocol = name := holds
      exact same.symm.trans fields.2.2
    case egress name => exact holds.symm

lemma coherent_same_body_has_same_visible_source {first second : LayeredFrame.Frame}
    {firstHeader secondHeader : PacketPolicy.Packet}
    (body : first.body = second.body) (firstCoherent : first.HeadersCoherent)
    (secondCoherent : second.HeadersCoherent)
    (firstVisible : first.visibleHeader = some firstHeader)
    (secondVisible : second.visibleHeader = some secondHeader) :
    firstHeader.source = secondHeader.source := by
  obtain ⟨firstNominal, firstBody, firstIdentity⟩ :=
    LayeredFrame.Frame.coherent_visible firstCoherent firstHeader firstVisible
  obtain ⟨secondNominal, secondBody, secondIdentity⟩ :=
    LayeredFrame.Frame.coherent_visible secondCoherent secondHeader secondVisible
  have same : firstNominal = secondNominal := by
    rw [body, secondBody] at firstBody
    exact Option.some.inj firstBody.symm
  subst firstNominal
  have left : firstHeader.source = secondNominal.source := by
    simpa only using congrArg (fun packet : PacketPolicy.Packet => packet.source) firstIdentity.1
  have right : secondHeader.source = secondNominal.source := by
    simpa only using congrArg (fun packet : PacketPolicy.Packet => packet.source) secondIdentity.1
  exact left.trans right.symm

lemma ingress_route_detailed_authentication {configuration : Config} (processing : HeaderProcessing)
    (mode : configuration.headerProcessing = some processing) (bounds : HeaderBounds processing)
    {entry entered final : State} {header : PacketPolicy.Packet}
    (coherent : entry.frame.HeadersCoherent)
    (ingress : PacketProcessing.Ingress configuration entry entered)
    (routed : Step configuration entered .route final)
    (visible : final.frame.visibleHeader = some header) :
    final.enteredIface = entry.iface ∧
      ((final.authenticated = [] ∧
        ∀ incoming, entry.frame.visibleHeader = some incoming → incoming.source = header.source) ∨
       ∃ policy ∈ configuration.ip.ingressPolicies entry.iface,
         policy.matches header = true ∧ final.authenticated = [policy.id] ∧
         (∀ incoming, entry.frame.visibleHeader = some incoming → incoming.source = policy.sender) ∧
         (PacketProcessing.InputAdmitted configuration entry → IPsecInputPossible configuration entry.iface policy)) := by
  have ingressIfaces := ingress_has_native_ifaces ingress
  have preserved := route_from_ingress_preserves_local_state ingressIfaces.2.2 routed
  refine ⟨preserved.2.1.trans ingressIfaces.2.1, ?_⟩
  rcases ingress with received | decrypted
  · have enteredCoherent := step_preserves_headers processing mode bounds received coherent
    have finalCoherent := step_preserves_headers processing mode bounds routed enteredCoherent
    cases received
    refine Or.inl ⟨preserved.2.2.1, ?_⟩
    intro incoming incomingVisible
    exact coherent_same_body_has_same_visible_source preserved.1.symm coherent finalCoherent incomingVisible visible
  · cases decrypted with
    | decryptIPsec policy association body nominal datapathStage encrypted configured installed bound bodyVisible selected tracking =>
      have actualStep := Step.decryptIPsec policy association body nominal datapathStage encrypted configured installed bound
        bodyVisible selected tracking
      have enteredCoherent := step_preserves_headers processing mode bounds actualStep coherent
      have finalCoherent := step_preserves_headers processing mode bounds routed enteredCoherent
      obtain ⟨actualNominal, finalBodyVisible, identity⟩ :=
        LayeredFrame.Frame.coherent_visible finalCoherent header visible
      have finalBody : final.frame.body = body := by
        simpa only [Config.restoredFrame, mode, LayeredFrame.Frame.popHeader] using preserved.1
      have sameNominal : actualNominal = nominal := by
        rw [finalBody, bodyVisible] at finalBodyVisible
        exact Option.some.inj finalBodyVisible.symm
      subst actualNominal
      have source : header.source = nominal.source := by
        simpa only using congrArg (fun packet : PacketPolicy.Packet => packet.source) identity.1
      have destination : header.destination = nominal.destination := by
        simpa only using congrArg (fun packet : PacketPolicy.Packet => packet.destination) identity.1
      refine Or.inr ⟨policy, configured,
        (association_matches_depends_on_addresses policy header nominal source destination).trans selected,
        preserved.2.2.1, ?_, ?_⟩
      · intro incoming incomingVisible
        exact (coherent_IPsec_visible_fields coherent encrypted incomingVisible).1.trans bound.2.1
      · exact admitted_decryption_has_possible_rule policy association body coherent encrypted bound

end TDN.MultiProtocolForwarding
