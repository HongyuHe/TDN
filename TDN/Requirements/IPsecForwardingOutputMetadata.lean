import TDN.Models.HeaderAwareEncapPreservation
import TDN.Requirements.IPsecForwardRuleGuards

namespace TDN.Requirements.Msc
open MultiProtocolForwarding LayeredFrame

def IPsecForwardHook (config : Config) (localHeader : Nat → PacketPolicy.Packet → Prop)
    (state : MultiProtocolForwarding.State) (header : PacketPolicy.Packet) : Prop :=
  DataPlaneForwarding.accepts (config.ip.forwardRules state.iface) (config.ip.forwardFallback state.iface)
    (policyHeader config state header) ∨
  (localHeader state.frame.originDomain header ∧
    DataPlaneForwarding.accepts (config.ip.outputRules state.iface) (config.ip.outputFallback state.iface)
      (policyHeader config state header))

def IPsecEncryptedOutput (config : Config) (state : MultiProtocolForwarding.State) : Prop :=
  ∃ iface policy association body route,
    policy ∈ config.ip.egressPolicies iface ∧ association ∈ config.ip.egressSAs iface ∧
    DataPlaneForwarding.saMatchesPolicy association policy ∧
    state.frame.body = .ipsec (policy.seal association) body ∧
    config.ip.owner iface = config.ip.owner state.iface ∧
    route ∈ config.ip.routes ∧ route.egress = state.iface ∧
    route.destPrefixLow ≤ association.receiver ∧ association.receiver ≤ route.destPrefixHigh

def IPsecOutputStageMetadata (config : Config) (localHeader : Nat → PacketPolicy.Packet → Prop)
    (state : MultiProtocolForwarding.State) : Prop :=
  match state.datapathStage with
  | .ingress => state.enteredIface = state.iface
  | .localOutput => ∃ header, state.frame.visibleHeader = some header ∧
      localHeader state.frame.originDomain header ∧ state.enteredIface = state.iface
  | .routed => ∃ header, state.frame.visibleHeader = some header ∧ Routed config state header
  | .outputRouted => ∃ header, state.frame.visibleHeader = some header ∧ Routed config state header ∧
      localHeader state.frame.originDomain header
  | .filtered => ∃ header, state.frame.visibleHeader = some header ∧ Routed config state header ∧
      IPsecForwardHook config localHeader state header
  | .encapsulated => ∃ policy association body,
      policy ∈ config.ip.egressPolicies state.iface ∧ association ∈ config.ip.egressSAs state.iface ∧
      DataPlaneForwarding.saMatchesPolicy association policy ∧ state.frame.body = .ipsec (policy.seal association) body
  | .egressReady => IPsecEncryptedOutput config state ∨
      ∃ header, state.frame.visibleHeader = some header ∧ Routed config state header ∧
        IPsecForwardHook config localHeader state header ∧
        DataPlaneForwarding.lookupSpdPolicies (config.ip.egressPolicies state.iface) header = []
  | _ => True

def IPsecForwardingMetadata (config : Config) (inner : Nat → Prop)
    (localHeader : Nat → PacketPolicy.Packet → Prop) (state : MultiProtocolForwarding.State) : Prop :=
  inner (config.ip.owner state.iface) → IPsecOutputStageMetadata config localHeader state

structure IPsecOutputMetadataChecks (config : Config) (inner : Nat → Prop) : Prop where
  noMACsec : config.macIfaces = []
  noCarriers : config.carriers = []
  routeOwners : ∀ route ∈ config.ip.routes, config.ip.owner route.egress = config.ip.owner route.ingress
  bridgeOutputs : ∀ first last, config.bridge first last → ¬ inner (config.ip.owner last)

lemma ipsec_step_preserves_output_metadata (config : Config) (inner : Nat → Prop)
    (localHeader : Nat → PacketPolicy.Packet → Prop) (checks : IPsecOutputMetadataChecks config inner)
    (processing : HeaderProcessing) (mode : config.headerProcessing = some processing)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step config before operation after)
    (coherent : before.frame.HeadersCoherent)
    (metadata : IPsecForwardingMetadata config inner localHeader before) :
    IPsecForwardingMetadata config inner localHeader after := by
  intro component
  cases step with
  | receive stage visible tracking => rfl
  | route route stage visible selected entry =>
    rename_i header
    have firstComponent : inner (config.ip.owner before.iface) := by
      simpa only [checks.routeOwners route selected.1, entry] using component
    have entered : before.enteredIface = before.iface := by
      simpa only [IPsecOutputStageMetadata, stage] using metadata firstComponent
    have shown := visible
    simp only [Config.visibleHeader, mode] at shown
    refine ⟨{ header with hopLimit := header.hopLimit - 1 }, ?_, route, ?_, ?_, rfl⟩
    · simpa only [Config.forwardedFrame, mode] using Frame.forwarded_visible shown
    · exact (selected_route_metadata _ _ header { header with hopLimit := header.hopLimit - 1 } rfl).mp selected
    · exact entry.trans entered.symm
  | routeLocalOutput route stage visible selected entry =>
    have firstComponent : inner (config.ip.owner before.iface) := by
      simpa only [checks.routeOwners route selected.1, entry] using component
    obtain ⟨oldHeader, shown, localSource, entered⟩ : ∃ header, before.frame.visibleHeader = some header ∧
        localHeader before.frame.originDomain header ∧ before.enteredIface = before.iface := by
      simpa only [IPsecOutputStageMetadata, stage] using metadata firstComponent
    have actual := visible
    simp only [Config.visibleHeader, mode] at actual
    have same := Option.some.inj (shown.symm.trans actual)
    subst oldHeader
    exact ⟨_, actual, ⟨route, selected, entry.trans entered.symm, rfl⟩, localSource⟩
  | forwardFilter stage visible accepted =>
    obtain ⟨oldHeader, shown, route⟩ : ∃ header, before.frame.visibleHeader = some header ∧ Routed config before header := by
      simpa only [IPsecOutputStageMetadata, stage] using metadata component
    have actual := visible
    simp only [Config.visibleHeader, mode] at actual
    have same := Option.some.inj (shown.symm.trans actual)
    subst oldHeader
    exact ⟨_, actual, route, Or.inl accepted⟩
  | outputFilter stage visible accepted =>
    obtain ⟨oldHeader, shown, route, localSource⟩ : ∃ header, before.frame.visibleHeader = some header ∧
        Routed config before header ∧ localHeader before.frame.originDomain header := by
      simpa only [IPsecOutputStageMetadata, stage] using metadata component
    have actual := visible
    simp only [Config.visibleHeader, mode] at actual
    have same := Option.some.inj (shown.symm.trans actual)
    subst oldHeader
    exact ⟨_, actual, route, Or.inr ⟨localSource, accepted⟩⟩
  | encryptIPsec policy association stage visible selected installed bound =>
    exact ⟨policy, association, before.frame.body, (DataPlaneForwarding.matched_policy_is_configured selected).1,
      installed, bound, Config.ipsecFrame_body config before.iface before.frame (policy.seal association)⟩
  | routeOuterPacket route stage visible selected entry =>
    have firstComponent : inner (config.ip.owner before.iface) := by
      simpa only [checks.routeOwners route selected.1, entry] using component
    obtain ⟨policy, association, body, configured, installed, bound, encrypted⟩ :
        ∃ policy association body, policy ∈ config.ip.egressPolicies before.iface ∧
          association ∈ config.ip.egressSAs before.iface ∧ DataPlaneForwarding.saMatchesPolicy association policy ∧
          before.frame.body = .ipsec (policy.seal association) body := by
      simpa only [IPsecOutputStageMetadata, stage] using metadata firstComponent
    have actual := visible
    simp only [Config.visibleHeader, mode] at actual
    obtain ⟨nominal, nominalHeader, identity⟩ := before.frame.coherent_visible coherent _ actual
    have nominalSame : nominal = outerHeader association.sender association.receiver "esp" 0 0 := by
      simpa only [encrypted, Body.visibleHeader, DataPlaneForwarding.IpsecPolicy.seal, Option.some.injEq] using nominalHeader.symm
    have destination := identity.destination
    rw [nominalSame] at destination
    exact Or.inl ⟨before.iface, policy, association, body, route, configured, installed, bound, encrypted,
      by rw [checks.routeOwners route selected.1, entry], selected.1, rfl,
      by simpa only [DataPlaneForwarding.FibRoute.matches, destination, outerHeader] using selected.2.1⟩
  | forwardWithoutEncap stage visible noPolicy =>
    obtain ⟨oldHeader, shown, route, hook⟩ : ∃ header, before.frame.visibleHeader = some header ∧
        Routed config before header ∧ IPsecForwardHook config localHeader before header := by
      simpa only [IPsecOutputStageMetadata, stage] using metadata component
    have actual := visible
    simp only [Config.visibleHeader, mode] at actual
    have same := Option.some.inj (shown.symm.trans actual)
    subst oldHeader
    exact Or.inr ⟨_, actual, route, hook, noPolicy⟩
  | decryptIPsec => rfl
  | inputFilter | deliver | deliverEthernet | linkTransmit | drop => trivial
  | bridge next stage connected | bridgeOutput next stage connected =>
    exact False.elim (checks.bridgeOutputs _ _ connected component)
  | encryptMACsec iface association configured
  | unprotectedMACsec iface configured
  | protectMACsec iface association configured
  | decryptMACsec iface association transmitted body configured
  | validateMACsec iface association transmitted encryptFrames confidentialityOffset body configured
  | uncheckedMACsec iface configured => simp [checks.noMACsec] at configured
  | encapsulate iface configured | decapsulate iface body configured => simp [checks.noCarriers] at configured

end TDN.Requirements.Msc
