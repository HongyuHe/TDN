import TDN.Deployments.NestedProtection_MixedSources

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma source_mtu_minimum (iface : Nat) : 1280 ≤ records.sourceMtu iface := by
  have checked : ∀ interface ∈ records.interfaces, 1280 ≤ interface.mtu.getD 1500 := by decide
  cases found : records.interfaces.find? (fun interface => interface.id == records.ifaceName iface) with
  | none => simp [Records.sourceMtu, found]
  | some interface => simpa only [Records.sourceMtu, found, Option.bind_some] using checked interface (List.mem_of_find?_eq_some found)

lemma allowed_source_iface (request : PacketSource.Request)
    (allowed : (binding deviceBinding ifaces).SourceRequestAllowed deployment request) : request.iface ∈ ifaces := by
  have entry := allowed.2.2
  change sourceEntry records.entries request.iface = some _ ∧ _ at entry
  obtain ⟨record, member, same, _⟩ := source_entry_is_recorded records.entries request.iface _ entry.1
  exact same ▸ (recorded_source_bindings.1 record member).1

lemma network_sources : ∀ network ∈ deployment.networks, ∃ request datagrams,
    (binding deviceBinding ifaces).SourceRequestAllowed deployment request ∧ request.application ≠ [] ∧
      deviceBinding.origin request.originDomain = .red network.id ∧
      deviceBinding.sourceProcessing.process request = .emitted datagrams := by
  have checked : ∀ network ∈ records.networks, ∃ flow ∈ records.sourceFlows,
      sourceEntry records.entries flow.iface = some network.id ∧
      records.redNetwork flow.domain = network.id ∧
      EmittedOutcome (PacketSource.processSource (records.sourceMtu flow.iface) flow.request) := by decide
  intro network member
  obtain ⟨flow, listed, entry, origin, emits⟩ := checked network member
  cases outcome : PacketSource.processSource (records.sourceMtu flow.iface) flow.request with
  | error error => simp only [outcome, EmittedOutcome] at emits
  | emitted datagrams =>
    refine ⟨flow.request, datagrams, ?_, by simp [SourceFlow.request], ?_, outcome⟩
    · change _ ∧ _ ∧ sourceEntry records.entries flow.iface = some (records.redNetwork flow.domain) ∧ _
      rw [origin]
      exact ⟨Or.inl ⟨_, rfl⟩, rfl, entry, network, member, by simpa only [SourceFlow.request] using origin.symm⟩
    · change PayloadOrigin.red (records.redNetwork flow.domain) = .red network.id
      rw [origin]

lemma link_encoding_complete (selected : MixedFlowEndpoints) (member : selected ∈ contexts)
    (state : MultiProtocolForwarding.State)
    (valid : FlowMixedBody deviceBinding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) state.frame.body)
    (framed : LinkPathMACsecFramed configuration state) : configuration.LinkEncodingComplete state := by
  intro path
  obtain ⟨association, contents, body⟩ := framed path
  have current : FlowMixedBody deviceBinding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) (.macsec association contents) := by simpa only [body] using valid
  have selectedAssociation := current.1.1
  have checked : ∀ selected ∈ contexts,
      ∃ encoded ∈ records.macFrames, encoded.1 = selected.outerAssociation ∧
      (records.macFrames.find? (fun entry => entry.1 == selected.outerAssociation)).map Prod.snd = some encoded.2 ∧
      encoded.2.DescribesBody (.macsec selected.outerAssociation contents) := by
    dsimp only [LinkAdmission.Frame.DescribesBody]
    decide
  obtain ⟨encoded, stored, same, found, describes⟩ := checked selected member
  refine ⟨encoded.2, ?_, ?_⟩
  · simpa only [Records.configuration, body, selectedAssociation] using found
  · simp only [LinkAdmission.Frame.Describes, Frame.visibleHeader, body, Body.visibleHeader]
    exact ⟨by simpa only [selectedAssociation] using describes, by simp⟩

theorem deployment_covered : forwarding.CoversDeployment deployment := by
  refine ⟨static_bindings.processing, standard_model_faithful deviceBinding ifaces deployment {},
    standard_model_covers_every_native_step deviceBinding ifaces deployment {} iface_conditions,
    standard_generated_source_coverage deviceBinding ifaces deployment {} records.sourceMtu rfl
      source_mtu_minimum rfl allowed_source_iface network_sources,
    by simp [forwarding, model, ObservedHistory.Valid],
    static_bindings.interfaceLinks, static_bindings.linkPolicies, static_bindings.headerGeneration, ?_,
    static_bindings.macsecKeys, static_bindings.ipsecKeys, static_bindings.redNetworks, static_bindings.peers,
    static_bindings.deviceIDs, static_bindings.interfaceIDs, static_bindings.tunnelIDs,
    static_bindings.interfaceIndices, ?_, static_bindings.physicalLinks, static_bindings.sourceEntries,
    static_bindings.macsecTunnels, static_bindings.ipsecTunnels⟩
  · intro start actions state initialized run
    have invariant : forwarding.system.TrInv ForwardingInvariant := by
      intro before action after step safe
      exact step_preserves_forwarding_invariant safe step
    have safe := Cslib.LTS.mtrInv_of_trInv invariant start actions state run (initial_selected_flow start initialized)
    exact ⟨safe.2.2.1.1.1, link_encoding_complete _ safe.1 state.native safe.2.2.1.2.1 safe.2.2.2.2⟩
  · intro state
    exact static_bindings.ifaceRecords state.native.iface state.ifacePresent

theorem snapshot_RG007_mixed_nested_layer_protection (independentKeys : String → String → Prop)
    (independent : IndependentLayerKeys independentKeys) :
    msc_nested_layer_protection deployment forwarding flows (fun start _ _ payload => flowAt start payload) independentKeys :=
  nested_layer_protection_from_local_checks deployment forwarding flows flowAt RemoteDestination
    ForwardingInvariant independentKeys deployment_covered architecture_services
    (flows_valid independentKeys independent) nested_flow_checks

end TDN.Deployments.NestedProtection_Mixed
