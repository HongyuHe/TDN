import TDN.Deployments.NestedProtection_MixedTraceAcceptance

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma protection_path_source_allowed (path : ProtectionPath) (listed : path ∈ protectionPaths) :
    (binding deviceBinding ifaces).SourceRequestAllowed deployment path.sourceFlow.request := by
  have checked : ∀ path ∈ protectionPaths,
      sourceEntry records.entries path.sourceFlow.iface = some (records.redNetwork path.sourceFlow.domain) ∧
      ∃ network ∈ records.networks, network.id = records.redNetwork path.sourceFlow.domain := by native_decide
  exact ⟨Or.inl ⟨_, rfl⟩, rfl, checked path listed⟩

lemma sample_path_0_source_emitted :
    deviceBinding.sourceProcessing.process (samplePath 0).sourceFlow.request = .emitted [(samplePath 0).datagram] := rfl

lemma sample_path_1_source_emitted :
    deviceBinding.sourceProcessing.process (samplePath 1).sourceFlow.request = .emitted [(samplePath 1).datagram] := rfl

lemma protection_path_reaches (path : ProtectionPath) (listed : path ∈ protectionPaths)
    (emitted : deviceBinding.sourceProcessing.process path.sourceFlow.request = .emitted [path.datagram])
    (operations : List MultiProtocolForwarding.Action)
    (run : (⟨deviceBinding.AcceptedStep⟩ : Cslib.LTS _ _).MTr path.start operations (path.state path.moves.length)) :
    ∃ start actions finish, forwarding.initial start ∧ forwarding.system.MTr start actions finish ∧
      finish.native = path.state path.moves.length := by
  have allowed := protection_path_source_allowed path listed
  obtain ⟨_, start, initialized, sameStart, _⟩ := deployment_covered.2.2.2.1.2.1
    path.sourceFlow.request [path.datagram] path.datagram allowed emitted (by simp)
  obtain ⟨actions, finish, trace, sameFinish⟩ := device_trace_has_model_trace forwarding
    deployment_covered.2.2.1 run sameStart
  exact ⟨start, actions, finish, initialized, trace, sameFinish⟩

lemma sample_path_delivery_endpoints : ∀ path ∈ protectionPaths,
    (path.state path.moves.length).datapathStage = .delivered ∧
    (path.state path.moves.length).iface = path.destinationIface ∧
    configuration.ip.ifaceSecurityDomain path.destinationIface = some path.destinationDomain ∧
    records.redNetwork path.destinationDomain = path.destinationNetwork ∧
    (path.state path.moves.length).frame.originDomain = path.sourceFlow.domain ∧
    (path.state path.moves.length).frame.payload ≠ 0 ∧
    (path.state path.moves.length).frame.body.protectionLayers = [] := by native_decide

lemma mixed_paths_use_both_protection_layers : ∀ path ∈ protectionPaths,
    path.moves.length = 28 ∧ (path.state 12).frame.body.protectionLayers = [2,1] ∧
    (path.moves.filter (fun move => move.operation == .encryptIPsec)).length = 1 ∧
    (path.moves.filter (fun move => move.operation == .encryptMACsec)).length = 1 ∧
    (path.moves.filter (fun move => move.operation == .decryptMACsec)).length = 1 ∧
    (path.moves.filter (fun move => move.operation == .decryptIPsec)).length = 1 := by native_decide

lemma protected_path_delivery (path : ProtectionPath) (listed : path ∈ protectionPaths)
    (emitted : deviceBinding.sourceProcessing.process path.sourceFlow.request = .emitted [path.datagram])
    (operations : List MultiProtocolForwarding.Action)
    (run : (⟨deviceBinding.AcceptedStep⟩ : Cslib.LTS _ _).MTr path.start operations (path.state path.moves.length)) :
    ∃ start actions finish, forwarding.initial start ∧ forwarding.system.MTr start actions finish ∧
      finish.native.datapathStage = .delivered ∧ finish.native.iface = path.destinationIface ∧
      finish.native.frame.originDomain = path.sourceFlow.domain ∧ finish.native.frame.payload ≠ 0 ∧
      finish.native.frame.body.protectionLayers = [] := by
  obtain ⟨start, actions, finish, initialized, trace, same⟩ := protection_path_reaches path listed emitted operations run
  have result := sample_path_delivery_endpoints path listed
  rw [← same] at result
  exact ⟨start, actions, finish, initialized, trace, result.1, result.2.1,
    result.2.2.2.2.1, result.2.2.2.2.2.1, result.2.2.2.2.2.2⟩

theorem snapshot_RG007_mixed_forward_payload_delivered :
    ∃ start actions finish, forwarding.initial start ∧ forwarding.system.MTr start actions finish ∧
      finish.native.datapathStage = .delivered ∧ finish.native.iface = (samplePath 0).destinationIface ∧
      finish.native.frame.originDomain = (samplePath 0).sourceFlow.domain ∧ finish.native.frame.payload ≠ 0 ∧
      finish.native.frame.body.protectionLayers = [] :=
  protected_path_delivery (samplePath 0) (by exact List.mem_cons_self) sample_path_0_source_emitted _ sample_path_0_device_trace

theorem snapshot_RG007_mixed_reverse_payload_delivered :
    ∃ start actions finish, forwarding.initial start ∧ forwarding.system.MTr start actions finish ∧
      finish.native.datapathStage = .delivered ∧ finish.native.iface = (samplePath 1).destinationIface ∧
      finish.native.frame.originDomain = (samplePath 1).sourceFlow.domain ∧ finish.native.frame.payload ≠ 0 ∧
      finish.native.frame.body.protectionLayers = [] :=
  protected_path_delivery (samplePath 1) (by exact List.mem_cons_of_mem _ List.mem_cons_self) sample_path_1_source_emitted _ sample_path_1_device_trace

lemma recorded_layer_key_contexts_are_nonempty : ∀ selected ∈ contexts,
    (flowKeyContexts selected).1 ≠ "" ∧ (flowKeyContexts selected).2 ≠ "" := by native_decide

theorem snapshot_RG007_mixed_missing_key_independence_rejected :
    ¬ msc_nested_layer_protection deployment forwarding flows
      (fun start _ _ payload => flowAt start payload) (fun _ _ => False) := by
  intro claimed
  have member : (contexts.head (by native_decide)).flow ∈ flows := by native_decide
  have valid := claimed.2.2.1 _ member
  obtain ⟨inner, innerMember, outer, outerMember, innerName, outerName, innerLayer, outerLayer,
    independent, remaining⟩ := valid
  exact independent

lemma mixed_source_and_destination_networks_differ : ∀ selected ∈ contexts,
    selected.flow.sourceNetwork ≠ selected.flow.destinationNetwork := by native_decide

lemma mismatched_macsec_sci_is_rejected :
    ¬ SameMACWireIdentity (sampleMove 0 10).transmitted (sampleMove 1 14).receiveAssociation := by
  unfold SameMACWireIdentity
  native_decide
lemma opposite_direction_macsec_key_is_rejected :
    ¬ MACsecKeyMaterialMatches records.macsecMaterial
      (sampleMove 0 10).transmitted (sampleMove 1 14).receiveAssociation := by
  rintro ⟨key, length, first, second⟩
  have different : records.macsecMaterial (sampleMove 0 10).transmitted ≠
      records.macsecMaterial (sampleMove 1 14).receiveAssociation := by native_decide
  exact different (first.trans second.symm)

end TDN.Deployments.NestedProtection_Mixed
