import TDN.Requirements.IPsecConfiguredEncapStack
import TDN.Requirements.OuterTunnelNoBypass
import TDN.Requirements.IPsecMultiIfacePolicyGuards
import TDN.Requirements.IPsecForwardingOutputMetadata
import TDN.Requirements.StandardEncapStackBridge

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

structure IPsecOuterBoundaryChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (stack : Nat → List Nat) (outer : Nat → Prop) (processing : HeaderProcessing) : Prop where
  layerNames : IPsecEncapLayerChecks binding d
  sourceNotGray : ∀ iface network, binding.sourceEntry iface = some network →
    ∀ interface ∈ d.interfaces, interface.id = binding.ifaceName iface →
      d.IsLayer interface.device .outer → interface.zone ≠ .gray
  stackSteps : HeaderedLocalConditions binding.configuration stack
  mode : binding.configuration.headerProcessing = some processing
  bounds : HeaderBounds processing
  metadata : IPsecOutputMetadataChecks binding.configuration outer
  redOrigins : ∀ domain, ∃ network, binding.origin domain = .red network
  sourceEncapStacks : ∀ iface network, binding.sourceEntry iface = some network → stack iface = []
  interfaceOwners : ∀ iface interface, interface ∈ d.interfaces → interface.id = binding.ifaceName iface →
    d.IsLayer interface.device .outer → outer (binding.configuration.ip.owner iface)
  internalInputs : ∀ first last, binding.configuration.physicalLink first last →
    ∀ interface ∈ d.interfaces, interface.id = binding.ifaceName last → d.IsLayer interface.device .outer →
      interface.zone = .gray → stack last = [1]
  internalOutputs : ∀ first last, binding.configuration.physicalLink first last →
    ∀ interface ∈ d.interfaces, interface.id = binding.ifaceName first → d.IsLayer interface.device .outer →
      interface.zone = .gray → stack first = [1]
  externalOutputs : ∀ iface next, binding.configuration.physicalLink iface next →
    ∀ interface ∈ d.interfaces, interface.id = binding.ifaceName iface →
    d.IsLayer interface.device .outer → interface.zone ≠ .gray →
      binding.configuration.ip.interfaceName iface = "black" ∧
      ForwardChainRequiresIPsecAcross binding.configuration iface "black"
  policyOwners : ∀ first last, binding.configuration.ip.owner first = binding.configuration.ip.owner last →
    binding.configuration.ip.egressPolicies first = binding.configuration.ip.egressPolicies last ∧
    binding.configuration.ip.egressSAs first = binding.configuration.ip.egressSAs last
  configuredOuterOutputs : ∀ iface policy association route,
    policy ∈ binding.configuration.ip.egressPolicies iface →
    association ∈ binding.configuration.ip.egressSAs iface →
    DataPlaneForwarding.saMatchesPolicy association policy →
    route ∈ binding.configuration.ip.routes → route.egress = iface →
    route.destPrefixLow ≤ association.receiver → association.receiver ≤ route.destPrefixHigh →
    ∀ interface ∈ d.interfaces, interface.id = binding.ifaceName iface → d.IsLayer interface.device .outer →
      ∃ tunnel ∈ d.tunnels, tunnel.layer = .outer ∧ tunnel.sender = interface.device ∧
        tunnel.id = binding.ipsecTunnel (policy.seal association)

def IPsecOuterBoundaryStateSafe {S A : Type} (binding : DeviceExecutionBinding S A) (d : Deployment) (config : Config) (stack : Nat → List Nat) (outer : Nat → Prop)
    (state : MultiProtocolForwarding.State) : Prop :=
  HeaderedStackInvariant config stack state ∧ IPsecForwardingMetadata config outer (fun _ _ => False) state ∧
    IPsecBodyHasConfiguredLayers binding d state.frame.body

lemma ipsec_outer_boundary_state_initialized {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (stack : Nat → List Nat) (outer : Nat → Prop) (processing : HeaderProcessing)
    (checks : IPsecOuterBoundaryChecks binding d stack outer processing)
    (state : MultiProtocolForwarding.State) (initial : binding.SourceInitial d state) :
    IPsecOuterBoundaryStateSafe binding d binding.configuration stack outer state := by
  obtain ⟨network, red⟩ := checks.redOrigins state.frame.originDomain
  have sourceShape := initial.2.2.2
  rw [red] at sourceShape
  refine ⟨binding.source_initial_red_stack d stack checks.sourceEncapStacks state initial network red,
    fun _ => by simp [IPsecOutputStageMetadata, sourceShape.1], ?_⟩
  rcases initial.2.1 with ⟨header, plain⟩ | ⟨header, plain⟩ <;> simp [plain, IPsecBodyHasConfiguredLayers]

lemma ipsec_outer_boundary_state_preserved {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (stack : Nat → List Nat) (outer : Nat → Prop) (processing : HeaderProcessing)
    (checks : IPsecOuterBoundaryChecks binding d stack outer processing)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (safe : IPsecOuterBoundaryStateSafe binding d binding.configuration stack outer before) :
    IPsecOuterBoundaryStateSafe binding d binding.configuration stack outer after :=
  ⟨headered_step_preserves_stack checks.stackSteps processing checks.mode checks.bounds step safe.1,
    ipsec_step_preserves_output_metadata binding.configuration outer (fun _ _ => False)
      checks.metadata processing checks.mode step safe.1.1 safe.2.1,
    ipsec_step_preserves_configured_layers binding d checks.layerNames step safe.2.2⟩

lemma ipsec_operation_events_have_outer_boundary_shape {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (stack : Nat → List Nat) (outer : Nat → Prop) (processing : HeaderProcessing)
    (checks : IPsecOuterBoundaryChecks binding d stack outer processing) (genuineControl : PayloadId → Prop)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (safe : IPsecOuterBoundaryStateSafe binding d binding.configuration stack outer before) :
    ∀ event ∈ (binding.withProjection id (fun action => some action)).OperationEvents before operation after,
      LayerOutboundEventShape d genuineControl .outer event := by
  by_cases transmitting : operation = .linkTransmit
  · subst operation
    have safeAfter := ipsec_outer_boundary_state_preserved binding d stack outer processing checks step safe
    cases step with
    | linkTransmit next ready linked =>
      have names : ∀ body, (binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
          (fun action : MultiProtocolForwarding.Action => some action)).LayerIds body = binding.LayerIds body :=
        layer_ids_with_tunnel_names binding _ _
      dsimp only [DeviceExecutionBinding.withProjection] at names
      intro event member
      simp only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq,
        List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl | rfl | rfl
      · trivial
      · intro _ interface stored name component
        constructor
        · intro internal tunnel member selectedLayer
          have expected := checks.internalOutputs _ _ linked interface stored name component internal
          have actual : before.frame.body.protectionLayers = [1] := by
            have invariant := safe.1.2.2
            simpa [ready, expected] using invariant
          simp only [names]
          exact single_inner_ipsec_stack_has_no_outer_name binding d checks.layerNames _ safe.2.2 actual tunnel member selectedLayer
        · intro external
          have owner := checks.interfaceOwners _ interface stored name component
          have metadata : IPsecEncryptedOutput binding.configuration before ∨
            (∃ header, before.frame.visibleHeader = some header ∧ Routed binding.configuration before header ∧
              IPsecForwardHook binding.configuration (fun _ _ => False) before header ∧
              DataPlaneForwarding.lookupSpdPolicies (binding.configuration.ip.egressPolicies before.iface) header = []) := by
            simpa only [IPsecOutputStageMetadata, ready] using safe.2.1 owner
          rcases metadata with encrypted | ⟨header, shown, route, hook, noPolicy⟩
          · obtain ⟨iface, policy, association, body, route, configured, installed, bound, framed,
                owner, routeMember, egress, low, high⟩ := encrypted
            obtain ⟨policies, associations⟩ := checks.policyOwners iface before.iface owner
            obtain ⟨tunnel, member, selectedLayer, sender, identity⟩ :=
              checks.configuredOuterOutputs before.iface policy association route (policies ▸ configured)
                (associations ▸ installed) bound routeMember egress low high interface stored name component
            refine ⟨tunnel, member, selectedLayer, sender, ?_⟩
            simp only [names, framed, DeviceExecutionBinding.LayerIds, identity, List.mem_cons, true_or]
          · obtain ⟨gray, guarded⟩ := checks.externalOutputs _ _ linked interface stored name component external
            rcases hook with accepted | ⟨impossible, accepted⟩
            · exact False.elim ((accepted_external_output_across_requires_policy binding.configuration before header "black"
                guarded gray accepted) noPolicy)
            · exact False.elim impossible
      · intro _ interface stored name component internal tunnel member selectedLayer
        have expected := checks.internalInputs _ _ linked interface stored name component internal
        have actual : before.frame.body.protectionLayers = [1] := by
          have invariant := safeAfter.1.2.2
          simpa [expected] using invariant
        simp only [names]
        exact single_inner_ipsec_stack_has_no_outer_name binding d checks.layerNames _ safeAfter.2.2 actual tunnel member selectedLayer
      · trivial
  · exact nontransmit_operation_events_have_boundary_shape _ d .outer genuineControl before after operation transmitting

def ipsecOuterOutboundChecks {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (stack : Nat → List Nat) (outer : Nat → Prop) (processing : HeaderProcessing)
    (covered : model.CoversDeployment d)
    (checks : IPsecOuterBoundaryChecks model.native d stack outer processing) : LayerOutboundLocalChecks d model .outer := by
  refine ⟨fun state => IPsecOuterBoundaryStateSafe model.native d model.native.configuration stack outer (model.native.state state), ?_, ?_, ?_⟩
  · intro state initial
    exact ipsec_outer_boundary_state_initialized model.native d stack outer processing checks _
      (covered.2.2.2.1.2.2.2.1 state initial).1
  · intro before action after step safe
    have faithful := covered.2.1 before action after step
    cases selected : model.native.action action with
    | none => rw [selected] at faithful; rw [← faithful.1]; exact safe
    | some operation =>
      rw [selected] at faithful
      exact ipsec_outer_boundary_state_preserved model.native d stack outer processing checks faithful.1.1 safe
  · intro before action after step safe event member
    by_cases network : event.NetworkOperation = true
    · have recorded := List.mem_filter.mpr ⟨member, network⟩
      have faithful := covered.2.1 before action after step
      cases selected : model.native.action action with
      | none => rw [selected] at faithful; rw [faithful.2] at recorded; simp at recorded
      | some operation =>
        rw [selected] at faithful
        rw [faithful.2, DeviceExecutionBinding.RequiredEvents] at recorded
        rcases List.mem_append.mp recorded with source | operationEvent
        · exact source_events_have_boundary_shape _ _ _ _ _ event source
        · have localEvents := ipsec_operation_events_have_outer_boundary_shape model.native d stack outer processing checks
            model.GenuineControl faithful.1.1 safe
          have projected : (model.native.withProjection id (fun action => some action)).OperationEvents
              (model.native.state before) operation (model.native.state after) =
              model.native.OperationEvents before operation after := by
            have names : ∀ body, (model.native.withProjection
                (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
                (fun action : MultiProtocolForwarding.Action => some action)).LayerIds body =
                model.native.LayerIds body := layer_ids_with_tunnel_names model.native _ _
            dsimp only [DeviceExecutionBinding.withProjection] at names
            simp only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq, names]
          rw [projected] at localEvents
          exact localEvents event operationEvent
    · exact non_network_event_has_boundary_shape d .outer model.GenuineControl event (by cases value : event.NetworkOperation <;> simp_all)

end TDN.Requirements.Msc
