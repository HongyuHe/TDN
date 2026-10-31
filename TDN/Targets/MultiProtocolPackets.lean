import TDN.Semantics.MultiProtocolEvents
import TDN.Targets.LayeredRequirements

namespace TDN.Targets
open MultiProtocolExecution LayeredFrame

def MixedRedOrigin (sources : List Nat) (state : MultiProtocolExecution.State) : Prop :=
  state.port ∈ sources ∧ state.enteredPort = state.port ∧ state.authenticated = [] ∧
  ((state.phase = .localOutput ∧ ∃ header, state.frame.body = .datagram header) ∨
   (state.phase = .ready ∧ ∃ header, state.frame.body = .ethernet header))

def mixedExecutionView (c : MultiProtocolExecution.Config)
    (sources grayPorts blackPorts : List Nat) (network : Nat → String) :
    PacketExecutionView MultiProtocolExecution.State MultiProtocolExecution.Action where
  system := MultiProtocolExecution.lts c
  source := MixedRedOrigin sources
  transmittedGray state := state.phase = .ready ∧ state.port ∈ grayPorts
  transmittedBlack state := state.phase = .ready ∧ state.port ∈ blackPorts
  plaintextDelivered state := state.phase = .delivered
  layers state := state.frame.body.protectionLayers.map (fun tag => if tag = 1 then .inner else .outer)
  network state := network state.port

lemma mixed_red_initial_invariant (c : MultiProtocolExecution.Config) (layout : Nat → List Nat)
    (sources : List Nat)
    (checked : ∀ port ∈ sources, layout port = [] ∧ c.ip.payloadOrigin port)
    {state : MultiProtocolExecution.State} (origin : MixedRedOrigin sources state) :
    MultiProtocolExecution.StackInvariant c layout state := by
  obtain ⟨member, entered, empty, source⟩ := origin
  obtain ⟨stack, admitted⟩ := checked state.port member
  rcases source with ⟨phase, header, plain⟩ | ⟨phase, header, plain⟩
  · refine ⟨?_, ?_⟩
    · simp [CarrierBodies, plain]
    · simp only [phase]
      refine ⟨header, by simp [plain, Body.visibleHeader], ⟨?_, Or.inl empty, ?_⟩,
        Or.inl ?_, empty, entered⟩
      · simp [plain, Body.protectionLayers, Execution.processingStack, empty, entered, stack]
      · simp [entered]
      · simpa [entered] using admitted
  · exact ⟨by simp [CarrierBodies, plain], by simp [phase, plain, Body.protectionLayers, stack]⟩

theorem mixed_nested_layers_from_local_checks
    (c : MultiProtocolExecution.Config) (layout : Nat → List Nat)
    (sources grayPorts blackPorts : List Nat) (network : Nat → String)
    (pairs : List ProtectionPair) (independentContexts : String → String → Prop)
    (conditions : MultiProtocolExecution.LocalConditions c layout)
    (sourceCheck : ∀ port ∈ sources, layout port = [] ∧ c.ip.payloadOrigin port)
    (grayCheck : ∀ port ∈ grayPorts, layout port = [1])
    (blackCheck : ∀ port ∈ blackPorts, layout port = [2, 1])
    (configuration : ∀ pair ∈ pairs, pair.infrastructureComponents = true ∧
      independentContexts pair.innerKeyContext pair.outerKeyContext ∧
      (pair.outerMechanism = .macsec → pair.communicatingSites.length = 2)) :
    msc_nested_layer_protection (mixedExecutionView c sources grayPorts blackPorts network)
      pairs independentContexts := by
  apply nested_layers_from_operational_invariant _ _ _
    (MultiProtocolExecution.StackInvariant c layout)
  · exact fun _ origin => mixed_red_initial_invariant c layout sources sourceCheck origin
  · exact fun _ _ _ step valid => MultiProtocolExecution.step_preserves_stack conditions step valid
  · intro state invariant
    refine ⟨?_, ?_, ?_⟩
    · intro gray
      obtain ⟨ready, member⟩ := gray
      have stack : state.frame.body.protectionLayers = layout state.port := by
        simpa only [ready] using invariant.2
      change state.frame.body.protectionLayers.map _ = _
      simp [stack, grayCheck state.port member]
    · intro black
      obtain ⟨ready, member⟩ := black
      have stack : state.frame.body.protectionLayers = layout state.port := by
        simpa only [ready] using invariant.2
      change state.frame.body.protectionLayers.map _ = _
      simp [stack, blackCheck state.port member]
    · intro delivered
      change state.phase = .delivered at delivered
      have empty : state.frame.body.protectionLayers = [] := by
        simpa only [delivered] using invariant.2
      change state.frame.body.protectionLayers.map _ = []
      simp [empty]
  · exact configuration

lemma mixed_red_origin_has_no_layers (sources : List Nat)
    {state : MultiProtocolExecution.State} (origin : MixedRedOrigin sources state) :
    state.frame.body.protectionLayers = [] := by
  rcases origin.2.2.2 with ⟨_, header, plain⟩ | ⟨_, header, plain⟩ <;>
    simp [plain, Body.protectionLayers]

theorem mixed_black_transmission_has_ordered_encryptions
    (c : MultiProtocolExecution.Config) (layout : Nat → List Nat)
    (sources blackPorts : List Nat)
    (conditions : MultiProtocolExecution.LocalConditions c layout)
    (sourceCheck : ∀ port ∈ sources, layout port = [] ∧ c.ip.payloadOrigin port)
    (blackCheck : ∀ port ∈ blackPorts, layout port = [2, 1])
    (placement : ∀ port, (layout port).head? = some 2 → layout port = [2, 1])
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : MixedRedOrigin sources start) (run : (lts c).MTr start actions finish)
    (ready : finish.phase = .ready) (black : finish.port ∈ blackPorts) :
    MultiProtocolExecution.OrderedEncryptions c 1 2 start actions finish := by
  have initial := mixed_red_initial_invariant c layout sources sourceCheck source
  have preserved := all_executions_preserve_stack c layout conditions run initial
  have layers : finish.frame.body.protectionLayers = layout finish.port := by
    simpa only [ready] using preserved.2
  apply MultiProtocolExecution.nested_stack_requires_ordered_encryptions c layout conditions 1 2
    placement run initial (mixed_red_origin_has_no_layers sources source)
  simp [layers, blackCheck finish.port black]

end TDN.Targets
