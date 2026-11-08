import TDN.Semantics.MultiProtocolEvents
import TDN.Targets.LayeredRequirements

namespace TDN.Targets
open MultiProtocolExecution LayeredFrame

def MixedRedOrigin (sources : List Nat) (state : MultiProtocolExecution.State) : Prop :=
  state.iface ∈ sources ∧ state.enteredIface = state.iface ∧ state.authenticated = [] ∧
  ((state.datapathStage = .localOutput ∧ ∃ header, state.frame.body = .datagram header) ∨
   (state.datapathStage = .ready ∧ ∃ header, state.frame.body = .ethernet header))

def mixedExecutionView (c : MultiProtocolExecution.Config)
    (sources grayIfaces blackIfaces : List Nat) (network : Nat → String) :
    PacketExecutionView MultiProtocolExecution.State MultiProtocolExecution.Action where
  system := MultiProtocolExecution.lts c
  source := MixedRedOrigin sources
  transmittedGray state := state.datapathStage = .ready ∧ state.iface ∈ grayIfaces
  transmittedBlack state := state.datapathStage = .ready ∧ state.iface ∈ blackIfaces
  plaintextDelivered state := state.datapathStage = .delivered
  layers state := state.frame.body.protectionLayers.map (fun tag => if tag = 1 then .inner else .outer)
  network state := network state.iface

lemma mixed_red_initial_invariant (c : MultiProtocolExecution.Config) (expectedEncapStack : Nat → List Nat)
    (sources : List Nat)
    (checked : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.ip.payloadOrigin iface)
    {state : MultiProtocolExecution.State} (origin : MixedRedOrigin sources state) :
    MultiProtocolExecution.StackInvariant c expectedEncapStack state := by
  obtain ⟨member, entered, empty, source⟩ := origin
  obtain ⟨stack, admitted⟩ := checked state.iface member
  rcases source with ⟨datapathStage, header, plain⟩ | ⟨datapathStage, header, plain⟩
  · refine ⟨?_, ?_⟩
    · simp [CarrierBodies, plain]
    · simp only [datapathStage]
      refine ⟨header, by simp [plain, Body.visibleHeader], ⟨?_, Or.inl empty, ?_⟩,
        Or.inl ?_, empty, entered⟩
      · simp [plain, Body.protectionLayers, Execution.encapStackAfterIngress, empty, entered, stack]
      · simp [entered]
      · simpa [entered] using admitted
  · exact ⟨by simp [CarrierBodies, plain], by simp [datapathStage, plain, Body.protectionLayers, stack]⟩

theorem mixed_nested_layers_from_local_checks
    (c : MultiProtocolExecution.Config) (expectedEncapStack : Nat → List Nat)
    (sources grayIfaces blackIfaces : List Nat) (network : Nat → String)
    (pairs : List ProtectionPair) (independentContexts : String → String → Prop)
    (conditions : MultiProtocolExecution.LocalConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.ip.payloadOrigin iface)
    (grayCheck : ∀ iface ∈ grayIfaces, expectedEncapStack iface = [1])
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    (configuration : ∀ pair ∈ pairs, pair.infrastructureComponents = true ∧
      independentContexts pair.innerKeyContext pair.outerKeyContext ∧
      (pair.outerMechanism = .macsec → pair.communicatingSites.length = 2)) :
    msc_nested_layer_protection (mixedExecutionView c sources grayIfaces blackIfaces network)
      pairs independentContexts := by
  apply nested_layers_from_operational_invariant _ _ _
    (MultiProtocolExecution.StackInvariant c expectedEncapStack)
  · exact fun _ origin => mixed_red_initial_invariant c expectedEncapStack sources sourceCheck origin
  · exact fun _ _ _ step valid => MultiProtocolExecution.step_preserves_stack conditions step valid
  · intro state invariant
    refine ⟨?_, ?_, ?_⟩
    · intro gray
      obtain ⟨ready, member⟩ := gray
      have stack : state.frame.body.protectionLayers = expectedEncapStack state.iface := by
        simpa only [ready] using invariant.2
      change state.frame.body.protectionLayers.map _ = _
      simp [stack, grayCheck state.iface member]
    · intro black
      obtain ⟨ready, member⟩ := black
      have stack : state.frame.body.protectionLayers = expectedEncapStack state.iface := by
        simpa only [ready] using invariant.2
      change state.frame.body.protectionLayers.map _ = _
      simp [stack, blackCheck state.iface member]
    · intro delivered
      change state.datapathStage = .delivered at delivered
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
    (c : MultiProtocolExecution.Config) (expectedEncapStack : Nat → List Nat)
    (sources blackIfaces : List Nat)
    (conditions : MultiProtocolExecution.LocalConditions c expectedEncapStack)
    (sourceCheck : ∀ iface ∈ sources, expectedEncapStack iface = [] ∧ c.ip.payloadOrigin iface)
    (blackCheck : ∀ iface ∈ blackIfaces, expectedEncapStack iface = [2, 1])
    (placement : ∀ iface, (expectedEncapStack iface).head? = some 2 → expectedEncapStack iface = [2, 1])
    {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}
    (source : MixedRedOrigin sources start) (run : (lts c).MTr start actions finish)
    (ready : finish.datapathStage = .ready) (black : finish.iface ∈ blackIfaces) :
    MultiProtocolExecution.OrderedEncryptions c 1 2 start actions finish := by
  have initial := mixed_red_initial_invariant c expectedEncapStack sources sourceCheck source
  have preserved := all_executions_preserve_stack c expectedEncapStack conditions run initial
  have layers : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
    simpa only [ready] using preserved.2
  apply MultiProtocolExecution.nested_stack_requires_ordered_encryptions c expectedEncapStack conditions 1 2
    placement run initial (mixed_red_origin_has_no_layers sources source)
  simp [layers, blackCheck finish.iface black]

end TDN.Targets
